// SPDX-License-Identifier: MIT
//! kernoid-sync: a folder kept in step with a file store of kernoid (RFC 0005) – the logic every one of kernoid's apps
//! shares, whatever shows the files (a folder, the system's file manager through a native shell).
//!
//! One round ([`Folder::sync`]): the store's changes since the state last read (`FileNode/changes`; the whole store
//! when there is no state or it is too old), the folder scanned (size and modification time tell a change), both
//! compared with what they were when they last agreed ([`plan`]), and the actions carried out. A change on both sides
//! keeps both: the server's version takes the name, the local one becomes a copy beside it. The local state is a
//! SQLite database outside the folder ([`state`]).
//!
//! OPEN: moves as moves (today a deletion and a creation), transfers resumed after an interruption (RFC 9404),
//! content hashes to tell a change that keeps size and time, vaults (RFC 0006, 6: their names are encrypted), the
//! file systems' own name rules (Windows).

pub mod plan;
pub mod state;

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use kernoid_client::{
    Client, FILENODE,
    files::{self, FileNode},
};
use serde_json::{Value, json};

use plan::{Action, Base, Local, RelPath, Remote};
use state::{Node, State};

/// Changes asked for at once.
const MAX_CHANGES: u64 = 500;
/// The suffix of a download not finished yet; such files are not part of the folder.
const PARTIAL: &str = ".kernoid-part";

#[derive(Debug)]
pub enum Error {
    /// Talking to kernoid.
    Client(kernoid_client::Error),
    /// The local state.
    State(String),
    /// The folder.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "{error}"),
            Self::State(error) => write!(f, "the local state: {error}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<kernoid_client::Error> for Error {
    fn from(error: kernoid_client::Error) -> Self {
        Self::Client(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// What a round did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub downloaded: usize,
    pub uploaded: usize,
    pub deleted_here: usize,
    pub deleted_there: usize,
    pub directories: usize,
    /// Local files kept as copies beside the server's version.
    pub conflicts: Vec<RelPath>,
    /// Actions that failed, with why; the next round tries them again.
    pub failed: Vec<(RelPath, String)>,
    /// Nodes of the store left out: names a folder cannot hold.
    pub skipped: Vec<String>,
}

/// A folder kept in step with one store (an account's own files, a drive, or files shared with the user).
#[derive(Debug)]
pub struct Folder {
    root: PathBuf,
    store: String,
    state: State,
}

impl Folder {
    /// The folder at `root` for the store `store` (a JMAP account id), with its state in `state` (made if missing).
    pub fn open(root: impl Into<PathBuf>, store: &str, state: &Path) -> Result<Folder> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        let state = State::open(state)?;
        match state.meta("store")? {
            Some(known) if known != store => {
                return Err(Error::State(format!("this state belongs to the store {known}, not {store}")));
            }
            Some(_) => {}
            None => state.set_meta("store", store)?,
        }
        Ok(Folder { root, store: store.to_owned(), state })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// One round: reads what changed on both sides and brings them into step.
    pub async fn sync(&mut self, client: &Client) -> Result<Report> {
        let mut report = Report::default();
        let mut nodes = self.read_store(client).await?;
        let remote = tree(&nodes, &mut report.skipped);
        let local = scan(&self.root)?;
        let mut base = self.state.base()?;
        let actions = plan::plan(&base, &paths(&remote), &local);
        let mut trash = None;
        // Paths changed on the server by this round: their node is read again at the end.
        let mut touched: Vec<RelPath> = Vec::new();
        for action in actions {
            let path = action_path(&action).to_owned();
            match self.run(client, &action, &remote, &mut base, &mut trash, &mut touched).await {
                Ok(()) => count(&mut report, &action),
                Err(error) => report.failed.push((path, error.to_string())),
            }
        }
        // Read the store again: what this round made there gets the server's ids and blobs. Changes by others in
        // the meantime stay with their old base, so the next round sees them.
        if !touched.is_empty() {
            nodes = self.read_store(client).await?;
            let after = tree(&nodes, &mut Vec::new());
            for path in touched {
                if let (Some((node, _)), Some(entry)) = (after.get(&path), base.get_mut(&path)) {
                    entry.remote = remote_of(node);
                }
            }
        }
        self.state.set_base(&base)?;
        Ok(report)
    }

    /// The store's tree, brought up to date with its changes – or read whole.
    async fn read_store(&mut self, client: &Client) -> Result<BTreeMap<String, Node>> {
        let mut nodes = self.state.remote()?;
        let mut since = self.state.meta("state")?.filter(|state| !state.is_empty());
        loop {
            let Some(state) = since.clone() else {
                let snapshot = files::snapshot(client, &self.store).await?;
                nodes = snapshot.nodes.iter().map(|node| (node.id.clone(), node_of(node))).collect();
                self.state.set_remote(&nodes, &snapshot.state)?;
                return Ok(nodes);
            };
            match files::changes(client, &self.store, &state, MAX_CHANGES).await {
                Ok(changes) => {
                    for id in &changes.destroyed {
                        nodes.remove(id);
                    }
                    for node in &changes.changed {
                        nodes.insert(node.id.clone(), node_of(node));
                    }
                    self.state.set_remote(&nodes, &changes.new_state)?;
                    if !changes.has_more_changes {
                        return Ok(nodes);
                    }
                    since = Some(changes.new_state);
                }
                Err(kernoid_client::Error::Method { kind, .. }) if kind == "cannotCalculateChanges" => since = None,
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn run(
        &self,
        client: &Client,
        action: &Action,
        remote: &BTreeMap<RelPath, (Node, Remote)>,
        base: &mut BTreeMap<RelPath, Base>,
        trash: &mut Option<Option<String>>,
        touched: &mut Vec<RelPath>,
    ) -> Result<()> {
        match action {
            Action::KeepLocalCopy(path) => {
                let from = self.local(path);
                tokio::fs::rename(&from, conflict_copy(&from)).await?;
                base.remove(path);
            }
            Action::DeleteLocal(path) => {
                let at = self.local(path);
                match tokio::fs::symlink_metadata(&at).await {
                    Ok(meta) if meta.is_dir() => tokio::fs::remove_dir_all(&at).await?,
                    Ok(_) => tokio::fs::remove_file(&at).await?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                forget(base, path);
            }
            Action::MakeLocalDirectory(path) => {
                let at = self.local(path);
                tokio::fs::create_dir_all(&at).await?;
                let (_, node) = remote.get(path).ok_or_else(|| gone(path))?;
                base.insert(path.clone(), Base { remote: node.clone(), local: stat(&at)? });
            }
            Action::Download { path, id, blob } => {
                let at = self.local(path);
                let partial = PathBuf::from(format!("{}{PARTIAL}", at.display()));
                let mut file = tokio::fs::File::create(&partial).await?;
                let name = path.rsplit('/').next().unwrap_or(path);
                let result = client
                    .download(&self.store, blob, name, "application/octet-stream", &mut file, &mut |_, _| {})
                    .await;
                if let Err(error) = result {
                    let _ = tokio::fs::remove_file(&partial).await;
                    return Err(error.into());
                }
                file.sync_all().await?;
                drop(file);
                tokio::fs::rename(&partial, &at).await?;
                let (_, node) = remote.get(path).filter(|(n, _)| &n.id == id).ok_or_else(|| gone(path))?;
                base.insert(path.clone(), Base { remote: node.clone(), local: stat(&at)? });
            }
            Action::MakeRemoteDirectory(path) => {
                let (parent, name) = self.parent_and_name(path, remote, base)?;
                let create = json!({ "create": { "d": { "@type": "Directory", "parentId": parent, "name": name } } });
                let result = client.set(&[FILENODE], "FileNode", &self.store, create, json!({})).await?;
                let id = created_id(&result)?;
                let local = stat(&self.local(path))?;
                base.insert(path.clone(), Base { remote: Remote { id, directory: true, blob: None, size: 0 }, local });
                touched.push(path.clone());
            }
            Action::Upload { path, id } => {
                let at = self.local(path);
                // The state of the file before it is read: a change while it travels shows in the next round.
                let local = stat(&at)?;
                let name = path.rsplit('/').next().unwrap_or(path).to_owned();
                let kind = files::media_type(&name);
                let file = tokio::fs::File::open(&at).await?;
                let upload = client.upload(&self.store, kind, file, local.size, |_, _| {}).await?;
                let node_id = match id {
                    Some(id) => {
                        let update =
                            json!({ "update": { id.as_str(): { "blobId": upload.blob_id, "mediaType": kind } } });
                        client.set(&[FILENODE], "FileNode", &self.store, update, json!({})).await?;
                        id.clone()
                    }
                    None => {
                        let (parent, _) = self.parent_and_name(path, remote, base)?;
                        let create = json!({ "create": { "f": {
                            "@type": "File", "parentId": parent, "name": name, "blobId": upload.blob_id,
                            "mediaType": kind,
                        } } });
                        let result = client.set(&[FILENODE], "FileNode", &self.store, create, json!({})).await?;
                        created_id(&result)?
                    }
                };
                let remote = Remote { id: node_id, directory: false, blob: Some(upload.blob_id), size: upload.size };
                base.insert(path.clone(), Base { remote, local });
                touched.push(path.clone());
            }
            Action::DeleteRemote { path, id } => {
                if trash.is_none() {
                    *trash = Some(files::trash(client, &self.store).await?.map(|node| node.id));
                }
                match trash.as_ref().and_then(Option::as_ref) {
                    Some(trash) => files::move_to(client, &self.store, id, Some(trash)).await?,
                    None => files::destroy(client, &self.store, id).await?,
                }
                forget(base, path);
            }
            Action::Adopt(path) => {
                let (_, node) = remote.get(path).ok_or_else(|| gone(path))?;
                base.insert(path.clone(), Base { remote: node.clone(), local: stat(&self.local(path))? });
            }
        }
        Ok(())
    }

    fn local(&self, path: &str) -> PathBuf {
        path.split('/').fold(self.root.clone(), |at, part| at.join(part))
    }

    /// The id of a path's parent in the store – `None` at the top – and its name.
    fn parent_and_name(
        &self,
        path: &str,
        remote: &BTreeMap<RelPath, (Node, Remote)>,
        base: &BTreeMap<RelPath, Base>,
    ) -> Result<(Option<String>, String)> {
        let Some((parent, name)) = path.rsplit_once('/') else { return Ok((None, path.to_owned())) };
        let id = base
            .get(parent)
            .map(|entry| entry.remote.id.clone())
            .or_else(|| remote.get(parent).map(|(node, _)| node.id.clone()))
            .ok_or_else(|| gone(parent))?;
        Ok((Some(id), name.to_owned()))
    }
}

fn gone(path: &str) -> Error {
    Error::State(format!("{path}: not in the store (any more)"))
}

fn action_path(action: &Action) -> &str {
    match action {
        Action::MakeLocalDirectory(path)
        | Action::MakeRemoteDirectory(path)
        | Action::DeleteLocal(path)
        | Action::KeepLocalCopy(path)
        | Action::Adopt(path) => path,
        Action::Download { path, .. } | Action::Upload { path, .. } | Action::DeleteRemote { path, .. } => path,
    }
}

fn count(report: &mut Report, action: &Action) {
    match action {
        Action::Download { .. } => report.downloaded += 1,
        Action::Upload { .. } => report.uploaded += 1,
        Action::DeleteLocal(_) => report.deleted_here += 1,
        Action::DeleteRemote { .. } => report.deleted_there += 1,
        Action::MakeLocalDirectory(_) | Action::MakeRemoteDirectory(_) => report.directories += 1,
        Action::KeepLocalCopy(path) => report.conflicts.push(path.clone()),
        Action::Adopt(_) => {}
    }
}

/// Forgets a path and what lies below it.
fn forget(base: &mut BTreeMap<RelPath, Base>, path: &str) {
    let prefix = format!("{path}/");
    base.retain(|known, _| known != path && !known.starts_with(&prefix));
}

fn created_id(result: &Value) -> Result<String> {
    result
        .get("created")
        .and_then(Value::as_object)
        .and_then(|created| created.values().next())
        .and_then(|node| node.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Client(kernoid_client::Error::Protocol("no id for what was made".into())))
}

fn node_of(node: &FileNode) -> Node {
    Node {
        id: node.id.clone(),
        parent: node.parent_id.clone(),
        name: node.name.clone(),
        directory: node.is_directory(),
        blob: node.blob_id.clone(),
        size: node.size.unwrap_or_default(),
        role: node.role.clone(),
    }
}

fn remote_of(node: &Node) -> Remote {
    Remote { id: node.id.clone(), directory: node.directory, blob: node.blob.clone(), size: node.size }
}

/// Whether a name of the store can be a name in a folder.
fn usable(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0']) && !name.ends_with(PARTIAL)
}

/// The store's nodes by path – without the trash and what is in it, and without names a folder cannot hold (they
/// go to `skipped`, with what is below them).
pub fn tree(nodes: &BTreeMap<String, Node>, skipped: &mut Vec<String>) -> BTreeMap<RelPath, (Node, Remote)> {
    let mut out = BTreeMap::new();
    for node in nodes.values() {
        let mut parts = Vec::new();
        let mut at = Some(node);
        let mut ok = true;
        while let Some(current) = at {
            if current.role.as_deref() == Some("trash") || !usable(&current.name) || parts.len() > 64 {
                ok = false;
                if !usable(&current.name) && current.id == node.id {
                    skipped.push(node.name.clone());
                }
                break;
            }
            parts.push(current.name.as_str());
            at = current.parent.as_ref().and_then(|parent| nodes.get(parent));
            if at.is_none() && current.parent.is_some() {
                // A parent the user cannot see: the node is not reachable from the top.
                ok = false;
            }
        }
        if ok {
            parts.reverse();
            out.insert(parts.join("/"), (node.clone(), remote_of(node)));
        }
    }
    out
}

fn paths(tree: &BTreeMap<RelPath, (Node, Remote)>) -> BTreeMap<RelPath, Remote> {
    tree.iter().map(|(path, (_, remote))| (path.clone(), remote.clone())).collect()
}

fn stat(path: &Path) -> Result<Local> {
    let meta = std::fs::symlink_metadata(path)?;
    let modified = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_nanos() as i128);
    Ok(Local { directory: meta.is_dir(), size: if meta.is_dir() { 0 } else { meta.len() }, modified })
}

/// The files and directories of a folder by path; links, unfinished downloads and other kinds are left out.
pub fn scan(root: &Path) -> Result<BTreeMap<RelPath, Local>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if !usable(&name) {
                continue;
            }
            let kind = entry.file_type()?;
            if !kind.is_dir() && !kind.is_file() {
                continue;
            }
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            out.insert(path.clone(), stat(&entry.path())?);
            if kind.is_dir() {
                stack.push((entry.path(), path));
            }
        }
    }
    Ok(out)
}

/// `report (conflict 2026-10-30 1412).txt` beside `report.txt` – a name not taken yet.
pub fn conflict_copy(path: &Path) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let extension = path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    let when = chrono::Local::now().format("%Y-%m-%d %H%M");
    let mut candidate = path.with_file_name(format!("{stem} (conflict {when}){extension}"));
    let mut n = 2;
    while candidate.exists() {
        candidate = path.with_file_name(format!("{stem} (conflict {when} {n}){extension}"));
        n += 1;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, parent: Option<&str>, name: &str, directory: bool) -> (String, Node) {
        (
            id.into(),
            Node {
                id: id.into(),
                parent: parent.map(Into::into),
                name: name.into(),
                directory,
                blob: (!directory).then(|| format!("b-{id}")),
                size: 1,
                role: None,
            },
        )
    }

    #[test]
    fn the_tree_by_path_without_the_trash_and_bad_names() {
        let mut nodes: BTreeMap<String, Node> = [
            node("1", None, "Projects", true),
            node("2", Some("1"), "plan.txt", false),
            node("3", None, "Trash", true),
            node("4", Some("3"), "old.txt", false),
            node("5", None, "..", false),
            node("6", Some("9"), "orphan.txt", false),
        ]
        .into_iter()
        .collect();
        nodes.get_mut("3").unwrap().role = Some("trash".into());
        let mut skipped = Vec::new();
        let tree = tree(&nodes, &mut skipped);
        assert_eq!(tree.keys().collect::<Vec<_>>(), ["Projects", "Projects/plan.txt"]);
        assert_eq!(skipped, [".."]);
    }

    #[test]
    fn a_folder_scanned_and_a_conflict_copy_named() {
        let root = std::env::temp_dir().join(format!("kernoid-sync-scan-{}", std::process::id()));
        std::fs::create_dir_all(root.join("D")).unwrap();
        std::fs::write(root.join("D/a.txt"), "abc").unwrap();
        std::fs::write(root.join(format!("b.txt{PARTIAL}")), "half").unwrap();
        let found = scan(&root).unwrap();
        assert_eq!(found.keys().collect::<Vec<_>>(), ["D", "D/a.txt"]);
        assert_eq!((found["D/a.txt"].size, found["D"].directory), (3, true));
        let copy = conflict_copy(&root.join("D/a.txt"));
        let name = copy.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("a (conflict ") && name.ends_with(").txt"), "{name}");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
