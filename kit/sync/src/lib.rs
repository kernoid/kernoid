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
//! Moves are carried over as moves ([`plan`]). A download that breaks off goes on where it stopped (an HTTP range); a
//! large upload goes in pieces of 8 MiB joined on the server (`Blob/upload`, RFC 9404), and one that breaks off goes on
//! with the pieces not sent yet. Vaults (RFC 0006, 6) are kept in step with the account's key unlocked
//! ([`Folder::sync_with`]): names and contents are decrypted here and encrypted before they go; while a vault's key is
//! not at hand, the vault and what is in it are left as they are on both sides. Names a file system cannot hold – on
//! Windows its reserved names and characters, and where case does not tell names apart a second name that differs
//! only in case – are left out ([`Names`]).
//!
//! OPEN: content hashes to tell a change that keeps size and time; vault contents in pieces (a file there is encrypted
//! in memory, as in the web app); file ids on Windows (moves there are a deletion and a creation).

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
    e2e::{E2e, Vaults},
    files::{self, FileNode},
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use plan::{Action, Base, Local, RelPath, Remote};
use state::{Node, Pieces, State};

/// Changes asked for at once.
const MAX_CHANGES: u64 = 500;
/// The suffix of a download not finished yet; such files are not part of the folder.
const PARTIAL: &str = ".kernoid-part";
/// Files larger than this go up in pieces of this size, each of which can be sent again alone.
pub const PIECE: u64 = 8 << 20;
/// Pieces older than this are sent again: the server keeps uploads for a day.
const PIECES_KEPT: i64 = 20 * 3600;

/// Which names the folder's file system can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Names {
    /// Windows' rules: no `<>:"|?*` or control characters, no name ending in a dot or space, none of its reserved
    /// names (`CON`, `NUL`, `COM1` …, with any extension).
    pub windows: bool,
    /// Names that differ only in case are the same name (Windows, macOS by default): of two such, the second is left
    /// out.
    pub ignore_case: bool,
}

impl Names {
    /// The rules of the system this runs on, as its file systems are by default.
    pub fn of_this_system() -> Names {
        Names { windows: cfg!(windows), ignore_case: cfg!(any(windows, target_os = "macos", target_os = "ios")) }
    }

    /// Whether a name of the store can be a name in the folder.
    pub fn usable(&self, name: &str) -> bool {
        if name.is_empty() || name == "." || name == ".." || name.len() > 255 {
            return false;
        }
        if name.contains(['/', '\\', '\0']) || name.ends_with(PARTIAL) {
            return false;
        }
        if self.windows {
            if name.chars().any(|c| c < ' ' || "<>:\"|?*".contains(c)) || name.ends_with(['.', ' ']) {
                return false;
            }
            let stem = name.split('.').next().unwrap_or_default().trim_end().to_ascii_uppercase();
            let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                    && stem.len() == 4
                    && stem.as_bytes()[3].is_ascii_digit()
                    && stem.as_bytes()[3] != b'0');
            if reserved {
                return false;
            }
        }
        true
    }
}

impl Default for Names {
    fn default() -> Names {
        Names::of_this_system()
    }
}

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
    /// Moved here because they were moved on the server, or the other way round.
    pub moved: usize,
    /// Local files kept as copies beside the server's version.
    pub conflicts: Vec<RelPath>,
    /// Actions that failed, with why; the next round tries them again.
    pub failed: Vec<(RelPath, String)>,
    /// Nodes of the store left out: names a folder cannot hold.
    pub skipped: Vec<String>,
    /// Vaults left as they are, their key not at hand (their ids).
    pub locked: Vec<String>,
}

/// A folder kept in step with one store (an account's own files, a drive, or files shared with the user).
#[derive(Debug)]
pub struct Folder {
    root: PathBuf,
    store: String,
    state: State,
    names: Names,
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
        Ok(Folder { root, store: store.to_owned(), state, names: Names::default() })
    }

    /// Other rules for names than the system's (a file system of another kind).
    pub fn set_names(&mut self, names: Names) {
        self.names = names;
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// One round: reads what changed on both sides and brings them into step. Vaults are left as they are.
    pub async fn sync(&mut self, client: &Client) -> Result<Report> {
        self.sync_with(client, None).await
    }

    /// One round, with the account's end-to-end key (RFC 0006): vaults whose key it opens are kept in step too.
    pub async fn sync_with(&mut self, client: &Client, e2e: Option<&mut E2e>) -> Result<Report> {
        self.sync_all(client, e2e, None).await
    }

    /// One round with vaults on spaces too (RFC 0010, 5): those this device has – or comes into with the account's
    /// key – are kept in step through `vaults`; the others are left as they are.
    pub async fn sync_all(
        &mut self,
        client: &Client,
        mut e2e: Option<&mut E2e>,
        vaults: Option<&Vaults>,
    ) -> Result<Report> {
        let mut report = Report::default();
        let mut nodes = self.read_store(client, e2e.as_deref_mut()).await?;
        // Vaults on spaces: their names from the space, what is in them below them; locked where not at hand.
        let mut spaces: BTreeMap<String, String> = BTreeMap::new();
        for node in nodes.values_mut().filter(|node| node.space.is_some() && node.vault.as_deref() == Some(&node.id)) {
            let opened = match vaults {
                Some(vaults) => open_space(client, e2e.as_deref_mut(), &self.store, vaults, node).await,
                None => None,
            };
            match opened {
                Some(name) => {
                    node.name = name;
                    node.locked = false;
                    spaces.insert(node.id.clone(), node.space.clone().unwrap_or_default());
                }
                None => node.locked = true,
            }
        }
        let mut remote = tree_with(&nodes, self.names, &mut report.skipped);
        if let Some(vaults) = vaults {
            let roots: Vec<(RelPath, Node)> = remote
                .iter()
                .filter(|(_, (node, _))| spaces.contains_key(&node.id))
                .map(|(path, (node, _))| (path.clone(), node.clone()))
                .collect();
            for (path, root) in roots {
                space_tree(vaults, &root, &path, self.names, &mut remote, &mut report.skipped).await?;
            }
        }
        let mut local = scan(&self.root)?;
        let mut base = self.state.base()?;
        // Vaults whose key is not at hand stay as they are on both sides: what was known of them is kept, nothing
        // in them is compared.
        let frozen = frozen(&nodes, &base, &mut report.locked);
        let kept: BTreeMap<RelPath, Base> = base.extract_if(.., |path, _| inside(path, &frozen)).collect();
        local.retain(|path, _| !inside(path, &frozen));
        let actions = plan::plan(&base, &paths(&remote), &local);
        let mut trash = None;
        // Paths changed on the server by this round: their node is read again at the end.
        let mut touched: Vec<RelPath> = Vec::new();
        let mut downloading = Vec::new();
        for action in actions {
            let path = action_path(&action).to_owned();
            if let Action::Download { path, .. } = &action {
                downloading.push(path.clone());
            }
            // What lies in a vault on a space goes to the space; so does renaming the vault's directory (its name is
            // there). Everything else about that directory is the store's.
            let in_space = match &action {
                Action::MoveRemote { id, .. } if spaces.contains_key(id) => Some(id.clone()),
                Action::MakeRemoteDirectory(_)
                | Action::Upload { .. }
                | Action::Download { .. }
                | Action::DeleteRemote { .. }
                | Action::MoveRemote { .. } => vault_of(plan::parent(action_path(&action)), &remote, &base),
                // What happens here only is the same as elsewhere.
                _ => None,
            }
            .and_then(|vault| spaces.get(&vault).map(|space| (vault, space.clone())));
            let result = match (in_space, vaults) {
                (Some((vault, space)), Some(vaults)) => {
                    self.run_in_space(client, vaults, &vault, &space, &action, &remote, &mut base).await
                }
                _ => self.run(client, e2e.as_deref_mut(), &action, &remote, &mut base, &mut trash, &mut touched).await,
            };
            match result {
                Ok(()) => count(&mut report, &action),
                Err(error) => report.failed.push((path, error.to_string())),
            }
        }
        // Partial downloads nothing wants any more.
        for path in self.state.downloads()? {
            if !downloading.contains(&path) {
                let _ = std::fs::remove_file(partial_of(&self.local(&path)));
                self.state.set_download(&path, None)?;
            }
        }
        // Read the store again: what this round made there gets the server's ids and blobs. Changes by others in
        // the meantime stay with their old base, so the next round sees them.
        if !touched.is_empty() {
            nodes = self.read_store(client, e2e).await?;
            let after = tree_with(&nodes, self.names, &mut Vec::new());
            for path in touched {
                if let (Some((node, _)), Some(entry)) = (after.get(&path), base.get_mut(&path)) {
                    entry.remote = remote_of(node);
                }
            }
        }
        base.extend(kept);
        self.state.set_base(&base)?;
        Ok(report)
    }

    /// The store's tree, brought up to date with its changes – or read whole; names in vaults opened where the key
    /// is at hand.
    async fn read_store(&mut self, client: &Client, e2e: Option<&mut E2e>) -> Result<BTreeMap<String, Node>> {
        let mut nodes = self.state.remote()?;
        let mut since = self.state.meta("state")?.filter(|state| !state.is_empty());
        let state = loop {
            let Some(state) = since.clone() else {
                let snapshot = files::snapshot(client, &self.store).await?;
                nodes = snapshot.nodes.iter().map(|node| (node.id.clone(), node_of(node))).collect();
                break snapshot.state;
            };
            match files::changes(client, &self.store, &state, MAX_CHANGES).await {
                Ok(changes) => {
                    for id in &changes.destroyed {
                        nodes.remove(id);
                    }
                    for node in &changes.changed {
                        nodes.insert(node.id.clone(), node_of(node));
                    }
                    if !changes.has_more_changes {
                        break changes.new_state;
                    }
                    self.state.set_remote(&nodes, &changes.new_state)?;
                    since = Some(changes.new_state);
                }
                Err(kernoid_client::Error::Method { kind, .. }) if kind == "cannotCalculateChanges" => since = None,
                Err(error) => return Err(error.into()),
            }
        };
        if let Some(e2e) = e2e {
            for node in nodes.values_mut().filter(|node| node.locked) {
                let (Some(vault), Some(sealed)) = (node.vault.clone(), node.sealed_name.clone()) else { continue };
                if let Some(name) = e2e.open_name(client, &self.store, &vault, &sealed).await {
                    node.name = name;
                    node.locked = false;
                }
            }
        }
        self.state.set_remote(&nodes, &state)?;
        Ok(nodes)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        &self,
        client: &Client,
        e2e: Option<&mut E2e>,
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
                let (node, known) = remote.get(path).filter(|(n, _)| &n.id == id).ok_or_else(|| gone(path))?;
                let at = self.local(path);
                match (&node.vault, e2e) {
                    (Some(vault), Some(e2e)) => self.download_sealed(client, e2e, vault, blob, &at).await?,
                    (Some(_), None) => return Err(locked()),
                    (None, _) => self.download(client, path, blob, &at).await?,
                }
                base.insert(path.clone(), Base { remote: known.clone(), local: stat(&at)? });
            }
            Action::MakeRemoteDirectory(path) => {
                let (parent, name) = self.parent_and_name(path, remote, base)?;
                let vault = vault_of(plan::parent(path), remote, base);
                let id = match (&vault, &parent, e2e) {
                    (Some(vault), Some(parent), Some(e2e)) => {
                        e2e.make_directory_in(client, &self.store, vault, parent, &name).await?
                    }
                    (Some(_), _, _) => return Err(locked()),
                    (None, _, _) => {
                        let create =
                            json!({ "create": { "d": { "@type": "Directory", "parentId": parent, "name": name } } });
                        let result = client.set(&[FILENODE], "FileNode", &self.store, create, json!({})).await?;
                        created_id(&result)?
                    }
                };
                let local = stat(&self.local(path))?;
                let remote = Remote { id, directory: true, blob: None, size: 0, vault };
                base.insert(path.clone(), Base { remote, local });
                touched.push(path.clone());
            }
            Action::Upload { path, id } => {
                let at = self.local(path);
                // The state of the file before it is read: a change while it travels shows in the next round.
                let local = stat(&at)?;
                let name = path.rsplit('/').next().unwrap_or(path).to_owned();
                let kind = files::media_type(&name);
                let vault = vault_of(plan::parent(path), remote, base);
                let mut e2e = e2e;
                let upload = match (&vault, e2e.as_deref_mut()) {
                    (Some(vault), Some(e2e)) => {
                        let data = tokio::fs::read(&at).await?;
                        let sealed = e2e.seal_content(client, &self.store, vault, data).await?;
                        let size = sealed.len() as u64;
                        client
                            .upload(
                                &self.store,
                                "application/octet-stream",
                                std::io::Cursor::new(sealed),
                                size,
                                |_, _| {},
                            )
                            .await?
                    }
                    (Some(_), None) => return Err(locked()),
                    (None, _) => self.upload(client, path, &at, &local, kind).await?,
                };
                let node_id = match id {
                    Some(id) => {
                        let update =
                            json!({ "update": { id.as_str(): { "blobId": upload.blob_id, "mediaType": kind } } });
                        client.set(&[FILENODE], "FileNode", &self.store, update, json!({})).await?;
                        id.clone()
                    }
                    None => {
                        let (parent, _) = self.parent_and_name(path, remote, base)?;
                        let mut create = json!({
                            "@type": "File", "parentId": parent, "name": name, "blobId": upload.blob_id,
                            "mediaType": kind,
                        });
                        if let (Some(vault), Some(e2e)) = (&vault, e2e) {
                            let (opaque, sealed) = e2e.name_in(client, &self.store, vault, &name).await?;
                            create["name"] = json!(opaque);
                            create["kernoid:encryptedName"] = json!(sealed);
                        }
                        let create = json!({ "create": { "f": create } });
                        let result = client.set(&[FILENODE], "FileNode", &self.store, create, json!({})).await?;
                        created_id(&result)?
                    }
                };
                let remote =
                    Remote { id: node_id, directory: false, blob: Some(upload.blob_id), size: upload.size, vault };
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
            Action::MoveLocal { from, to } => {
                let target = self.local(to);
                if let Some(parent) = target.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::rename(self.local(from), &target).await?;
                plan::rename(base, from, to);
            }
            Action::MoveRemote { from, to, id } => {
                let (parent, name) = self.parent_and_name(to, remote, base)?;
                let vault = base.get(from).and_then(|entry| entry.remote.vault.clone());
                match (&vault, &parent, e2e) {
                    // A vault's root moves like any directory, its name encrypted.
                    (Some(vault), parent, Some(e2e)) if vault == id => {
                        let (opaque, sealed) = e2e.name_in(client, &self.store, vault, &name).await?;
                        let update = json!({ "update": { id.as_str(): {
                            "parentId": parent, "name": opaque, "kernoid:encryptedName": sealed,
                        } } });
                        client.set(&[FILENODE], "FileNode", &self.store, update, json!({})).await?;
                    }
                    (Some(vault), Some(parent), Some(e2e)) => {
                        e2e.move_in(client, &self.store, vault, id, parent, &name).await?;
                    }
                    (Some(_), _, _) => return Err(locked()),
                    (None, _, _) => {
                        let update = json!({ "update": { id.as_str(): { "parentId": parent, "name": name } } });
                        client.set(&[FILENODE], "FileNode", &self.store, update, json!({})).await?;
                    }
                }
                plan::rename(base, from, to);
                touched.push(to.clone());
            }
        }
        Ok(())
    }

    /// An action on what lies in a vault on a space – or on the vault's directory itself, which the store keeps.
    #[allow(clippy::too_many_arguments, reason = "one action with all it needs")]
    async fn run_in_space(
        &self,
        client: &Client,
        vaults: &Vaults,
        vault: &str,
        space: &str,
        action: &Action,
        remote: &BTreeMap<RelPath, (Node, Remote)>,
        base: &mut BTreeMap<RelPath, Base>,
    ) -> Result<()> {
        let node = FileNode { id: vault.to_owned(), space: Some(space.to_owned()), ..FileNode::default() };
        // The stream of the directory a path lies in: none for the vault's top.
        let parent_of = |path: &str, base: &BTreeMap<RelPath, Base>| -> Result<Option<String>> {
            let parent = plan::parent(path);
            let id = base
                .get(parent)
                .map(|entry| entry.remote.id.clone())
                .or_else(|| remote.get(parent).map(|(node, _)| node.id.clone()))
                .ok_or_else(|| gone(parent))?;
            Ok((id != vault).then_some(id))
        };
        let name_of = |path: &str| path.rsplit('/').next().unwrap_or(path).to_owned();
        match action {
            Action::MakeRemoteDirectory(path) => {
                let parent = parent_of(path, base)?;
                let id = vaults.make_directory(&node, parent.as_deref(), &name_of(path)).await?;
                let remote = Remote { id, directory: true, blob: None, size: 0, vault: Some(vault.to_owned()) };
                base.insert(path.clone(), Base { remote, local: stat(&self.local(path))? });
            }
            Action::Upload { path, id } => {
                let at = self.local(path);
                let local = stat(&at)?;
                let data = tokio::fs::read(&at).await?;
                let size = data.len() as u64;
                let parent = parent_of(path, base)?;
                let name = name_of(path);
                let modified = std::fs::metadata(&at)
                    .ok()
                    .and_then(|meta| meta.modified().ok())
                    .and_then(|time| jiff::Timestamp::try_from(time).ok())
                    .map(|time| format!("{time:.0}"));
                let kind = files::media_type(&name);
                let stream = vaults
                    .put_file(&node, parent.as_deref(), &name, data, Some(kind), modified.as_deref(), id.as_deref())
                    .await?;
                let version = vaults
                    .list(&node, parent.as_deref())
                    .await?
                    .into_iter()
                    .find(|entry| entry.id == stream)
                    .map(|entry| entry.version);
                let remote =
                    Remote { id: stream, directory: false, blob: version, size, vault: Some(vault.to_owned()) };
                base.insert(path.clone(), Base { remote, local });
            }
            Action::Download { path, id, .. } => {
                let (_, known) = remote.get(path).filter(|(n, _)| &n.id == id).ok_or_else(|| gone(path))?;
                let at = self.local(path);
                let data = vaults.read_file(&node, id).await?;
                let partial = partial_of(&at);
                let mut file = tokio::fs::File::create(&partial).await?;
                file.write_all(&data).await?;
                file.sync_all().await?;
                drop(file);
                tokio::fs::rename(&partial, &at).await?;
                base.insert(path.clone(), Base { remote: known.clone(), local: stat(&at)? });
            }
            Action::DeleteRemote { path, id } if id != vault => {
                // Into the vault's own trash, from where an app can bring it back.
                let parent = parent_of(path, base)?;
                vaults.set_trashed(&node, parent.as_deref(), id, true).await?;
                forget(base, path);
            }
            Action::MoveRemote { from, to, id } if id != vault => {
                let (old, new) = (parent_of(from, base)?, parent_of(to, base)?);
                if old != new {
                    vaults.move_to(&node, old.as_deref(), id, new.as_deref()).await?;
                }
                if name_of(from) != name_of(to) {
                    vaults.rename(&node, new.as_deref(), id, &name_of(to)).await?;
                }
                plan::rename(base, from, to);
            }
            Action::MoveRemote { from, to, id } => {
                // The vault's directory: moved in the store (its name there stays an id), renamed in the space.
                if plan::parent(from) != plan::parent(to) {
                    let (parent, _) = self.parent_and_name(to, remote, base)?;
                    let update = json!({ "update": { id.as_str(): { "parentId": parent } } });
                    client.set(&[FILENODE], "FileNode", &self.store, update, json!({})).await?;
                }
                if name_of(from) != name_of(to) {
                    vaults.rename_vault(&node, &name_of(to)).await?;
                }
                plan::rename(base, from, to);
            }
            // What happens here only is the same as elsewhere.
            _ => return Err(Error::State("not an action in a vault on a space".into())),
        }
        Ok(())
    }

    /// Downloads a blob to a path through its partial file – going on with one that broke off for the same blob.
    async fn download(&self, client: &Client, path: &str, blob: &str, at: &Path) -> Result<()> {
        let partial = partial_of(at);
        let resume = self.state.download(path)?.as_deref() == Some(blob);
        let from = if resume { tokio::fs::metadata(&partial).await.map(|m| m.len()).unwrap_or(0) } else { 0 };
        let mut file = if from > 0 {
            tokio::fs::OpenOptions::new().append(true).open(&partial).await?
        } else {
            tokio::fs::File::create(&partial).await?
        };
        self.state.set_download(path, Some(blob))?;
        let name = path.rsplit('/').next().unwrap_or(path);
        let result = client
            .download_from(&self.store, blob, name, "application/octet-stream", from, &mut file, &mut |_, _| {})
            .await;
        match result {
            Ok(_) => {}
            // The range was not served (the server's content changed under the same blob, or it does not do
            // ranges): from the start next time.
            Err(error @ kernoid_client::Error::Status(..)) if from > 0 => {
                drop(file);
                let _ = tokio::fs::remove_file(&partial).await;
                self.state.set_download(path, None)?;
                return Err(error.into());
            }
            Err(error) => {
                // What came is kept for the next round.
                let _ = file.flush().await;
                return Err(error.into());
            }
        }
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&partial, at).await?;
        self.state.set_download(path, None)?;
        Ok(())
    }

    /// Downloads a file of a vault, decrypted here (in memory, as the SDK does).
    async fn download_sealed(&self, client: &Client, e2e: &mut E2e, vault: &str, blob: &str, at: &Path) -> Result<()> {
        let mut sealed = Vec::new();
        client
            .download(&self.store, blob, "encrypted", "application/octet-stream", &mut sealed, &mut |_, _| {})
            .await?;
        let data = e2e.open_content(client, &self.store, vault, sealed).await?;
        let partial = partial_of(at);
        let mut file = tokio::fs::File::create(&partial).await?;
        file.write_all(&data).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&partial, at).await?;
        Ok(())
    }

    /// Uploads a file: at once when small, else in pieces – those of an upload that broke off are not sent again
    /// while the file is unchanged and they are fresh.
    async fn upload(
        &self,
        client: &Client,
        path: &str,
        at: &Path,
        local: &Local,
        kind: &str,
    ) -> Result<kernoid_client::Upload> {
        if local.size <= PIECE {
            let file = tokio::fs::File::open(at).await?;
            return Ok(client.upload(&self.store, kind, file, local.size, |_, _| {}).await?);
        }
        let now = jiff::Timestamp::now().as_second();
        let mut pieces = self
            .state
            .upload(path)?
            .filter(|p| p.size == local.size && p.modified == local.modified && now - p.started < PIECES_KEPT)
            .unwrap_or(Pieces { size: local.size, modified: local.modified, blobs: Vec::new(), started: now });
        let mut file = tokio::fs::File::open(at).await?;
        let count = local.size.div_ceil(PIECE);
        while (pieces.blobs.len() as u64) < count {
            let start = pieces.blobs.len() as u64 * PIECE;
            let length = PIECE.min(local.size - start);
            file.seek(std::io::SeekFrom::Start(start)).await?;
            let mut piece = Vec::with_capacity(length as usize);
            (&mut file).take(length).read_to_end(&mut piece).await?;
            if piece.len() as u64 != length {
                return Err(Error::Io(std::io::Error::other("the file changed while it was sent")));
            }
            let sent = client
                .upload(&self.store, "application/octet-stream", std::io::Cursor::new(piece), length, |_, _| {})
                .await?;
            pieces.blobs.push(sent.blob_id);
            self.state.set_upload(path, Some(&pieces))?;
        }
        let joined = client.join(&self.store, kind, &pieces.blobs).await;
        // Joined or not, these pieces are done with: a failure (pieces gone) starts afresh next round.
        self.state.set_upload(path, None)?;
        Ok(joined?)
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

/// Brings this device into a vault on a space (with the account's key, where it is not in yet) and reads what is new;
/// its name, or `None` where it is not at hand.
async fn open_space(
    client: &Client,
    e2e: Option<&mut E2e>,
    store: &str,
    vaults: &Vaults,
    node: &Node,
) -> Option<String> {
    let file = FileNode { id: node.id.clone(), space: node.space.clone(), ..FileNode::default() };
    let entered = match e2e {
        Some(e2e) => vaults.enter(client, e2e, store, &file).await.ok()?,
        None => vaults.sync(&file).await.is_ok(),
    };
    if !entered {
        return None;
    }
    vaults.name(&file).await.ok().flatten()
}

/// What lies in a vault on a space, below its directory at `root_path`: its streams as nodes of the tree (trashed ones
/// left out), a file's version as its blob.
async fn space_tree(
    vaults: &Vaults,
    root: &Node,
    root_path: &str,
    names: Names,
    tree: &mut BTreeMap<RelPath, (Node, Remote)>,
    skipped: &mut Vec<String>,
) -> Result<()> {
    let file = FileNode { id: root.id.clone(), space: root.space.clone(), ..FileNode::default() };
    let mut pending: Vec<(Option<String>, String)> = vec![(None, root_path.to_owned())];
    while let Some((directory, at)) = pending.pop() {
        let mut seen: Vec<String> = Vec::new();
        for entry in vaults.list(&file, directory.as_deref()).await? {
            let key = if names.ignore_case { entry.name.to_lowercase() } else { entry.name.clone() };
            if entry.trashed || !names.usable(&entry.name) || seen.contains(&key) {
                if !entry.trashed {
                    skipped.push(entry.name.clone());
                }
                continue;
            }
            seen.push(key);
            let path = format!("{at}/{}", entry.name);
            let node = Node {
                id: entry.id.clone(),
                parent: Some(directory.clone().unwrap_or_else(|| root.id.clone())),
                name: entry.name.clone(),
                directory: entry.directory,
                blob: (!entry.directory).then(|| entry.version.clone()),
                size: entry.size,
                role: None,
                vault: Some(root.id.clone()),
                sealed_name: None,
                locked: false,
                space: root.space.clone(),
            };
            let remote = remote_of(&node);
            if entry.directory {
                pending.push((Some(entry.id.clone()), path.clone()));
            }
            tree.insert(path, (node, remote));
        }
    }
    Ok(())
}

fn gone(path: &str) -> Error {
    Error::State(format!("{path}: not in the store (any more)"))
}

fn locked() -> Error {
    Error::Client(kernoid_client::Error::E2e("the vault's key is not at hand".into()))
}

fn partial_of(at: &Path) -> PathBuf {
    PathBuf::from(format!("{}{PARTIAL}", at.display()))
}

/// The vault a path lies in, from what this round knows: what it made (`base`) or what the store has.
fn vault_of(
    mut path: &str,
    remote: &BTreeMap<RelPath, (Node, Remote)>,
    base: &BTreeMap<RelPath, Base>,
) -> Option<String> {
    while !path.is_empty() {
        if let Some(entry) = base.get(path) {
            return entry.remote.vault.clone();
        }
        if let Some((_, node)) = remote.get(path) {
            return node.vault.clone();
        }
        path = plan::parent(path);
    }
    None
}

/// The paths (as last agreed) of vaults, and of what lies in them, whose names are not open: their key not at hand.
fn frozen(nodes: &BTreeMap<String, Node>, base: &BTreeMap<RelPath, Base>, locked: &mut Vec<String>) -> Vec<RelPath> {
    let mut vaults: Vec<&str> =
        nodes.values().filter(|node| node.locked).filter_map(|node| node.vault.as_deref()).collect();
    vaults.sort_unstable();
    vaults.dedup();
    locked.extend(vaults.iter().map(|vault| (*vault).to_owned()));
    // A vault's root as known before, by its id.
    base.iter().filter(|(_, entry)| vaults.contains(&entry.remote.id.as_str())).map(|(path, _)| path.clone()).collect()
}

/// Whether a path is one of `roots` or lies below one.
fn inside(path: &str, roots: &[RelPath]) -> bool {
    roots.iter().any(|root| path == root || path.strip_prefix(root.as_str()).is_some_and(|rest| rest.starts_with('/')))
}

fn action_path(action: &Action) -> &str {
    match action {
        Action::MakeLocalDirectory(path)
        | Action::MakeRemoteDirectory(path)
        | Action::DeleteLocal(path)
        | Action::KeepLocalCopy(path)
        | Action::Adopt(path) => path,
        Action::Download { path, .. } | Action::Upload { path, .. } | Action::DeleteRemote { path, .. } => path,
        Action::MoveLocal { to, .. } | Action::MoveRemote { to, .. } => to,
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
        Action::MoveLocal { .. } | Action::MoveRemote { .. } => report.moved += 1,
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
        vault: node.vault.clone(),
        sealed_name: node.encrypted_name.clone(),
        // Opened when the key is at hand (`read_store`).
        locked: node.vault.is_some() && node.encrypted_name.is_some(),
        space: node.space.clone(),
    }
}

fn remote_of(node: &Node) -> Remote {
    Remote {
        id: node.id.clone(),
        directory: node.directory,
        blob: node.blob.clone(),
        size: node.size,
        vault: node.vault.clone(),
    }
}

/// The store's nodes by path – without the trash and what is in it, without vaults whose names are not open, and
/// without names the folder cannot hold (they go to `skipped`, with what is below them).
pub fn tree(nodes: &BTreeMap<String, Node>, skipped: &mut Vec<String>) -> BTreeMap<RelPath, (Node, Remote)> {
    tree_with(nodes, Names::default(), skipped)
}

/// [`tree`] with the rules for names of another file system.
pub fn tree_with(
    nodes: &BTreeMap<String, Node>,
    names: Names,
    skipped: &mut Vec<String>,
) -> BTreeMap<RelPath, (Node, Remote)> {
    // Where case does not tell names apart, the first of a parent's children by id keeps a name; the others are left
    // out.
    let mut taken: BTreeMap<(Option<&str>, String), &str> = BTreeMap::new();
    if names.ignore_case {
        for node in nodes.values() {
            taken.entry((node.parent.as_deref(), node.name.to_lowercase())).or_insert(node.id.as_str());
        }
    }
    let fits = |node: &Node| {
        names.usable(&node.name)
            && (!names.ignore_case
                || taken.get(&(node.parent.as_deref(), node.name.to_lowercase())) == Some(&node.id.as_str()))
    };
    let mut out = BTreeMap::new();
    for node in nodes.values() {
        let mut parts = Vec::new();
        let mut at = Some(node);
        let mut ok = true;
        while let Some(current) = at {
            if current.role.as_deref() == Some("trash") || current.locked || !fits(current) || parts.len() > 64 {
                ok = false;
                if !current.locked && !fits(current) && current.id == node.id {
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
    Ok(Local {
        directory: meta.is_dir(),
        size: if meta.is_dir() { 0 } else { meta.len() },
        modified,
        file: file_id(&meta),
    })
}

/// The file's id on its file system: the inode on Unix; none elsewhere yet (**OPEN**: Windows' file index).
#[cfg(unix)]
fn file_id(meta: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}

#[cfg(not(unix))]
fn file_id(_: &std::fs::Metadata) -> u64 {
    0
}

/// The files and directories of a folder by path; links, unfinished downloads and other kinds are left out.
pub fn scan(root: &Path) -> Result<BTreeMap<RelPath, Local>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if name.is_empty() || name.ends_with(PARTIAL) {
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
    let when = jiff::ZonedDateTime::now().strftime("%Y-%m-%d %H%M");
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
                vault: None,
                sealed_name: None,
                locked: false,
                space: None,
            },
        )
    }

    #[test]
    fn a_round_runs_on_any_thread() {
        fn send<T: Send>(_: T) {}
        fn shared<T: Send + Sync>() {}
        shared::<Folder>();
        let client: Option<&Client> = None;
        if let Some(client) = client {
            let mut folder = Folder::open(std::env::temp_dir(), "x", Path::new("unused.db")).unwrap();
            send(async move { folder.sync_with(client, None).await });
        }
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
        let tree = tree_with(&nodes, Names { windows: false, ignore_case: false }, &mut skipped);
        assert_eq!(tree.keys().collect::<Vec<_>>(), ["Projects", "Projects/plan.txt"]);
        assert_eq!(skipped, [".."]);
    }

    #[test]
    fn names_a_file_system_cannot_hold_are_left_out() {
        let nodes: BTreeMap<String, Node> = [
            node("1", None, "Notes.txt", false),
            node("2", None, "notes.TXT", false),
            node("3", None, "a:b.txt", false),
            node("4", None, "CON.txt", false),
            node("5", None, "trailing.", false),
            node("6", None, "COM0", false),
        ]
        .into_iter()
        .collect();
        let mut skipped = Vec::new();
        let unix = tree_with(&nodes, Names { windows: false, ignore_case: false }, &mut skipped);
        assert_eq!(unix.len(), 6);
        let mut skipped = Vec::new();
        let windows = tree_with(&nodes, Names { windows: true, ignore_case: true }, &mut skipped);
        assert_eq!(windows.keys().collect::<Vec<_>>(), ["COM0", "Notes.txt"]);
        assert_eq!(skipped, ["notes.TXT", "a:b.txt", "CON.txt", "trailing."]);
        let names = Names { windows: true, ignore_case: true };
        assert!(!names.usable("lpt1") && !names.usable("aux.tar.gz") && !names.usable("a\u{1}b"));
        assert!(names.usable("COM10") && names.usable("console.txt"));
    }

    #[test]
    fn a_locked_vault_is_left_out() {
        let mut nodes: BTreeMap<String, Node> =
            [node("1", None, "k-1", true), node("2", Some("1"), "k-2", false), node("3", None, "open.txt", false)]
                .into_iter()
                .collect();
        for id in ["1", "2"] {
            let node = nodes.get_mut(id).unwrap();
            node.vault = Some("1".into());
            node.locked = true;
        }
        let tree = tree_with(&nodes, Names { windows: false, ignore_case: false }, &mut Vec::new());
        assert_eq!(tree.keys().collect::<Vec<_>>(), ["open.txt"]);
        let base = BTreeMap::from([(
            "Vault".to_owned(),
            Base {
                remote: Remote { id: "1".into(), directory: true, blob: None, size: 0, vault: Some("1".into()) },
                local: Local { directory: true, size: 0, modified: 0, file: 0 },
            },
        )]);
        let mut locked = Vec::new();
        assert_eq!(frozen(&nodes, &base, &mut locked), ["Vault"]);
        assert_eq!(locked, ["1"]);
        assert!(inside("Vault/a", &["Vault".into()]) && !inside("Vaults", &["Vault".into()]));
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
