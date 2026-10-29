// SPDX-License-Identifier: MIT
//! Files over JMAP (draft-ietf-jmap-filenode-19): the stores the user reaches – their own, those shared with them,
//! the tenant's drives –, directories and files with the rights on them, downloads, uploads, kernoid's versions of a
//! file (`https://kernoid.dev/jmap/file-versions`) and its links for people without an account
//! (`https://kernoid.dev/jmap/file-links`).

use std::{collections::BTreeMap, path::Path};

use serde::Deserialize;
use serde_json::{Value, json};

use super::{Client, Error, FILE_LINKS, FILE_VERSIONS, FILENODE, PRINCIPALS, Result, ids_of};

const USING: [&str; 3] = [FILENODE, FILE_VERSIONS, PRINCIPALS];
const PROPERTIES: [&str; 9] =
    ["parentId", "name", "role", "blobId", "size", "mediaType", "modified", "myRights", "shareWith"];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Rights {
    pub may_read: bool,
    pub may_add_children: bool,
    pub may_rename: bool,
    pub may_delete: bool,
    pub may_modify_content: bool,
    pub may_share: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileNode {
    #[serde(rename = "@type", default)]
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub blob_id: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub my_rights: Option<Rights>,
    #[serde(default)]
    pub share_with: Option<BTreeMap<String, Rights>>,
}

impl FileNode {
    pub fn is_directory(&self) -> bool {
        self.kind == "Directory" || (self.kind.is_empty() && self.blob_id.is_none())
    }

    pub fn rights(&self) -> Rights {
        self.my_rights.unwrap_or_default()
    }
}

/// What kind of store an account is to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoreKind {
    Own,
    Drive,
    Shared,
}

/// A file store the user reaches.
#[derive(Debug, Clone)]
pub struct Store {
    pub id: String,
    pub name: String,
    pub kind: StoreKind,
}

/// The stores of the session: the own first, then drives, then other people's.
pub fn stores(client: &Client) -> Vec<Store> {
    let own = client.session.primary(FILENODE);
    let mut out: Vec<Store> = client
        .session
        .accounts_with(FILENODE)
        .into_iter()
        .map(|(id, account)| Store {
            id: id.to_owned(),
            name: account.name.clone(),
            kind: if Some(id) == own {
                StoreKind::Own
            } else if account.drive {
                StoreKind::Drive
            } else {
                StoreKind::Shared
            },
        })
        .collect();
    out.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    out
}

#[derive(Deserialize)]
struct List<T> {
    list: Vec<T>,
}

fn list<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> Result<Vec<T>> {
    let value = value.cloned().unwrap_or(json!({ "list": [] }));
    serde_json::from_value::<List<T>>(value).map(|list| list.list).map_err(|error| Error::Protocol(error.to_string()))
}

/// Directories first, then by name, ignoring case.
pub fn sort(nodes: &mut [FileNode]) {
    nodes.sort_by(|a, b| {
        b.is_directory().cmp(&a.is_directory()).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

/// The nodes in a directory of a store – or at its top, for `None` – sorted.
pub fn children(client: &Client, account: &str, parent: Option<&str>) -> Result<Vec<FileNode>> {
    let filter = match parent {
        Some(parent) => json!({ "parentId": parent }),
        None => json!({ "isTopLevel": true }),
    };
    let responses = client.request(
        &USING,
        vec![
            ("FileNode/query", json!({ "accountId": account, "filter": filter }), "q"),
            (
                "FileNode/get",
                json!({ "accountId": account, "properties": PROPERTIES, "#ids": ids_of("q", "FileNode/query") }),
                "g",
            ),
        ],
    )?;
    let mut nodes = list(responses.get("g"))?;
    sort(&mut nodes);
    Ok(nodes)
}

/// The directory with the role `trash`, if the store has one.
pub fn trash(client: &Client, account: &str) -> Result<Option<FileNode>> {
    let responses = client.request(
        &USING,
        vec![
            ("FileNode/query", json!({ "accountId": account, "filter": { "role": "trash" } }), "q"),
            (
                "FileNode/get",
                json!({ "accountId": account, "properties": PROPERTIES, "#ids": ids_of("q", "FileNode/query") }),
                "g",
            ),
        ],
    )?;
    Ok(list(responses.get("g"))?.into_iter().next())
}

pub fn create_directory(client: &Client, account: &str, parent: Option<&str>, name: &str) -> Result<()> {
    let create = json!({ "create": { "d": { "@type": "Directory", "parentId": parent, "name": name } } });
    client.set(&USING, "FileNode", account, create, json!({}))?;
    Ok(())
}

pub fn rename(client: &Client, account: &str, id: &str, name: &str) -> Result<()> {
    client.set(&USING, "FileNode", account, json!({ "update": { id: { "name": name } } }), json!({}))?;
    Ok(())
}

/// Moves a node into another directory (`None`: the top); a name taken there gets a number.
pub fn move_to(client: &Client, account: &str, id: &str, parent: Option<&str>) -> Result<()> {
    let update = json!({ "update": { id: { "parentId": parent } } });
    client.set(&USING, "FileNode", account, update, json!({ "onExists": "rename" }))?;
    Ok(())
}

/// Copies a node – a directory with all it holds – from one store into a directory of another (`None`: its top); with
/// `move_it` the original goes (it needs the right to delete). A name taken there gets a number.
pub fn copy_to(client: &Client, from: &str, to: &str, id: &str, parent: Option<&str>, move_it: bool) -> Result<()> {
    let result = client.call(
        &USING,
        "FileNode/copy",
        json!({
            "fromAccountId": from,
            "accountId": to,
            "create": { "c": { "id": id, "parentId": parent } },
            "onSuccessDestroyOriginal": move_it,
            "onExists": "rename",
        }),
    )?;
    super::set_error(&result)
}

/// A node found by a search, and the directories above it, the top first.
#[derive(Debug, Clone)]
pub struct Found {
    pub node: FileNode,
    pub path: Vec<FileNode>,
}

/// The nodes of a store whose name or text content holds `text` (kernoid's `text` filter), with where they are.
pub fn search(client: &Client, account: &str, text: &str) -> Result<Vec<Found>> {
    let responses = client.request(
        &USING,
        vec![
            ("FileNode/query", json!({ "accountId": account, "filter": { "text": text }, "limit": 200 }), "q"),
            (
                "FileNode/get",
                json!({
                    "accountId": account, "properties": PROPERTIES, "fetchParents": true,
                    "#ids": ids_of("q", "FileNode/query"),
                }),
                "g",
            ),
        ],
    )?;
    let hits: Vec<String> = responses
        .get("q")
        .and_then(|query| query.get("ids"))
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    let nodes: Vec<FileNode> = list(responses.get("g"))?;
    let by_id: BTreeMap<&str, &FileNode> = nodes.iter().map(|node| (node.id.as_str(), node)).collect();
    Ok(hits
        .iter()
        .filter_map(|id| by_id.get(id.as_str()))
        .map(|node| {
            let mut path = Vec::new();
            let mut next = node.parent_id.as_deref();
            while let Some(parent) = next.and_then(|id| by_id.get(id)) {
                if path.len() > 64 {
                    break;
                }
                path.insert(0, (*parent).clone());
                next = parent.parent_id.as_deref();
            }
            Found { node: (*node).clone(), path }
        })
        .collect())
}

/// Removes a node and all it holds, for good.
pub fn destroy(client: &Client, account: &str, id: &str) -> Result<()> {
    client.set(&USING, "FileNode", account, json!({ "destroy": [id] }), json!({ "onDestroyRemoveChildren": true }))?;
    Ok(())
}

/// A media type for a file name, from its extension; `application/octet-stream` for what is not known.
pub fn media_type(name: &str) -> &'static str {
    let extension = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match extension.as_str() {
        "txt" | "text" | "log" => "text/plain",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "ics" => "text/calendar",
        "vcf" => "text/vcard",
        "eml" => "message/rfc822",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }
}

/// Uploads a local file into a directory. A file of the same name there gets it as new content – what it had stays
/// as a version; otherwise a new file is made (a name taken by a directory gets a number).
pub fn upload_file(
    client: &Client,
    account: &str,
    parent: Option<&str>,
    path: &Path,
    existing: Option<&FileNode>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Protocol("the file name is not UTF-8".into()))?
        .to_owned();
    let kind = media_type(&name);
    let upload = client.upload(account, kind, file, metadata.len(), progress)?;
    let modified = metadata
        .modified()
        .ok()
        .map(|time| chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    match existing.filter(|node| !node.is_directory()) {
        Some(node) => {
            let update = json!({ "update": { node.id.as_str(): {
                "blobId": upload.blob_id, "mediaType": kind, "modified": modified,
            } } });
            client.set(&USING, "FileNode", account, update, json!({}))?;
        }
        None => {
            let create = json!({ "create": { "f": {
                "@type": "File", "parentId": parent, "name": name, "blobId": upload.blob_id,
                "mediaType": kind, "modified": modified,
            } } });
            client.set(&USING, "FileNode", account, create, json!({ "onExists": "rename" }))?;
        }
    }
    Ok(())
}

/// A content of a file: the current one or an earlier version.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub id: String,
    pub blob_id: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub is_current: bool,
}

/// The current content and the earlier versions of a file, newest first.
pub fn versions(client: &Client, account: &str, node: &str) -> Result<Vec<Version>> {
    let result = client.call(&USING, "FileVersion/get", json!({ "accountId": account, "nodeId": node }))?;
    list(Some(&result))
}

/// Makes an earlier version the file's content again.
pub fn restore(client: &Client, account: &str, node: &str, version: &Version) -> Result<()> {
    let update = json!({ "update": { node: { "blobId": version.blob_id } } });
    client.set(&USING, "FileNode", account, update, json!({}))?;
    Ok(())
}

/// The levels the app offers when sharing, as the web app has them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Read,
    Edit,
    Full,
}

impl Level {
    pub fn rights(self) -> Rights {
        let edit = self != Level::Read;
        Rights {
            may_read: true,
            may_add_children: edit,
            may_rename: edit,
            may_delete: edit,
            may_modify_content: edit,
            may_share: self == Level::Full,
        }
    }

    pub fn of(rights: &Rights) -> Self {
        if rights.may_share {
            Level::Full
        } else if rights.may_modify_content || rights.may_add_children {
            Level::Edit
        } else {
            Level::Read
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Level::Read => "read",
            Level::Edit => "edit",
            Level::Full => "edit and share",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Level::Read => Level::Edit,
            Level::Edit => Level::Full,
            Level::Full => Level::Read,
        }
    }
}

impl Rights {
    fn json(&self) -> Value {
        json!({
            "mayRead": self.may_read, "mayAddChildren": self.may_add_children, "mayRename": self.may_rename,
            "mayDelete": self.may_delete, "mayModifyContent": self.may_modify_content, "mayShare": self.may_share,
        })
    }
}

/// Sets with whom a directory is shared, replacing what was (draft-ietf-jmap-filenode, 11).
pub fn share(client: &Client, account: &str, node: &str, with: &[(String, Level)]) -> Result<()> {
    let share_with: serde_json::Map<String, Value> =
        with.iter().map(|(principal, level)| (principal.clone(), level.rights().json())).collect();
    let update = json!({ "update": { node: { "shareWith": share_with } } });
    client.set(&USING, "FileNode", account, update, json!({}))?;
    Ok(())
}

/// People and groups of the tenant whose name or address holds `text` (RFC 9670).
pub fn find_principals(client: &Client, text: &str) -> Result<Vec<Principal>> {
    let account = client.primary(PRINCIPALS)?;
    let filter = if text.trim().is_empty() { json!({}) } else { json!({ "text": text.trim() }) };
    let responses = client.request(
        &USING,
        vec![
            ("Principal/query", json!({ "accountId": account, "filter": filter, "limit": 20 }), "q"),
            ("Principal/get", json!({ "accountId": account, "#ids": ids_of("q", "Principal/query") }), "g"),
        ],
    )?;
    list(responses.get("g"))
}

/// A person or group of the tenant (RFC 9670).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Principal {
    pub id: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
}

/// The people and groups named – those a directory is shared with.
pub fn principals(client: &Client, ids: &[&str]) -> Result<Vec<Principal>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let account = client.primary(PRINCIPALS)?;
    let result = client.call(&USING, "Principal/get", json!({ "accountId": account, "ids": ids }))?;
    list(Some(&result))
}

/// A link to a file or folder for people without an account; its address is known only when it is made.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileLink {
    pub id: String,
    pub node_id: String,
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub has_password: bool,
    #[serde(default = "yes")]
    pub may_read: bool,
    #[serde(default)]
    pub may_add: bool,
    #[serde(default)]
    pub created: Option<String>,
}

fn yes() -> bool {
    true
}

/// What a link lets people do: view, view and add files, or only add them (a drop box) – the last two for folders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    View,
    Add,
    Drop,
}

impl LinkMode {
    pub fn of(link: &FileLink) -> Self {
        match (link.may_read, link.may_add) {
            (_, false) => LinkMode::View,
            (true, true) => LinkMode::Add,
            (false, true) => LinkMode::Drop,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            LinkMode::View => "view and download",
            LinkMode::Add => "view, download and add files",
            LinkMode::Drop => "only add files (drop box)",
        }
    }

    /// The next mode; for a file there is only one.
    pub fn next(self, folder: bool) -> Self {
        match self {
            _ if !folder => LinkMode::View,
            LinkMode::View => LinkMode::Add,
            LinkMode::Add => LinkMode::Drop,
            LinkMode::Drop => LinkMode::View,
        }
    }
}

/// Whether the server makes links at all.
pub fn links_available(client: &Client) -> bool {
    client.session.capabilities.contains_key(FILE_LINKS)
}

/// The links to a node.
pub fn links(client: &Client, account: &str, node: &str) -> Result<Vec<FileLink>> {
    let result =
        client.call(&[FILENODE, FILE_LINKS], "FileLink/get", json!({ "accountId": account, "nodeId": node }))?;
    list(Some(&result))
}

/// Makes a link, with an expiry (a UTCDate) and a password if given; answers its address – the only time it can be
/// known.
pub fn create_link(
    client: &Client,
    account: &str,
    node: &str,
    mode: LinkMode,
    expires: Option<&str>,
    password: Option<&str>,
) -> Result<String> {
    let link = json!({
        "nodeId": node,
        "mayRead": mode != LinkMode::Drop,
        "mayAdd": mode != LinkMode::View,
        "expires": expires,
        "password": password,
    });
    let result =
        client.set(&[FILENODE, FILE_LINKS], "FileLink", account, json!({ "create": { "l": link } }), json!({}))?;
    let token = result
        .pointer("/created/l/token")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol("the link was made without a token".into()))?;
    let template = client
        .session
        .capabilities
        .get(FILE_LINKS)
        .and_then(|capability| capability.get("urlTemplate"))
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol("the server names no address for links".into()))?;
    // The address goes to other people, as the server names it; the app does not open it.
    Ok(template.replace("{token}", token))
}

pub fn remove_link(client: &Client, account: &str, id: &str) -> Result<()> {
    client.set(&[FILENODE, FILE_LINKS], "FileLink", account, json!({ "destroy": [id] }), json!({}))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_types() {
        assert_eq!(media_type("Report.PDF"), "application/pdf");
        assert_eq!(media_type("noextension"), "application/octet-stream");
    }

    #[test]
    fn sorting() {
        let node = |kind: &str, name: &str| FileNode {
            kind: kind.into(),
            id: name.into(),
            parent_id: None,
            name: name.into(),
            role: None,
            blob_id: None,
            size: None,
            media_type: None,
            modified: None,
            my_rights: None,
            share_with: None,
        };
        let mut nodes = vec![node("File", "b"), node("Directory", "z"), node("File", "A")];
        sort(&mut nodes);
        let names: Vec<_> = nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["z", "A", "b"]);
    }
}
