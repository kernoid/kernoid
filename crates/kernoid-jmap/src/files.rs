// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP for files (draft-ietf-jmap-filenode-19; RFC 0005, 8): `FileNode/get`, `/changes`, `/set`, `/query` on the
//! caller's own file store, on stores shared with it and on the tenant's drives – with the rights of the draft's
//! section 5, sharing through `shareWith` (11), kernoid's `FileVersion/get` for earlier contents (6) and
//! `FileLink/*` for links (11.3).

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use bytes::Bytes;
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::Stream;
use kernoid_files::{
    Content, FileAccess, Files, FilesError, MAX_DEPTH, MAX_NAME, NewNode, NodeInfo, NodeType, NodeUpdate, OnExists,
    Rights, SetOptions, View,
};
use kernoid_identity::role::Principal;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    BlobId, Caller, Jmap, MAX_OBJECTS_IN_GET, MAX_OBJECTS_IN_SET,
    mailbox::{ids, invalid_properties},
    request::{Context, MethodError, MethodResult},
};

/// What the account capability `urn:ietf:params:jmap:filenode` says for one store.
pub(crate) fn capability(access: &FileAccess) -> Value {
    json!({
        "maxFileNodeDepth": MAX_DEPTH,
        "maxSizeFileNodeName": MAX_NAME,
        "forbiddenNameChars": kernoid_files::FORBIDDEN_CHARS,
        "supportedNodeTypes": ["Directory", "File"],
        "fileNodeQuerySortOptions": SORT_PROPERTIES,
        "mayCreateTopLevelFileNode": access.may_create_top_level(),
        "webTrashUrl": null,
        "caseInsensitiveNames": false,
        "webUrlTemplate": null,
        "webWriteUrlTemplate": null,
    })
}

pub(crate) const SORT_PROPERTIES: [&str; 7] = ["name", "size", "mediaType", "created", "modified", "nodeType", "tree"];

const DIRECTORY_PROPERTIES: [&str; 4] = ["role", "isSubscribed", "myRights", "shareWith"];
const FILE_PROPERTIES: [&str; 4] = ["blobId", "size", "mediaType", "executable"];
const COMMON_PROPERTIES: [&str; 8] = ["@type", "id", "parentId", "name", "created", "modified", "accessed", "changed"];
/// kernoid's own (RFC 0006, 6): the vault a node lies in, the vault's public key (on its root), the encrypted name;
/// `kernoid:newVault` (`publicKey`, `sealed`) makes a new directory a vault.
const VAULT_PROPERTIES: [&str; 4] = ["kernoid:vault", "kernoid:vaultKey", "kernoid:encryptedName", "kernoid:newVault"];
/// What `FileNode/get` shows of a node the user can discover but not read (draft, section 5).
const VISIBLE_UNREADABLE: [&str; 7] = ["@type", "id", "name", "parentId", "myRights", "isSubscribed", "shareWith"];

/// A `SetError` for what the store refused.
fn set_error(error: &FilesError) -> Value {
    if matches!(error, FilesError::Store(_) | FilesError::Blob(_)) {
        return crate::mailbox::internal_error(error);
    }
    let kind = match error {
        FilesError::NotFound("the node") => "notFound",
        FilesError::NotFound(_) | FilesError::Invalid(_) => "invalidProperties",
        FilesError::AlreadyExists(existing) => {
            return json!({ "type": "alreadyExists", "existingId": existing.to_string(), "description": error.to_string() });
        }
        FilesError::HasChildren => "nodeHasChildren",
        FilesError::OverQuota => "overQuota",
        FilesError::TooLarge { .. } => "tooLarge",
        _ => "forbidden",
    };
    json!({ "type": kind, "description": error.to_string() })
}

impl From<FilesError> for MethodError {
    fn from(error: FilesError) -> Self {
        match error {
            FilesError::CannotCalculateChanges => Self::new("cannotCalculateChanges", error.to_string()),
            FilesError::NotFound(_) | FilesError::Invalid(_) => Self::invalid(error.to_string()),
            other => Self::server_fail(other),
        }
    }
}

fn utc(date: DateTime<Utc>) -> Value {
    json!(date.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

fn parse_date(value: &Value) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.as_str()?).ok().map(|date| date.with_timezone(&Utc))
}

fn type_name(node_type: NodeType) -> &'static str {
    match node_type {
        NodeType::Directory => "Directory",
        NodeType::File => "File",
    }
}

/// A `FilesRights` object.
pub(crate) fn rights_object(rights: Rights) -> Value {
    json!({
        "mayRead": rights.contains(Rights::READ),
        "mayAddChildren": rights.contains(Rights::ADD),
        "mayRename": rights.contains(Rights::RENAME),
        "mayDelete": rights.contains(Rights::DELETE),
        "mayModifyContent": rights.contains(Rights::WRITE),
        "mayShare": rights.contains(Rights::SHARE),
    })
}

/// Rights from a `FilesRights` object; missing members are false.
fn rights_from(value: &Value) -> Option<Rights> {
    let object = value.as_object()?;
    let mut rights = Rights::NONE;
    for (name, right) in [
        ("mayRead", Rights::READ),
        ("mayAddChildren", Rights::ADD),
        ("mayRename", Rights::RENAME),
        ("mayDelete", Rights::DELETE),
        ("mayModifyContent", Rights::WRITE),
        ("mayShare", Rights::SHARE),
    ] {
        if object.get(name).and_then(Value::as_bool).unwrap_or(false) {
            rights |= right;
        }
    }
    Some(rights)
}

/// The grants on each directory of a store, as `shareWith` shows them: principal id → rights.
type Shares = HashMap<Uuid, Map<String, Value>>;

/// A node as `FileNode/get` shows it to the user of `view`, with `properties` (all if `None`); `@type` and `id`
/// always.
fn node_object(node: &NodeInfo, view: &View, shares: &Shares, properties: Option<&HashSet<String>>) -> Value {
    let readable = view.readable(node.id);
    let rights = view.rights(node.id);
    let wanted = |property: &str| properties.is_none_or(|properties| properties.contains(property));
    let mut out = Map::new();
    out.insert("@type".into(), json!(type_name(node.node_type)));
    out.insert("id".into(), json!(node.id.to_string()));
    let mut put = |property: &str, value: Value| {
        if wanted(property) {
            let shown = readable || VISIBLE_UNREADABLE.contains(&property);
            out.insert(property.into(), if shown { value } else { Value::Null });
        }
    };
    put("parentId", json!(node.parent.map(|parent| parent.to_string())));
    put("name", json!(node.name));
    put("created", utc(node.created));
    put("modified", utc(node.modified));
    put("accessed", utc(node.accessed));
    put("changed", utc(node.changed));
    if node.vault.is_some() {
        let b64 = |bytes: &Option<Vec<u8>>| {
            use base64::Engine;
            bytes.as_deref().map_or(Value::Null, |b| json!(base64::engine::general_purpose::STANDARD.encode(b)))
        };
        put("kernoid:vault", json!(node.vault.map(|vault| vault.to_string())));
        put("kernoid:vaultKey", b64(&node.vault_key));
        put("kernoid:encryptedName", b64(&node.encrypted_name));
    }
    match node.node_type {
        NodeType::Directory => {
            put("role", json!(node.role.map(|role| role.as_str())));
            put("isSubscribed", json!(node.is_subscribed));
            put("myRights", rights_object(rights));
            let share_with = shares.get(&node.id).filter(|_| rights.contains(Rights::SHARE));
            put("shareWith", share_with.map_or(Value::Null, |map| Value::Object(map.clone())));
        }
        NodeType::File => {
            put("blobId", json!(node.content.map(|content| BlobId::File(content).to_string())));
            put("size", json!(node.size));
            put("mediaType", json!(node.media_type));
            put("executable", json!(node.executable));
        }
    }
    Value::Object(out)
}

/// The names from the top down to the node, for sorting as a tree.
fn path(view: &View, id: Uuid) -> Vec<String> {
    let name = |id: Uuid| view.node(id).map(|node| node.name.clone());
    let mut path: Vec<String> = view.ancestors(id).iter().rev().filter_map(|id| name(*id)).collect();
    path.extend(name(id));
    path
}

/// A glob as the draft's `nameMatch` reads it: `*`, `?` and brackets, case-insensitive.
fn glob(pattern: &str, value: &str) -> bool {
    fn matches(pattern: &[char], value: &[char]) -> bool {
        match pattern.split_first() {
            None => value.is_empty(),
            Some(('*', rest)) => (0..=value.len()).any(|skip| matches(rest, &value[skip..])),
            Some(('?', rest)) => !value.is_empty() && matches(rest, &value[1..]),
            Some(('[', rest)) => {
                let Some(close) = rest.iter().skip(1).position(|c| *c == ']').map(|at| at + 1) else {
                    return value.first() == Some(&'[') && matches(rest, &value[1..]);
                };
                let Some((first, value_rest)) = value.split_first() else { return false };
                let (negate, set) = match rest[..close].split_first() {
                    Some(('!' | '^', set)) => (true, set),
                    _ => (false, &rest[..close]),
                };
                let mut found = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        found |= (set[i]..=set[i + 2]).contains(first);
                        i += 3;
                    } else {
                        found |= set[i] == *first;
                        i += 1;
                    }
                }
                found != negate && matches(&rest[close + 1..], value_rest)
            }
            Some((c, rest)) => value.first() == Some(c) && matches(rest, &value[1..]),
        }
    }
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let value: Vec<char> = value.to_lowercase().chars().collect();
    matches(&pattern, &value)
}

/// The texts a filter searches file contents for (`body` and `text`, in any condition).
fn searched_texts(filter: &Map<String, Value>, out: &mut HashSet<String>) {
    if let Some(Value::Array(conditions)) = filter.get("conditions") {
        for condition in conditions.iter().filter_map(Value::as_object) {
            searched_texts(condition, out);
        }
    }
    for key in ["body", "text"] {
        if let Some(text) = filter.get(key).and_then(Value::as_str) {
            out.insert(text.to_owned());
        }
    }
}

/// Files whose content holds a text, by the text (RFC 0005, 8; the worker's index, `kernoid_files::housekeeping`).
type BodyMatches = HashMap<String, HashSet<Uuid>>;

/// Whether a node matches a filter (a condition, or an operator with conditions). Conditions on what the user may
/// not read do not match (draft, 3.2.5).
fn filter_matches(
    view: &View,
    node: &NodeInfo,
    filter: &Map<String, Value>,
    bodies: &BodyMatches,
) -> Result<bool, MethodError> {
    if let Some(operator) = filter.get("operator").and_then(Value::as_str) {
        let conditions = filter
            .get("conditions")
            .and_then(Value::as_array)
            .ok_or_else(|| MethodError::new("unsupportedFilter", "an operator needs conditions"))?;
        let mut results = Vec::new();
        for condition in conditions {
            let condition =
                condition.as_object().ok_or_else(|| MethodError::new("unsupportedFilter", "conditions are objects"))?;
            results.push(filter_matches(view, node, condition, bodies)?);
        }
        return match operator {
            "AND" => Ok(results.iter().all(|result| *result)),
            "OR" => Ok(results.iter().any(|result| *result)),
            "NOT" => Ok(!results.iter().any(|result| *result)),
            _ => Err(MethodError::new("unsupportedFilter", format!("unknown operator {operator}"))),
        };
    }
    let readable = view.readable(node.id);
    let file = node.node_type == NodeType::File && readable;
    let directory = node.node_type == NodeType::Directory && readable;
    let id = |value: &Value| value.as_str().and_then(|id| Uuid::parse_str(id).ok());
    let date = |value: &Value| parse_date(value).ok_or_else(|| MethodError::invalid("a date is UTCDate"));
    for (key, value) in filter {
        let matched = match key.as_str() {
            "isTopLevel" => (node.parent.is_none()) == value.as_bool().unwrap_or(false),
            "parentId" => node.parent.is_some() && node.parent == id(value),
            "ancestorId" => id(value).is_some_and(|ancestor| view.ancestors(node.id).contains(&ancestor)),
            "descendantId" => id(value).is_some_and(|descendant| view.ancestors(descendant).contains(&node.id)),
            "nodeType" => value.as_str() == Some(type_name(node.node_type)),
            "role" => directory && node.role.map(|role| role.as_str()) == value.as_str(),
            "hasAnyRole" => directory && node.role.is_some() == value.as_bool().unwrap_or(false),
            "blobId" => {
                file && node.content.map(|content| BlobId::File(content).to_string()).as_deref() == value.as_str()
            }
            "isExecutable" => file && node.executable == value.as_bool(),
            "createdBefore" => readable && node.created < date(value)?,
            "createdAfter" => readable && node.created >= date(value)?,
            "modifiedBefore" => readable && node.modified < date(value)?,
            "modifiedAfter" => readable && node.modified >= date(value)?,
            "accessedBefore" => readable && node.accessed < date(value)?,
            "accessedAfter" => readable && node.accessed >= date(value)?,
            "minSize" => file && node.size >= value.as_u64(),
            "maxSize" => file && value.as_u64().is_some_and(|max| node.size.unwrap_or(0) < max),
            "name" => value.as_str() == Some(node.name.as_str()),
            "nameMatch" => value.as_str().is_some_and(|pattern| glob(pattern, &node.name)),
            "mediaType" => file && node.media_type.as_deref() == value.as_str(),
            "mediaTypeMatch" => {
                file && value
                    .as_str()
                    .zip(node.media_type.as_deref())
                    .is_some_and(|(pattern, kind)| glob(pattern, kind))
            }
            "text" => {
                let needle = value.as_str().unwrap_or_default().to_lowercase();
                let in_body =
                    value.as_str().and_then(|text| bodies.get(text)).is_some_and(|ids| ids.contains(&node.id));
                node.name.to_lowercase().contains(&needle)
                    || (file && node.media_type.as_deref().is_some_and(|kind| kind.contains(&needle)))
                    || (file && in_body)
            }
            "body" => {
                file && value.as_str().and_then(|text| bodies.get(text)).is_some_and(|ids| ids.contains(&node.id))
            }
            other => return Err(MethodError::new("unsupportedFilter", format!("{other} is not supported"))),
        };
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Compares two nodes by one property of a sort; nodes without it come first.
fn compare(view: &View, a: &NodeInfo, b: &NodeInfo, property: &str) -> Ordering {
    let type_rank = |node: &NodeInfo| match node.node_type {
        NodeType::Directory => 0,
        NodeType::File => 2,
    };
    // What the user may not read sorts as absent, first (draft, 3.2.5).
    fn key<'a>(view: &View, node: &'a NodeInfo) -> Option<&'a NodeInfo> {
        view.readable(node.id).then_some(node)
    }
    let key = |node| key(view, node);
    match property {
        "name" => a.name.cmp(&b.name),
        "size" => key(a).and_then(|node| node.size).cmp(&key(b).and_then(|node| node.size)),
        "mediaType" => {
            key(a).and_then(|node| node.media_type.as_ref()).cmp(&key(b).and_then(|node| node.media_type.as_ref()))
        }
        "created" => key(a).map(|node| node.created).cmp(&key(b).map(|node| node.created)),
        "modified" => key(a).map(|node| node.modified).cmp(&key(b).map(|node| node.modified)),
        "nodeType" => type_rank(a).cmp(&type_rank(b)),
        "tree" => path(view, a.id).cmp(&path(view, b.id)),
        _ => Ordering::Equal,
    }
}

/// Content to send: its size, type, digest and the bytes as they are read.
pub struct FileDownload {
    pub size: u64,
    pub start: u64,
    pub end: u64,
    pub media_type: String,
    pub sha256: Vec<u8>,
    pub content: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, kernoid_store::BlobError>> + Send>>,
}

impl std::fmt::Debug for FileDownload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileDownload").field("size", &self.size).field("media_type", &self.media_type).finish()
    }
}

impl Jmap {
    pub fn files(&self) -> Option<&Files> {
        self.files.as_ref()
    }

    /// What the caller may do in `owner`'s file store: its own (with the service `files`), or what it was granted.
    pub async fn file_access(&self, caller: &Caller, owner: Uuid) -> Result<Option<FileAccess>, FilesError> {
        let Some(files) = &self.files else { return Ok(None) };
        if owner == caller.account && !caller.files {
            return Ok(None);
        }
        let access = files.access(caller.account, owner).await?;
        Ok(access.any().then_some(access))
    }

    /// The grants on the directories of a store, as `shareWith` shows them.
    async fn shares(&self, owner: Uuid) -> Shares {
        let mut shares = Shares::new();
        let Some(identity) = &self.identity else { return shares };
        for grant in identity.file_access(owner, None).await.unwrap_or_default() {
            let Some(node) = grant.node else { continue };
            let principal = match grant.grantee {
                Principal::Account(id) | Principal::Group(id) => id,
            };
            shares.entry(node).or_default().insert(principal.to_string(), rights_object(Rights::parse(&grant.rights)));
        }
        shares
    }

    /// Content for a file of `access.owner`'s store from a blob the caller may read there – an upload (whose parts
    /// the file takes over), a file's content (whose parts it shares), an email or one of its parts (copied).
    pub(crate) async fn blob_for_file(&self, caller: &Caller, access: &FileAccess, blob: &str) -> Option<Content> {
        let files = self.files.as_ref()?;
        match BlobId::parse(blob)? {
            BlobId::File(content) => Some(files.readable(access, content).await.ok()?.content),
            BlobId::Upload(id) => {
                let upload = self.mail.upload_info(access.owner, id).await.ok()?;
                match upload.parts {
                    Some((prefix, stored)) => Some(Content { tenant: upload.tenant, prefix, stored }),
                    None => {
                        let (content, _) = self.mail.upload(access.owner, id).await.ok()?;
                        files.store_bytes(access.owner, content).await.ok()
                    }
                }
            }
            BlobId::Email(_) | BlobId::Part(..) if caller.mail && access.owned => {
                let bytes = self.blob_bytes(&kernoid_mail::Access::own(caller.account), blob).await?;
                files.store_bytes(access.owner, bytes).await.ok()
            }
            BlobId::Email(_) | BlobId::Part(..) => None,
        }
    }

    /// A file's content – current or a version – for the caller, or the part `range` asks for (from a start to an
    /// inclusive end, or to the end).
    pub async fn file_content(
        &self,
        caller: &Caller,
        owner: Uuid,
        content: Uuid,
        range: Option<(u64, Option<u64>)>,
    ) -> Result<FileDownload, FilesError> {
        let files = self.files.as_ref().ok_or(FilesError::NotFound("the content"))?;
        let access = self.file_access(caller, owner).await?.ok_or(FilesError::NotFound("the content"))?;
        let readable = files.readable(&access, content).await?;
        let size = readable.info.size;
        let (start, end) = crate::blob::bounds(size, range);
        Ok(FileDownload {
            size,
            start,
            end,
            media_type: readable.info.media_type.clone(),
            sha256: readable.info.sha256.clone(),
            content: Box::pin(files.read(&readable.content, start, end)),
        })
    }

    /// Replaces a file's content as it arrives (the draft's direct write, section 4): the answer's `blobId`, `size`,
    /// `mediaType` and SHA-256.
    pub async fn write_file<S, E>(
        &self,
        caller: &Caller,
        account: &str,
        node: &str,
        media_type: Option<&str>,
        content: S,
    ) -> Result<Value, FilesError>
    where
        S: Stream<Item = Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        let files = self.files.as_ref().ok_or(FilesError::NotFound("the node"))?;
        let owner = Uuid::parse_str(account).map_err(|_| FilesError::NotFound("the node"))?;
        let access = self.file_access(caller, owner).await?.ok_or(FilesError::NotFound("the node"))?;
        let node = Uuid::parse_str(node).map_err(|_| FilesError::NotFound("the node"))?;
        if !files.rights(&access, node).await?.contains(Rights::WRITE) {
            return Err(FilesError::Forbidden("not allowed".into()));
        }
        // Only the type and subtype: parameters such as charset are not kept.
        let media_type = media_type.map(|kind| kind.split(';').next().unwrap_or_default().trim());
        let media_type = media_type.map(kernoid_files::check_media_type).transpose()?;
        let stored = files.store(owner, content).await?;
        let sha256 = stored.stored.sha256;
        let node = files.write(&access, node, stored, media_type.as_deref()).await?;
        use base64::Engine;
        Ok(json!({
            "blobId": node.content.map(|content| BlobId::File(content).to_string()),
            "size": node.size,
            "mediaType": node.media_type,
            "digest:sha-256": base64::engine::general_purpose::STANDARD.encode(sha256),
        }))
    }
}

impl Context<'_> {
    /// The file store `accountId` names and what the caller may do in it.
    async fn file_store(&self, args: &Map<String, Value>) -> Result<(Uuid, Files, FileAccess), MethodError> {
        let files = self.jmap.files.clone().ok_or_else(|| MethodError::new("unknownMethod", "no files here"))?;
        let id = args
            .get("accountId")
            .and_then(Value::as_str)
            .ok_or_else(|| MethodError::invalid("accountId is required"))?;
        let not_found = || MethodError::new("accountNotFound", "no such account");
        let owner = Uuid::parse_str(id).map_err(|_| not_found())?;
        if owner == self.caller.account && !self.caller.files {
            return Err(MethodError::new("accountNotSupportedByMethod", "this account has no files"));
        }
        let access = self.jmap.file_access(self.caller, owner).await?.ok_or_else(not_found)?;
        Ok((owner, files, access))
    }

    pub async fn file_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, files, access) = self.file_store(&args).await?;
        let state = files.state(owner).await?;
        let view = files.view(access).await?;
        let shares = self.jmap.shares(owner).await;
        let properties: Option<HashSet<String>> = match args.get("properties") {
            Some(Value::Array(list)) => Some(list.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
            _ => None,
        };
        let fetch_parents = args.get("fetchParents").and_then(Value::as_bool).unwrap_or(false);
        let object = |node: &NodeInfo| node_object(node, &view, &shares, properties.as_ref());
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        match ids(&args)? {
            None => {
                let mut nodes: Vec<&NodeInfo> = view.nodes().collect();
                nodes.sort_by_key(|node| node.id);
                list.extend(nodes.into_iter().map(object));
            }
            Some(wanted) => {
                if wanted.len() > MAX_OBJECTS_IN_GET {
                    return Err(MethodError::new("requestTooLarge", "too many ids"));
                }
                let mut seen = HashSet::new();
                let mut parents = Vec::new();
                for id in wanted {
                    let Some(node) = Uuid::parse_str(&id).ok().and_then(|id| view.node(id)) else {
                        not_found.push(id);
                        continue;
                    };
                    if seen.insert(node.id) {
                        list.push(object(node));
                    }
                    if fetch_parents {
                        parents.extend(view.ancestors(node.id));
                    }
                }
                for parent in parents {
                    if seen.insert(parent)
                        && let Some(node) = view.node(parent)
                    {
                        list.push(object(node));
                    }
                }
            }
        }
        Ok(vec![(
            "FileNode/get".into(),
            json!({ "accountId": owner.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    pub async fn file_changes(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, files, access) = self.file_store(&args).await?;
        let since = args
            .get("sinceState")
            .and_then(Value::as_str)
            .and_then(|state| state.parse::<i64>().ok())
            .ok_or_else(|| MethodError::new("cannotCalculateChanges", "unknown state"))?;
        let max = args.get("maxChanges").and_then(Value::as_u64).map(|max| max as usize);
        if max == Some(0) {
            return Err(MethodError::invalid("maxChanges must be positive"));
        }
        let mut changes = files.changes(owner, since, max).await?;
        // Someone else's store: what the user cannot see (any more) is gone for them (draft, section 5).
        if !access.owned {
            let view = files.view(access).await?;
            let visible = |id: &Uuid| view.node(*id).is_some();
            // Created and gone again since: the user never needs to know.
            changes.created.retain(visible);
            let (updated, hidden): (Vec<Uuid>, Vec<Uuid>) = changes.updated.into_iter().partition(visible);
            changes.updated = updated;
            changes.destroyed.extend(hidden);
        }
        let ids = |ids: Vec<Uuid>| ids.into_iter().map(|id| id.to_string()).collect::<Vec<_>>();
        Ok(vec![(
            "FileNode/changes".into(),
            json!({
                "accountId": owner.to_string(),
                "oldState": changes.old_state.to_string(),
                "newState": changes.new_state.to_string(),
                "hasMoreChanges": changes.has_more_changes,
                "created": ids(changes.created),
                "updated": ids(changes.updated),
                "destroyed": ids(changes.destroyed),
            }),
        )])
    }

    pub async fn file_query(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, files, access) = self.file_store(&args).await?;
        let state = files.state(owner).await?;
        let view = files.view(access).await?;
        let depth = args.get("depth").and_then(Value::as_u64).map(|depth| depth as usize);
        let filter = match args.get("filter") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(filter)) => filter.clone(),
            Some(_) => return Err(MethodError::invalid("filter is an object")),
        };
        let mut texts = HashSet::new();
        searched_texts(&filter, &mut texts);
        let mut bodies = BodyMatches::new();
        for text in texts {
            let found = files.body_matches(owner, &text).await?;
            bodies.insert(text, found);
        }
        let mut matched = Vec::new();
        for node in view.nodes() {
            if depth.is_some_and(|depth| view.ancestors(node.id).len() > depth) {
                continue;
            }
            if filter_matches(&view, node, &filter, &bodies)? {
                matched.push(node);
            }
        }
        let mut sort = Vec::new();
        if let Some(Value::Array(comparators)) = args.get("sort") {
            for comparator in comparators {
                let property = comparator.get("property").and_then(Value::as_str).unwrap_or_default();
                if !SORT_PROPERTIES.contains(&property) {
                    return Err(MethodError::new("unsupportedSort", format!("cannot sort by {property}")));
                }
                sort.push((
                    property.to_owned(),
                    comparator.get("isAscending").and_then(Value::as_bool).unwrap_or(true),
                ));
            }
        }
        matched.sort_by(|a, b| {
            sort.iter()
                .map(|(property, ascending)| {
                    let order = compare(&view, a, b, property);
                    if *ascending { order } else { order.reverse() }
                })
                .find(|order| *order != Ordering::Equal)
                .unwrap_or_else(|| a.id.cmp(&b.id))
        });
        let ids: Vec<String> = matched.iter().map(|node| node.id.to_string()).collect();
        let total = ids.len();
        let mut position = match args.get("position").and_then(Value::as_i64).unwrap_or(0) {
            negative if negative < 0 => total.saturating_sub(negative.unsigned_abs() as usize),
            position => position as usize,
        };
        if let Some(anchor) = args.get("anchor").and_then(Value::as_str) {
            let at =
                ids.iter().position(|id| id == anchor).ok_or_else(|| MethodError::new("anchorNotFound", anchor))?;
            let offset = args.get("anchorOffset").and_then(Value::as_i64).unwrap_or(0);
            position = (at as i64 + offset).max(0) as usize;
        }
        let limit = args.get("limit").and_then(Value::as_u64).map_or(usize::MAX, |limit| limit as usize);
        let page: Vec<&String> = ids.iter().skip(position).take(limit).collect();
        let mut response = json!({
            "accountId": owner.to_string(),
            "queryState": state.to_string(),
            "canCalculateChanges": false,
            "position": position.min(total),
            "ids": page,
        });
        if args.get("calculateTotal").and_then(Value::as_bool).unwrap_or(false) {
            response["total"] = json!(total);
        }
        Ok(vec![("FileNode/query".into(), response)])
    }

    /// kernoid's `FileVersion/get` (RFC 0005, 6): the contents of one file, the current one first, then the earlier
    /// ones, newest first; a version is restored by `FileNode/set` giving the file its `blobId`.
    /// `VaultKey/get` (RFC 0006, 6): for each vault asked for (`ids`, required), the caller's wrapped key (`sealed`,
    /// base64, null until a member gave it) and the accounts that have one (`members`).
    pub async fn vault_key_get(&self, args: Map<String, Value>) -> MethodResult {
        use base64::Engine;
        let (owner, files, access) = self.file_store(&args).await?;
        let ids = crate::mailbox::ids(&args)?.ok_or_else(|| MethodError::invalid("ids is required"))?;
        let (mut list, mut not_found) = (Vec::new(), Vec::new());
        for id in ids {
            let Some(vault) = self.id(&id) else {
                not_found.push(Value::String(id));
                continue;
            };
            let sealed = files.vault_key(&access, vault).await;
            let members = files.vault_members(&access, vault).await;
            match (sealed, members) {
                (Ok(sealed), Ok(members)) => list.push(json!({
                    "id": id,
                    "sealed": sealed.map(|s| base64::engine::general_purpose::STANDARD.encode(s)),
                    "members": members.iter().map(Uuid::to_string).collect::<Vec<_>>(),
                })),
                (Err(FilesError::NotFound(_) | FilesError::Forbidden(_)), _)
                | (_, Err(FilesError::NotFound(_) | FilesError::Forbidden(_))) => not_found.push(Value::String(id)),
                (Err(error), _) | (_, Err(error)) => return Err(error.into()),
            }
        }
        Ok(vec![(
            "VaultKey/get".into(),
            json!({ "accountId": owner.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    /// `VaultKey/set`: `update` of a vault with `members/<account id>` set to a wrapped key (base64) or null – a
    /// member who may share gives the vault's key to another account, or takes it away.
    pub async fn vault_key_set(&self, args: Map<String, Value>) -> MethodResult {
        use base64::Engine;
        let (owner, files, access) = self.file_store(&args).await?;
        let (mut updated, mut not_updated) = (Map::new(), Map::new());
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, patch) in update {
                let result = async {
                    let vault = self.id(id).ok_or_else(|| json!({ "type": "notFound" }))?;
                    let patch = patch.as_object().ok_or_else(|| invalid_properties("a patch object"))?;
                    for (key, value) in patch {
                        let account = key
                            .strip_prefix("members/")
                            .and_then(|account| Uuid::parse_str(account).ok())
                            .ok_or_else(|| invalid_properties(format!("{key} cannot be set")))?;
                        let outcome = match value {
                            Value::Null => files.remove_vault_key(&access, vault, account).await,
                            Value::String(sealed) => {
                                let sealed = base64::engine::general_purpose::STANDARD
                                    .decode(sealed)
                                    .map_err(|_| invalid_properties("a wrapped key is base64"))?;
                                files.set_vault_key(&access, vault, account, &sealed).await
                            }
                            _ => return Err(invalid_properties("a wrapped key or null")),
                        };
                        outcome.map_err(|error| set_error(&error))?;
                    }
                    Ok::<_, Value>(())
                }
                .await;
                match result {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), error);
                    }
                }
            }
        }
        let or_null = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
        Ok(vec![(
            "VaultKey/set".into(),
            json!({ "accountId": owner.to_string(), "updated": or_null(updated), "notUpdated": or_null(not_updated) }),
        )])
    }

    pub async fn file_versions(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, files, access) = self.file_store(&args).await?;
        let node = args
            .get("nodeId")
            .and_then(Value::as_str)
            .and_then(|id| self.id(id))
            .ok_or_else(|| MethodError::invalid("nodeId is required"))?;
        let versions = match files.versions(&access, node).await {
            Ok(versions) => versions,
            Err(FilesError::NotFound(_) | FilesError::Forbidden(_)) => {
                return Err(MethodError::invalid("no such file"));
            }
            Err(error) => return Err(error.into()),
        };
        let list: Vec<Value> = versions
            .into_iter()
            .map(|version| {
                json!({
                    "id": version.id.to_string(),
                    "blobId": BlobId::File(version.id).to_string(),
                    "size": version.size,
                    "mediaType": version.media_type,
                    "modified": utc(version.modified),
                    "created": utc(version.created_at),
                    "isCurrent": version.current,
                })
            })
            .collect();
        Ok(vec![(
            "FileVersion/get".into(),
            json!({ "accountId": owner.to_string(), "nodeId": node.to_string(), "list": list }),
        )])
    }

    /// kernoid's `FileLink/get` (RFC 0005, 11.3): the links to nodes the caller may share – all of them, those of
    /// `nodeId`, or those of `ids`. Tokens are shown only when a link is made.
    pub async fn file_link_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, files, access) = self.file_store(&args).await?;
        let identity = self.jmap.identity.as_ref().ok_or_else(|| MethodError::new("unknownMethod", "no links here"))?;
        let node = match args.get("nodeId") {
            Some(Value::String(id)) => Some(self.id(id).ok_or_else(|| MethodError::invalid("no such node"))?),
            _ => None,
        };
        let wanted: Option<HashSet<Uuid>> =
            ids(&args)?.map(|list| list.iter().filter_map(|id| Uuid::parse_str(id).ok()).collect());
        let view = files.view(access).await?;
        let list: Vec<Value> = identity
            .file_links(owner, node)
            .await
            .map_err(|_| MethodError::new("serverFail", "the links cannot be read"))?
            .into_iter()
            .filter(|link| view.rights(link.node).contains(Rights::SHARE))
            .filter(|link| wanted.as_ref().is_none_or(|wanted| wanted.contains(&link.id)))
            .map(|link| {
                json!({
                    "id": link.id.to_string(),
                    "nodeId": link.node.to_string(),
                    "expires": link.expires_at.map_or(Value::Null, utc),
                    "hasPassword": link.password,
                    "mayRead": link.rights.read,
                    "mayAdd": link.rights.add,
                    "created": utc(link.created_at),
                })
            })
            .collect();
        let found: HashSet<String> = list.iter().filter_map(|link| link["id"].as_str().map(str::to_owned)).collect();
        let not_found: Vec<Value> = match ids(&args)? {
            Some(list) => list.into_iter().filter(|id| !found.contains(id)).map(Value::String).collect(),
            None => Vec::new(),
        };
        Ok(vec![(
            "FileLink/get".into(),
            json!({ "accountId": owner.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    /// kernoid's `FileLink/set`: makes links (`nodeId`, `mayRead`, `mayAdd`, `expires`, `password`) to nodes the caller
    /// may share – never letting people do more than the caller may – each created link answers its `id` and its
    /// `token`, shown this once – and destroys them. Links are not updated.
    pub async fn file_link_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let (owner, files, access) = self.file_store(&args).await?;
        let identity = self.jmap.identity.clone().ok_or_else(|| MethodError::new("unknownMethod", "no links here"))?;
        let who = format!("account:{}", self.caller.account);
        let forbidden = |description: &str| json!({ "type": "forbidden", "description": description });
        let view = files.view(access).await?;
        let mut created = Map::new();
        let mut not_created = Map::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for (key, value) in create {
                let result = async {
                    let object = value.as_object().ok_or_else(|| invalid_properties("a link is an object"))?;
                    let node = object
                        .get("nodeId")
                        .and_then(Value::as_str)
                        .and_then(|id| self.id(id))
                        .ok_or_else(|| invalid_properties("nodeId names a node"))?;
                    if !view.rights(node).contains(Rights::SHARE) {
                        return Err(forbidden("a link needs mayShare"));
                    }
                    let flag = |name: &str, default: bool| match object.get(name) {
                        None => Ok(default),
                        Some(Value::Bool(value)) => Ok(*value),
                        Some(_) => Err(invalid_properties(format!("{name} is a boolean"))),
                    };
                    let rights = kernoid_identity::file_link::LinkRights {
                        read: flag("mayRead", true)?,
                        add: flag("mayAdd", false)?,
                    };
                    if rights.add && !view.rights(node).contains(Rights::ADD) {
                        return Err(forbidden("a link that adds needs mayAddChildren"));
                    }
                    let expires = match object.get("expires") {
                        None | Some(Value::Null) => None,
                        Some(Value::String(date)) => Some(
                            DateTime::parse_from_rfc3339(date)
                                .map_err(|_| invalid_properties("expires is a UTCDate"))?
                                .with_timezone(&Utc),
                        ),
                        Some(_) => return Err(invalid_properties("expires is a UTCDate or null")),
                    };
                    let password = match object.get("password") {
                        None | Some(Value::Null) => None,
                        Some(Value::String(password)) => Some(password.as_str()),
                        Some(_) => return Err(invalid_properties("password is a string or null")),
                    };
                    identity.add_file_link(owner, node, rights, expires, password, &who).await.map_err(|error| {
                        match error {
                            kernoid_identity::IdentityError::Refused(reason) => invalid_properties(reason),
                            kernoid_identity::IdentityError::NotFound(_) => invalid_properties("nodeId names a node"),
                            _ => json!({ "type": "serverFail" }),
                        }
                    })
                }
                .await;
                match result {
                    Ok((id, token)) => {
                        self.created.insert(format!("#{key}"), id.to_string());
                        created.insert(key.clone(), json!({ "id": id.to_string(), "token": token }));
                    }
                    Err(error) => {
                        not_created.insert(key.clone(), error);
                    }
                }
            }
        }
        let mut destroyed = Vec::new();
        let mut not_destroyed = Map::new();
        if let Some(Value::Array(list)) = args.get("destroy") {
            let links = identity
                .file_links(owner, None)
                .await
                .map_err(|_| MethodError::new("serverFail", "the links cannot be read"))?;
            for id in list.iter().filter_map(Value::as_str) {
                let link = Uuid::parse_str(id).ok().and_then(|id| links.iter().find(|link| link.id == id));
                let result = match link {
                    None => Err(json!({ "type": "notFound" })),
                    Some(link) if !view.rights(link.node).contains(Rights::SHARE) => {
                        Err(forbidden("removing a link needs mayShare"))
                    }
                    Some(link) => {
                        identity.remove_file_link(owner, link.id, &who).await.map_err(|_| json!({ "type": "notFound" }))
                    }
                };
                match result {
                    Ok(()) => destroyed.push(json!(id)),
                    Err(error) => {
                        not_destroyed.insert(id.to_owned(), error);
                    }
                }
            }
        }
        let or_null = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
        Ok(vec![(
            "FileLink/set".into(),
            json!({
                "accountId": owner.to_string(),
                "created": or_null(created),
                "notCreated": or_null(not_created),
                "destroyed": if destroyed.is_empty() { Value::Null } else { Value::Array(destroyed) },
                "notDestroyed": or_null(not_destroyed),
            }),
        )])
    }

    pub async fn file_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let (owner, files, access) = self.file_store(&args).await?;
        let old_state = files.state(owner).await?;
        crate::mailbox::if_in_state(&args, old_state as u64)?;
        let count = ["create", "update", "destroy"]
            .iter()
            .map(|key| {
                args.get(*key)
                    .map_or(0, |value| value.as_object().map_or(0, Map::len).max(value.as_array().map_or(0, Vec::len)))
            })
            .sum::<usize>();
        if count > MAX_OBJECTS_IN_SET {
            return Err(MethodError::new("requestTooLarge", "too many changes"));
        }
        let on_exists = match args.get("onExists") {
            None | Some(Value::Null) => OnExists::Refuse,
            Some(Value::String(value)) if value == "replace" => OnExists::Replace,
            Some(Value::String(value)) if value == "rename" => OnExists::Rename,
            Some(_) => return Err(MethodError::invalid("onExists is replace, rename or null")),
        };
        let options = SetOptions {
            on_exists,
            case_insensitive: args.get("compareCaseInsensitively").and_then(Value::as_bool).unwrap_or(false),
            remove_children: args.get("onDestroyRemoveChildren").and_then(Value::as_bool).unwrap_or(false),
        };
        let mut created = Map::new();
        let mut not_created = Map::new();
        let mut updated = Map::new();
        let mut not_updated = Map::new();
        let mut destroyed: Vec<String> = Vec::new();
        let mut not_destroyed = Map::new();

        // Destroys first, so that a node of the same name can be created in the same call (RFC 0005, 8).
        if let Some(Value::Array(ids)) = args.get("destroy") {
            for id in ids {
                let Some(id) = id.as_str() else { continue };
                if destroyed.iter().any(|gone| gone == id) {
                    continue;
                }
                let Some(node) = self.id(id) else {
                    not_destroyed.insert(id.to_owned(), json!({ "type": "notFound" }));
                    continue;
                };
                match files.destroy(&access, node, options.remove_children).await {
                    Ok(gone) => destroyed.extend(gone.into_iter().map(|id| id.to_string())),
                    Err(FilesError::Store(error)) => return Err(MethodError::server_fail(error)),
                    Err(error) => {
                        not_destroyed.insert(id.to_owned(), set_error(&error));
                    }
                }
            }
        }

        // Creates whose parent is created in this call wait for it.
        let mut pending: Vec<(String, Map<String, Value>)> = Vec::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for (creation, value) in create {
                match value.as_object() {
                    Some(object) => pending.push((creation.clone(), object.clone())),
                    None => {
                        not_created.insert(creation.clone(), invalid_properties("an object"));
                    }
                }
            }
        }
        loop {
            let waiting = |object: &Map<String, Value>, pending: &[(String, Map<String, Value>)]| {
                object
                    .get("parentId")
                    .and_then(Value::as_str)
                    .and_then(|parent| parent.strip_prefix('#'))
                    .is_some_and(|parent| pending.iter().any(|(creation, _)| creation == parent))
            };
            let Some(next) = pending.iter().position(|(_, object)| !waiting(object, &pending)) else { break };
            let (creation, object) = pending.remove(next);
            match self.create_node(&files, &access, &object, &options).await {
                Ok(written) => {
                    self.created.insert(creation.clone(), written.node.id.to_string());
                    destroyed.extend(written.destroyed.iter().map(Uuid::to_string));
                    if let Some(share_with) = object.get("shareWith").filter(|value| !value.is_null())
                        && let Err(error) = self.share(&access, written.node.id, share_with, true).await
                    {
                        not_created.insert(creation.clone(), error);
                        continue;
                    }
                    let view = files.view(access.clone()).await?;
                    let shares = self.jmap.shares(owner).await;
                    created.insert(creation, node_object(&written.node, &view, &shares, None));
                }
                Err(CreateError::Method(error)) => return Err(error),
                Err(CreateError::Set(error)) => {
                    not_created.insert(creation, error);
                }
            }
        }
        for (creation, _) in pending {
            not_created.insert(creation, invalid_properties("parentId refers to itself"));
        }

        if let Some(Value::Object(update)) = args.get("update") {
            for (id, patch) in update {
                let (Some(node), Some(patch)) = (self.id(id), patch.as_object()) else {
                    not_updated.insert(id.clone(), json!({ "type": "notFound" }));
                    continue;
                };
                // Sharing first: `shareWith` and `shareWith/<principal>`.
                let (sharing, rest): (Map<String, Value>, Map<String, Value>) =
                    patch.clone().into_iter().partition(|(key, _)| key == "shareWith" || key.starts_with("shareWith/"));
                if !sharing.is_empty()
                    && let Err(error) = self.share_patch(&access, node, &sharing).await
                {
                    not_updated.insert(id.clone(), error);
                    continue;
                }
                if rest.is_empty() {
                    updated.insert(id.clone(), Value::Null);
                    continue;
                }
                match self.update_node(&files, &access, node, &rest, &options).await {
                    Ok(written) => {
                        destroyed.extend(written.destroyed.iter().map(Uuid::to_string));
                        let node = &written.node;
                        let mut changed = json!({ "name": node.name, "changed": utc(node.changed) });
                        if node.node_type == NodeType::File {
                            changed["blobId"] = json!(node.content.map(|content| BlobId::File(content).to_string()));
                            changed["size"] = json!(node.size);
                            changed["mediaType"] = json!(node.media_type);
                            changed["modified"] = utc(node.modified);
                        }
                        updated.insert(id.clone(), changed);
                    }
                    Err(CreateError::Method(error)) => return Err(error),
                    Err(CreateError::Set(error)) => {
                        not_updated.insert(id.clone(), error);
                    }
                }
            }
        }

        let new_state = files.state(owner).await?;
        let or_null = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
        Ok(vec![(
            "FileNode/set".into(),
            json!({
                "accountId": owner.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": or_null(created),
                "updated": or_null(updated),
                "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
                "notCreated": or_null(not_created),
                "notUpdated": or_null(not_updated),
                "notDestroyed": or_null(not_destroyed),
            }),
        )])
    }

    /// `FileNode/copy` (RFC 8620, 5.4): nodes of another store – a directory with what it holds – copied into this
    /// one, a file's copy sharing its content; with `onSuccessDestroyOriginal` they are moved, which needs the right
    /// to delete them, and the destroying is answered as a `FileNode/set` of the store they came from.
    pub async fn file_copy(&mut self, args: Map<String, Value>) -> MethodResult {
        let (owner, files, access) = self.file_store(&args).await?;
        let from_id = args
            .get("fromAccountId")
            .and_then(Value::as_str)
            .ok_or_else(|| MethodError::invalid("fromAccountId is required"))?;
        if Uuid::parse_str(from_id).ok() == Some(owner) {
            return Err(MethodError::invalid("fromAccountId and accountId differ: FileNode/set moves within a store"));
        }
        let mut from_args = Map::new();
        from_args.insert("accountId".into(), json!(from_id));
        let (from, _, from_access) = self.file_store(&from_args).await?;
        let from_state = files.state(from).await?;
        if let Some(Value::String(expected)) = args.get("ifFromInState")
            && *expected != from_state.to_string()
        {
            return Err(MethodError::new("stateMismatch", "the store copied from has changed"));
        }
        let old_state = files.state(owner).await?;
        crate::mailbox::if_in_state(&args, old_state as u64)?;
        let create = match args.get("create") {
            Some(Value::Object(create)) => create.clone(),
            _ => return Err(MethodError::invalid("create is required")),
        };
        if create.len() > MAX_OBJECTS_IN_SET {
            return Err(MethodError::new("requestTooLarge", "too many copies"));
        }
        let move_them = args.get("onSuccessDestroyOriginal").and_then(Value::as_bool).unwrap_or(false);
        let on_exists = match args.get("onExists") {
            None | Some(Value::Null) => OnExists::Refuse,
            Some(Value::String(value)) if value == "replace" => OnExists::Replace,
            Some(Value::String(value)) if value == "rename" => OnExists::Rename,
            Some(_) => return Err(MethodError::invalid("onExists is replace, rename or null")),
        };
        let options = SetOptions { on_exists, ..SetOptions::default() };
        let view = files.view(from_access.clone()).await?;
        let mut created = Map::new();
        let mut not_created = Map::new();
        let mut originals = Vec::new();
        for (creation, value) in create {
            let result = async {
                let object = value.as_object().ok_or_else(|| set(invalid_properties("an object")))?;
                let id = object.get("id").and_then(Value::as_str).ok_or_else(|| set(invalid_properties("id")))?;
                let node = Uuid::parse_str(id)
                    .ok()
                    .and_then(|id| view.node(id))
                    .ok_or_else(|| set(json!({ "type": "notFound", "description": "no such node to copy" })))?;
                if move_them && !view.rights(node.id).contains(Rights::DELETE) {
                    return Err(set(json!({ "type": "forbidden", "description": "moving needs the right to delete" })));
                }
                let parent = self.parent(object.get("parentId").unwrap_or(&Value::Null))?;
                let name = match object.get("name") {
                    Some(Value::String(name)) => name.clone(),
                    None | Some(Value::Null) => node.name.clone(),
                    Some(_) => return Err(set(invalid_properties("name"))),
                };
                let copy = files
                    .copy_tree(&access, &view, node, parent, name, &options)
                    .await
                    .map_err(|error| set(set_error(&error)))?;
                Ok((node.id, copy))
            }
            .await;
            match result {
                Ok((original, copy)) => {
                    self.created.insert(creation.clone(), copy.id.to_string());
                    let target = files.view(access.clone()).await?;
                    let shares = self.jmap.shares(owner).await;
                    created.insert(creation, node_object(&copy, &target, &shares, None));
                    originals.push(original);
                }
                Err(CreateError::Method(error)) => return Err(error),
                Err(CreateError::Set(error)) => {
                    not_created.insert(creation, error);
                }
            }
        }
        let new_state = files.state(owner).await?;
        let or_null = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
        let mut responses = vec![(
            "FileNode/copy".into(),
            json!({
                "fromAccountId": from.to_string(),
                "accountId": owner.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": or_null(created),
                "notCreated": or_null(not_created),
            }),
        )];
        if move_them {
            let mut destroyed = Vec::new();
            let mut not_destroyed = Map::new();
            for original in originals {
                match files.destroy(&from_access, original, true).await {
                    Ok(gone) => destroyed.extend(gone.iter().map(Uuid::to_string)),
                    Err(error) => {
                        not_destroyed.insert(original.to_string(), set_error(&error));
                    }
                }
            }
            responses.push((
                "FileNode/set".into(),
                json!({
                    "accountId": from.to_string(),
                    "oldState": from_state.to_string(),
                    "newState": files.state(from).await?.to_string(),
                    "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
                    "notDestroyed": or_null(not_destroyed),
                }),
            ));
        }
        Ok(responses)
    }

    /// Sets the grants on a directory to `share_with` (a map of principal ids to `FilesRights`), replacing all
    /// earlier ones if `replace`; needs `mayShare` (RFC 0005, 11).
    async fn share(&self, access: &FileAccess, node: Uuid, share_with: &Value, replace: bool) -> Result<(), Value> {
        let identity = self.jmap.identity.as_ref().ok_or_else(|| json!({ "type": "forbidden" }))?;
        let files = self.jmap.files.as_ref().ok_or_else(|| json!({ "type": "forbidden" }))?;
        let forbidden = |description: &str| json!({ "type": "forbidden", "description": description });
        let rights = files.rights(access, node).await.map_err(|error| set_error(&error))?;
        if !rights.contains(Rights::SHARE) {
            return Err(forbidden("sharing this needs mayShare"));
        }
        let wanted = share_with.as_object().ok_or_else(|| invalid_properties("shareWith is an object or null"))?;
        let owner = access.owner;
        let existing: Vec<Principal> = identity
            .file_access(owner, Some(node))
            .await
            .map_err(|_| forbidden("the grants cannot be read"))?
            .into_iter()
            .map(|grant| grant.grantee)
            .collect();
        let who = format!("account:{}", self.caller.account);
        let mut keep = HashSet::new();
        for (principal, value) in wanted {
            let id = Uuid::parse_str(principal).map_err(|_| invalid_properties("shareWith names principals"))?;
            let grantee = identity
                .principal(self.caller.tenant, id)
                .await
                .ok()
                .flatten()
                .ok_or_else(|| invalid_properties(format!("{principal} is no person or group of the tenant")))?;
            if grantee == Principal::Account(owner) {
                return Err(invalid_properties("the owner is not in shareWith"));
            }
            keep.insert(grantee);
            match value {
                Value::Null => {
                    if existing.contains(&grantee) {
                        identity.remove_file_access(owner, Some(node), grantee, &who).await.ok();
                    }
                }
                value => {
                    let granted = rights_from(value).ok_or_else(|| invalid_properties("rights are FilesRights"))?;
                    // Nobody grants more than they have.
                    if !rights.contains(granted) {
                        return Err(forbidden("you cannot grant rights you do not have"));
                    }
                    if granted.is_empty() {
                        identity.remove_file_access(owner, Some(node), grantee, &who).await.ok();
                    } else {
                        identity
                            .set_file_access(owner, Some(node), grantee, &granted.letters(), &who)
                            .await
                            .map_err(|error| invalid_properties(error.to_string()))?;
                    }
                }
            }
        }
        if replace {
            for grantee in existing.into_iter().filter(|grantee| !keep.contains(grantee)) {
                identity.remove_file_access(owner, Some(node), grantee, &who).await.ok();
            }
        }
        files.touch(owner, Some(node)).await.map_err(|error| set_error(&error))?;
        Ok(())
    }

    /// `shareWith` as a whole, or `shareWith/<principal>` one by one.
    async fn share_patch(&self, access: &FileAccess, node: Uuid, patch: &Map<String, Value>) -> Result<(), Value> {
        if let Some(whole) = patch.get("shareWith") {
            let empty = json!({});
            return self.share(access, node, if whole.is_null() { &empty } else { whole }, true).await;
        }
        let mut one = Map::new();
        for (key, value) in patch {
            if let Some(principal) = key.strip_prefix("shareWith/") {
                one.insert(principal.to_owned(), value.clone());
            }
        }
        self.share(access, node, &Value::Object(one), false).await
    }

    /// The parent a create or update names: `null`, an id or `#creationId`.
    fn parent(&self, value: &Value) -> Result<Option<Uuid>, CreateError> {
        match value {
            Value::Null => Ok(None),
            Value::String(id) => self.id(id).map(Some).ok_or_else(|| set(invalid_properties("no such parent"))),
            _ => Err(set(invalid_properties("parentId is an id or null"))),
        }
    }

    /// The content a file takes from `blobId`, checked against `size` if given.
    async fn content(&self, access: &FileAccess, object: &Map<String, Value>) -> Result<Content, CreateError> {
        let blob = object.get("blobId").and_then(Value::as_str).ok_or_else(|| set(invalid_properties("blobId")))?;
        let content = self
            .jmap
            .blob_for_file(self.caller, access, blob)
            .await
            .ok_or_else(|| set(json!({ "type": "blobNotFound", "notFound": [blob] })))?;
        if let Some(size) = object.get("size").filter(|size| !size.is_null())
            && size.as_u64() != Some(content.stored.size)
        {
            return Err(set(invalid_properties("size is not the size of the blob")));
        }
        Ok(content)
    }

    async fn create_node(
        &self,
        files: &Files,
        access: &FileAccess,
        object: &Map<String, Value>,
        options: &SetOptions,
    ) -> Result<kernoid_files::Written, CreateError> {
        let node_type = match object.get("@type").and_then(Value::as_str) {
            Some("Directory") => NodeType::Directory,
            Some("File") => NodeType::File,
            _ => return Err(set(invalid_properties("@type is Directory or File"))),
        };
        let other_type: &[&str] = match node_type {
            NodeType::Directory => &FILE_PROPERTIES,
            NodeType::File => &DIRECTORY_PROPERTIES,
        };
        for (key, value) in object {
            let known = COMMON_PROPERTIES.contains(&key.as_str())
                || DIRECTORY_PROPERTIES.contains(&key.as_str())
                || FILE_PROPERTIES.contains(&key.as_str())
                || VAULT_PROPERTIES.contains(&key.as_str());
            if !known || (other_type.contains(&key.as_str()) && !value.is_null()) {
                return Err(set(invalid_properties(format!("{key} is not a property of this node"))));
            }
            if matches!(key.as_str(), "id" | "changed" | "role" | "myRights" | "kernoid:vault" | "kernoid:vaultKey")
                && !value.is_null()
            {
                return Err(set(invalid_properties(format!("{key} is set by the server"))));
            }
        }
        let name = object.get("name").and_then(Value::as_str).ok_or_else(|| set(invalid_properties("name")))?;
        let parent = self.parent(object.get("parentId").unwrap_or(&Value::Null))?;
        let date = |key: &str| match object.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => parse_date(value).map(Some).ok_or_else(|| set(invalid_properties(key.to_owned()))),
        };
        let mut new = NewNode::directory(parent, name);
        new.node_type = node_type;
        new.created = date("created")?;
        new.modified = date("modified")?;
        new.accessed = date("accessed")?;
        new.is_subscribed = object.get("isSubscribed").and_then(Value::as_bool).unwrap_or(true);
        new.encrypted_name = base64_property(object, "kernoid:encryptedName")?;
        if let Some(vault) = object.get("kernoid:newVault").filter(|value| !value.is_null()) {
            let vault = vault.as_object().ok_or_else(|| set(invalid_properties("kernoid:newVault is an object")))?;
            new.vault = Some(kernoid_files::NewVault {
                public_key: base64_property(vault, "publicKey")?.ok_or_else(|| set(invalid_properties("publicKey")))?,
                sealed: base64_property(vault, "sealed")?.ok_or_else(|| set(invalid_properties("sealed")))?,
            });
        }
        if node_type == NodeType::File {
            new.content = Some(self.content(access, object).await?);
            new.media_type = object.get("mediaType").and_then(Value::as_str).map(str::to_owned);
            new.executable = object.get("executable").and_then(Value::as_bool).unwrap_or(false);
        }
        files.create(access, new, options).await.map_err(store_error)
    }

    async fn update_node(
        &self,
        files: &Files,
        access: &FileAccess,
        id: Uuid,
        patch: &Map<String, Value>,
        options: &SetOptions,
    ) -> Result<kernoid_files::Written, CreateError> {
        let mut update = NodeUpdate::default();
        let date = |value: &Value| match value {
            // null sets it to now (draft, 3.1.1).
            Value::Null => Ok(Utc::now()),
            value => parse_date(value).ok_or_else(|| set(invalid_properties("a date is UTCDate"))),
        };
        // The blob of one of the file's own versions restores it (RFC 0005, 6).
        if let Some(BlobId::File(version)) = patch.get("blobId").and_then(Value::as_str).and_then(BlobId::parse)
            && let Ok(versions) = files.versions(access, id).await
            && versions.iter().any(|content| content.id == version && !content.current)
        {
            let node = files.restore(access, id, version).await.map_err(store_error)?;
            if patch.len() == 1 || patch.keys().all(|key| matches!(key.as_str(), "blobId" | "size")) {
                return Ok(kernoid_files::Written { node, destroyed: Vec::new() });
            }
        }
        for (key, value) in patch {
            match key.as_str() {
                "parentId" => update.parent = Some(self.parent(value)?),
                "name" => {
                    update.name = Some(value.as_str().ok_or_else(|| set(invalid_properties("name")))?.to_owned());
                }
                "blobId" => {
                    let restored = files.get(access.owner, &[id]).await.ok().and_then(|mut nodes| nodes.pop());
                    let current =
                        restored.and_then(|node| node.content).map(|content| BlobId::File(content).to_string());
                    if current.as_deref() != value.as_str() {
                        update.content = Some(self.content(access, patch).await?);
                    }
                }
                // Checked with the blob.
                "size" => {}
                "mediaType" => update.media_type = Some(value.as_str().unwrap_or("application/octet-stream").into()),
                "executable" => update.executable = Some(value.as_bool().unwrap_or(false)),
                "modified" => update.modified = Some(date(value)?),
                "accessed" => update.accessed = Some(date(value)?),
                "isSubscribed" => update.is_subscribed = Some(value.as_bool().unwrap_or(true)),
                "kernoid:encryptedName" => update.encrypted_name = base64_property(patch, "kernoid:encryptedName")?,
                other => return Err(set(invalid_properties(format!("{other} cannot be changed")))),
            }
        }
        files.update(access, id, update, options).await.map_err(store_error)
    }
}

/// A base64 property of an object: `None` if missing or null.
fn base64_property(object: &Map<String, Value>, key: &str) -> Result<Option<Vec<u8>>, CreateError> {
    use base64::Engine;
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
            .map(Some)
            .ok_or_else(|| set(invalid_properties(format!("{key} is base64")))),
    }
}

/// Why one create or update failed: a `SetError` for it, or an error of the whole method.
enum CreateError {
    Set(Value),
    Method(MethodError),
}

fn set(error: Value) -> CreateError {
    CreateError::Set(error)
}

fn store_error(error: FilesError) -> CreateError {
    match error {
        FilesError::Store(error) => CreateError::Method(MethodError::server_fail(error)),
        FilesError::Blob(error) => CreateError::Method(MethodError::server_fail(error)),
        other => CreateError::Set(set_error(&other)),
    }
}

impl From<FilesError> for CreateError {
    fn from(error: FilesError) -> Self {
        store_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_like_the_draft_says() {
        assert!(glob("*.PDF", "report.pdf"));
        assert!(glob("rep?rt.*", "Report.txt"));
        assert!(glob("[abc]*", "beta"));
        assert!(!glob("[!abc]*", "beta"));
        assert!(glob("[a-c]x", "bx"));
        assert!(!glob("*.pdf", "report.pdf.txt"));
        assert!(glob("[x", "[x"));
    }

    #[test]
    fn rights_round_trip() {
        let rights = Rights::READ | Rights::WRITE;
        assert_eq!(rights_from(&rights_object(rights)), Some(rights));
    }
}
