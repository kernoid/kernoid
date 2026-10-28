// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebDAV for files (RFC 4918; RFC 0005, 9) at `/webdav/`: for the file managers of operating systems (Finder,
//! Windows Explorer, GNOME Files, Dolphin) and other WebDAV programs. Class 1 and 2: PROPFIND, GET and HEAD (with
//! ranges), PUT, DELETE, MKCOL, COPY, MOVE, PROPPATCH, LOCK and UNLOCK. Content streams both ways.
//!
//! `/webdav/` lists the stores the caller reaches – its own, those shared with it, the tenant's drives – each named
//! as JMAP names it; below a store the path is the names of the nodes. Rights and locks are `kernoid-files`'s; the
//! XML is Stalwart's dav-proto (`kernoid_dav::proto`). A caller logs in like a JMAP program.

use axum::{
    Router,
    body::Body,
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use kernoid_dav::proto::{
    Depth, RequestHeaders, Timeout,
    parser::{DavParser, tokenizer::Tokenizer},
    schema::{
        property::{
            ActiveLock, DavProperty, DavValue, LockDiscovery, LockScope, ResourceType, Rfc1123DateTime, SupportedLock,
            WebDavProperty,
        },
        request::{DavPropertyValue, LockInfo, PropFind, PropertyUpdate},
        response::{List, MultiStatus, PropResponse, PropStat, Response as DavResponse},
    },
};
use kernoid_files::{
    FileAccess, Files, FilesError, LockRequest, NewNode, NodeInfo, NodeType, NodeUpdate, OnExists, SetOptions, View,
};
use kernoid_jmap::Caller;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use uuid::Uuid;

use crate::{AppState, Problem, jmap::JmapCaller};

const BASE: &str = "/webdav/";
/// Largest XML body of PROPFIND, PROPPATCH and LOCK.
const XML_LIMIT: usize = 256 * 1024;
/// How long a lock lasts when the client does not say (RFC 4918, 10.7 leaves it to the server).
const DEFAULT_LOCK_SECONDS: u64 = 600;
/// Characters escaped in a path segment.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\');

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/webdav", axum::routing::any(handle))
        .route("/webdav/", axum::routing::any(handle))
        .route("/webdav/{*path}", axum::routing::any(handle))
}

/// A store at the top of `/webdav/`: its owner, its name there and what the caller may do in it.
struct Store {
    owner: Uuid,
    name: String,
    access: FileAccess,
}

/// Why a request failed.
enum Failure {
    Status(StatusCode),
    Files(FilesError),
}

impl From<FilesError> for Failure {
    fn from(error: FilesError) -> Self {
        Self::Files(error)
    }
}

impl From<StatusCode> for Failure {
    fn from(status: StatusCode) -> Self {
        Self::Status(status)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Status(status) => status,
            Self::Files(error) => match error {
                FilesError::NotFound(_) => StatusCode::NOT_FOUND,
                FilesError::Forbidden(_) => StatusCode::FORBIDDEN,
                FilesError::Invalid(_) => StatusCode::BAD_REQUEST,
                FilesError::AlreadyExists(_) => StatusCode::PRECONDITION_FAILED,
                FilesError::HasChildren => StatusCode::CONFLICT,
                FilesError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                FilesError::OverQuota => StatusCode::INSUFFICIENT_STORAGE,
                FilesError::Locked => StatusCode::LOCKED,
                other => {
                    tracing::warn!(error = %other, "a WebDAV request");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            },
        };
        Problem::new(status).into_response()
    }
}

type Result<T> = std::result::Result<T, Failure>;

/// The path's segments below `/webdav/`, decoded; `None` for a path that is not below it or not UTF-8.
fn segments(path: &str) -> Option<Vec<String>> {
    let rest = path.strip_prefix("/webdav")?;
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    rest.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| percent_decode_str(segment).decode_utf8().ok().map(|segment| segment.into_owned()))
        .collect()
}

/// The path of a `Destination` header, which may be a whole URL.
fn destination(value: &str) -> Option<Vec<String>> {
    let path = match value.split_once("://") {
        Some((_, rest)) => &rest[rest.find('/')?..],
        None => value,
    };
    segments(path)
}

fn href(store: &str, names: &[String], collection: bool) -> String {
    let mut out = String::from(BASE);
    out.push_str(&utf8_percent_encode(store, SEGMENT).to_string());
    for name in names {
        out.push('/');
        out.push_str(&utf8_percent_encode(name, SEGMENT).to_string());
    }
    if collection {
        out.push('/');
    }
    out
}

/// The stores the caller reaches, with names unique among them.
async fn stores(state: &AppState, caller: &Caller) -> Result<(Files, Vec<Store>)> {
    let jmap = state.jmap.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let files = jmap.files().ok_or(StatusCode::NOT_FOUND)?.clone();
    let mut stores = Vec::new();
    if caller.files {
        stores.push(Store {
            owner: caller.account,
            name: caller.username.clone(),
            access: FileAccess::own(caller.account),
        });
    }
    for shared in files.shared_with(caller.account).await? {
        let access = files.access(caller.account, shared.owner).await?;
        let mut name = shared.name.replace('/', "-");
        let mut number = 2;
        while stores.iter().any(|store: &Store| store.name == name) {
            name = format!("{} ({number})", shared.name.replace('/', "-"));
            number += 1;
        }
        stores.push(Store { owner: shared.owner, name, access });
    }
    Ok((files, stores))
}

/// The node at `names` below the top of a store's view: `None` for the top itself.
fn resolve<'a>(view: &'a View, names: &[String]) -> std::result::Result<Option<&'a NodeInfo>, StatusCode> {
    let mut parent: Option<&NodeInfo> = None;
    for name in names {
        let next = view
            .nodes()
            .find(|node| node.parent == parent.map(|parent| parent.id) && &node.name == name)
            .ok_or(StatusCode::NOT_FOUND)?;
        parent = Some(next);
    }
    Ok(parent)
}

fn children(view: &View, parent: Option<Uuid>) -> Vec<&NodeInfo> {
    let mut out: Vec<&NodeInfo> = view.nodes().filter(|node| node.parent == parent).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The names from the top of the store down to a node.
fn names(view: &View, node: &NodeInfo) -> Vec<String> {
    let mut out: Vec<String> =
        view.ancestors(node.id).iter().rev().filter_map(|id| view.node(*id).map(|node| node.name.clone())).collect();
    out.push(node.name.clone());
    out
}

/// The lock tokens the client names in its `If` header.
fn tokens(headers: &RequestHeaders<'_>) -> Vec<String> {
    headers
        .if_
        .iter()
        .flat_map(|condition| condition.list.iter())
        .filter_map(|condition| match condition {
            kernoid_dav::proto::Condition::StateToken { is_not: false, token } => Some((*token).to_owned()),
            _ => None,
        })
        .collect()
}

/// A media type for a file by its name, where the client sent none of use.
fn guess(name: &str) -> &'static str {
    let extension = name.rsplit_once('.').map(|(_, extension)| extension.to_ascii_lowercase()).unwrap_or_default();
    match extension.as_str() {
        "txt" => "text/plain",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "heic" => "image/heic",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "ics" => "text/calendar",
        "vcf" => "text/vcard",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }
}

fn etag(node: &NodeInfo) -> String {
    match node.content {
        Some(content) => format!("\"{content}\""),
        None => format!("\"{}\"", node.changed.timestamp_micros()),
    }
}

fn xml(status: StatusCode, body: impl std::fmt::Display) -> Response {
    let mut response = (status, format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>{body}")).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"));
    response
}

pub(crate) async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let (mut parts, body) = request.into_parts();
    if parts.method == Method::OPTIONS {
        return options();
    }
    let caller = match JmapCaller::from_request_parts(&mut parts, &state).await {
        Ok(JmapCaller(caller, _)) => caller,
        Err(response) => return response,
    };
    let path = parts.uri.path().to_owned();
    match dispatch(&state, &caller, &parts.method, &path, &parts.headers, body).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

fn options() -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert("dav", HeaderValue::from_static("1, 2"));
    headers.insert("ms-author-via", HeaderValue::from_static("DAV"));
    headers.insert(
        header::ALLOW,
        HeaderValue::from_static(
            "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK",
        ),
    );
    response
}

async fn xml_body(body: Body) -> Result<Vec<u8>> {
    Ok(axum::body::to_bytes(body, XML_LIMIT).await.map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?.to_vec())
}

async fn dispatch(
    state: &AppState,
    caller: &Caller,
    method: &Method,
    path: &str,
    raw_headers: &HeaderMap,
    body: Body,
) -> Result<Response> {
    let mut headers = RequestHeaders::new(path);
    for (name, value) in raw_headers {
        if let Ok(value) = value.to_str() {
            headers.parse(name.as_str(), value);
        }
    }
    let path_names = segments(path).ok_or(StatusCode::NOT_FOUND)?;
    let (files, stores) = stores(state, caller).await?;
    // The top: the stores, read-only.
    let Some((store_name, below)) = path_names.split_first() else {
        return match method.as_str() {
            "PROPFIND" => {
                let propfind = parse_propfind(xml_body(body).await?)?;
                let mut responses = vec![props(&propfind, &Item::Top, BASE.to_owned(), &files).await];
                if headers.depth != Depth::Zero {
                    for store in &stores {
                        let item = Item::Store(store);
                        responses.push(props(&propfind, &item, href(&store.name, &[], true), &files).await);
                    }
                }
                Ok(xml(StatusCode::MULTI_STATUS, MultiStatus::new(responses)))
            }
            "GET" | "HEAD" => Err(StatusCode::METHOD_NOT_ALLOWED.into()),
            _ => Err(StatusCode::FORBIDDEN.into()),
        };
    };
    let store = stores.iter().find(|store| &store.name == store_name).ok_or(StatusCode::NOT_FOUND)?;
    let view = files.view(store.access.clone()).await?;
    let tokens = tokens(&headers);
    match method.as_str() {
        "PROPFIND" => {
            let propfind = parse_propfind(xml_body(body).await?)?;
            let node = resolve(&view, below)?;
            let item = node.map_or(Item::Store(store), |node| Item::Node(store, node));
            let mut responses = vec![props(&propfind, &item, item.href(&view), &files).await];
            let directory = node.is_none_or(|node| node.node_type == NodeType::Directory);
            if directory && headers.depth != Depth::Zero {
                for child in children(&view, node.map(|node| node.id)) {
                    let item = Item::Node(store, child);
                    responses.push(props(&propfind, &item, item.href(&view), &files).await);
                }
            }
            Ok(xml(StatusCode::MULTI_STATUS, MultiStatus::new(responses)))
        }
        "GET" | "HEAD" => {
            let node = resolve(&view, below)?.ok_or(StatusCode::METHOD_NOT_ALLOWED)?;
            let content = node.content.ok_or(StatusCode::METHOD_NOT_ALLOWED)?;
            let jmap = state.jmap.as_ref().ok_or(StatusCode::NOT_FOUND)?;
            let range = crate::jmap::byte_range(raw_headers);
            let download = jmap.file_content(caller, store.owner, content, range).await?;
            if range.is_some_and(|(start, _)| start >= download.size && download.size > 0) {
                return Err(StatusCode::RANGE_NOT_SATISFIABLE.into());
            }
            let download = kernoid_jmap::Download {
                size: download.size,
                start: download.start,
                end: download.end,
                kind: Some(download.media_type),
                content: download.content,
            };
            let mut response = crate::jmap::download_response(download, range.is_some());
            if let Ok(value) = HeaderValue::from_str(&etag(node)) {
                response.headers_mut().insert(header::ETAG, value);
            }
            if let Ok(value) = HeaderValue::from_str(&node.modified.to_rfc2822().replace("+0000", "GMT")) {
                response.headers_mut().insert(header::LAST_MODIFIED, value);
            }
            if method == Method::HEAD {
                *response.body_mut() = Body::empty();
            }
            Ok(response)
        }
        "PUT" => {
            let (parent_names, name) =
                below.split_last().map(|(name, parent)| (parent, name)).ok_or(StatusCode::CONFLICT)?;
            let parent = resolve(&view, parent_names).map_err(|_| StatusCode::CONFLICT)?;
            if parent.is_some_and(|parent| parent.node_type != NodeType::Directory) {
                return Err(StatusCode::CONFLICT.into());
            }
            let existing = resolve(&view, below).ok().flatten();
            if existing.is_some_and(|node| node.node_type == NodeType::Directory) {
                return Err(StatusCode::METHOD_NOT_ALLOWED.into());
            }
            let lock_target = existing.or(parent);
            if let Some(target) = lock_target {
                files.check_unlocked(&store.access, target.id, false, &tokens).await?;
            }
            let sent = raw_headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
            let sent = sent.map(|kind| kind.split(';').next().unwrap_or_default().trim().to_owned());
            let media_type = match sent.filter(|kind| !kind.is_empty() && kind != "application/octet-stream") {
                Some(kind) => kind,
                None => guess(name).to_owned(),
            };
            let media_type = kernoid_files::check_media_type(&media_type).unwrap_or_else(|_| guess(name).to_owned());
            let content = files.store(store.owner, body.into_data_stream()).await?;
            let (status, node) = match existing {
                Some(node) => {
                    (StatusCode::NO_CONTENT, files.write(&store.access, node.id, content, Some(&media_type)).await?)
                }
                None => {
                    let new = NewNode::file(parent.map(|parent| parent.id), name.clone(), content, Some(media_type));
                    (StatusCode::CREATED, files.create(&store.access, new, &SetOptions::default()).await?.node)
                }
            };
            let mut response = status.into_response();
            if let Ok(value) = HeaderValue::from_str(&etag(&node)) {
                response.headers_mut().insert(header::ETAG, value);
            }
            Ok(response)
        }
        "DELETE" => {
            let node = resolve(&view, below)?.ok_or(StatusCode::FORBIDDEN)?;
            files.check_unlocked(&store.access, node.id, true, &tokens).await?;
            files.destroy(&store.access, node.id, true).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        "MKCOL" => {
            if !xml_body(body).await?.is_empty() {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into());
            }
            let (parent_names, name) =
                below.split_last().map(|(name, parent)| (parent, name)).ok_or(StatusCode::METHOD_NOT_ALLOWED)?;
            if resolve(&view, below).is_ok() {
                return Err(StatusCode::METHOD_NOT_ALLOWED.into());
            }
            let parent = resolve(&view, parent_names).map_err(|_| StatusCode::CONFLICT)?;
            if let Some(parent) = parent {
                files.check_unlocked(&store.access, parent.id, false, &tokens).await?;
            }
            let new = NewNode::directory(parent.map(|parent| parent.id), name.clone());
            files.create(&store.access, new, &SetOptions::default()).await?;
            Ok(StatusCode::CREATED.into_response())
        }
        "COPY" | "MOVE" => {
            let node = resolve(&view, below)?.ok_or(StatusCode::FORBIDDEN)?;
            let target = headers.destination.and_then(destination).ok_or(StatusCode::BAD_REQUEST)?;
            let (target_store, target_below) = target.split_first().ok_or(StatusCode::FORBIDDEN)?;
            // Between stores is not supported (OPEN): the client copies itself.
            if target_store != store_name {
                return Err(StatusCode::BAD_GATEWAY.into());
            }
            let (parent_names, name) =
                target_below.split_last().map(|(name, parent)| (parent, name)).ok_or(StatusCode::FORBIDDEN)?;
            let parent = resolve(&view, parent_names).map_err(|_| StatusCode::CONFLICT)?;
            let existing = resolve(&view, target_below).ok().flatten();
            if existing.is_some() && headers.overwrite_fail {
                return Err(StatusCode::PRECONDITION_FAILED.into());
            }
            if let Some(existing) = existing {
                files.check_unlocked(&store.access, existing.id, true, &tokens).await?;
            }
            let options = SetOptions { on_exists: OnExists::Replace, remove_children: true, ..SetOptions::default() };
            let parent_id = parent.map(|parent| parent.id);
            if method.as_str() == "MOVE" {
                files.check_unlocked(&store.access, node.id, true, &tokens).await?;
                let update = NodeUpdate { parent: Some(parent_id), name: Some(name.clone()), ..NodeUpdate::default() };
                files.update(&store.access, node.id, update, &options).await?;
            } else {
                copy(&files, &store.access, &view, node, parent_id, name.clone(), &options, 0).await?;
            }
            Ok(if existing.is_some() { StatusCode::NO_CONTENT } else { StatusCode::CREATED }.into_response())
        }
        "PROPPATCH" => {
            let node = resolve(&view, below)?;
            if let Some(node) = node {
                files.check_unlocked(&store.access, node.id, false, &tokens).await?;
            }
            let update = PropertyUpdate::parse(&mut Tokenizer::new(&xml_body(body).await?))
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            // Properties programs set (Windows' times and attributes) are accepted and not kept (OPEN).
            let changed: Vec<DavPropertyValue> = update
                .set
                .into_iter()
                .map(|value| value.property)
                .chain(update.remove)
                .map(|property| DavPropertyValue::new(property, DavValue::Null))
                .collect();
            let item = node.map_or(Item::Store(store), |node| Item::Node(store, node));
            let response = DavResponse::new_propstat(item.href(&view), vec![PropStat::new_list(changed)]);
            Ok(xml(StatusCode::MULTI_STATUS, MultiStatus::new(vec![response])))
        }
        "LOCK" => {
            let timeout = match headers.timeout {
                Timeout::Second(seconds) => seconds,
                Timeout::Infinite | Timeout::None => DEFAULT_LOCK_SECONDS,
            };
            let timeout = chrono::Duration::seconds(i64::try_from(timeout).unwrap_or(i64::MAX).min(3600));
            let body = xml_body(body).await?;
            // No body: a refresh of a lock named in the If header.
            if body.is_empty() {
                let token = tokens.first().ok_or(StatusCode::BAD_REQUEST)?;
                let lock = files.refresh_lock(&store.access, token, timeout).await?;
                let node = view.node(lock.node).ok_or(StatusCode::NOT_FOUND)?;
                return Ok(lock_response(StatusCode::OK, &lock, &href(&store.name, &names(&view, node), false), None));
            }
            let info = LockInfo::parse(&mut Tokenizer::new(&body)).map_err(|_| StatusCode::BAD_REQUEST)?;
            // A lock on a name that is free makes an empty file there (RFC 4918, 9.10.4).
            let (node, status) = match resolve(&view, below) {
                Ok(Some(node)) => (node.clone(), StatusCode::OK),
                Ok(None) => return Err(StatusCode::FORBIDDEN.into()),
                Err(_) => {
                    let (parent_names, name) =
                        below.split_last().map(|(name, parent)| (parent, name)).ok_or(StatusCode::CONFLICT)?;
                    let parent = resolve(&view, parent_names).map_err(|_| StatusCode::CONFLICT)?;
                    let empty = files.store_bytes(store.owner, bytes::Bytes::new()).await?;
                    let new =
                        NewNode::file(parent.map(|parent| parent.id), name.clone(), empty, Some(guess(name).into()));
                    (files.create(&store.access, new, &SetOptions::default()).await?.node, StatusCode::CREATED)
                }
            };
            let request = LockRequest {
                exclusive: info.lock_scope == LockScope::Exclusive,
                deep: headers.depth != Depth::Zero && node.node_type == NodeType::Directory,
                owner_info: None,
                timeout,
            };
            let lock = files.lock(&store.access, node.id, request).await?;
            let collection = node.node_type == NodeType::Directory;
            Ok(lock_response(status, &lock, &href(&store.name, &names(&view, &node), collection), info.owner))
        }
        "UNLOCK" => {
            let token = headers.lock_token.ok_or(StatusCode::BAD_REQUEST)?;
            files.unlock(&store.access, token).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Err(StatusCode::METHOD_NOT_ALLOWED.into()),
    }
}

/// A LOCK's answer: the lock in `lockdiscovery`, and its token in `Lock-Token`.
fn lock_response(
    status: StatusCode,
    lock: &kernoid_files::Lock,
    root: &str,
    owner: Option<kernoid_dav::proto::types::dead_property::DeadProperty>,
) -> Response {
    let seconds = (lock.expires_at - chrono::Utc::now()).num_seconds().max(1) as u64;
    let scope = if lock.exclusive { LockScope::Exclusive } else { LockScope::Shared };
    let active = ActiveLock::new(root, scope)
        .with_depth(if lock.deep { Depth::Infinity } else { Depth::Zero })
        .with_timeout(seconds)
        .with_owner_opt(owner)
        .with_lock_token(lock.token.clone());
    let discovery = DavPropertyValue::new(WebDavProperty::LockDiscovery, DavValue::ActiveLocks(List(vec![active])));
    let mut response = xml(status, PropResponse::new(vec![discovery]));
    if let Ok(value) = HeaderValue::from_str(&format!("<{}>", lock.token)) {
        response.headers_mut().insert("lock-token", value);
    }
    response
}

/// Copies a node – a directory with what it holds – below `parent` as `name`; a file's copy shares its content.
#[allow(clippy::too_many_arguments, reason = "one step of a recursive copy")]
fn copy<'a>(
    files: &'a Files,
    access: &'a FileAccess,
    view: &'a View,
    node: &'a NodeInfo,
    parent: Option<Uuid>,
    name: String,
    options: &'a SetOptions,
    depth: usize,
) -> std::pin::Pin<Box<dyn Future<Output = std::result::Result<(), FilesError>> + Send + 'a>> {
    Box::pin(async move {
        if depth > kernoid_files::MAX_DEPTH {
            return Err(FilesError::Invalid("too deep".into()));
        }
        let new = match (node.node_type, node.content) {
            (NodeType::File, Some(content)) => {
                NewNode::file(parent, name, files.existing(content).await?, node.media_type.clone())
            }
            _ => NewNode::directory(parent, name),
        };
        let created = files.create(access, new, options).await?.node;
        if node.node_type == NodeType::Directory {
            for child in children(view, Some(node.id)) {
                let fresh = SetOptions::default();
                copy(files, access, view, child, Some(created.id), child.name.clone(), &fresh, depth + 1).await?;
            }
        }
        Ok(())
    })
}

fn parse_propfind(body: Vec<u8>) -> Result<PropFind> {
    if body.is_empty() {
        return Ok(PropFind::AllProp(Vec::new()));
    }
    PropFind::parse(&mut Tokenizer::new(&body)).map_err(|_| StatusCode::BAD_REQUEST.into())
}

/// What a PROPFIND answers for.
enum Item<'a> {
    Top,
    Store(&'a Store),
    Node(&'a Store, &'a NodeInfo),
}

impl Item<'_> {
    fn href(&self, view: &View) -> String {
        match self {
            Self::Top => BASE.to_owned(),
            Self::Store(store) => href(&store.name, &[], true),
            Self::Node(store, node) => href(&store.name, &names(view, node), node.node_type == NodeType::Directory),
        }
    }
}

const ALL_PROPERTIES: [WebDavProperty; 11] = [
    WebDavProperty::DisplayName,
    WebDavProperty::ResourceType,
    WebDavProperty::GetContentLength,
    WebDavProperty::GetContentType,
    WebDavProperty::GetETag,
    WebDavProperty::GetLastModified,
    WebDavProperty::CreationDate,
    WebDavProperty::SupportedLock,
    WebDavProperty::LockDiscovery,
    WebDavProperty::QuotaUsedBytes,
    WebDavProperty::QuotaAvailableBytes,
];

/// The properties of one item that a PROPFIND asks for, found and not found.
async fn props(propfind: &PropFind, item: &Item<'_>, href: String, files: &Files) -> DavResponse {
    let (wanted, names_only): (Vec<DavProperty>, bool) = match propfind {
        PropFind::PropName => (ALL_PROPERTIES.iter().cloned().map(DavProperty::WebDav).collect(), true),
        PropFind::AllProp(_) => (ALL_PROPERTIES.iter().cloned().map(DavProperty::WebDav).collect(), false),
        PropFind::Prop(list) => (list.clone(), false),
    };
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for property in wanted {
        let value = if names_only { Some(DavValue::Null) } else { value(&property, item, files).await };
        match value {
            Some(value) => found.push(DavPropertyValue::new(property, value)),
            None if !matches!(propfind, PropFind::Prop(_)) => {}
            None => missing.push(DavPropertyValue::new(property, DavValue::Null)),
        }
    }
    let mut propstat = Vec::new();
    if !found.is_empty() {
        propstat.push(PropStat::new_list(found));
    }
    if !missing.is_empty() {
        propstat.push(PropStat::new_list(missing).with_status(StatusCode::NOT_FOUND));
    }
    DavResponse::new_propstat(href, propstat)
}

async fn value(property: &DavProperty, item: &Item<'_>, files: &Files) -> Option<DavValue> {
    let DavProperty::WebDav(property) = property else { return None };
    let node = match item {
        Item::Node(_, node) => Some(*node),
        _ => None,
    };
    let collection = node.is_none_or(|node| node.node_type == NodeType::Directory);
    match property {
        WebDavProperty::DisplayName => Some(DavValue::String(match item {
            Item::Top => "kernoid".into(),
            Item::Store(store) => store.name.clone(),
            Item::Node(_, node) => node.name.clone(),
        })),
        WebDavProperty::ResourceType => {
            Some(DavValue::ResourceTypes(List(if collection { vec![ResourceType::Collection] } else { Vec::new() })))
        }
        WebDavProperty::GetContentLength => node.and_then(|node| node.size).map(DavValue::Uint64),
        WebDavProperty::GetContentType => node.and_then(|node| node.media_type.clone()).map(DavValue::String),
        WebDavProperty::GetETag => node.map(|node| DavValue::String(etag(node))),
        WebDavProperty::GetLastModified => {
            node.map(|node| DavValue::Rfc1123Date(Rfc1123DateTime::new(node.modified.timestamp())))
        }
        WebDavProperty::CreationDate => node.map(|node| DavValue::Timestamp(node.created.timestamp())),
        WebDavProperty::SupportedLock => Some(SupportedLock::default().into()),
        WebDavProperty::LockDiscovery => {
            let Item::Node(store, node) = item else { return Some(DavValue::ActiveLocks(List(Vec::new()))) };
            let locks = files.locks(node.id).await.unwrap_or_default();
            let active = locks
                .into_iter()
                .map(|lock| {
                    let scope = if lock.exclusive { LockScope::Exclusive } else { LockScope::Shared };
                    let seconds = (lock.expires_at - chrono::Utc::now()).num_seconds().max(1) as u64;
                    ActiveLock::new(href(&store.name, &[], true), scope)
                        .with_depth(if lock.deep { Depth::Infinity } else { Depth::Zero })
                        .with_timeout(seconds)
                })
                .collect();
            Some(LockDiscovery(List(active)).into())
        }
        WebDavProperty::QuotaUsedBytes | WebDavProperty::QuotaAvailableBytes => {
            let Item::Store(store) = item else { return None };
            let (used, quota) = files.usage(store.owner).await.ok()?;
            match property {
                WebDavProperty::QuotaUsedBytes => Some(DavValue::Uint64(used)),
                _ => quota.map(|quota| DavValue::Uint64(quota.saturating_sub(used))),
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_decoded_and_encoded_back() {
        assert_eq!(segments("/webdav/").unwrap(), Vec::<String>::new());
        assert_eq!(segments("/webdav/alice%40firma.de/A%20B/c.txt").unwrap(), vec!["alice@firma.de", "A B", "c.txt"]);
        assert_eq!(href("alice@firma.de", &["A B".into()], true), "/webdav/alice@firma.de/A%20B/");
        assert_eq!(destination("https://host.example/webdav/s/x%23y").unwrap(), vec!["s", "x#y"]);
        assert!(segments("/other").is_none());
    }

    #[test]
    fn types_are_guessed_by_extension() {
        assert_eq!(guess("Report.PDF"), "application/pdf");
        assert_eq!(guess("noextension"), "application/octet-stream");
    }
}
