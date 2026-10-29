// SPDX-License-Identifier: AGPL-3.0-or-later
//! Links to files for people without an account (RFC 0005, 11.3): what a link opens, its directories' contents and
//! downloads – anonymous, within the file or directory the link names –, and files added to a directory where the link
//! lets people add (`mayAdd`; without `mayRead` a drop box: nothing in it is shown). A link with a password is opened
//! with `POST /v1/links/{token}/unlock`, whose access token the other requests carry as `access`. The web app's
//! `link.html` shows them; links are made with JMAP's `FileLink/set`.

use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use kernoid_files::{FileAccess, Files, NewNode, NodeInfo, NodeType, OnExists, Rights, SetOptions, View};
use kernoid_identity::file_link::OpenLink;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, CurrentInstance, Problem, jmap::byte_range};

#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct LinkQuery {
    /// The access token from `unlock`, for a link with a password.
    access: Option<String>,
    /// `nodes`: the directory whose contents to list; the link's own if not given.
    parent: Option<String>,
    /// `download`: `1` to show in place (`Content-Disposition: inline`) rather than save.
    inline: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkNodeView {
    id: String,
    /// The directory it is in; none for what the link names.
    parent_id: Option<String>,
    name: String,
    /// `directory` or `file`.
    node_type: String,
    size: Option<u64>,
    media_type: Option<String>,
    modified: DateTime<Utc>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkView {
    /// What the link names.
    node: LinkNodeView,
    /// Its contents can be seen and downloaded.
    may_read: bool,
    /// Files can be added to it (a directory).
    may_add: bool,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AddQuery {
    /// The access token from `unlock`, for a link with a password.
    access: Option<String>,
    /// The directory to add to: the link's own unless it names one below it (for a link that reads too).
    parent: Option<String>,
    /// The file's name; one taken already gets a number – `report (2).pdf` –, nothing is replaced.
    name: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasswordRequired {
    password_required: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct Unlock {
    password: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct Unlocked {
    /// Pass it as `access` with the other requests.
    access: String,
    expires_in: u64,
}

fn not_found() -> Response {
    Problem::new(StatusCode::NOT_FOUND).detail("no such link, or it has expired").into_response()
}

/// The link of `token` and a view of its owner's store that reads only what the link names – or the answer: unknown,
/// or the password needed.
async fn opened(
    state: &AppState,
    instance: Uuid,
    token: &str,
    query: &LinkQuery,
) -> Result<(Files, OpenLink, View), Box<Response>> {
    let Some(files) = state.jmap.as_ref().and_then(|jmap| jmap.files()).cloned() else {
        return Err(Box::new(not_found()));
    };
    let link = match state.identity.open_file_link(instance, token).await {
        Ok(Some(link)) => link,
        Ok(None) => return Err(Box::new(not_found())),
        Err(error) => return Err(Box::new(crate::sessions::problem(error))),
    };
    if link.needs_password {
        let unlocked = match &query.access {
            Some(access) => state.identity.file_link_unlocked(link.id, access).await.unwrap_or(false),
            None => false,
        };
        if !unlocked {
            return Err(Box::new(
                (StatusCode::UNAUTHORIZED, Json(PasswordRequired { password_required: true })).into_response(),
            ));
        }
    }
    let access = FileAccess {
        user: Uuid::nil(),
        owner: link.owner,
        owned: false,
        store: Rights::NONE,
        nodes: HashMap::from([(link.node, rights(&link))]),
    };
    let view = files.view(access).await.map_err(|_| Box::new(not_found()))?;
    Ok((files, link, view))
}

fn rights(link: &OpenLink) -> Rights {
    let read = if link.rights.read { "r" } else { "" };
    let add = if link.rights.add { "a" } else { "" };
    Rights::parse(&format!("{read}{add}"))
}

/// A node the link reaches: what it names, or – if it reads – something below it.
fn within<'a>(view: &'a View, link: &OpenLink, id: Uuid) -> Option<&'a NodeInfo> {
    let node = view.node(id).filter(|node| view.readable(node.id) || node.id == link.node)?;
    (id == link.node || view.ancestors(id).contains(&link.node)).then_some(node)
}

fn node_view(node: &NodeInfo, link: &OpenLink) -> LinkNodeView {
    LinkNodeView {
        id: node.id.to_string(),
        parent_id: node.parent.filter(|_| node.id != link.node).map(|parent| parent.to_string()),
        name: node.name.clone(),
        node_type: match node.node_type {
            NodeType::Directory => "directory".into(),
            NodeType::File => "file".into(),
        },
        size: node.size,
        media_type: node.media_type.clone(),
        modified: node.modified,
    }
}

/// What a link opens (RFC 0005, 11.3).
#[utoipa::path(get, path = "/v1/links/{token}", tag = "links", params(LinkQuery), responses(
    (status = 200, body = LinkView),
    (status = 401, description = "the link has a password: unlock it first", body = PasswordRequired),
    (status = 404, description = "no such link, or it has expired", body = Problem),
))]
pub(crate) async fn link(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Path(token): Path<String>,
    Query(query): Query<LinkQuery>,
) -> Response {
    let (_, link, view) = match opened(&state, instance.id, &token, &query).await {
        Ok(opened) => opened,
        Err(response) => return *response,
    };
    match within(&view, &link, link.node) {
        Some(node) => {
            Json(LinkView { node: node_view(node, &link), may_read: link.rights.read, may_add: link.rights.add })
                .into_response()
        }
        None => not_found(),
    }
}

/// Opens a link with its password; the answer's `access` opens it for a while. Wrong passwords are counted: too many
/// and the link refuses for a quarter of an hour.
#[utoipa::path(post, path = "/v1/links/{token}/unlock", tag = "links", request_body = Unlock, responses(
    (status = 200, body = Unlocked),
    (status = 401, description = "the password is wrong", body = Problem),
    (status = 404, description = "no such link, or it has expired", body = Problem),
    (status = 429, description = "too many wrong passwords", body = Problem),
))]
pub(crate) async fn unlock(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Path(token): Path<String>,
    Json(body): Json<Unlock>,
) -> Response {
    let link = match state.identity.open_file_link(instance.id, &token).await {
        Ok(Some(link)) if link.needs_password => link,
        Ok(_) => return not_found(),
        Err(error) => return crate::sessions::problem(error),
    };
    match state.identity.unlock_file_link(link.id, &body.password).await {
        Ok(access) => Json(Unlocked { access, expires_in: kernoid_identity::file_link::ACCESS_LIFETIME.as_secs() })
            .into_response(),
        Err(error) => crate::sessions::problem(error),
    }
}

/// The contents of a directory the link reaches – the link's own unless `parent` names one below it.
#[utoipa::path(get, path = "/v1/links/{token}/nodes", tag = "links", params(LinkQuery), responses(
    (status = 200, body = [LinkNodeView]),
    (status = 401, description = "the link has a password: unlock it first", body = PasswordRequired),
    (status = 404, description = "no such link or directory", body = Problem),
))]
pub(crate) async fn nodes(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Path(token): Path<String>,
    Query(query): Query<LinkQuery>,
) -> Response {
    let (_, link, view) = match opened(&state, instance.id, &token, &query).await {
        Ok(opened) => opened,
        Err(response) => return *response,
    };
    let parent = match query.parent.as_deref() {
        None => link.node,
        Some(id) => match Uuid::parse_str(id) {
            Ok(id) => id,
            Err(_) => return not_found(),
        },
    };
    match within(&view, &link, parent) {
        Some(directory) if directory.node_type == NodeType::Directory && link.rights.read => {}
        _ => return not_found(),
    }
    let mut children: Vec<&NodeInfo> =
        view.nodes().filter(|node| node.parent == Some(parent) && view.readable(node.id)).collect();
    children.sort_by(|a, b| {
        (a.node_type != NodeType::Directory, a.name.to_lowercase())
            .cmp(&(b.node_type != NodeType::Directory, b.name.to_lowercase()))
    });
    Json(children.into_iter().map(|node| node_view(node, &link)).collect::<Vec<_>>()).into_response()
}

/// A file the link reaches, also in ranges (`Range`), under the same sandbox as every download.
#[utoipa::path(get, path = "/v1/links/{token}/download/{node}", tag = "links", params(LinkQuery), responses(
    (status = 200, description = "the content"),
    (status = 206, description = "the range asked for"),
    (status = 401, description = "the link has a password: unlock it first", body = PasswordRequired),
    (status = 404, description = "no such link or file", body = Problem),
))]
pub(crate) async fn download(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Path((token, node)): Path<(String, String)>,
    Query(query): Query<LinkQuery>,
    headers: HeaderMap,
) -> Response {
    let (files, link, view) = match opened(&state, instance.id, &token, &query).await {
        Ok(opened) => opened,
        Err(response) => return *response,
    };
    let Some(node) = Uuid::parse_str(&node).ok().and_then(|id| within(&view, &link, id)) else { return not_found() };
    let Some(content) = node.content else { return not_found() };
    let name = node.name.clone();
    let readable = match files.readable(&view.access, content).await {
        Ok(readable) => readable,
        Err(_) => return not_found(),
    };
    let range = byte_range(&headers);
    let size = readable.info.size;
    if range.is_some_and(|(start, _)| start >= size && size > 0) {
        let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
        if let Ok(value) = HeaderValue::from_str(&format!("bytes */{size}")) {
            response.headers_mut().insert(header::CONTENT_RANGE, value);
        }
        return response;
    }
    let (start, end) = match range {
        Some((start, last)) => {
            let end = last.map_or(size, |last| last.saturating_add(1)).min(size);
            (start.min(end), end)
        }
        None => (0, size),
    };
    let download = kernoid_jmap::Download {
        size,
        start,
        end,
        kind: Some(readable.info.media_type.clone()),
        content: Box::pin(files.read(&readable.content, start, end)),
    };
    let mut response = crate::jmap::download_response(download, range.is_some()).await;
    if !response.status().is_success() {
        return response;
    }
    let ascii: String = name.chars().filter(|c| c.is_ascii_graphic() && *c != '"' && *c != '\\').collect();
    let encoded = url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>().replace('+', "%20");
    let disposition = if query.inline.as_deref() == Some("1") { "inline" } else { "attachment" };
    if let Ok(value) =
        HeaderValue::from_str(&format!("{disposition}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"))
    {
        response.headers_mut().insert(header::CONTENT_DISPOSITION, value);
    }
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}

/// Adds a file – the request's body, streamed – to the directory a link names (or one below it, for a link that reads
/// too), where the link lets people add. It counts against the owner's quota and is scanned like every upload.
#[utoipa::path(post, path = "/v1/links/{token}/files", tag = "links", params(AddQuery),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"), responses(
    (status = 201, description = "the file as it is now named", body = LinkNodeView),
    (status = 400, description = "the name is not allowed", body = Problem),
    (status = 401, description = "the link has a password: unlock it first", body = PasswordRequired),
    (status = 403, description = "the link does not let people add files", body = Problem),
    (status = 404, description = "no such link or directory", body = Problem),
    (status = 413, description = "the file is too large", body = Problem),
    (status = 507, description = "the owner's quota does not leave room for it", body = Problem),
))]
pub(crate) async fn add(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    Path(token): Path<String>,
    Query(query): Query<AddQuery>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let opening = LinkQuery { access: query.access.clone(), ..LinkQuery::default() };
    let (files, link, view) = match opened(&state, instance.id, &token, &opening).await {
        Ok(opened) => opened,
        Err(response) => return *response,
    };
    if !link.rights.add {
        return Problem::new(StatusCode::FORBIDDEN).detail("this link does not let people add files").into_response();
    }
    let parent = match query.parent.as_deref() {
        None => link.node,
        Some(id) => match Uuid::parse_str(id) {
            Ok(id) if id == link.node || link.rights.read => id,
            _ => return not_found(),
        },
    };
    match within(&view, &link, parent) {
        Some(directory) if directory.node_type == NodeType::Directory => {}
        _ => return not_found(),
    }
    // Checked before the content is stored, not after.
    if let Err(error) = kernoid_files::check_name(&query.name) {
        return crate::jmap::write_problem(error);
    }
    let sent = headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
    let sent = sent.map(|kind| kind.split(';').next().unwrap_or_default().trim().to_owned());
    let media_type = sent
        .filter(|kind| !kind.is_empty() && kind != "application/octet-stream")
        .and_then(|kind| kernoid_files::check_media_type(&kind).ok())
        .unwrap_or_else(|| crate::webdav::guess(&query.name).to_owned());
    let added = async {
        let content = files.store(link.owner, body.into_data_stream()).await?;
        let new = NewNode::file(Some(parent), query.name.clone(), content, Some(media_type));
        let options = SetOptions { on_exists: OnExists::Rename, ..SetOptions::default() };
        files.create(&view.access, new, &options).await
    }
    .await;
    match added {
        Ok(written) => {
            let size = written.node.size.unwrap_or_default();
            if let Err(error) = state.identity.record_file_link_arrival(link.id, &written.node.name, size).await {
                tracing::warn!(%error, "a file added through a link was not noted for its notice");
            }
            (StatusCode::CREATED, Json(node_view(&written.node, &link))).into_response()
        }
        Err(error) => crate::jmap::write_problem(error),
    }
}

/// How long nothing must have come in through a link before its maker is told – so that a batch of files is one notice.
pub const NOTICE_AFTER_QUIET: std::time::Duration = std::time::Duration::from_secs(2 * 60);

/// Tells the makers of links – or the stores' owners – by mail what came in through links quiet for `quiet` (the
/// worker, every minute, with [`NOTICE_AFTER_QUIET`]). Someone without a mailbox is not told. `hostname` is the MX's name for the sender; otherwise the
/// recipient's domain. Returns how many notices were delivered.
pub async fn notify_arrivals(
    identity: &kernoid_identity::Identity,
    mail: &kernoid_mail::Mail,
    hostname: Option<&str>,
    quiet: std::time::Duration,
) -> Result<usize, kernoid_identity::IdentityError> {
    let mut delivered = 0;
    for arrivals in identity.take_file_link_arrivals(quiet).await? {
        let recipient = arrivals.maker.unwrap_or(arrivals.owner);
        let address = match identity.account_addresses(recipient).await {
            Ok(addresses) => addresses.into_iter().find(|(_, primary)| *primary).map(|(address, _)| address),
            Err(_) => None,
        };
        let Some(address) = address else { continue };
        let host =
            hostname.map(str::to_owned).unwrap_or_else(|| address.rsplit('@').next().unwrap_or_default().to_owned());
        let raw = arrival_notice(&host, &address, &arrivals);
        // An empty envelope sender, as for bounces: nothing answers a notice.
        let delivery = kernoid_mail::Delivery { from: "", to: &address, junk: false };
        match mail.deliver(recipient, raw.into(), delivery).await {
            Ok(_) => delivered += 1,
            Err(error) => tracing::warn!(%error, link = %arrivals.link, "a notice of files added through a link"),
        }
    }
    Ok(delivered)
}

/// At most this many files are named in a notice; the rest are counted.
const NOTICE_NAMES: usize = 50;

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// The notice: which files came in, through the link to which folder.
fn arrival_notice(host: &str, to: &str, arrivals: &kernoid_identity::file_link::LinkArrivals) -> Vec<u8> {
    let count = arrivals.files.len();
    let mut text = format!(
        "{count} {} added through your link to the folder \"{}\":\r\n\r\n",
        if count == 1 { "file was" } else { "files were" },
        arrivals.folder
    );
    for (name, size) in arrivals.files.iter().take(NOTICE_NAMES) {
        text.push_str(&format!("  {name} ({})\r\n", human_size(*size)));
    }
    if count > NOTICE_NAMES {
        text.push_str(&format!("  and {} more\r\n", count - NOTICE_NAMES));
    }
    text.push_str("\r\nThey are in the folder now. A link can be removed in the web app: Files, the folder, Link.\r\n");
    mail_builder::MessageBuilder::new()
        .from(mail_builder::headers::address::Address::new_address(Some("kernoid"), format!("mailer-daemon@{host}")))
        .to(to)
        .subject(format!("Files added to \"{}\"", arrivals.folder))
        .header("Auto-Submitted", mail_builder::headers::raw::Raw::new("auto-generated"))
        .text_body(text)
        .write_to_vec()
        .expect("writing to memory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notice_names_the_files_and_counts_the_rest() {
        let arrivals = kernoid_identity::file_link::LinkArrivals {
            link: Uuid::nil(),
            owner: Uuid::nil(),
            maker: None,
            folder: "Submissions".into(),
            files: (0..52).map(|n| (format!("file {n}.pdf"), 1536)).collect(),
        };
        let notice = String::from_utf8(arrival_notice("mx.firma.de", "bob@firma.de", &arrivals)).unwrap();
        assert!(notice.contains("Subject: Files added to \"Submissions\""), "{notice}");
        assert!(notice.contains("Auto-Submitted: auto-generated"), "{notice}");
        assert!(notice.contains("52 files were added"), "{notice}");
        assert!(notice.contains("file 49.pdf (1.5 KiB)") && !notice.contains("file 50.pdf"), "{notice}");
        assert!(notice.contains("and 2 more"), "{notice}");
        assert_eq!(human_size(10), "10 B");
    }
}
