// SPDX-License-Identifier: AGPL-3.0-or-later
//! Links to files for people without an account (RFC 0005, 11.3): what a link opens, its directories' contents and
//! downloads – anonymous, read only, within the file or directory the link names. A link with a password is opened
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
use kernoid_files::{FileAccess, Files, NodeInfo, NodeType, Rights, View};
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
pub(crate) struct LinkView {
    /// What the link names.
    node: LinkNodeView,
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
        nodes: HashMap::from([(link.node, Rights::READ)]),
    };
    let view = files.view(access).await.map_err(|_| Box::new(not_found()))?;
    Ok((files, link, view))
}

/// A node the link reaches: what it names, or something below it.
fn within<'a>(view: &'a View, link: &OpenLink, id: Uuid) -> Option<&'a NodeInfo> {
    let node = view.node(id).filter(|node| view.readable(node.id))?;
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
        Some(node) => Json(LinkView { node: node_view(node, &link) }).into_response(),
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
        Some(directory) if directory.node_type == NodeType::Directory => {}
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
