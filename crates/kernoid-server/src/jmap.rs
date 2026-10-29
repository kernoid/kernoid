// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP over HTTP (RFC 8620, RFC 0002 11.1): the session at `/.well-known/jmap`, the API, uploads, downloads and the
//! push stream. A caller logs in with a kernoid session (bearer token or cookie) or with HTTP Basic – an address and
//! an app password, or the password of an account that needs no second factor. The protocol itself is
//! `kernoid-jmap`'s.

use std::{convert::Infallible, time::Duration};

use axum::{
    Json,
    body::Bytes,
    extract::{FromRef, FromRequestParts, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{
        IntoResponse, Redirect, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use base64::Engine;
use futures_util::stream::{self, Stream, StreamExt};
use kernoid_identity::{IdentityError, services::Service};
use kernoid_jmap::{Caller, Jmap};
use serde::Deserialize;

use crate::{AppState, Client, Problem, instance::of_request};

/// The JMAP of this installation; absent where kernoid handles no mail and no files.
#[allow(clippy::result_large_err, reason = "the error is the finished answer, built once on the error path")]
fn jmap(state: &AppState) -> Result<&Jmap, Response> {
    state.jmap.as_ref().ok_or_else(|| Problem::new(StatusCode::NOT_FOUND).detail("no mail here").into_response())
}

pub(crate) fn unauthorized() -> Response {
    let mut response = Problem::new(StatusCode::UNAUTHORIZED).detail("log in").into_response();
    response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"kernoid\""));
    response
}

/// The account of a request by a mail program – CalDAV, CardDAV – logged in, with the service `mail`.
pub(crate) struct MailCaller {
    pub account: kernoid_identity::account::AccountInfo,
}

#[allow(clippy::result_large_err, reason = "the error is the finished answer, built once on the error path")]
/// Logs in the caller of a program's request – with a kernoid session or HTTP Basic – as an account of this instance
/// with one of `services`.
async fn log_in(
    parts: &Parts,
    state: &AppState,
    services: &[Service],
) -> Result<(kernoid_identity::account::AccountInfo, String), Response> {
    let client = parts.extensions.get::<Client>().cloned();
    let instance = of_request(&state.identity, client.as_ref())
        .await
        .map_err(IntoResponse::into_response)?
        .ok_or_else(|| Problem::new(StatusCode::NOT_FOUND).detail("no instance at this host").into_response())?;
    let base = state.oidc.issuer(&instance.primary_domain);
    let basic = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .and_then(|(_, token)| base64::engine::general_purpose::STANDARD.decode(token.trim()).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok());
    let account = if let Some(basic) = basic {
        let (user, password) = basic.split_once(':').ok_or_else(unauthorized)?;
        let address = client.as_ref().map(|client| client.address);
        match state.identity.program_login(user, password, address, services, Some(instance.id)).await {
            Ok(account) => account,
            Err(IdentityError::InvalidCredentials) => return Err(unauthorized()),
            Err(error) => return Err(crate::sessions::problem(error)),
        }
    } else {
        let token = crate::cookie::session_token(state, &parts.method, &parts.headers, Some(&instance))
            .map_err(|_| unauthorized())?;
        state.identity.session(instance.id, &token).await.map_err(|_| unauthorized())?.account
    };
    // An account of another instance does not use this one.
    if account.instance != instance.id {
        return Err(unauthorized());
    }
    Ok((account, base))
}

impl<S> FromRequestParts<S> for MailCaller
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let state = AppState::from_ref(state);
        let (account, _) = log_in(parts, &state, &[Service::Mail]).await?;
        // Only an account with the service `mail` has mail, calendars and contacts (RFC 0003, 4; RFC 0004, 2).
        match state.identity.has_service(account.id, Service::Mail).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(Problem::new(StatusCode::FORBIDDEN).detail("this account has no mail").into_response());
            }
            Err(error) => return Err(crate::sessions::problem(error)),
        }
        Ok(Self { account })
    }
}

/// The caller of a JMAP request, logged in: an account with mail, files or both (RFC 0005, 8).
pub(crate) struct JmapCaller(pub(crate) Caller, pub(crate) String);

impl<S> FromRequestParts<S> for JmapCaller
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let state = AppState::from_ref(state);
        let (account, base) = log_in(parts, &state, &[Service::Mail, Service::Files]).await?;
        let has = |service| state.identity.has_service(account.id, service);
        let (mail, files) = match (has(Service::Mail).await, has(Service::Files).await) {
            (Ok(mail), Ok(files)) => (mail, files),
            (Err(error), _) | (_, Err(error)) => return Err(crate::sessions::problem(error)),
        };
        if !mail && !files {
            return Err(Problem::new(StatusCode::FORBIDDEN)
                .detail("this account has no mail and no files")
                .into_response());
        }
        let caller = Caller { account: account.id, tenant: account.tenant, username: account.address, mail, files };
        Ok(Self(caller, base))
    }
}

pub(crate) async fn well_known() -> Redirect {
    Redirect::permanent("/jmap/session")
}

pub(crate) async fn session(State(state): State<AppState>, JmapCaller(caller, base): JmapCaller) -> Response {
    let jmap = match jmap(&state) {
        Ok(jmap) => jmap,
        Err(response) => return response,
    };
    match jmap.session(&caller, &base).await {
        Ok(session) => Json(session).into_response(),
        Err(error) => {
            tracing::warn!(%error, "the JMAP session");
            Problem::new(StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
    }
}

pub(crate) async fn api(State(state): State<AppState>, JmapCaller(caller, _): JmapCaller, body: Bytes) -> Response {
    let jmap = match jmap(&state) {
        Ok(jmap) => jmap,
        Err(response) => return response,
    };
    if body.len() > kernoid_jmap::MAX_SIZE_REQUEST {
        return (StatusCode::BAD_REQUEST, Json(kernoid_jmap::RequestError::Limit("maxSizeRequest").problem()))
            .into_response();
    }
    match jmap.api(&caller, &body).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => {
            let mut response = (StatusCode::BAD_REQUEST, Json(error.problem())).into_response();
            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
            response
        }
    }
}

fn blob_problem(error: kernoid_jmap::blob::BlobError) -> Response {
    use kernoid_jmap::blob::BlobError;
    match error {
        BlobError::NotFound => Problem::new(StatusCode::NOT_FOUND).detail("no such blob").into_response(),
        BlobError::Forbidden => Problem::new(StatusCode::FORBIDDEN).detail("not your account").into_response(),
        BlobError::TooLarge(detail) => Problem::new(StatusCode::PAYLOAD_TOO_LARGE).detail(detail).into_response(),
        BlobError::Refused(refused) => refused_problem(&refused),
        BlobError::Mail(error) => {
            tracing::warn!(%error, "a JMAP blob");
            Problem::new(StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
        BlobError::Files(error) => {
            tracing::warn!(%error, "a JMAP blob");
            Problem::new(StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
        BlobError::Blob(error) => {
            tracing::warn!(%error, "a JMAP blob");
            Problem::new(StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
    }
}

/// Content the malware scanner refused: 422 with the malware's name, or 503 when it could not be asked.
pub(crate) fn refused_problem(refused: &kernoid_store::scan::Refused) -> Response {
    let status = match refused {
        kernoid_store::scan::Refused::Infected(_) => StatusCode::UNPROCESSABLE_ENTITY,
        kernoid_store::scan::Refused::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    };
    Problem::new(status).detail(refused.to_string()).into_response()
}

/// A `Range` header with one range of bytes (RFC 9110, 14.1.2): its start and inclusive end; `bytes=-n` (the last n
/// bytes) is not supported and reads as the whole.
pub(crate) fn byte_range(headers: &HeaderMap) -> Option<(u64, Option<u64>)> {
    let value = headers.get(header::RANGE)?.to_str().ok()?.strip_prefix("bytes=")?;
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    let start = start.trim().parse().ok()?;
    let end = match end.trim() {
        "" => None,
        end => Some(end.parse().ok()?),
    };
    Some((start, end))
}

/// The answer to a download: the whole, or the part a range asked for (206).
/// What a downloaded blob may do in the browser. Its type comes from whoever stored it, and it is served from the
/// instance's origin: an HTML or SVG file opened directly would run its scripts there. So the browser takes the type
/// as given (`nosniff`) and treats the content as a sandboxed document of its own origin – except a PDF, which the
/// browsers' viewers refuse in a sandbox, and which the web app shows in a frame of the same origin.
const DOWNLOAD_POLICY: &str = "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'";
/// The PDF viewers of browsers are plugins: `default-src 'none'` (and so `object-src`) would block them.
const PDF_POLICY: &str = "frame-ancestors 'self'";

/// An email shown as its sender laid it out (`/jmap/view`): its own styles, embedded images – nothing else. No scripts,
/// forms or plugins (sandbox), nothing loaded from elsewhere – no remote images, so no tracking –, framed only by the
/// web app; links open outside the frame.
const VIEW_POLICY: &str = "sandbox allow-popups allow-popups-to-escape-sandbox; default-src 'none'; \
    style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'; \
    frame-ancestors 'self'";

/// The HTML part of an email as a page of its own, for the web app's original view.
pub(crate) async fn view(
    State(state): State<AppState>,
    JmapCaller(caller, _): JmapCaller,
    Path((account, blob)): Path<(String, String)>,
) -> Response {
    let jmap = match jmap(&state) {
        Ok(jmap) => jmap,
        Err(response) => return response,
    };
    match jmap.email_view(&caller, &account, &blob).await {
        Ok(html) => {
            let mut response = html.into_response();
            let headers = response.headers_mut();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
            headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(VIEW_POLICY));
            headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
            response
        }
        Err(error) => blob_problem(error),
    }
}

/// The response for a download – once its first part could be read: content that cannot be read (an object missing in
/// storage, a key that does not open it) is a problem with a status, not a connection that breaks off empty.
pub(crate) async fn download_response(download: kernoid_jmap::Download, ranged: bool) -> Response {
    let length = download.end - download.start;
    let mut content = download.content;
    let first = match content.next().await {
        Some(Err(error)) => {
            tracing::error!(%error, "a download could not be read");
            return Problem::new(StatusCode::INTERNAL_SERVER_ERROR)
                .detail("the content could not be read")
                .into_response();
        }
        first => first,
    };
    let mut response = axum::body::Body::from_stream(stream::iter(first).chain(content)).into_response();
    if ranged {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        let range = format!("bytes {}-{}/{}", download.start, download.end.saturating_sub(1), download.size);
        if let Ok(range) = HeaderValue::from_str(&range) {
            response.headers_mut().insert(header::CONTENT_RANGE, range);
        }
    }
    response.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    response.headers_mut().insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    let pdf = download.kind.as_deref().is_some_and(|kind| kind.eq_ignore_ascii_case("application/pdf"));
    if let Some(kind) = download.kind.and_then(|kind| HeaderValue::from_str(&kind).ok()) {
        response.headers_mut().insert(header::CONTENT_TYPE, kind);
    }
    let headers = response.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(if pdf { PDF_POLICY } else { DOWNLOAD_POLICY }),
    );
    response
}

pub(crate) async fn upload(
    State(state): State<AppState>,
    JmapCaller(caller, _): JmapCaller,
    Path(account): Path<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let jmap = match jmap(&state) {
        Ok(jmap) => jmap,
        Err(response) => return response,
    };
    let kind =
        headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("application/octet-stream");
    match jmap.upload(&caller, &account, kind, body.into_data_stream()).await {
        Ok(answer) => (StatusCode::CREATED, Json(answer)).into_response(),
        Err(error) => blob_problem(error),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DownloadQuery {
    accept: Option<String>,
    /// `1`: shown in place (`Content-Disposition: inline`) rather than saved.
    inline: Option<String>,
}

pub(crate) async fn download(
    State(state): State<AppState>,
    JmapCaller(caller, _): JmapCaller,
    Path((account, blob, name)): Path<(String, String, String)>,
    Query(query): Query<DownloadQuery>,
    headers: HeaderMap,
) -> Response {
    let jmap = match jmap(&state) {
        Ok(jmap) => jmap,
        Err(response) => return response,
    };
    let range = byte_range(&headers);
    match jmap.download(&caller, &account, &blob, range).await {
        Ok(mut download) => {
            if range.is_some_and(|(start, _)| start >= download.size && download.size > 0) {
                let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
                if let Ok(value) = HeaderValue::from_str(&format!("bytes */{}", download.size)) {
                    response.headers_mut().insert(header::CONTENT_RANGE, value);
                }
                return response;
            }
            download.kind = Some(query.accept.or(download.kind).unwrap_or_else(|| "application/octet-stream".into()));
            let mut response = download_response(download, range.is_some()).await;
            if !response.status().is_success() {
                return response;
            }
            // The name as the client gave it, quoted; only printable ASCII, so that it cannot break the header. With
            // `inline=1` the browser shows it in place (the web app's viewer) – under the download's sandbox policy.
            let name: String = name.chars().filter(|c| c.is_ascii_graphic() && *c != '"' && *c != '\\').collect();
            let disposition = if query.inline.as_deref() == Some("1") { "inline" } else { "attachment" };
            if let Ok(disposition) = HeaderValue::from_str(&format!("{disposition}; filename=\"{name}\"")) {
                response.headers_mut().insert(header::CONTENT_DISPOSITION, disposition);
            }
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("private, immutable, max-age=31536000"));
            response
        }
        Err(error) => blob_problem(error),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct EventSourceQuery {
    closeafter: Option<String>,
    ping: Option<u64>,
}

/// Writes a file's content directly (draft-ietf-jmap-filenode, 4.1; RFC 0005, 8): `PUT` with the new content.
pub(crate) async fn write_file(
    State(state): State<AppState>,
    JmapCaller(caller, _): JmapCaller,
    Path((account, node)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let jmap = match jmap(&state) {
        Ok(jmap) => jmap,
        Err(response) => return response,
    };
    let kind = headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
    match jmap.write_file(&caller, &account, &node, kind, body.into_data_stream()).await {
        Ok(answer) => Json(answer).into_response(),
        Err(error) => write_problem(error),
    }
}

/// A file that could not be written, as a problem – a direct write, or a file added through a link.
pub(crate) fn write_problem(error: kernoid_files::FilesError) -> Response {
    use kernoid_files::FilesError;
    let status = match &error {
        FilesError::NotFound(_) => StatusCode::NOT_FOUND,
        FilesError::Invalid(_) => StatusCode::BAD_REQUEST,
        FilesError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        FilesError::OverQuota => StatusCode::INSUFFICIENT_STORAGE,
        FilesError::Forbidden(_) => StatusCode::FORBIDDEN,
        FilesError::Refused(refused) => return refused_problem(refused),
        _ => {
            tracing::warn!(%error, "a file was not written");
            return Problem::new(StatusCode::INTERNAL_SERVER_ERROR).into_response();
        }
    };
    Problem::new(status).detail(error.to_string()).into_response()
}

/// The push stream (RFC 8620, 7.3): a `state` event whenever the mail of the caller's account or of one shared with
/// it changes, or the caller's files, and pings if asked for.
pub(crate) async fn event_source(
    State(state): State<AppState>,
    JmapCaller(caller, _): JmapCaller,
    Query(query): Query<EventSourceQuery>,
) -> Response {
    let jmap = match jmap(&state) {
        Ok(jmap) => jmap.clone(),
        Err(response) => return response,
    };
    let Some(events) = state.mail_events.clone() else {
        return Problem::new(StatusCode::NOT_FOUND).detail("no push here").into_response();
    };
    let close_after_state = query.closeafter.as_deref() == Some("state");
    let receiver = events.subscribe();
    // The caller's own account and those shared with it when the stream began.
    let watched = jmap.watched(&caller).await.unwrap_or_else(|_| vec![caller.account]);
    let first = jmap.state_change(&caller, &watched).await.ok();
    let watching = (receiver, jmap, watched, caller);
    let changes = stream::unfold(watching, move |(mut receiver, jmap, watched, caller)| async move {
        loop {
            match receiver.recv().await {
                Ok(changed) if !watched.contains(&changed) => continue,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let change = jmap.state_change(&caller, &watched).await.ok()?;
                    return Some((change, (receiver, jmap, watched, caller)));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    let stream: std::pin::Pin<Box<dyn Stream<Item = serde_json::Value> + Send>> =
        Box::pin(stream::iter(first).chain(changes));
    let stream = if close_after_state { Box::pin(stream.take(1)) } else { stream };
    let events = stream.map(|change| Ok::<_, Infallible>(Event::default().event("state").data(change.to_string())));
    // A ping interval of at least 30 seconds (RFC 8620, 7.3 lets the server choose); without, keep-alive comments.
    let keep_alive = match query.ping.filter(|ping| *ping > 0) {
        Some(ping) => KeepAlive::new().interval(Duration::from_secs(ping.max(30))).event(
            Event::default().event("ping").data(format!("{{\"@type\":\"Ping\",\"interval\":{}}}", ping.max(30))),
        ),
        None => KeepAlive::new().interval(Duration::from_secs(60)),
    };
    Sse::new(events).keep_alive(keep_alive).into_response()
}
