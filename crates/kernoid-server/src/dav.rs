// SPDX-License-Identifier: AGPL-3.0-or-later
//! CalDAV and CardDAV over HTTP (RFC 0004, 8.1): everything below `/dav/`, and `/.well-known/caldav` and
//! `/.well-known/carddav` pointing there (RFC 6764). A caller logs in like a mail program (`jmap::MailCaller`); the
//! protocol itself is `kernoid-dav`'s.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use kernoid_dav::DavRequest;

use crate::{AppState, Problem, jmap::MailCaller};

/// Largest request body: an object of at most 1 MiB, in XML or not.
pub(crate) const DAV_BODY_LIMIT: usize = 2 * 1024 * 1024;

pub(crate) async fn handle(
    State(state): State<AppState>,
    caller: MailCaller,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(dav) = &state.dav else {
        return Problem::new(StatusCode::NOT_FOUND).detail("no calendars here").into_response();
    };
    let request =
        DavRequest { method, path: uri.path().to_owned(), headers, body: body.to_vec(), account: caller.account.id };
    let response = dav.handle(request).await;
    let (parts, body) = response.into_parts();
    let mut response = (parts.status, body).into_response();
    for (name, value) in parts.headers {
        if let Some(name) = name {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

/// `/.well-known/caldav` and `/.well-known/carddav`: the context path, for any method (RFC 6764, 5).
pub(crate) async fn well_known() -> Response {
    let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
    response.headers_mut().insert(header::LOCATION, HeaderValue::from_static("/dav/"));
    response
}
