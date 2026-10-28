// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cross-origin requests from the instance's own login UI (`login_ui_url`): its origin – and no other – may call the
//! API from the browser, with the session cookie (on the same site) or a bearer token.

use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{AppState, Client, instance};

/// How long a browser may keep a preflight answer.
const MAX_AGE: &str = "600";

pub(crate) async fn login_ui(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(origin) = request.headers().get(header::ORIGIN).cloned() else { return next.run(request).await };
    let instance = instance::of_request(&state.identity, request.extensions().get::<Client>()).await.ok().flatten();
    let allowed = instance
        .and_then(|instance| instance.login_ui)
        .and_then(|url| url::Url::parse(&url).ok())
        .is_some_and(|url| origin.to_str().is_ok_and(|origin| origin == url.origin().ascii_serialization()));
    if !allowed {
        return next.run(request).await;
    }
    let preflight =
        request.method() == Method::OPTIONS && request.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
    let mut response = if preflight { StatusCode::NO_CONTENT.into_response() } else { next.run(request).await };
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
    headers.append(header::VARY, HeaderValue::from_static("origin"));
    headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("x-request-id, retry-after"));
    if preflight {
        headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE"));
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, content-type, kernoid-tenant, kernoid-csrf"),
        );
        headers.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static(MAX_AGE));
    }
    response
}
