// SPDX-License-Identifier: AGPL-3.0-or-later
//! Errors of the HTTP API as problem details (RFC 9457, `application/problem+json`) – one format for every error,
//! including unknown paths and panics. Problems say what went wrong for the caller, never internal details; those go
//! to the log, findable by the `x-request-id` every response carries.

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct Problem {
    /// A URI identifying the kind of problem; `about:blank` when the status says it all.
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Problem {
    pub fn new(status: StatusCode) -> Self {
        Self {
            kind: "about:blank".to_owned(),
            title: status.canonical_reason().unwrap_or("Error").to_owned(),
            status: status.as_u16(),
            detail: None,
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (status, axum::Json(self)).into_response();
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
        response
    }
}

/// For paths nothing is served at.
pub async fn not_found() -> Problem {
    Problem::new(StatusCode::NOT_FOUND)
}

/// For handlers that panicked: the request fails, the process keeps running.
pub fn panicked(_: Box<dyn std::any::Any + Send + 'static>) -> Response {
    tracing::error!("request handler panicked");
    Problem::new(StatusCode::INTERNAL_SERVER_ERROR).into_response()
}
