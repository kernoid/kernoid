// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pictures of accounts: each account sets, replaces and removes its own; everyone logged in to the same tenant sees
//! them (mail lists, contacts, the account's menu). A picture is content like a file's – sealed with the tenant's key
//! in object storage under `avatars/<account>/<version>` – and only PNG, JPEG or WebP: what the browser shows as an
//! image and nothing it would run (no SVG). Each new picture gets a new version, so its address changes and caches
//! never show an old one.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use uuid::Uuid;

use crate::{AppState, CurrentInstance, Problem, sessions::SessionToken, sessions::problem};

/// The largest picture taken: enough for a sharp square photo, small enough for lists.
const MAX_SIZE: usize = 1024 * 1024;

/// The media type of a picture by its first bytes – PNG, JPEG or WebP –, whatever the request claims.
fn media_type(content: &[u8]) -> Option<&'static str> {
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if content.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if content.len() > 12 && &content[..4] == b"RIFF" && &content[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

fn blob_key(account: Uuid, version: Uuid) -> String {
    format!("avatars/{account}/{version}")
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AvatarView {
    account: String,
    /// Changes with every new picture: `GET /v1/avatars/{account}?v=<version>` may be cached for good.
    version: String,
    /// The account's addresses, to find the picture of someone who wrote an email.
    addresses: Vec<String>,
}

/// The pictures of the caller's tenant – which accounts have one, and their addresses.
#[utoipa::path(get, path = "/v1/avatars", tag = "account", responses(
    (status = 200, body = Vec<AvatarView>),
    (status = 401, description = "no valid session or app token", body = Problem),
))]
pub(crate) async fn list(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let account = match state.identity.settings_account(instance.id, &token, true).await {
        Ok(account) => account,
        Err(error) => return problem(error),
    };
    let rows = sqlx::query!(
        r#"SELECT v.account_id, v.version,
                  COALESCE(array_agg(a.address ORDER BY a.is_primary DESC, a.address) FILTER (WHERE a.address IS NOT NULL),
                           '{}') AS "addresses!"
           FROM account_avatars v
           LEFT JOIN addresses a ON a.account_id = v.account_id
           WHERE v.tenant_id = $1
           GROUP BY v.account_id, v.version"#,
        account.tenant,
    )
    .fetch_all(&state.db)
    .await;
    match rows {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|row| AvatarView {
                    account: row.account_id.to_string(),
                    version: row.version.to_string(),
                    addresses: row.addresses,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            tracing::error!(%error, "listing avatars");
            Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response()
        }
    }
}

/// The picture of an account of the caller's tenant.
#[utoipa::path(get, path = "/v1/avatars/{account}", tag = "account", params(("account" = String, Path)), responses(
    (status = 200, description = "the picture (PNG, JPEG or WebP)"),
    (status = 401, description = "no valid session or app token", body = Problem),
    (status = 404, description = "no picture", body = Problem),
))]
pub(crate) async fn get(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    Path(account): Path<Uuid>,
) -> Response {
    let caller = match state.identity.settings_account(instance.id, &token, true).await {
        Ok(caller) => caller,
        Err(error) => return problem(error),
    };
    let row = sqlx::query!(
        "SELECT version, media_type FROM account_avatars WHERE account_id = $1 AND tenant_id = $2",
        account,
        caller.tenant,
    )
    .fetch_optional(&state.db)
    .await;
    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => return Problem::new(StatusCode::NOT_FOUND).detail("no picture").into_response(),
        Err(error) => {
            tracing::error!(%error, "reading an avatar");
            return Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
        }
    };
    let content = match state.blobs.get(caller.tenant, &blob_key(account, row.version)).await {
        Ok(content) => content,
        Err(error) => {
            tracing::warn!(%error, %account, "an avatar's content cannot be read");
            return Problem::new(StatusCode::SERVICE_UNAVAILABLE)
                .detail("stored content could not be read")
                .into_response();
        }
    };
    let mut response = content.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&row.media_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", row.version)) {
        headers.insert(header::ETAG, value);
    }
    // Private to the tenant; the address carries the version, so a cached copy is never stale for long.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=86400"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    response
}

/// Sets one's own picture: the body is the image, PNG, JPEG or WebP, up to 1 MiB.
#[utoipa::path(put, path = "/v1/account/avatar", tag = "account", request_body(content = Vec<u8>, content_type = "image/*"), responses(
    (status = 204),
    (status = 400, description = "not a PNG, JPEG or WebP image", body = Problem),
    (status = 401, description = "no valid session or app token", body = Problem),
    (status = 413, description = "larger than 1 MiB", body = Problem),
))]
pub(crate) async fn set(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
    body: Bytes,
) -> Response {
    let account = match state.identity.settings_account(instance.id, &token, true).await {
        Ok(account) => account,
        Err(error) => return problem(error),
    };
    if body.len() > MAX_SIZE {
        return Problem::new(StatusCode::PAYLOAD_TOO_LARGE).detail("a picture may have up to 1 MiB").into_response();
    }
    let Some(media_type) = media_type(&body) else {
        return Problem::new(StatusCode::BAD_REQUEST).detail("a picture is a PNG, JPEG or WebP image").into_response();
    };
    let (account, tenant) = (account.id, account.tenant);
    let version = Uuid::now_v7();
    let size = body.len() as i32;
    if let Err(error) = state.blobs.put(tenant, &blob_key(account, version), body).await {
        tracing::error!(%error, "storing an avatar");
        return Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
    }
    let previous = sqlx::query_scalar!("SELECT version FROM account_avatars WHERE account_id = $1", account)
        .fetch_optional(&state.db)
        .await;
    let stored = sqlx::query!(
        "INSERT INTO account_avatars (account_id, tenant_id, version, media_type, size) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (account_id) DO UPDATE
         SET version = EXCLUDED.version, media_type = EXCLUDED.media_type, size = EXCLUDED.size, updated_at = now()",
        account,
        tenant,
        version,
        media_type,
        size,
    )
    .execute(&state.db)
    .await;
    if let Err(error) = stored {
        tracing::error!(%error, "recording an avatar");
        let _ = state.blobs.delete(tenant, &blob_key(account, version)).await;
        return Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
    }
    if let Ok(Some(old)) = previous {
        forget(&state, tenant, account, old).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Removes one's own picture; the initials show again.
#[utoipa::path(delete, path = "/v1/account/avatar", tag = "account", responses(
    (status = 204),
    (status = 401, description = "no valid session or app token", body = Problem),
))]
pub(crate) async fn remove(
    State(state): State<AppState>,
    CurrentInstance(instance): CurrentInstance,
    SessionToken(token): SessionToken,
) -> Response {
    let account = match state.identity.settings_account(instance.id, &token, true).await {
        Ok(account) => account,
        Err(error) => return problem(error),
    };
    let (account, tenant) = (account.id, account.tenant);
    let removed = sqlx::query_scalar!("DELETE FROM account_avatars WHERE account_id = $1 RETURNING version", account)
        .fetch_optional(&state.db)
        .await;
    match removed {
        Ok(Some(version)) => forget(&state, tenant, account, version).await,
        Ok(None) => {}
        Err(error) => {
            tracing::error!(%error, "removing an avatar");
            return Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Removes a replaced picture's content; one left behind only takes space.
async fn forget(state: &AppState, tenant: Uuid, account: Uuid, version: Uuid) {
    if let Err(error) = state.blobs.delete(tenant, &blob_key(account, version)).await {
        tracing::warn!(%error, %account, "removing an old avatar's content");
    }
}

#[cfg(test)]
mod tests {
    use super::media_type;

    #[test]
    fn only_images_the_browser_shows_are_pictures() {
        assert_eq!(media_type(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(media_type(&[0xff, 0xd8, 0xff, 0xe0, 0, 0]), Some("image/jpeg"));
        assert_eq!(media_type(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(media_type(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"), None);
        assert_eq!(media_type(b"GIF89a"), None);
        assert_eq!(media_type(b""), None);
    }
}
