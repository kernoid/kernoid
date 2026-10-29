// SPDX-License-Identifier: AGPL-3.0-or-later
//! The audit log: the events of the tenant administered, or of the instance – newest first, a page at a time.

use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use kernoid_identity::{
    IdentityError,
    audit::{AuditEntry, AuditQuery, AuditScope},
};
use serde::{Deserialize, Serialize};

use super::{AdminSession, respond, tenant::TenantHeader};
use crate::AppState;

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct AuditParams {
    /// `tenant` (default: the tenant administered, needs `directory.read`) or `instance` (its own aggregates, needs
    /// `instance.read`).
    scope: Option<String>,
    /// Only events before this position – the `position` of the last entry of the previous page.
    before: Option<i64>,
    /// At most this many events (1–200, default 50).
    limit: Option<i64>,
    /// Only one kind of object, e.g. `account`, `group`, `tenant`.
    aggregate_type: Option<String>,
    /// Only one object (with `aggregate_type`).
    aggregate_id: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AuditEntryView {
    position: i64,
    aggregate_type: String,
    aggregate_id: String,
    sequence: i64,
    /// E.g. `account.added`, `group.member_added`.
    event_type: String,
    payload: serde_json::Value,
    /// An account id, `system`, `operator` or a service.
    creator: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<AuditEntry> for AuditEntryView {
    fn from(entry: AuditEntry) -> Self {
        Self {
            position: entry.position,
            aggregate_type: entry.aggregate_type,
            aggregate_id: entry.aggregate_id,
            sequence: entry.sequence,
            event_type: entry.event_type,
            payload: entry.payload,
            creator: entry.creator,
            created_at: entry.created_at,
        }
    }
}

pub(crate) fn scope(value: Option<&str>) -> Result<AuditScope, IdentityError> {
    match value {
        None | Some("tenant") => Ok(AuditScope::Tenant),
        Some("instance") => Ok(AuditScope::Instance),
        Some(other) => Err(IdentityError::Refused(format!("the scope is tenant or instance, not {other:?}"))),
    }
}

/// What happened in the tenant or the instance, and who did it: the events, newest first (needs `directory.read`
/// for the tenant, `instance.read` for the instance).
#[utoipa::path(get, path = "/v1/audit", tag = "audit", params(TenantHeader, AuditParams),
    responses((status = 200, body = [AuditEntryView]), (status = 403, body = crate::Problem)))]
pub(crate) async fn log(
    State(state): State<AppState>,
    AdminSession(admin): AdminSession,
    Query(params): Query<AuditParams>,
) -> Response {
    let result = async {
        let scope = scope(params.scope.as_deref())?;
        let query = AuditQuery {
            before: params.before,
            limit: params.limit,
            aggregate_type: params.aggregate_type,
            aggregate_id: params.aggregate_id,
        };
        state.identity.admin_audit_log(&admin, scope, &query).await
    }
    .await;
    respond(result, |list| Json(list.into_iter().map(AuditEntryView::from).collect::<Vec<_>>()).into_response())
}
