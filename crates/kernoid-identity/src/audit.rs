// SPDX-License-Identifier: AGPL-3.0-or-later
//! The audit log (RFC 0001, 4): identity and administration are events, so what happened, when and by whom is read
//! from the events themselves – the tenant's (with `directory.read`, the auditor's permission) or the instance's own
//! (with `instance.read`). Newest first, a page at a time. Payloads hold no credentials: those never enter events.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    Identity, IdentityError, Result,
    role::{Admin, Permission},
};

/// The most entries one page holds.
pub const MAX_PAGE: i64 = 200;

/// Whose events: the tenant administered, or the instance's own aggregates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditScope {
    Tenant,
    Instance,
}

/// Which events, newest first.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Only events older than this position (the `position` of the last entry of the page before).
    pub before: Option<i64>,
    pub limit: Option<i64>,
    /// Only one kind of object (`account`, `group`, `tenant` …) – and, with `aggregate_id`, one object.
    pub aggregate_type: Option<String>,
    pub aggregate_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    /// Where the event stands in the event store; pass it as `before` for the next page.
    pub position: i64,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub sequence: i64,
    pub event_type: String,
    pub payload: serde_json::Value,
    /// An account id, `system`, `operator` or a service.
    pub creator: String,
    pub created_at: DateTime<Utc>,
}

impl Identity {
    pub async fn admin_audit_log(
        &self,
        admin: &Admin,
        scope: AuditScope,
        query: &AuditQuery,
    ) -> Result<Vec<AuditEntry>> {
        let owner: Uuid = match scope {
            AuditScope::Tenant => {
                admin.require(Permission::DirectoryRead)?;
                admin.tenant()
            }
            AuditScope::Instance => {
                admin.require(Permission::InstanceRead)?;
                admin.instance()
            }
        };
        let limit = query.limit.unwrap_or(50).clamp(1, MAX_PAGE);
        let rows = sqlx::query!(
            "SELECT position, aggregate_type, aggregate_id, sequence, event_type, payload, creator, created_at
             FROM events
             WHERE instance_id = $1 AND owner = $2
               AND ($3::bigint IS NULL OR position < $3)
               AND ($4::text IS NULL OR aggregate_type = $4)
               AND ($5::text IS NULL OR aggregate_id = $5)
             ORDER BY position DESC
             LIMIT $6",
            admin.instance(),
            owner,
            query.before,
            query.aggregate_type.as_deref(),
            query.aggregate_id.as_deref(),
            limit,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|error| IdentityError::Store(error.into()))?;
        Ok(rows
            .into_iter()
            .map(|row| AuditEntry {
                position: row.position,
                aggregate_type: row.aggregate_type,
                aggregate_id: row.aggregate_id,
                sequence: row.sequence,
                event_type: row.event_type,
                payload: row.payload,
                creator: row.creator,
                created_at: row.created_at,
            })
            .collect())
    }
}
