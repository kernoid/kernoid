// SPDX-License-Identifier: AGPL-3.0-or-later
//! The journal of the file store (RFC 0005, 6): one row per changed node and modification sequence, read by JMAP's
//! `FileNode/changes`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use kernoid_store::PgPool;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Files, FilesError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    Created,
    Updated,
    Destroyed,
}

impl Change {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Destroyed => "destroyed",
        }
    }
}

/// Writes that a node changed at `modseq`. A node changed twice in one modification sequence keeps its first entry.
pub(crate) async fn record(
    connection: &mut PgConnection,
    account: Uuid,
    modseq: i64,
    node: Uuid,
    change: Change,
) -> Result<()> {
    sqlx::query!(
        "INSERT INTO file_changes (account_id, modseq, node_id, change) VALUES ($1, $2, $3, $4)
         ON CONFLICT (account_id, modseq, node_id) DO NOTHING",
        account,
        modseq,
        node,
        change.as_str(),
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// What changed between two states (RFC 8620, 5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub old_state: i64,
    pub new_state: i64,
    /// More changes follow after `new_state`.
    pub has_more_changes: bool,
    pub created: Vec<Uuid>,
    pub updated: Vec<Uuid>,
    pub destroyed: Vec<Uuid>,
}

/// Most journal rows read at once when the caller sets no maximum.
const DEFAULT_MAX: usize = 5000;

impl Files {
    /// The nodes that changed after `since`, at most about `max` of them: a modification sequence is never split.
    pub async fn changes(&self, account: Uuid, since: i64, max: Option<usize>) -> Result<Changes> {
        let max = max.unwrap_or(DEFAULT_MAX).clamp(1, DEFAULT_MAX);
        let mut tx = self.pool.begin().await?;
        let locked = self.open(&mut tx, account).await?;
        let state = locked.modseq;
        let floor = sqlx::query_scalar!("SELECT changes_floor FROM file_accounts WHERE account_id = $1", account)
            .fetch_one(&mut *tx)
            .await?;
        if since < floor || since > state {
            return Err(FilesError::CannotCalculateChanges);
        }
        let mut rows = sqlx::query!(
            "SELECT modseq, node_id, change FROM file_changes
             WHERE account_id = $1 AND modseq > $2 AND modseq <= $3
             ORDER BY modseq, node_id LIMIT $4",
            account,
            since,
            state,
            (max + 1) as i64,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut has_more = false;
        let mut new_state = state;
        if rows.len() > max {
            // Stop before the last modification sequence read, which may be incomplete – unless it is the only one.
            let last = rows[max].modseq;
            if last != rows[0].modseq {
                rows.retain(|row| row.modseq < last);
                new_state = last - 1;
                has_more = true;
            }
        }
        let mut seen: BTreeMap<Uuid, (String, String)> = BTreeMap::new();
        for row in rows {
            seen.entry(row.node_id)
                .and_modify(|(_, last)| *last = row.change.clone())
                .or_insert((row.change.clone(), row.change));
        }
        let mut changes = Changes { old_state: since, new_state, has_more_changes: has_more, ..Changes::default() };
        for (id, (first, last)) in seen {
            match (first.as_str(), last.as_str()) {
                ("created", "destroyed") => {}
                ("created", _) => changes.created.push(id),
                (_, "destroyed") => changes.destroyed.push(id),
                _ => changes.updated.push(id),
            }
        }
        Ok(changes)
    }
}

/// Removes up to `limit` journal rows written before `before` and raises each account's floor past them; returns how
/// many went. For the worker, beside the mail journal's pruning.
pub async fn prune_changes(pool: &PgPool, before: DateTime<Utc>, limit: i64) -> Result<u64> {
    let pruned = sqlx::query_scalar!(
        r#"WITH gone AS (
               DELETE FROM file_changes WHERE (account_id, modseq, node_id) IN (
                   SELECT account_id, modseq, node_id FROM file_changes
                   WHERE changed_at < $1 ORDER BY changed_at LIMIT $2)
               RETURNING account_id, modseq),
           floors AS (
               UPDATE file_accounts f SET changes_floor = greatest(f.changes_floor, g.modseq)
               FROM (SELECT account_id, max(modseq) AS modseq FROM gone GROUP BY account_id) g
               WHERE f.account_id = g.account_id
               RETURNING 1)
           SELECT count(*) AS "count!" FROM gone"#,
        before,
        limit,
    )
    .fetch_one(pool)
    .await?;
    Ok(pruned as u64)
}
