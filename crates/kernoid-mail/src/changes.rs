// SPDX-License-Identifier: AGPL-3.0-or-later
//! The journal of changes (RFC 0002, 6): one row per changed object and modification sequence, read by JMAP's
//! `*/changes` and pruned by the worker after `mail.changes_kept_days`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Mail, MailError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Mailbox,
    Email,
    Thread,
}

impl ObjectType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Mailbox => "mailbox",
            Self::Email => "email",
            Self::Thread => "thread",
        }
    }
}

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

/// Writes that `id` changed at `modseq`. An object changed twice in one modification sequence keeps its first entry.
pub(crate) async fn record(
    connection: &mut PgConnection,
    account: Uuid,
    modseq: i64,
    object_type: ObjectType,
    id: Uuid,
    change: Change,
) -> Result<()> {
    sqlx::query!(
        "INSERT INTO mail_changes (account_id, modseq, object_type, object_id, change) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (account_id, object_type, modseq, object_id) DO NOTHING",
        account,
        modseq,
        object_type.as_str(),
        id,
        change.as_str(),
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// What changed between two states, as JMAP's `*/changes` answers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub old_state: u64,
    pub new_state: u64,
    /// More changes follow after `new_state`.
    pub has_more_changes: bool,
    pub created: Vec<Uuid>,
    pub updated: Vec<Uuid>,
    pub destroyed: Vec<Uuid>,
}

/// Most journal rows read at once when the caller sets no maximum.
const DEFAULT_MAX: usize = 5000;

impl Mail {
    /// The objects of `object_type` that changed after `since`, at most about `max` of them: a modification
    /// sequence is never split, so the result may hold more when one change touched more objects.
    pub async fn changes(
        &self,
        account: Uuid,
        object_type: ObjectType,
        since: u64,
        max: Option<usize>,
    ) -> Result<Changes> {
        let max = max.unwrap_or(DEFAULT_MAX).clamp(1, DEFAULT_MAX);
        let since = i64::try_from(since).map_err(|_| MailError::CannotCalculateChanges)?;
        let mut tx = self.pool.begin().await?;
        let locked = self.open(&mut tx, account).await?;
        let floor = sqlx::query_scalar!("SELECT changes_floor FROM mail_accounts WHERE account_id = $1", account)
            .fetch_one(&mut *tx)
            .await?;
        if since < floor || since > locked.modseq {
            return Err(MailError::CannotCalculateChanges);
        }
        let mut rows = sqlx::query_as!(
            Row,
            "SELECT modseq, object_id, change FROM mail_changes
             WHERE account_id = $1 AND object_type = $2 AND modseq > $3 AND modseq <= $4
             ORDER BY modseq, object_id LIMIT $5",
            account,
            object_type.as_str(),
            since,
            locked.modseq,
            (max + 1) as i64,
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut has_more = false;
        let mut new_state = locked.modseq;
        if rows.len() > max {
            has_more = true;
            let last = rows[max].modseq;
            if rows[0].modseq == last {
                // One change touched more objects than asked for: it is returned whole.
                rows = sqlx::query_as!(
                    Row,
                    "SELECT modseq, object_id, change FROM mail_changes
                     WHERE account_id = $1 AND object_type = $2 AND modseq = $3
                     ORDER BY object_id",
                    account,
                    object_type.as_str(),
                    last,
                )
                .fetch_all(&mut *tx)
                .await?;
                new_state = last;
            } else {
                rows.retain(|row| row.modseq < last);
                new_state = rows.last().map_or(since, |row| row.modseq);
            }
            has_more = has_more && new_state < locked.modseq;
        }
        tx.commit().await?;

        // First and last change of each object in the range.
        let mut seen: BTreeMap<Uuid, (String, String)> = BTreeMap::new();
        for row in rows {
            seen.entry(row.object_id)
                .and_modify(|(_, last)| last.clone_from(&row.change))
                .or_insert((row.change.clone(), row.change));
        }
        let mut changes = Changes {
            old_state: since as u64,
            new_state: new_state as u64,
            has_more_changes: has_more,
            ..Changes::default()
        };
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

    /// Removes up to `limit` journal rows written before `before` and raises each account's floor past them;
    /// returns how many went. For the worker.
    pub async fn prune_changes(&self, before: DateTime<Utc>, limit: i64) -> Result<u64> {
        let pruned = sqlx::query_scalar!(
            r#"WITH gone AS (
                   DELETE FROM mail_changes WHERE (account_id, object_type, modseq, object_id) IN (
                       SELECT account_id, object_type, modseq, object_id FROM mail_changes
                       WHERE changed_at < $1 ORDER BY changed_at LIMIT $2)
                   RETURNING account_id, modseq),
               floors AS (
                   UPDATE mail_accounts m SET changes_floor = greatest(m.changes_floor, g.modseq)
                   FROM (SELECT account_id, max(modseq) AS modseq FROM gone GROUP BY account_id) g
                   WHERE m.account_id = g.account_id
                   RETURNING 1)
               SELECT count(*) AS "count!" FROM gone"#,
            before,
            limit,
        )
        .fetch_one(&self.pool)
        .await?;
        // Expunged UIDs go with the journal: a client away longer than that starts over anyway.
        sqlx::query!("DELETE FROM mailbox_expunged WHERE expunged_at < $1", before).execute(&self.pool).await?;
        Ok(pruned as u64)
    }
}

/// A journal row.
struct Row {
    modseq: i64,
    object_id: Uuid,
    change: String,
}
