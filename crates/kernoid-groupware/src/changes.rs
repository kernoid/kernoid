// SPDX-License-Identifier: AGPL-3.0-or-later
//! The journal of calendars and contacts (RFC 0004, 2): one row per changed object and modification sequence, with
//! its collection and resource name, read by JMAP's `*/changes` and by DAV's `sync-collection`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use kernoid_store::PgPool;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Changes, Groupware, GroupwareError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Calendar,
    Event,
    Notification,
    AddressBook,
    Contact,
}

impl ObjectType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Calendar => "calendar",
            Self::Event => "event",
            Self::Notification => "notification",
            Self::AddressBook => "addressbook",
            Self::Contact => "contact",
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

/// A row of the journal to write.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry<'a> {
    pub object_type: ObjectType,
    pub id: Uuid,
    pub collection: Option<Uuid>,
    pub resource_name: Option<&'a str>,
    pub change: Change,
}

/// Writes that an object changed at `modseq`. An object changed twice in one modification sequence keeps its first
/// entry.
pub(crate) async fn record(connection: &mut PgConnection, account: Uuid, modseq: i64, entry: Entry<'_>) -> Result<()> {
    sqlx::query!(
        "INSERT INTO groupware_changes (account_id, modseq, object_type, object_id, collection_id, resource_name, change)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (account_id, object_type, modseq, object_id) DO NOTHING",
        account,
        modseq,
        entry.object_type.as_str(),
        entry.id,
        entry.collection,
        entry.resource_name,
        entry.change.as_str(),
    )
    .execute(connection)
    .await?;
    Ok(())
}

/// What changed in one collection since a sync token, as DAV's `sync-collection` answers (RFC 6578).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sync {
    pub token: i64,
    /// Resources created or changed: their names.
    pub changed: Vec<String>,
    /// Resources gone or moved away: their names.
    pub removed: Vec<String>,
}

/// Most journal rows read at once when the caller sets no maximum.
const DEFAULT_MAX: usize = 5000;

impl Groupware {
    /// The objects of `object_type` that changed after `since`, at most about `max` of them: a modification
    /// sequence is never split.
    pub async fn changes(
        &self,
        account: Uuid,
        object_type: ObjectType,
        since: i64,
        max: Option<usize>,
    ) -> Result<Changes> {
        let max = max.unwrap_or(DEFAULT_MAX).clamp(1, DEFAULT_MAX);
        let mut read = self.read(account).await?;
        let state = read.modseq();
        let floor = read.changes_floor().await?;
        if since < floor || since > state {
            return Err(GroupwareError::CannotCalculateChanges);
        }
        let mut rows = sqlx::query!(
            "SELECT modseq, object_id, change FROM groupware_changes
             WHERE account_id = $1 AND object_type = $2 AND modseq > $3 AND modseq <= $4
             ORDER BY modseq, object_id LIMIT $5",
            account,
            object_type.as_str(),
            since,
            state,
            (max + 1) as i64,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        let mut has_more = false;
        let mut new_state = state;
        if rows.len() > max {
            // Stop before the last modification sequence read, which may be incomplete – unless it is the only one.
            let last = rows[max].modseq;
            let first = rows[0].modseq;
            if last != first {
                rows.retain(|row| row.modseq < last);
                new_state = last - 1;
                has_more = true;
            }
        }
        let mut seen: BTreeMap<Uuid, (String, String)> = BTreeMap::new();
        for row in rows {
            seen.entry(row.object_id)
                .and_modify(|(_, last)| *last = row.change.clone())
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

    /// The resources of `collection` (a calendar or address book of `account`) that changed after `since`; `since`
    /// 0 lists everything there is. RFC 6578's token is the account's modification sequence.
    pub async fn sync(&self, account: Uuid, collection: Uuid, since: i64) -> Result<Sync> {
        let mut read = self.read(account).await?;
        let state = read.modseq();
        if since == 0 {
            let changed = sqlx::query_scalar!(
                r#"SELECT resource_name AS "resource_name!" FROM calendar_events WHERE account_id = $1 AND calendar_id = $2
                   UNION ALL
                   SELECT resource_name FROM contacts WHERE account_id = $1 AND addressbook_id = $2"#,
                account,
                collection,
            )
            .fetch_all(read.connection())
            .await?;
            read.finish().await?;
            return Ok(Sync { token: state, changed, removed: Vec::new() });
        }
        let floor = read.changes_floor().await?;
        if since < floor || since > state {
            return Err(GroupwareError::CannotCalculateChanges);
        }
        let rows = sqlx::query!(
            r#"SELECT resource_name AS "resource_name!", change FROM groupware_changes
               WHERE account_id = $1 AND collection_id = $2 AND modseq > $3 AND modseq <= $4
                 AND object_type IN ('event', 'contact') AND resource_name IS NOT NULL
               ORDER BY modseq"#,
            account,
            collection,
            since,
            state,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        // The last change of each name counts: created then destroyed is removed, destroyed then created is changed.
        let mut last: BTreeMap<String, String> = BTreeMap::new();
        for row in rows {
            last.insert(row.resource_name, row.change);
        }
        let mut sync = Sync { token: state, ..Sync::default() };
        for (name, change) in last {
            if change == "destroyed" { sync.removed.push(name) } else { sync.changed.push(name) }
        }
        Ok(sync)
    }
}

/// Removes up to `limit` journal rows written before `before` and raises each account's floor past them;
/// returns how many went. For the worker, beside the mail journal's pruning.
pub async fn prune_changes(pool: &PgPool, before: DateTime<Utc>, limit: i64) -> Result<u64> {
    let pruned = sqlx::query_scalar!(
        r#"WITH gone AS (
               DELETE FROM groupware_changes WHERE (account_id, object_type, modseq, object_id) IN (
                   SELECT account_id, object_type, modseq, object_id FROM groupware_changes
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
    .fetch_one(pool)
    .await?;
    Ok(pruned as u64)
}
