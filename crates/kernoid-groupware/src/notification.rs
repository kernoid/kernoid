// SPDX-License-Identifier: AGPL-3.0-or-later
//! Notifications (RFC 0004, 6): what scheduling changed in an account's events, for JMAP's
//! `CalendarEventNotification`; the iTIP message is kept sealed. They go after 30 days.

use calcard::icalendar::ICalendar;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    Groupware, GroupwareError, Result,
    changes::{self, Change, Entry, ObjectType},
};

/// A notification as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationInfo {
    pub id: Uuid,
    pub event: Option<Uuid>,
    /// `created`, `updated` or `destroyed`.
    pub kind: String,
    /// The address of who changed it.
    pub changed_by: String,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

fn path(tenant: Uuid, account: Uuid, id: Uuid) -> String {
    format!("tenants/{tenant}/calendar-notifications/{account}/{id}")
}

impl Groupware {
    /// Records that scheduling changed an event.
    pub(crate) async fn notify(
        &self,
        account: Uuid,
        event: Option<Uuid>,
        kind: &str,
        changed_by: &str,
        itip: &ICalendar,
    ) -> Result<Uuid> {
        let mut change = self.change(account).await?;
        let tenant = change.tenant();
        let id = Uuid::now_v7();
        let sealed = self.seal(tenant, &path(tenant, account, id), &itip.to_string()).await?;
        let modseq = change.next_modseq().await?;
        sqlx::query!(
            "INSERT INTO calendar_notifications (id, account_id, event_id, kind, changed_by, data)
             VALUES ($1, $2, $3, $4, $5, $6)",
            id,
            account,
            event,
            kind,
            serde_json::json!({ "calendarAddress": format!("mailto:{changed_by}") }),
            sealed,
        )
        .execute(change.connection())
        .await?;
        let entry = Entry {
            object_type: ObjectType::Notification,
            id,
            collection: None,
            resource_name: None,
            change: Change::Created,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.commit().await?;
        Ok(id)
    }

    /// The account's notifications, newest first.
    pub async fn notifications(&self, account: Uuid) -> Result<Vec<NotificationInfo>> {
        let rows = sqlx::query!(
            r#"SELECT id, event_id, kind, changed_by->>'calendarAddress' AS "changed_by", comment, created_at
               FROM calendar_notifications WHERE account_id = $1 ORDER BY created_at DESC, id DESC"#,
            account,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| NotificationInfo {
                id: row.id,
                event: row.event_id,
                kind: row.kind,
                changed_by: row.changed_by.unwrap_or_default().trim_start_matches("mailto:").to_owned(),
                comment: row.comment,
                created_at: row.created_at,
            })
            .collect())
    }

    /// The iTIP message of a notification, opened.
    pub async fn notification_data(&self, account: Uuid, id: Uuid) -> Result<String> {
        let row = sqlx::query!(
            "SELECT n.data, m.tenant_id FROM calendar_notifications n JOIN mail_accounts m ON m.account_id = n.account_id
             WHERE n.id = $1 AND n.account_id = $2",
            id,
            account
        )
        .fetch_optional(self.pool())
        .await?
        .ok_or(GroupwareError::NotFound("the notification"))?;
        self.open(row.tenant_id, &path(row.tenant_id, account, id), &row.data).await
    }

    /// Destroys a notification (JMAP `CalendarEventNotification/set`).
    pub async fn destroy_notification(&self, account: Uuid, id: Uuid) -> Result<()> {
        let mut change = self.change(account).await?;
        let gone = sqlx::query!("DELETE FROM calendar_notifications WHERE id = $1 AND account_id = $2", id, account)
            .execute(change.connection())
            .await?;
        if gone.rows_affected() == 0 {
            return Err(GroupwareError::NotFound("the notification"));
        }
        let modseq = change.next_modseq().await?;
        let entry = Entry {
            object_type: ObjectType::Notification,
            id,
            collection: None,
            resource_name: None,
            change: Change::Destroyed,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.commit().await?;
        Ok(())
    }
}

/// Removes notifications older than 30 days (RFC 0004, 6); returns how many went. For the worker.
pub async fn prune_notifications(pool: &kernoid_store::PgPool, limit: i64) -> Result<u64> {
    let gone = sqlx::query!(
        "DELETE FROM calendar_notifications WHERE id IN (
             SELECT id FROM calendar_notifications WHERE created_at < now() - interval '30 days' LIMIT $1)",
        limit
    )
    .execute(pool)
    .await?;
    Ok(gone.rows_affected())
}
