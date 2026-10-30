// SPDX-License-Identifier: AGPL-3.0-or-later
//! Events and tasks (RFC 0004, 4): one iCalendar object per resource, sealed, with its index.

use chrono::{DateTime, Utc};
use kernoid_mail::StoreChange;
use sqlx::postgres::types::PgRange;
use uuid::Uuid;

use crate::{
    Expect, Groupware, GroupwareError, Result,
    changes::{self, Change, Entry, ObjectType},
    check_resource_name, event_path,
    ical::{self, ParsedEvent},
    resource_name,
};

/// An event as listed: everything but its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventInfo {
    pub id: Uuid,
    pub account: Uuid,
    pub calendar: Uuid,
    pub resource_name: String,
    pub uid: String,
    pub component: String,
    pub organized: bool,
    pub size: i64,
    pub schedule_tag: i64,
    /// The modification sequence of its last change: its ETag.
    pub modseq: i64,
}

/// What became of a write by resource name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub event: EventInfo,
    pub created: bool,
}

struct Row {
    id: Uuid,
    calendar_id: Uuid,
    resource_name: String,
    uid: String,
    component: String,
    organized: bool,
    size: i64,
    schedule_tag: i64,
    modseq: i64,
}

impl Row {
    fn info(self, account: Uuid) -> EventInfo {
        EventInfo {
            id: self.id,
            account,
            calendar: self.calendar_id,
            resource_name: self.resource_name,
            uid: self.uid,
            component: self.component,
            organized: self.organized,
            size: self.size,
            schedule_tag: self.schedule_tag,
            modseq: self.modseq,
        }
    }
}

fn range(span: Option<(DateTime<Utc>, Option<DateTime<Utc>>)>) -> Option<PgRange<DateTime<Utc>>> {
    use std::ops::Bound;
    span.map(|(start, end)| PgRange {
        start: Bound::Included(start),
        end: end.map_or(Bound::Unbounded, Bound::Included),
    })
}

/// Whether the account organizes the event: the organizer is one of its addresses, or there is none.
async fn organized(change: &mut StoreChange, organizer: Option<&str>) -> Result<bool> {
    let Some(organizer) = organizer else { return Ok(false) };
    let own = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!" FROM addresses WHERE account_id = $1 AND lower(address) = $2"#,
        change.account(),
        organizer,
    )
    .fetch_optional(change.connection())
    .await?;
    Ok(own.is_some())
}

impl Groupware {
    /// The events of a calendar.
    pub async fn events(&self, account: Uuid, calendar: Uuid) -> Result<Vec<EventInfo>> {
        let mut read = self.read(account).await?;
        let rows = sqlx::query_as!(
            Row,
            "SELECT id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq
             FROM calendar_events WHERE account_id = $1 AND calendar_id = $2 ORDER BY resource_name",
            account,
            calendar,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        Ok(rows.into_iter().map(|row| row.info(account)).collect())
    }

    /// The events of the account, or of one calendar, whose span meets `[start, end)` – candidates for a time
    /// range: recurring ones still have to be expanded.
    pub async fn events_between(
        &self,
        account: Uuid,
        calendar: Option<Uuid>,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Result<Vec<EventInfo>> {
        use std::ops::Bound;
        let window = PgRange {
            start: start.map_or(Bound::Unbounded, Bound::Included),
            end: end.map_or(Bound::Unbounded, Bound::Excluded),
        };
        let mut read = self.read(account).await?;
        let rows = sqlx::query_as!(
            Row,
            "SELECT id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq
             FROM calendar_events
             WHERE account_id = $1 AND ($2::uuid IS NULL OR calendar_id = $2) AND span && $3
             ORDER BY lower(span), id",
            account,
            calendar,
            window,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        Ok(rows.into_iter().map(|row| row.info(account)).collect())
    }

    /// Every event of the account with this UID (one per calendar at most).
    pub async fn events_by_uid(&self, account: Uuid, uid: &str) -> Result<Vec<EventInfo>> {
        let mut read = self.read(account).await?;
        let rows = sqlx::query_as!(
            Row,
            "SELECT id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq
             FROM calendar_events WHERE account_id = $1 AND uid = $2 ORDER BY id",
            account,
            uid,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        Ok(rows.into_iter().map(|row| row.info(account)).collect())
    }

    /// One event by id.
    pub async fn event(&self, account: Uuid, id: Uuid) -> Result<EventInfo> {
        let mut read = self.read(account).await?;
        let row = sqlx::query_as!(
            Row,
            "SELECT id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq
             FROM calendar_events WHERE account_id = $1 AND id = $2",
            account,
            id,
        )
        .fetch_optional(read.connection())
        .await?;
        read.finish().await?;
        row.map(|row| row.info(account)).ok_or(GroupwareError::NotFound("the event"))
    }

    /// One event by its resource name in a calendar.
    pub async fn event_by_name(&self, account: Uuid, calendar: Uuid, name: &str) -> Result<Option<EventInfo>> {
        let mut read = self.read(account).await?;
        let row = sqlx::query_as!(
            Row,
            "SELECT id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq
             FROM calendar_events WHERE account_id = $1 AND calendar_id = $2 AND resource_name = $3",
            account,
            calendar,
            name,
        )
        .fetch_optional(read.connection())
        .await?;
        read.finish().await?;
        Ok(row.map(|row| row.info(account)))
    }

    /// The iCalendar objects of events, opened; ids that are not the account's are left out.
    pub async fn event_data(&self, account: Uuid, ids: &[Uuid]) -> Result<Vec<(EventInfo, String)>> {
        let mut read = self.read(account).await?;
        let tenant = read.tenant();
        let rows = sqlx::query!(
            "SELECT id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq, data
             FROM calendar_events WHERE account_id = $1 AND id = ANY($2)",
            account,
            ids,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let text = self.open(tenant, &event_path(tenant, account, row.id), &row.data).await?;
            let info = Row {
                id: row.id,
                calendar_id: row.calendar_id,
                resource_name: row.resource_name,
                uid: row.uid,
                component: row.component,
                organized: row.organized,
                size: row.size,
                schedule_tag: row.schedule_tag,
                modseq: row.modseq,
            }
            .info(account);
            out.push((info, text));
        }
        Ok(out)
    }

    /// Stores an iCalendar object under `name` in a calendar (CalDAV `PUT`): creates the resource or replaces it.
    pub async fn put_event(
        &self,
        account: Uuid,
        calendar: Uuid,
        name: &str,
        text: &str,
        expect: Expect,
    ) -> Result<Written> {
        check_resource_name(name)?;
        let mut change = self.change(account).await?;
        let calendar_row = sqlx::query!(
            "SELECT timezone, components FROM calendars WHERE id = $1 AND account_id = $2",
            calendar,
            account
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the calendar"))?;
        let parsed = ical::parse_event(text, ical::time_zone(calendar_row.timezone.as_deref()))?;
        if !calendar_row.components.iter().any(|c| c == parsed.component) {
            return Err(GroupwareError::Invalid(format!("this calendar does not take {}", parsed.component)));
        }
        let existing = sqlx::query!(
            "SELECT id, modseq, size, uid FROM calendar_events WHERE calendar_id = $1 AND resource_name = $2 FOR UPDATE",
            calendar,
            name,
        )
        .fetch_optional(change.connection())
        .await?;
        match (expect, &existing) {
            (Expect::New, Some(_)) => return Err(GroupwareError::PreconditionFailed),
            (Expect::Version(version), Some(row)) if row.modseq != version => {
                return Err(GroupwareError::PreconditionFailed);
            }
            (Expect::Version(_), None) => return Err(GroupwareError::PreconditionFailed),
            _ => {}
        }
        let conflict = sqlx::query_scalar!(
            "SELECT resource_name FROM calendar_events WHERE calendar_id = $1 AND uid = $2 AND resource_name <> $3",
            calendar,
            parsed.uid,
            name,
        )
        .fetch_optional(change.connection())
        .await?;
        if let Some(other) = conflict {
            return Err(GroupwareError::UidConflict(other));
        }
        if let Some(row) = &existing
            && row.uid != parsed.uid
        {
            // RFC 4791, 5.3.2.1: a resource keeps its UID.
            return Err(GroupwareError::UidConflict(name.to_owned()));
        }
        let id = existing.as_ref().map_or_else(Uuid::now_v7, |row| row.id);
        let written = self.write(&mut change, calendar, id, name, text, &parsed, existing.map(|row| row.size)).await?;
        change.commit().await?;
        Ok(written)
    }

    /// Creates an event from an iCalendar object (JMAP `CalendarEvent/set`, scheduling): its resource name comes from
    /// its UID.
    pub async fn create_event(&self, account: Uuid, calendar: Uuid, text: &str) -> Result<EventInfo> {
        let mut change = self.change(account).await?;
        let timezone =
            sqlx::query_scalar!("SELECT timezone FROM calendars WHERE id = $1 AND account_id = $2", calendar, account)
                .fetch_optional(change.connection())
                .await?
                .ok_or(GroupwareError::NotFound("the calendar"))?;
        let parsed = ical::parse_event(text, ical::time_zone(timezone.as_deref()))?;
        let taken = sqlx::query_scalar!(
            "SELECT resource_name FROM calendar_events WHERE calendar_id = $1 AND uid = $2",
            calendar,
            parsed.uid,
        )
        .fetch_optional(change.connection())
        .await?;
        if let Some(other) = taken {
            return Err(GroupwareError::UidConflict(other));
        }
        let id = Uuid::now_v7();
        let mut name = resource_name(&parsed.uid, id, "ics");
        let name_taken = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM calendar_events WHERE calendar_id = $1 AND resource_name = $2",
            calendar,
            name,
        )
        .fetch_optional(change.connection())
        .await?;
        if name_taken.is_some() {
            name = format!("{id}.ics");
        }
        let written = self.write(&mut change, calendar, id, &name, text, &parsed, None).await?;
        change.commit().await?;
        Ok(written.event)
    }

    /// Replaces the content of an event, keeping where it is (JMAP `CalendarEvent/set` update, scheduling). The UID
    /// must stay; `bump_schedule_tag` when scheduling changed it (RFC 6638, 3.2).
    pub async fn replace_event(
        &self,
        account: Uuid,
        id: Uuid,
        text: &str,
        bump_schedule_tag: bool,
    ) -> Result<EventInfo> {
        let mut change = self.change(account).await?;
        let row = sqlx::query!(
            "SELECT e.calendar_id, e.resource_name, e.uid, e.size, c.timezone
             FROM calendar_events e JOIN calendars c ON c.id = e.calendar_id
             WHERE e.id = $1 AND e.account_id = $2 FOR UPDATE OF e",
            id,
            account,
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the event"))?;
        let parsed = ical::parse_event(text, ical::time_zone(row.timezone.as_deref()))?;
        if parsed.uid != row.uid {
            return Err(GroupwareError::Invalid("an event keeps its UID".into()));
        }
        let mut written =
            self.write(&mut change, row.calendar_id, id, &row.resource_name, text, &parsed, Some(row.size)).await?;
        if bump_schedule_tag {
            written.event.schedule_tag = sqlx::query_scalar!(
                "UPDATE calendar_events SET schedule_tag = schedule_tag + 1 WHERE id = $1 RETURNING schedule_tag",
                id
            )
            .fetch_one(change.connection())
            .await?;
        }
        change.commit().await?;
        Ok(written.event)
    }

    /// Writes an event's row and journal in a change.
    #[allow(clippy::too_many_arguments)]
    async fn write(
        &self,
        change: &mut StoreChange,
        calendar: Uuid,
        id: Uuid,
        name: &str,
        text: &str,
        parsed: &ParsedEvent,
        old_size: Option<i64>,
    ) -> Result<Written> {
        let account = change.account();
        let tenant = change.tenant();
        crate::sealed::refuse_plain(change.connection(), calendar).await?;
        let size = text.len() as i64;
        change.charge(size - old_size.unwrap_or(0)).await?;
        let modseq = change.next_modseq().await?;
        let sealed = self.seal(tenant, &event_path(tenant, account, id), text).await?;
        let organized = organized(change, parsed.organizer.as_deref()).await?;
        let row = sqlx::query_as!(
            Row,
            "INSERT INTO calendar_events
                 (id, account_id, calendar_id, resource_name, uid, component, span, organized, data, size, modseq)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (id) DO UPDATE SET span = excluded.span, organized = excluded.organized,
                 data = excluded.data, size = excluded.size, modseq = excluded.modseq
             RETURNING id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq",
            id,
            account,
            calendar,
            name,
            parsed.uid,
            parsed.component,
            range(parsed.span),
            organized,
            sealed,
            size,
            modseq,
        )
        .fetch_one(change.connection())
        .await?;
        let created = old_size.is_none();
        let entry = Entry {
            object_type: ObjectType::Event,
            id,
            collection: Some(calendar),
            resource_name: Some(name),
            change: if created { Change::Created } else { Change::Updated },
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        Ok(Written { event: row.info(account), created })
    }

    /// Destroys an event (CalDAV `DELETE`, JMAP destroy).
    pub async fn destroy_event(&self, account: Uuid, id: Uuid, expect: Expect) -> Result<EventInfo> {
        let mut change = self.change(account).await?;
        let row = sqlx::query_as!(
            Row,
            "DELETE FROM calendar_events WHERE id = $1 AND account_id = $2
             RETURNING id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq",
            id,
            account,
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the event"))?;
        if let Expect::Version(version) = expect
            && version != row.modseq
        {
            return Err(GroupwareError::PreconditionFailed);
        }
        let modseq = change.next_modseq().await?;
        let entry = Entry {
            object_type: ObjectType::Event,
            id,
            collection: Some(row.calendar_id),
            resource_name: Some(&row.resource_name),
            change: Change::Destroyed,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.charge(-row.size).await?;
        change.commit().await?;
        Ok(row.info(account))
    }

    /// Moves an event to another calendar of the account, under `name` there (CalDAV `MOVE`, JMAP `calendarIds`).
    pub async fn move_event(&self, account: Uuid, id: Uuid, to: Uuid, name: Option<&str>) -> Result<EventInfo> {
        if let Some(name) = name {
            check_resource_name(name)?;
        }
        let mut change = self.change(account).await?;
        let row = sqlx::query!(
            "SELECT calendar_id, resource_name, uid FROM calendar_events WHERE id = $1 AND account_id = $2 FOR UPDATE",
            id,
            account
        )
        .fetch_optional(change.connection())
        .await?
        .ok_or(GroupwareError::NotFound("the event"))?;
        let target =
            sqlx::query_scalar!("SELECT 1 AS \"one!\" FROM calendars WHERE id = $1 AND account_id = $2", to, account)
                .fetch_optional(change.connection())
                .await?;
        if target.is_none() {
            return Err(GroupwareError::NotFound("the calendar"));
        }
        let name = name.unwrap_or(&row.resource_name).to_owned();
        let clash = sqlx::query_scalar!(
            "SELECT id FROM calendar_events WHERE calendar_id = $1 AND (resource_name = $2 OR uid = $3) AND id <> $4",
            to,
            name,
            row.uid,
            id,
        )
        .fetch_optional(change.connection())
        .await?;
        if clash.is_some() {
            return Err(GroupwareError::PreconditionFailed);
        }
        // DAV sees a removal from one collection and a new resource in the other – two modification sequences, since
        // the journal has one row per object and sequence; JMAP sees an update.
        let left = change.next_modseq().await?;
        let gone = Entry {
            object_type: ObjectType::Event,
            id,
            collection: Some(row.calendar_id),
            resource_name: Some(&row.resource_name),
            change: Change::Destroyed,
        };
        changes::record(change.connection(), account, left, gone).await?;
        let modseq = change.next_modseq().await?;
        let moved = sqlx::query_as!(
            Row,
            "UPDATE calendar_events SET calendar_id = $3, resource_name = $4, modseq = $5 WHERE id = $1 AND account_id = $2
             RETURNING id, calendar_id, resource_name, uid, component, organized, size, schedule_tag, modseq",
            id,
            account,
            to,
            name,
            modseq,
        )
        .fetch_one(change.connection())
        .await?;
        let arrived = Entry {
            object_type: ObjectType::Event,
            id,
            collection: Some(to),
            resource_name: Some(&name),
            change: Change::Created,
        };
        changes::record(change.connection(), account, modseq, arrived).await?;
        change.commit().await?;
        Ok(moved.info(account))
    }
}
