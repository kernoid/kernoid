// SPDX-License-Identifier: AGPL-3.0-or-later
//! Calendars (RFC 0004, 4): collections of events, one of them the account's default.

use kernoid_mail::StoreChange;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    Groupware, GroupwareError, Result,
    changes::{self, Change, Entry, ObjectType},
    check_collection_name,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CalendarInfo {
    pub id: Uuid,
    pub account: Uuid,
    /// Its name in the account's home (DAV).
    pub resource_name: String,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
    pub sort_order: i64,
    pub timezone: Option<String>,
    /// `VEVENT`, `VTODO`.
    pub components: Vec<String>,
    pub is_default: bool,
    pub is_subscribed: bool,
    pub is_visible: bool,
    /// Properties clients set that kernoid does not know (WebDAV dead properties), as JSON.
    pub dead_properties: serde_json::Value,
    /// The modification sequence of the last change of one of its events or of itself (`getctag`).
    pub modseq: i64,
    /// Encrypted (RFC 0006, 7): the collection's public key; its entries are the members' apps' (`sealed`).
    pub collection_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct NewCalendar {
    /// Its name in the account's home; the id if none.
    pub resource_name: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
    pub sort_order: i64,
    pub timezone: Option<String>,
    /// Empty: events and tasks.
    pub components: Vec<String>,
    pub is_default: bool,
}

/// What changes; `None` keeps a value, `Some(None)` clears an optional one.
#[derive(Debug, Clone, Default)]
pub struct CalendarUpdate {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub color: Option<Option<String>>,
    pub sort_order: Option<i64>,
    pub timezone: Option<Option<String>>,
    pub is_default: Option<bool>,
    pub is_subscribed: Option<bool>,
    pub is_visible: Option<bool>,
}

fn check_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
        return Err(GroupwareError::Invalid("a name has 1 to 255 characters, none of them control characters".into()));
    }
    Ok(())
}

fn check_timezone(timezone: Option<&str>) -> Result<()> {
    match timezone {
        Some(name) if name.parse::<chrono_tz::Tz>().is_err() => {
            Err(GroupwareError::Invalid(format!("{name} is not a known time zone")))
        }
        _ => Ok(()),
    }
}

fn check_components(components: &[String]) -> Result<Vec<String>> {
    if components.is_empty() {
        return Ok(vec!["VEVENT".into(), "VTODO".into()]);
    }
    let mut list: Vec<String> = components.iter().map(|c| c.to_ascii_uppercase()).collect();
    list.sort();
    list.dedup();
    if list.iter().any(|c| !matches!(c.as_str(), "VEVENT" | "VTODO" | "VJOURNAL")) {
        return Err(GroupwareError::Invalid("a calendar takes VEVENT, VTODO or VJOURNAL".into()));
    }
    Ok(list)
}

/// Creates the default calendar in a change that has just made the account's groupware.
pub(crate) async fn create_default(change: &mut StoreChange, name: &str) -> Result<()> {
    let new = NewCalendar { name: name.into(), is_default: true, ..NewCalendar::default() };
    insert(change, Uuid::now_v7(), &new).await
}

async fn insert(change: &mut StoreChange, id: Uuid, new: &NewCalendar) -> Result<()> {
    let modseq = change.next_modseq().await?;
    let account = change.account();
    let components = check_components(&new.components)?;
    let resource_name = new.resource_name.clone().unwrap_or_else(|| id.to_string());
    if new.is_default {
        sqlx::query!("UPDATE calendars SET is_default = false WHERE account_id = $1 AND is_default", account)
            .execute(change.connection())
            .await?;
    }
    sqlx::query!(
        "INSERT INTO calendars
             (id, account_id, resource_name, name, description, color, sort_order, timezone, components, is_default)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        id,
        account,
        resource_name,
        new.name,
        new.description,
        new.color,
        new.sort_order,
        new.timezone,
        &components,
        new.is_default,
    )
    .execute(change.connection())
    .await?;
    let entry =
        Entry { object_type: ObjectType::Calendar, id, collection: None, resource_name: None, change: Change::Created };
    changes::record(change.connection(), account, modseq, entry).await
}

impl Groupware {
    /// The account's calendars, by sort order and name.
    pub async fn calendars(&self, account: Uuid) -> Result<Vec<CalendarInfo>> {
        let mut read = self.read(account).await?;
        let rows = sqlx::query!(
            r#"SELECT c.id, c.resource_name, c.dead_properties, c.name, c.description, c.color, c.sort_order, c.timezone, c.components, c.is_default,
                      c.is_subscribed, c.is_visible, c.collection_key,
                      greatest((SELECT max(modseq) FROM groupware_changes g
                                WHERE g.account_id = c.account_id AND (g.object_id = c.id OR g.collection_id = c.id)), 0)
                          AS "modseq!"
               FROM calendars c WHERE c.account_id = $1 ORDER BY c.sort_order, c.name, c.id"#,
            account,
        )
        .fetch_all(read.connection())
        .await?;
        read.finish().await?;
        Ok(rows
            .into_iter()
            .map(|row| CalendarInfo {
                id: row.id,
                account,
                resource_name: row.resource_name,
                dead_properties: row.dead_properties,
                name: row.name,
                description: row.description,
                color: row.color,
                sort_order: row.sort_order,
                timezone: row.timezone,
                components: row.components,
                is_default: row.is_default,
                is_subscribed: row.is_subscribed,
                is_visible: row.is_visible,
                modseq: row.modseq,
                collection_key: row.collection_key,
            })
            .collect())
    }

    pub async fn calendar(&self, account: Uuid, id: Uuid) -> Result<CalendarInfo> {
        self.calendars(account)
            .await?
            .into_iter()
            .find(|calendar| calendar.id == id)
            .ok_or(GroupwareError::NotFound("the calendar"))
    }

    /// The account's default calendar, where invitations land (RFC 0004, 7).
    pub async fn default_calendar(&self, account: Uuid) -> Result<CalendarInfo> {
        self.calendars(account)
            .await?
            .into_iter()
            .find(|calendar| calendar.is_default)
            .ok_or(GroupwareError::NotFound("the default calendar"))
    }

    /// The calendar with this name in the account's home (CalDAV).
    pub async fn calendar_by_name(&self, account: Uuid, name: &str) -> Result<Option<CalendarInfo>> {
        Ok(self.calendars(account).await?.into_iter().find(|calendar| calendar.resource_name == name))
    }

    /// Creates a calendar; CalDAV's `MKCALENDAR` names it with `new.resource_name`.
    pub async fn create_calendar(&self, account: Uuid, new: NewCalendar) -> Result<Uuid> {
        check_name(&new.name)?;
        check_timezone(new.timezone.as_deref())?;
        if let Some(name) = &new.resource_name {
            check_collection_name(name)?;
        }
        let id = Uuid::now_v7();
        let mut change = self.change(account).await?;
        let taken = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM calendars WHERE account_id = $1 AND resource_name = $2",
            account,
            new.resource_name.clone().unwrap_or_else(|| id.to_string()),
        )
        .fetch_optional(change.connection())
        .await?;
        if taken.is_some() {
            return Err(GroupwareError::PreconditionFailed);
        }
        insert(&mut change, id, &new).await?;
        change.commit().await?;
        Ok(id)
    }

    pub async fn update_calendar(&self, account: Uuid, id: Uuid, update: CalendarUpdate) -> Result<()> {
        if let Some(name) = &update.name {
            check_name(name)?;
        }
        if let Some(timezone) = &update.timezone {
            check_timezone(timezone.as_deref())?;
        }
        let mut change = self.change(account).await?;
        let current =
            sqlx::query!("SELECT is_default FROM calendars WHERE id = $1 AND account_id = $2 FOR UPDATE", id, account)
                .fetch_optional(change.connection())
                .await?
                .ok_or(GroupwareError::NotFound("the calendar"))?;
        if update.is_default == Some(false) && current.is_default {
            // Another calendar becomes the default by being set so; this one cannot just stop being it.
            return Err(GroupwareError::IsDefault);
        }
        let modseq = change.next_modseq().await?;
        if update.is_default == Some(true) && !current.is_default {
            sqlx::query!("UPDATE calendars SET is_default = false WHERE account_id = $1 AND is_default", account)
                .execute(change.connection())
                .await?;
        }
        sqlx::query!(
            "UPDATE calendars SET
                 name = coalesce($3, name),
                 description = CASE WHEN $4 THEN $5 ELSE description END,
                 color = CASE WHEN $6 THEN $7 ELSE color END,
                 sort_order = coalesce($8, sort_order),
                 timezone = CASE WHEN $9 THEN $10 ELSE timezone END,
                 is_default = coalesce($11, is_default),
                 is_subscribed = coalesce($12, is_subscribed),
                 is_visible = coalesce($13, is_visible)
             WHERE id = $1 AND account_id = $2",
            id,
            account,
            update.name,
            update.description.is_some(),
            update.description.flatten(),
            update.color.is_some(),
            update.color.flatten(),
            update.sort_order,
            update.timezone.is_some(),
            update.timezone.flatten(),
            update.is_default,
            update.is_subscribed,
            update.is_visible,
        )
        .execute(change.connection())
        .await?;
        let entry = Entry {
            object_type: ObjectType::Calendar,
            id,
            collection: None,
            resource_name: None,
            change: Change::Updated,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.commit().await?;
        Ok(())
    }

    /// Replaces the properties clients set that kernoid does not know (WebDAV `PROPPATCH`).
    pub async fn set_calendar_dead_properties(
        &self,
        account: Uuid,
        id: Uuid,
        properties: serde_json::Value,
    ) -> Result<()> {
        let mut change = self.change(account).await?;
        let modseq = change.next_modseq().await?;
        let updated = sqlx::query!(
            "UPDATE calendars SET dead_properties = $3 WHERE id = $1 AND account_id = $2",
            id,
            account,
            properties
        )
        .execute(change.connection())
        .await?;
        if updated.rows_affected() == 0 {
            return Err(GroupwareError::NotFound("the calendar"));
        }
        let entry = Entry {
            object_type: ObjectType::Calendar,
            id,
            collection: None,
            resource_name: None,
            change: Change::Updated,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.commit().await?;
        Ok(())
    }

    /// Destroys a calendar; with events in it only if `remove_events` (JMAP `onDestroyRemoveEvents`, DAV `DELETE`).
    /// The default calendar cannot be destroyed. Grants on it stay, without effect, until they are removed (RFC 0004,
    /// 9).
    pub async fn destroy_calendar(&self, account: Uuid, id: Uuid, remove_events: bool) -> Result<()> {
        let mut change = self.change(account).await?;
        let current =
            sqlx::query!("SELECT is_default FROM calendars WHERE id = $1 AND account_id = $2 FOR UPDATE", id, account)
                .fetch_optional(change.connection())
                .await?
                .ok_or(GroupwareError::NotFound("the calendar"))?;
        if current.is_default {
            return Err(GroupwareError::IsDefault);
        }
        let events = sqlx::query!(
            "SELECT id, resource_name, size FROM calendar_events WHERE calendar_id = $1 AND account_id = $2",
            id,
            account
        )
        .fetch_all(change.connection())
        .await?;
        let sealed = crate::sealed::sizes(change.connection(), id).await?;
        if (!events.is_empty() || !sealed.is_empty()) && !remove_events {
            return Err(GroupwareError::NotEmpty);
        }
        let modseq = change.next_modseq().await?;
        let mut freed: i64 = sealed.iter().sum();
        crate::sealed::remove_collection(change.connection(), id).await?;
        for event in &events {
            freed += event.size;
            let entry = Entry {
                object_type: ObjectType::Event,
                id: event.id,
                collection: Some(id),
                resource_name: Some(&event.resource_name),
                change: Change::Destroyed,
            };
            changes::record(change.connection(), account, modseq, entry).await?;
        }
        sqlx::query!("DELETE FROM calendar_events WHERE calendar_id = $1 AND account_id = $2", id, account)
            .execute(change.connection())
            .await?;
        sqlx::query!("DELETE FROM calendars WHERE id = $1 AND account_id = $2", id, account)
            .execute(change.connection())
            .await?;
        let entry = Entry {
            object_type: ObjectType::Calendar,
            id,
            collection: None,
            resource_name: None,
            change: Change::Destroyed,
        };
        changes::record(change.connection(), account, modseq, entry).await?;
        change.charge(-freed).await?;
        change.commit().await?;
        Ok(())
    }
}
