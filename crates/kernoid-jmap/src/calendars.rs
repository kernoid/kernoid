// SPDX-License-Identifier: AGPL-3.0-or-later
//! JMAP for Calendars (draft-ietf-jmap-calendars; RFC 0004, 8.2): `Calendar/get`, `/changes`, `/set`;
//! `CalendarEvent/get`, `/changes`, `/query`, `/set`, `/parse`; `CalendarEventNotification/get`, `/changes`, `/set`;
//! `ParticipantIdentity/get`. Events are stored as iCalendar and shown as JSCalendar (`js`).
//!
//! `CalendarEvent/query` with `expandRecurrences` returns one id per instance – `<event id>.<Unix start>` – that
//! `CalendarEvent/get` answers with the instance: the event's properties, its override applied, `recurrenceId` and
//! `baseEventId` set. Instances are read-only (OPEN: changing one instance through JMAP).

use std::collections::HashMap;

use calcard::{Entry, Parser, common::timezone::Tz};
use chrono::{DateTime, TimeZone, Utc};
use kernoid_groupware::{CalendarInfo, CalendarUpdate, CollectionAccess, Expect, Level, NewCalendar, ical};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    MAX_OBJECTS_IN_GET, js,
    mailbox::{ids, invalid_properties, properties},
    request::{Context, MethodError, MethodResult},
};

fn forbidden(description: &str) -> Value {
    json!({ "type": "forbidden", "description": description })
}

const CALENDAR_PROPERTIES: [&str; 12] = [
    "id",
    "name",
    "description",
    "color",
    "sortOrder",
    "isSubscribed",
    "isVisible",
    "isDefault",
    "includeInAvailability",
    "timeZone",
    "shareWith",
    "myRights",
];

fn calendar_rights(access: &CollectionAccess, calendar: Uuid) -> Value {
    let level = access.level(calendar);
    let at_least = |wanted: Level| level.is_some_and(|level| level >= wanted);
    json!({
        "mayReadFreeBusy": at_least(Level::Freebusy),
        "mayReadItems": at_least(Level::Read),
        "mayWriteAll": at_least(Level::Write),
        "mayWriteOwn": at_least(Level::Write),
        "mayUpdatePrivate": at_least(Level::Write),
        "mayRSVP": at_least(Level::Rsvp),
        "mayAdmin": at_least(Level::Admin),
        "mayDelete": access.owned,
    })
}

fn calendar_object(calendar: &CalendarInfo, access: &CollectionAccess, properties: &[String]) -> Value {
    let mut out = Map::new();
    for property in properties {
        let value = match property.as_str() {
            "name" => json!(calendar.name),
            "description" => json!(calendar.description),
            "color" => json!(calendar.color),
            "sortOrder" => json!(calendar.sort_order),
            "isSubscribed" => json!(calendar.is_subscribed),
            "isVisible" => json!(calendar.is_visible),
            "isDefault" => json!(calendar.is_default && access.owned),
            "includeInAvailability" => json!(if access.owned { "all" } else { "none" }),
            "timeZone" => json!(calendar.timezone),
            "shareWith" => Value::Null,
            "myRights" => calendar_rights(access, calendar.id),
            _ => continue,
        };
        out.insert(property.clone(), value);
    }
    out.insert("id".into(), json!(calendar.id.to_string()));
    Value::Object(out)
}

/// An instance id: the event's id and the instance's start in seconds since 1970.
fn instance_id(event: Uuid, start: i64) -> String {
    format!("{event}.{start}")
}

fn parse_instance_id(id: &str) -> Option<(Uuid, i64)> {
    let (event, start) = id.split_once('.')?;
    Some((Uuid::parse_str(event).ok()?, start.parse().ok()?))
}

/// A UTC time as JMAP's `UTCDateTime`.
fn utc(timestamp: i64) -> Value {
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .map_or(Value::Null, |time| json!(time.format("%Y-%m-%dT%H:%M:%SZ").to_string()))
}

/// A UTC time as a JSCalendar `LocalDateTime` in the event's time zone.
fn local(timestamp: i64, time_zone: Option<&str>) -> String {
    let utc = Utc.timestamp_opt(timestamp, 0).single().unwrap_or_default();
    match time_zone.and_then(|name| name.parse::<chrono_tz::Tz>().ok()) {
        Some(zone) => utc.with_timezone(&zone).format("%Y-%m-%dT%H:%M:%S").to_string(),
        None => utc.format("%Y-%m-%dT%H:%M:%S").to_string(),
    }
}

/// The instances of an iCalendar object as (start, end) in seconds since 1970, in a time window.
fn instances(text: &str, default_tz: Tz, after: Option<i64>, before: Option<i64>) -> Vec<(i64, i64)> {
    let Entry::ICalendar(parsed) = Parser::new(text).entry() else { return Vec::new() };
    let expanded = parsed.expand_dates(ical::expansion_tz(&parsed, default_tz), ical::MAX_INSTANCES);
    let mut out: Vec<(i64, i64)> = expanded
        .events
        .into_iter()
        .map(|event| {
            let start = event.start.timestamp();
            let end = match event.end {
                calcard::icalendar::dates::TimeOrDelta::Time(end) => end.timestamp(),
                calcard::icalendar::dates::TimeOrDelta::Delta(delta) => start + delta.num_seconds(),
            };
            (start, end.max(start))
        })
        .filter(|(start, end)| after.is_none_or(|after| *end > after) && before.is_none_or(|before| *start < before))
        .collect();
    out.sort_unstable();
    out
}

fn parse_utc(value: Option<&Value>) -> Result<Option<i64>, MethodError> {
    match value.and_then(Value::as_str) {
        None => Ok(None),
        Some(text) => DateTime::parse_from_rfc3339(text)
            .map(|time| Some(time.timestamp()))
            .map_err(|_| MethodError::invalid(format!("{text} is not a UTCDateTime"))),
    }
}

impl Context<'_> {
    pub async fn calendar_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let state = groupware.state(owner).await?;
        let properties = properties(&args, "properties", &CALENDAR_PROPERTIES);
        let calendars: Vec<CalendarInfo> = groupware
            .calendars(owner)
            .await?
            .into_iter()
            .filter(|calendar| access.allows(calendar.id, Level::Freebusy))
            .collect();
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        match ids(&args)? {
            None => list.extend(calendars.iter().map(|calendar| calendar_object(calendar, &access, &properties))),
            Some(wanted) => {
                for id in wanted {
                    match calendars.iter().find(|calendar| calendar.id.to_string() == id) {
                        Some(calendar) => list.push(calendar_object(calendar, &access, &properties)),
                        None => not_found.push(id),
                    }
                }
            }
        }
        Ok(vec![(
            "Calendar/get".into(),
            json!({ "accountId": owner.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    pub async fn calendar_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?.clone();
        let old_state = groupware.state(owner).await?;
        crate::mailbox::if_in_state(&args, old_state as u64)?;
        let mut created = Map::new();
        let mut not_created = Map::new();
        let mut updated = Map::new();
        let mut not_updated = Map::new();
        let mut destroyed = Vec::new();
        let mut not_destroyed = Map::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for (creation, value) in create {
                if !access.owned {
                    not_created.insert(creation.clone(), forbidden("only the owner creates calendars"));
                    continue;
                }
                let Some(object) = value.as_object() else {
                    not_created.insert(creation.clone(), invalid_properties("an object"));
                    continue;
                };
                let Some(name) = object.get("name").and_then(Value::as_str) else {
                    not_created.insert(creation.clone(), invalid_properties("name is required"));
                    continue;
                };
                let new = NewCalendar {
                    resource_name: None,
                    name: name.to_owned(),
                    description: object.get("description").and_then(Value::as_str).map(str::to_owned),
                    color: object.get("color").and_then(Value::as_str).map(str::to_owned),
                    sort_order: object.get("sortOrder").and_then(Value::as_i64).unwrap_or(0),
                    timezone: object.get("timeZone").and_then(Value::as_str).map(str::to_owned),
                    components: Vec::new(),
                    is_default: false,
                };
                match groupware.create_calendar(owner, new).await {
                    Ok(id) => {
                        self.created.insert(creation.clone(), id.to_string());
                        created.insert(creation.clone(), json!({ "id": id.to_string(), "isDefault": false }));
                    }
                    Err(error) => {
                        not_created.insert(creation.clone(), crate::contacts::set_error(&error));
                    }
                }
            }
        }
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, value) in update {
                let Some(calendar) = self.id(id) else {
                    not_updated.insert(id.clone(), json!({ "type": "notFound" }));
                    continue;
                };
                let Some(patch) = value.as_object() else {
                    not_updated.insert(id.clone(), invalid_properties("an object"));
                    continue;
                };
                // The display settings are the owner's; a grantee with admin changes the rest.
                let display_only = patch.keys().all(|key| matches!(key.as_str(), "isSubscribed" | "isVisible"));
                if !(access.allows(calendar, Level::Admin) || (display_only && access.owned)) {
                    not_updated.insert(id.clone(), forbidden("this needs the right to administer the calendar"));
                    continue;
                }
                let update = CalendarUpdate {
                    name: patch.get("name").and_then(Value::as_str).map(str::to_owned),
                    description: patch.get("description").map(|value| value.as_str().map(str::to_owned)),
                    color: patch.get("color").map(|value| value.as_str().map(str::to_owned)),
                    sort_order: patch.get("sortOrder").and_then(Value::as_i64),
                    timezone: patch.get("timeZone").map(|value| value.as_str().map(str::to_owned)),
                    is_default: patch.get("isDefault").and_then(Value::as_bool).filter(|_| access.owned),
                    is_subscribed: patch.get("isSubscribed").and_then(Value::as_bool),
                    is_visible: patch.get("isVisible").and_then(Value::as_bool),
                };
                match groupware.update_calendar(owner, calendar, update).await {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), crate::contacts::set_error(&error));
                    }
                }
            }
        }
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            let remove = args.get("onDestroyRemoveEvents").and_then(Value::as_bool).unwrap_or(false);
            for id in destroy.iter().filter_map(Value::as_str) {
                let Some(calendar) = self.id(id) else {
                    not_destroyed.insert(id.to_owned(), json!({ "type": "notFound" }));
                    continue;
                };
                if !access.owned {
                    not_destroyed.insert(id.to_owned(), forbidden("only the owner destroys calendars"));
                    continue;
                }
                match groupware.destroy_calendar(owner, calendar, remove).await {
                    Ok(()) => destroyed.push(id.to_owned()),
                    Err(kernoid_groupware::GroupwareError::NotEmpty) => {
                        not_destroyed.insert(id.to_owned(), json!({ "type": "calendarHasEvent" }));
                    }
                    Err(error) => {
                        not_destroyed.insert(id.to_owned(), crate::contacts::set_error(&error));
                    }
                }
            }
        }
        if let Some(target) = args.get("onSuccessSetIsDefault").and_then(Value::as_str)
            && access.owned
            && let Some(calendar) = self.id(target)
        {
            let _ = groupware
                .update_calendar(owner, calendar, CalendarUpdate { is_default: Some(true), ..Default::default() })
                .await;
        }
        let new_state = groupware.state(owner).await?;
        Ok(vec![(
            "Calendar/set".into(),
            json!({
                "accountId": owner.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": created, "notCreated": not_created,
                "updated": updated, "notUpdated": not_updated,
                "destroyed": destroyed, "notDestroyed": not_destroyed,
            }),
        )])
    }

    pub async fn event_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let state = groupware.state(owner).await?;
        let zones: HashMap<Uuid, Option<String>> =
            groupware.calendars(owner).await?.into_iter().map(|calendar| (calendar.id, calendar.timezone)).collect();
        let wanted = match ids(&args)? {
            Some(wanted) => {
                if wanted.len() > MAX_OBJECTS_IN_GET {
                    return Err(MethodError::new("requestTooLarge", "too many ids"));
                }
                wanted
            }
            None => {
                let mut all = Vec::new();
                for calendar in zones.keys().filter(|calendar| access.allows(**calendar, Level::Read)) {
                    all.extend(groupware.events(owner, *calendar).await?.into_iter().map(|event| event.id.to_string()));
                }
                all.truncate(MAX_OBJECTS_IN_GET);
                all
            }
        };
        let selected: Option<Vec<String>> = match args.get("properties") {
            Some(Value::Array(list)) => Some(list.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
            _ => None,
        };
        let bases: Vec<Uuid> = wanted
            .iter()
            .filter_map(|id| Uuid::parse_str(id).ok().or_else(|| parse_instance_id(id).map(|(event, _)| event)))
            .collect();
        let data: HashMap<Uuid, (kernoid_groupware::EventInfo, String)> = groupware
            .event_data(owner, &bases)
            .await?
            .into_iter()
            .map(|(event, text)| (event.id, (event, text)))
            .collect();
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        for id in wanted {
            let (base, instance) = match Uuid::parse_str(&id) {
                Ok(base) => (base, None),
                Err(_) => match parse_instance_id(&id) {
                    Some((base, start)) => (base, Some(start)),
                    None => {
                        not_found.push(id);
                        continue;
                    }
                },
            };
            let Some((event, text)) = data.get(&base).filter(|(event, _)| access.allows(event.calendar, Level::Read))
            else {
                not_found.push(id);
                continue;
            };
            let Some(mut object) = js::event_to_json(text) else {
                not_found.push(id);
                continue;
            };
            let zone = ical::time_zone(zones.get(&event.calendar).cloned().flatten().as_deref());
            let time_zone = object.get("timeZone").and_then(Value::as_str).map(str::to_owned);
            let found = instances(text, zone, None, None);
            match instance {
                Some(start) => {
                    let Some((_, end)) = found.iter().find(|(s, _)| *s == start).copied() else {
                        not_found.push(id);
                        continue;
                    };
                    let recurrence_id = local(start, time_zone.as_deref());
                    let override_patch = object
                        .get("recurrenceOverrides")
                        .and_then(Value::as_object)
                        .and_then(|overrides| overrides.get(&recurrence_id))
                        .and_then(Value::as_object)
                        .cloned();
                    for key in ["recurrenceRule", "recurrenceRules", "recurrenceOverrides", "excludedRecurrenceRules"] {
                        object.remove(key);
                    }
                    object.insert("start".into(), json!(recurrence_id));
                    if let Some(patch) = override_patch {
                        let _ = js::patch(&mut object, &patch);
                    }
                    object.insert("recurrenceId".into(), json!(recurrence_id));
                    object.insert("baseEventId".into(), json!(base.to_string()));
                    object.insert("utcStart".into(), utc(start));
                    object.insert("utcEnd".into(), utc(end));
                }
                None => {
                    if let Some((start, end)) = found.first() {
                        object.insert("utcStart".into(), utc(*start));
                        object.insert("utcEnd".into(), utc(*end));
                    }
                }
            }
            object.insert("id".into(), json!(id));
            object.insert("calendarIds".into(), json!({ event.calendar.to_string(): true }));
            object.insert("isDraft".into(), json!(false));
            object.insert("isOrigin".into(), json!(event.organized || !object.contains_key("participants")));
            if let Some(selected) = &selected {
                object.retain(|key, _| key == "id" || selected.iter().any(|wanted| wanted == key));
            }
            list.push(Value::Object(object));
        }
        Ok(vec![(
            "CalendarEvent/get".into(),
            json!({ "accountId": owner.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    pub async fn event_query(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let state = groupware.state(owner).await?;
        let filter = args.get("filter").and_then(Value::as_object).cloned().unwrap_or_default();
        let in_calendar = filter.get("inCalendar").and_then(Value::as_str).and_then(|id| Uuid::parse_str(id).ok());
        let after = parse_utc(filter.get("after"))?;
        let before = parse_utc(filter.get("before"))?;
        let text = filter.get("text").or_else(|| filter.get("title")).and_then(Value::as_str).map(str::to_lowercase);
        let uid = filter.get("uid").and_then(Value::as_str);
        let expand = args.get("expandRecurrences").and_then(Value::as_bool).unwrap_or(false);
        if expand && (after.is_none() || before.is_none()) {
            return Err(MethodError::invalid("expandRecurrences needs after and before"));
        }
        let zones: HashMap<Uuid, Option<String>> =
            groupware.calendars(owner).await?.into_iter().map(|calendar| (calendar.id, calendar.timezone)).collect();
        let candidates = groupware
            .events_between(
                owner,
                in_calendar,
                after.and_then(|after| DateTime::from_timestamp(after, 0)),
                before.and_then(|before| DateTime::from_timestamp(before, 0)),
            )
            .await?;
        let mut candidates: Vec<_> = candidates
            .into_iter()
            .filter(|event| access.allows(event.calendar, Level::Read))
            .filter(|event| uid.is_none_or(|uid| event.uid == uid))
            .collect();
        if after.is_none() && before.is_none() {
            // Events without times have no span: an unbounded query includes them too.
            let mut all = Vec::new();
            for calendar in zones.keys().filter(|calendar| in_calendar.is_none_or(|wanted| wanted == **calendar)) {
                all.extend(
                    groupware
                        .events(owner, *calendar)
                        .await?
                        .into_iter()
                        .filter(|event| access.allows(event.calendar, Level::Read))
                        .filter(|event| uid.is_none_or(|uid| event.uid == uid)),
                );
            }
            candidates = all;
        }
        let wanted: Vec<Uuid> = candidates.iter().map(|event| event.id).collect();
        let mut hits: Vec<(i64, String)> = Vec::new();
        for (event, text_data) in groupware.event_data(owner, &wanted).await? {
            if let Some(text) = &text
                && !text_data.to_lowercase().contains(text.as_str())
            {
                continue;
            }
            let zone = ical::time_zone(zones.get(&event.calendar).cloned().flatten().as_deref());
            let found = instances(&text_data, zone, after, before);
            if expand {
                hits.extend(found.into_iter().map(|(start, _)| (start, instance_id(event.id, start))));
            } else if after.is_none() && before.is_none() || !found.is_empty() {
                hits.push((found.first().map_or(i64::MIN, |(start, _)| *start), event.id.to_string()));
            }
        }
        hits.sort();
        let total = hits.len();
        let position = args.get("position").and_then(Value::as_i64).unwrap_or(0).max(0) as usize;
        let limit = args.get("limit").and_then(Value::as_u64).map_or(usize::MAX, |limit| limit as usize);
        let page: Vec<String> = hits.into_iter().skip(position).take(limit).map(|(_, id)| id).collect();
        Ok(vec![(
            "CalendarEvent/query".into(),
            json!({
                "accountId": owner.to_string(),
                "queryState": state.to_string(),
                "canCalculateChanges": false,
                "position": position,
                "ids": page,
                "total": total,
            }),
        )])
    }

    pub async fn event_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?.clone();
        let old_state = groupware.state(owner).await?;
        crate::mailbox::if_in_state(&args, old_state as u64)?;
        let schedule = args.get("sendSchedulingMessages").and_then(Value::as_bool).unwrap_or(false);
        let default_calendar = groupware.calendars(owner).await?.into_iter().find(|c| c.is_default).map(|c| c.id);
        let mut created = Map::new();
        let mut not_created = Map::new();
        let mut updated = Map::new();
        let mut not_updated = Map::new();
        let mut destroyed = Vec::new();
        let mut not_destroyed = Map::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for (creation, value) in create {
                let result: Result<(Uuid, String), Value> = async {
                    let mut object = value.as_object().cloned().ok_or_else(|| invalid_properties("an object"))?;
                    let calendar = match object.remove("calendarIds") {
                        Some(Value::Object(calendars)) if calendars.len() == 1 => {
                            calendars.keys().next().and_then(|id| self.id(id))
                        }
                        None => default_calendar,
                        _ => return Err(invalid_properties("one calendar per event")),
                    };
                    let calendar = calendar
                        .filter(|calendar| access.allows(*calendar, Level::Write))
                        .ok_or_else(|| forbidden("the calendar may not be written"))?;
                    for key in ["id", "isDraft", "isOrigin", "utcStart", "utcEnd", "baseEventId"] {
                        object.remove(key);
                    }
                    object.entry("@type").or_insert(json!("Event"));
                    object.entry("uid").or_insert_with(|| json!(format!("{}@kernoid", Uuid::now_v7())));
                    let text = js::json_to_event(&object).map_err(invalid_properties)?;
                    let uid = object.get("uid").and_then(Value::as_str).unwrap_or_default().to_owned();
                    let event = if schedule {
                        let name = kernoid_groupware::resource_name(&uid, Uuid::now_v7(), "ics");
                        match groupware
                            .put_event_scheduled(owner, calendar, &name, &text, Expect::New)
                            .await
                            .map_err(|error| crate::contacts::set_error(&error))?
                        {
                            Ok(scheduled) => scheduled.written.event,
                            Err(_) => return Err(forbidden("scheduling refused the change")),
                        }
                    } else {
                        groupware
                            .create_event(owner, calendar, &text)
                            .await
                            .map_err(|error| crate::contacts::set_error(&error))?
                    };
                    Ok((event.id, event.uid))
                }
                .await;
                match result {
                    Ok((id, uid)) => {
                        self.created.insert(creation.clone(), id.to_string());
                        created.insert(creation.clone(), json!({ "id": id.to_string(), "uid": uid }));
                    }
                    Err(error) => {
                        not_created.insert(creation.clone(), error);
                    }
                }
            }
        }
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, value) in update {
                let result: Result<(), Value> = async {
                    let event_id = self.id(id).ok_or_else(|| forbidden("instances are changed through their event"))?;
                    let patch = value.as_object().ok_or_else(|| invalid_properties("an object"))?;
                    let (event, text) = groupware
                        .event_data(owner, &[event_id])
                        .await
                        .map_err(|error| crate::contacts::set_error(&error))?
                        .pop()
                        .ok_or_else(|| json!({ "type": "notFound" }))?;
                    if !access.allows(event.calendar, Level::Write) {
                        return Err(forbidden("the calendar may not be written"));
                    }
                    let mut patch = patch.clone();
                    let target = match patch.remove("calendarIds") {
                        Some(Value::Object(calendars)) if calendars.len() == 1 => {
                            calendars.keys().next().and_then(|id| self.id(id))
                        }
                        Some(_) => return Err(invalid_properties("one calendar per event")),
                        None => None,
                    };
                    for key in ["isDraft", "isOrigin", "utcStart", "utcEnd"] {
                        patch.remove(key);
                    }
                    if !patch.is_empty() {
                        let mut object = js::event_to_json(&text).ok_or_else(|| invalid_properties("unreadable"))?;
                        js::patch(&mut object, &patch).map_err(invalid_properties)?;
                        let text = js::json_to_event(&object).map_err(invalid_properties)?;
                        if schedule {
                            match groupware
                                .put_event_scheduled(owner, event.calendar, &event.resource_name, &text, Expect::Any)
                                .await
                                .map_err(|error| crate::contacts::set_error(&error))?
                            {
                                Ok(_) => {}
                                Err(_) => return Err(forbidden("scheduling refused the change")),
                            }
                        } else {
                            groupware
                                .replace_event(owner, event_id, &text, false)
                                .await
                                .map_err(|error| crate::contacts::set_error(&error))?;
                        }
                    }
                    if let Some(target) = target.filter(|target| *target != event.calendar) {
                        if !access.allows(target, Level::Write) {
                            return Err(forbidden("the calendar may not be written"));
                        }
                        groupware
                            .move_event(owner, event_id, target, None)
                            .await
                            .map_err(|error| crate::contacts::set_error(&error))?;
                    }
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), error);
                    }
                }
            }
        }
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy.iter().filter_map(Value::as_str) {
                let result: Result<(), Value> = async {
                    let event_id = self.id(id).ok_or_else(|| forbidden("instances are removed through their event"))?;
                    let event =
                        groupware.event(owner, event_id).await.map_err(|error| crate::contacts::set_error(&error))?;
                    if !access.allows(event.calendar, Level::Write) {
                        return Err(forbidden("the calendar may not be written"));
                    }
                    if schedule {
                        groupware.destroy_event_scheduled(owner, event_id, Expect::Any).await
                    } else {
                        groupware.destroy_event(owner, event_id, Expect::Any).await.map(|_| 0)
                    }
                    .map_err(|error| crate::contacts::set_error(&error))?;
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => destroyed.push(id.to_owned()),
                    Err(error) => {
                        not_destroyed.insert(id.to_owned(), error);
                    }
                }
            }
        }
        let new_state = groupware.state(owner).await?;
        Ok(vec![(
            "CalendarEvent/set".into(),
            json!({
                "accountId": owner.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": created, "notCreated": not_created,
                "updated": updated, "notUpdated": not_updated,
                "destroyed": destroyed, "notDestroyed": not_destroyed,
            }),
        )])
    }

    /// `CalendarEvent/parse`: iCalendar blobs as JSCalendar.
    pub async fn event_parse(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let blob_ids: Vec<String> = match args.get("blobIds") {
            Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            _ => return Err(MethodError::invalid("blobIds is required")),
        };
        let mut parsed = Map::new();
        let mut not_parsable = Vec::new();
        let mut not_found = Vec::new();
        for blob in blob_ids {
            match self.jmap.blob_bytes(&access, &blob).await {
                Some(bytes) => match std::str::from_utf8(&bytes).ok().and_then(js::event_to_json) {
                    Some(object) => {
                        parsed.insert(blob, json!([object]));
                    }
                    None => not_parsable.push(blob),
                },
                None => not_found.push(blob),
            }
        }
        Ok(vec![(
            "CalendarEvent/parse".into(),
            json!({
                "accountId": access.owner.to_string(),
                "parsed": parsed,
                "notParsable": not_parsable,
                "notFound": not_found,
            }),
        )])
    }

    pub async fn notification_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        if !access.owned {
            return Err(MethodError::new("forbidden", "notifications are the owner's"));
        }
        let groupware = self.groupware()?;
        let state = groupware.state(owner).await?;
        let notifications = groupware.notifications(owner).await?;
        let wanted = ids(&args)?;
        let mut list = Vec::new();
        let mut not_found = wanted.clone().unwrap_or_default();
        for note in notifications {
            if let Some(wanted) = &wanted
                && !wanted.contains(&note.id.to_string())
            {
                continue;
            }
            not_found.retain(|id| *id != note.id.to_string());
            let event =
                groupware.notification_data(owner, note.id).await.ok().and_then(|text| js::event_to_json(&text));
            list.push(json!({
                "id": note.id.to_string(),
                "created": note.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                "changedBy": { "calendarAddress": format!("mailto:{}", note.changed_by) },
                "comment": note.comment,
                "type": note.kind,
                "calendarEventId": note.event.map(|id| id.to_string()),
                "isDraft": false,
                "event": event,
                "eventPatch": null,
            }));
        }
        Ok(vec![(
            "CalendarEventNotification/get".into(),
            json!({ "accountId": owner.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    /// Only destroying is allowed (draft-ietf-jmap-calendars, CalendarEventNotification/set).
    pub async fn notification_set(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        if !access.owned {
            return Err(MethodError::new("forbidden", "notifications are the owner's"));
        }
        let groupware = self.groupware()?;
        let old_state = groupware.state(owner).await?;
        let mut destroyed = Vec::new();
        let mut not_destroyed = Map::new();
        let mut not_created = Map::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for creation in create.keys() {
                not_created.insert(creation.clone(), forbidden("notifications are made by kernoid"));
            }
        }
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy.iter().filter_map(Value::as_str) {
                let result = match Uuid::parse_str(id) {
                    Ok(note) => groupware
                        .destroy_notification(owner, note)
                        .await
                        .map_err(|error| crate::contacts::set_error(&error)),
                    Err(_) => Err(json!({ "type": "notFound" })),
                };
                match result {
                    Ok(()) => destroyed.push(id.to_owned()),
                    Err(error) => {
                        not_destroyed.insert(id.to_owned(), error);
                    }
                }
            }
        }
        let new_state = groupware.state(owner).await?;
        Ok(vec![(
            "CalendarEventNotification/set".into(),
            json!({
                "accountId": owner.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": {}, "notCreated": not_created,
                "updated": {}, "notUpdated": {},
                "destroyed": destroyed, "notDestroyed": not_destroyed,
            }),
        )])
    }

    /// The addresses the account takes part in events with.
    pub async fn participant_identity_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, _) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let principal = groupware.principal(owner).await?;
        let state = groupware.state(owner).await?;
        let list: Vec<Value> = principal
            .addresses
            .iter()
            .map(|address| {
                json!({
                    "id": address,
                    "name": principal.display_name,
                    "calendarAddress": format!("mailto:{address}"),
                    "isDefault": Some(address) == principal.addresses.first(),
                })
            })
            .collect();
        Ok(vec![(
            "ParticipantIdentity/get".into(),
            json!({ "accountId": owner.to_string(), "state": state.to_string(), "list": list, "notFound": [] }),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_ids_and_local_times() {
        let event = Uuid::from_u128(5);
        let id = instance_id(event, 1_791_190_800);
        assert_eq!(parse_instance_id(&id), Some((event, 1_791_190_800)));
        assert_eq!(local(1_791_190_800, Some("Europe/Berlin")), "2026-10-05T11:00:00");
        assert_eq!(local(1_791_190_800, None), "2026-10-05T09:00:00");
        assert_eq!(utc(1_791_190_800), json!("2026-10-05T09:00:00Z"));
    }
}
