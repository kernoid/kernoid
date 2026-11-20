// SPDX-License-Identifier: MIT
//! JSCalendar (RFC 8984, with the names of JMAP for Calendars and JSCalendar 2.0: `recurrenceRule`,
//! `organizerCalendarAddress`, a participant's `calendarAddress` and `expectReply`) as JSON objects, converted from and
//! to iCalendar after draft-ietf-calext-jscalendar-icalendar.
//!
//! One object per `UID`: the series (or single event or task) with its overrides as `recurrenceOverrides` – a
//! component with `RECURRENCE-ID` becomes the patch of what it changes, an `RDATE` an empty patch, an `EXDATE`
//! `{"excluded": true}`. Times keep their zone: a `TZID` becomes its IANA name, UTC `Etc/UTC`, a floating time no
//! `timeZone`, a date `showWithoutTime`; a zone only the calendar's `VTIMEZONE` defines is converted to UTC (OPEN:
//! `timeZones`). What has no JSCalendar property is kept: properties in `iCalProps` (`[name, params, "unknown",
//! value]`, the value as written) and components in `iCalComponents` (their text), so that they go back unchanged.
//! Back to iCalendar, every override is a whole component, and each IANA zone used gets its `VTIMEZONE`.

use std::sync::atomic::{AtomicU64, Ordering};

use jiff::{Timestamp, civil::DateTime, tz::TimeZone};
use serde_json::{Map, Value, json};

use crate::{
    content::{Error, Param, Property, escape},
    expand::{duration_of, start_of},
    ical::Component,
    jmap,
    recur::{Frequency, Rule, parse_weekday, weekday_code},
    time::{self, Duration, Time, format_local, format_utc, parse_local, parse_utc},
    tz::{self, Zones},
};

type Object = Map<String, Value>;

/// Keys of an object that do not belong into an override's patch.
const NOT_PATCHED: [&str; 11] = [
    "@type",
    "uid",
    "prodId",
    "method",
    "updated",
    "created",
    "recurrenceRule",
    "recurrenceRules",
    "recurrenceOverrides",
    "excludedRecurrenceRules",
    "recurrenceId",
];

/// A new UID: the time and a counter of this process, as a UUID's text. Callers that have a source of randomness may
/// set their own.
pub fn new_uid() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = Timestamp::now().as_nanosecond() as u128;
    let count = COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    let mixed = now.wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835) ^ (count << 64 | count);
    let hex = format!("{mixed:032x}");
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// The objects of a `Group`, or the object itself.
pub fn entries(object: &Object) -> Vec<Object> {
    if object.get("@type").and_then(Value::as_str) == Some("Group") {
        return object
            .get("entries")
            .and_then(Value::as_array)
            .map(|entries| entries.iter().filter_map(|entry| entry.as_object().cloned()).collect())
            .unwrap_or_default();
    }
    vec![object.clone()]
}

/// Objects as a `Group`.
pub fn group(objects: Vec<Object>, prod_id: Option<&str>) -> Object {
    let mut group = Object::new();
    group.insert("@type".into(), json!("Group"));
    if let Some(prod_id) = prod_id {
        group.insert("prodId".into(), json!(prod_id));
    }
    group.insert("entries".into(), Value::Array(objects.into_iter().map(Value::Object).collect()));
    group
}

// ---------------------------------------------------------------------------------------------------------------
// iCalendar → JSCalendar

/// The events and tasks of a `VCALENDAR` as JSCalendar objects, one per `UID` in the order of the file.
pub fn from_icalendar(calendar: &Component) -> Vec<Object> {
    let zones = Zones::of(calendar);
    let prod_id = calendar.text("PRODID");
    let method = calendar.method().map(|method| method.to_ascii_lowercase());
    let mut uids: Vec<String> = Vec::new();
    for component in calendar.schedulable() {
        let uid = component.uid().unwrap_or_default();
        if !uids.contains(&uid) {
            uids.push(uid);
        }
    }
    let mut out = Vec::new();
    for uid in uids {
        let parts: Vec<&Component> =
            calendar.schedulable().filter(|component| component.uid().unwrap_or_default() == uid).collect();
        let master = parts.iter().find(|part| part.property("RECURRENCE-ID").is_none()).copied();
        let overrides: Vec<&Component> =
            parts.iter().filter(|part| part.property("RECURRENCE-ID").is_some()).copied().collect();
        match master {
            Some(master) => {
                let mut object = component_object(master, &zones);
                let frame = Frame::of(master, &zones);
                let mut patches = Object::new();
                for rdate in master.properties("RDATE") {
                    let period = rdate.param("VALUE").is_some_and(|v| v.eq_ignore_ascii_case("PERIOD"));
                    for item in rdate.value.split(',') {
                        let (first, second) = item.split_once('/').map_or((item, None), |(a, b)| (a, Some(b)));
                        let Some(time) = Time::parse(
                            first,
                            rdate.param("TZID"),
                            rdate.param("VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE")),
                        ) else {
                            continue;
                        };
                        let mut patch = Object::new();
                        if let Some(second) = second.filter(|_| period || second.is_some()) {
                            let duration = Duration::parse(second).or_else(|| {
                                let end =
                                    Time::parse(second, rdate.param("TZID"), false)?.resolve(&zones, &TimeZone::UTC);
                                Some(Duration::seconds(
                                    end.as_second() - time.resolve(&zones, &TimeZone::UTC).as_second(),
                                ))
                            });
                            if let Some(duration) = duration {
                                patch.insert("duration".into(), json!(duration.to_string()));
                            }
                        }
                        patches.insert(frame.local_key(&time, &zones), Value::Object(patch));
                    }
                }
                for exdate in master.properties("EXDATE") {
                    for time in exdate.time_values() {
                        patches.insert(frame.local_key(&time, &zones), json!({ "excluded": true }));
                    }
                }
                let mut base = object.clone();
                for key in NOT_PATCHED {
                    base.remove(key);
                }
                for part in overrides {
                    let Some(id) = part.property("RECURRENCE-ID").and_then(Property::time_value) else { continue };
                    let key = frame.local_key(&id, &zones);
                    let mut full = component_object(part, &zones);
                    if part.property("DTEND").is_none()
                        && part.property("DURATION").is_none()
                        && part.property("DUE").is_none()
                    {
                        // Lasts as its series.
                        if let Some(duration) = base.get("duration") {
                            full.insert("duration".into(), duration.clone());
                        }
                    }
                    let mut base = base.clone();
                    base.insert("start".into(), json!(key));
                    patches.insert(key, Value::Object(diff(&base, &full)));
                }
                if !patches.is_empty() {
                    object.insert("recurrenceOverrides".into(), Value::Object(patches));
                }
                finish(&mut object, prod_id.as_deref(), method.as_deref());
                out.push(object);
            }
            None => {
                // Instances without their series (an invitation to one of them): each an object of its own.
                for part in overrides {
                    let mut object = component_object(part, &zones);
                    if let Some(id) = part.property("RECURRENCE-ID").and_then(Property::time_value) {
                        let frame = Frame::of(part, &zones);
                        object.insert("recurrenceId".into(), json!(frame.local_key(&id, &zones)));
                    }
                    finish(&mut object, prod_id.as_deref(), method.as_deref());
                    out.push(object);
                }
            }
        }
    }
    out
}

fn finish(object: &mut Object, prod_id: Option<&str>, method: Option<&str>) {
    if let Some(prod_id) = prod_id {
        object.insert("prodId".into(), json!(prod_id));
    }
    if let Some(method) = method {
        object.insert("method".into(), json!(method));
    }
}

/// The patch that turns `base` into `full`, at the top level.
fn diff(base: &Object, full: &Object) -> Object {
    let mut patch = Object::new();
    for (key, value) in full {
        if NOT_PATCHED.contains(&key.as_str()) {
            continue;
        }
        if base.get(key) != Some(value) {
            patch.insert(key.clone(), value.clone());
        }
    }
    for key in base.keys() {
        if !full.contains_key(key) && !NOT_PATCHED.contains(&key.as_str()) {
            patch.insert(key.clone(), Value::Null);
        }
    }
    patch
}

/// How a series writes its times: its start's kind and zone.
struct Frame {
    start: Option<Time>,
    /// The IANA zone of the series, if it has one (UTC included).
    zone: Option<TimeZone>,
}

impl Frame {
    fn of(component: &Component, zones: &Zones) -> Frame {
        let start = start_of(component);
        let zone = match &start {
            Some(Time::Utc(_)) => Some(TimeZone::UTC),
            Some(Time::Zoned(_, tzid)) => Some(zones.get(tzid).unwrap_or(TimeZone::UTC)),
            _ => None,
        };
        Frame { start, zone }
    }

    /// A time of the series (a recurrence id, an exception) as a `LocalDateTime` in the series' zone.
    fn local_key(&self, time: &Time, zones: &Zones) -> String {
        match (&self.zone, time) {
            (_, Time::Date(date)) => format_local(date.to_datetime(jiff::civil::Time::midnight())),
            (Some(zone), time) => format_local(zone.to_datetime(time.resolve(zones, zone))),
            (None, time) => match self.start {
                Some(Time::Date(_)) => format_local(time.civil().date().to_datetime(jiff::civil::Time::midnight())),
                _ => format_local(time.civil()),
            },
        }
    }
}

/// A component's own properties as an object (without overrides).
fn component_object(component: &Component, zones: &Zones) -> Object {
    let mut object = Object::new();
    let task = component.is("VTODO");
    object.insert("@type".into(), json!(if task { "Task" } else { "Event" }));
    if let Some(uid) = component.uid() {
        object.insert("uid".into(), json!(uid));
    }
    let mut extra: Vec<&Property> = Vec::new();
    // Times.
    let start = component.property("DTSTART").and_then(Property::time_value);
    let (start_local, zone_name) = match &start {
        Some(start) => {
            let (local, zone) = local_and_zone(start, zones);
            (Some(local), zone)
        }
        None => (None, None),
    };
    if let Some(local) = &start_local {
        object.insert("start".into(), json!(local));
    }
    if let Some(zone) = &zone_name {
        object.insert("timeZone".into(), json!(zone));
    }
    if start.as_ref().is_some_and(Time::is_date) {
        object.insert("showWithoutTime".into(), json!(true));
    }
    if task {
        if let Some(due) = component.property("DUE").and_then(Property::time_value) {
            let (local, zone) = local_and_zone(&due, zones);
            object.insert("due".into(), json!(local));
            if zone_name.is_none()
                && let Some(zone) = zone
            {
                object.insert("timeZone".into(), json!(zone));
            }
            if due.is_date() {
                object.insert("showWithoutTime".into(), json!(true));
            }
        }
        if let Some(duration) = component.property("DURATION").and_then(|d| Duration::parse(&d.value)) {
            object.insert("estimatedDuration".into(), json!(duration.to_string()));
        }
    } else if let Some(start) = &start {
        let duration = civil_duration(component, start, zones);
        if !duration.is_zero() {
            object.insert("duration".into(), json!(duration.to_string()));
        }
    }
    let mut locations = Object::new();
    let mut virtual_locations = Object::new();
    let mut keywords = Object::new();
    let mut links = Object::new();
    let mut related = Object::new();
    for property in &component.properties {
        match property.name.as_str() {
            "SUMMARY" => insert_text(&mut object, "title", property),
            "DESCRIPTION" if !object.contains_key("description") => insert_text(&mut object, "description", property),
            "LOCATION" => {
                let mut location = Object::new();
                location.insert("@type".into(), json!("Location"));
                location.insert("name".into(), json!(property.as_text()));
                locations.insert(format!("l{}", locations.len() + 1), Value::Object(location));
            }
            "GEO" => {
                let fields = property.fields();
                if let [lat, lon] = fields.as_slice() {
                    let uri = format!("geo:{},{}", lat.trim(), lon.trim());
                    match locations.values_mut().find(|l| l.get("coordinates").is_none()) {
                        Some(Value::Object(location)) => {
                            location.insert("coordinates".into(), json!(uri));
                        }
                        _ => {
                            locations.insert(
                                format!("l{}", locations.len() + 1),
                                json!({ "@type": "Location", "coordinates": uri }),
                            );
                        }
                    }
                } else {
                    extra.push(property);
                }
            }
            "CONFERENCE" => {
                let mut location = Object::new();
                location.insert("@type".into(), json!("VirtualLocation"));
                location.insert("uri".into(), json!(property.value.trim()));
                if let Some(label) = property.param("LABEL") {
                    location.insert("name".into(), json!(label));
                }
                let features: Object =
                    property.param_values("FEATURE").map(|f| (f.to_ascii_lowercase(), json!(true))).collect();
                if !features.is_empty() {
                    location.insert("features".into(), Value::Object(features));
                }
                virtual_locations.insert(format!("v{}", virtual_locations.len() + 1), Value::Object(location));
            }
            "STATUS" => {
                let status = property.as_text().trim().to_ascii_lowercase();
                object.insert(if task { "progress" } else { "status" }.into(), json!(status));
            }
            "TRANSP" => match property.as_text().trim().to_ascii_uppercase().as_str() {
                "TRANSPARENT" => {
                    object.insert("freeBusyStatus".into(), json!("free"));
                }
                "OPAQUE" => {
                    object.insert("freeBusyStatus".into(), json!("busy"));
                }
                _ => extra.push(property),
            },
            "CLASS" => match property.as_text().trim().to_ascii_uppercase().as_str() {
                "PUBLIC" => {
                    object.insert("privacy".into(), json!("public"));
                }
                "PRIVATE" => {
                    object.insert("privacy".into(), json!("private"));
                }
                "CONFIDENTIAL" => {
                    object.insert("privacy".into(), json!("secret"));
                }
                _ => extra.push(property),
            },
            "SEQUENCE" | "PRIORITY" | "PERCENT-COMPLETE" => match property.integer() {
                Some(number) => {
                    let key = match property.name.as_str() {
                        "SEQUENCE" => "sequence",
                        "PRIORITY" => "priority",
                        _ => "percentComplete",
                    };
                    object.insert(key.into(), json!(number));
                }
                None => extra.push(property),
            },
            "CREATED" | "DTSTAMP" => match property.time_value().map(|time| time.resolve(zones, &TimeZone::UTC)) {
                Some(instant) => {
                    object.insert(
                        if property.is("CREATED") { "created" } else { "updated" }.into(),
                        json!(format_utc(instant)),
                    );
                }
                None => extra.push(property),
            },
            "CATEGORIES" => {
                for word in property.texts() {
                    keywords.insert(word, json!(true));
                }
            }
            "COLOR" => insert_text(&mut object, "color", property),
            "ATTACH" if property.param("ENCODING").is_none() && !property.has_param_value("VALUE", "BINARY") => {
                let mut link = Object::new();
                link.insert("@type".into(), json!("Link"));
                link.insert("href".into(), json!(property.value.trim()));
                if let Some(media) = property.param("FMTTYPE") {
                    link.insert("contentType".into(), json!(media));
                }
                if let Some(name) = property.param("FILENAME").or(property.param("X-FILENAME")) {
                    link.insert("title".into(), json!(name));
                }
                link.insert("rel".into(), json!("enclosure"));
                links.insert(format!("k{}", links.len() + 1), Value::Object(link));
            }
            "RELATED-TO" => {
                let relation = property.param("RELTYPE").unwrap_or("PARENT").to_ascii_lowercase();
                let entry = related
                    .entry(property.as_text().trim().to_owned())
                    .or_insert_with(|| json!({ "@type": "Relation", "relation": {} }));
                if let Some(Value::Object(relations)) = entry.get_mut("relation") {
                    relations.insert(relation, json!(true));
                }
            }
            "RRULE" if !object.contains_key("recurrenceRule") => match property.value.parse::<Rule>() {
                Ok(rule) => {
                    object.insert("recurrenceRule".into(), rule_object(&rule, start.as_ref(), zones));
                }
                Err(_) => extra.push(property),
            },
            "UID" | "DTSTART" | "DTEND" | "DUE" | "DURATION" | "ORGANIZER" | "ATTENDEE" | "RDATE" | "EXDATE"
            | "RECURRENCE-ID" => {}
            _ => extra.push(property),
        }
    }
    let participants = participants(component, &mut object);
    if !participants.is_empty() {
        object.insert("participants".into(), Value::Object(participants));
    }
    for (key, map) in [
        ("locations", locations),
        ("virtualLocations", virtual_locations),
        ("keywords", keywords),
        ("links", links),
        ("relatedTo", related),
    ] {
        if !map.is_empty() {
            object.insert(key.into(), Value::Object(map));
        }
    }
    // Alerts; other components are kept as they are.
    let mut alerts = Object::new();
    let mut components = Vec::new();
    for inner in &component.components {
        match alert_object(inner) {
            Some(alert) => {
                alerts.insert(format!("a{}", alerts.len() + 1), Value::Object(alert));
            }
            None => components.push(json!(inner.to_string())),
        }
    }
    if !alerts.is_empty() {
        object.insert("alerts".into(), Value::Object(alerts));
    }
    if !extra.is_empty() {
        object.insert("iCalProps".into(), Value::Array(extra.into_iter().map(prop_json).collect()));
    }
    if !components.is_empty() {
        object.insert("iCalComponents".into(), Value::Array(components));
    }
    object
}

fn insert_text(object: &mut Object, key: &str, property: &Property) {
    object.insert(key.into(), json!(property.as_text()));
}

/// A time as a `LocalDateTime` and the name of its zone (`None` for floating times and dates).
fn local_and_zone(time: &Time, zones: &Zones) -> (String, Option<String>) {
    match time {
        Time::Date(date) => (format_local(date.to_datetime(jiff::civil::Time::midnight())), None),
        Time::Floating(civil) => (format_local(*civil), None),
        Time::Utc(civil) => (format_local(*civil), Some("Etc/UTC".into())),
        Time::Zoned(civil, tzid) => match zones.iana_name(tzid) {
            Some(name) => (format_local(*civil), Some(name)),
            // A zone only the calendar defines: the instant, in UTC.
            None => {
                let instant = time.resolve(zones, &TimeZone::UTC);
                (format_local(TimeZone::UTC.to_datetime(instant)), Some("Etc/UTC".into()))
            }
        },
    }
}

/// How long an event lasts, as days and time of the calendar when start and end are in the same zone.
fn civil_duration(component: &Component, start: &Time, zones: &Zones) -> Duration {
    if let Some(end) = component.property("DTEND").and_then(Property::time_value) {
        let same_frame = match (start, &end) {
            (Time::Floating(_), Time::Floating(_)) | (Time::Utc(_), Time::Utc(_)) => true,
            (Time::Zoned(_, a), Time::Zoned(_, b)) => a == b,
            _ => false,
        };
        if same_frame {
            let (a, b) = (start.civil(), end.civil());
            let mut days = time::day_number(b.date()) - time::day_number(a.date());
            let mut seconds = seconds_of_day(b) - seconds_of_day(a);
            if days > 0 && seconds < 0 {
                days -= 1;
                seconds += 86_400;
            }
            if days < 0 || (days == 0 && seconds < 0) {
                return Duration::ZERO;
            }
            return Duration { days, seconds };
        }
    }
    duration_of(component, zones, &TimeZone::UTC)
}

fn seconds_of_day(time: DateTime) -> i64 {
    i64::from(time.hour()) * 3600 + i64::from(time.minute()) * 60 + i64::from(time.second())
}

/// An id for a participant from its address, the same in a series and its overrides.
fn participant_id(address: &str, taken: &Object) -> String {
    let base: String = address
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(200)
        .collect();
    let base = if base.is_empty() { "p".to_owned() } else { base };
    let mut id = base.clone();
    let mut n = 2;
    while taken.contains_key(&id) {
        id = format!("{base}-{n}");
        n += 1;
    }
    id
}

fn addresses(property: &Property, name: &str) -> Object {
    property.param_values(name).map(|value| (value.to_owned(), json!(true))).collect()
}

fn participants(component: &Component, object: &mut Object) -> Object {
    let mut out = Object::new();
    let organizer = component.property("ORGANIZER");
    if let Some(organizer) = organizer {
        object.insert("organizerCalendarAddress".into(), json!(organizer.value.trim()));
    }
    let organizer_address = organizer.and_then(Property::address).map(|a| a.to_lowercase());
    let mut organizer_merged = false;
    for attendee in component.properties("ATTENDEE") {
        let mut participant = Object::new();
        participant.insert("@type".into(), json!("Participant"));
        participant.insert("calendarAddress".into(), json!(attendee.value.trim()));
        if let Some(name) = attendee.param("CN") {
            participant.insert("name".into(), json!(name));
        }
        if let Some(kind) = attendee.param("CUTYPE") {
            let kind = match kind.to_ascii_uppercase().as_str() {
                "ROOM" => "location".to_owned(),
                other => other.to_ascii_lowercase(),
            };
            participant.insert("kind".into(), json!(kind));
        }
        let mut roles = Object::new();
        match attendee.param("ROLE").map(str::to_ascii_uppercase).as_deref() {
            Some("CHAIR") => {
                roles.insert("chair".into(), json!(true));
                roles.insert("attendee".into(), json!(true));
            }
            Some("OPT-PARTICIPANT") => {
                roles.insert("attendee".into(), json!(true));
                roles.insert("optional".into(), json!(true));
            }
            Some("NON-PARTICIPANT") => {
                roles.insert("informational".into(), json!(true));
            }
            _ => {
                roles.insert("attendee".into(), json!(true));
            }
        }
        let address = attendee.address().map(|a| a.to_lowercase());
        if address.is_some() && address == organizer_address {
            roles.insert("owner".into(), json!(true));
            organizer_merged = true;
        }
        participant.insert("roles".into(), Value::Object(roles));
        if let Some(status) = attendee.param("PARTSTAT") {
            participant.insert("participationStatus".into(), json!(status.to_ascii_lowercase()));
        }
        if attendee.param("RSVP").is_some_and(|rsvp| rsvp.eq_ignore_ascii_case("TRUE")) {
            participant.insert("expectReply".into(), json!(true));
        }
        participant_params(attendee, &mut participant);
        let id = participant_id(address.as_deref().unwrap_or(""), &out);
        out.insert(id, Value::Object(participant));
    }
    if let Some(organizer) = organizer
        && !organizer_merged
    {
        let mut participant = Object::new();
        participant.insert("@type".into(), json!("Participant"));
        participant.insert("calendarAddress".into(), json!(organizer.value.trim()));
        if let Some(name) = organizer.param("CN") {
            participant.insert("name".into(), json!(name));
        }
        participant.insert("roles".into(), json!({ "owner": true }));
        participant_params(organizer, &mut participant);
        let id = participant_id(organizer_address.as_deref().unwrap_or(""), &out);
        out.insert(id, Value::Object(participant));
    } else if let Some(organizer) = organizer {
        // The organizer's own parameters on the merged participant.
        let address = organizer_address.clone().unwrap_or_default();
        if let Some(Value::Object(participant)) = out.values_mut().find(|p| {
            p.get("calendarAddress")
                .and_then(Value::as_str)
                .is_some_and(|a| crate::content::strip_mailto(a.trim()).eq_ignore_ascii_case(&address))
        }) {
            if !participant.contains_key("name")
                && let Some(name) = organizer.param("CN")
            {
                participant.insert("name".into(), json!(name));
            }
            if let Some(agent) = organizer.param("SCHEDULE-AGENT") {
                participant.insert("organizerScheduleAgent".into(), json!(agent.to_ascii_lowercase()));
            }
        }
    }
    out
}

fn participant_params(property: &Property, participant: &mut Object) {
    for (param, key) in [("DELEGATED-TO", "delegatedTo"), ("DELEGATED-FROM", "delegatedFrom"), ("MEMBER", "memberOf")] {
        let map = addresses(property, param);
        if !map.is_empty() {
            participant.insert(key.into(), Value::Object(map));
        }
    }
    if let Some(sent_by) = property.param("SENT-BY") {
        participant.insert("sentBy".into(), json!(sent_by));
    }
    if let Some(agent) = property.param("SCHEDULE-AGENT") {
        participant.insert("scheduleAgent".into(), json!(agent.to_ascii_lowercase()));
    }
    if let Some(force) = property.param("SCHEDULE-FORCE-SEND") {
        participant.insert("scheduleForceSend".into(), json!(force.eq_ignore_ascii_case("REQUEST")));
    }
    let status: Vec<Value> = property.param_values("SCHEDULE-STATUS").map(|s| json!(s)).collect();
    if !status.is_empty() {
        participant.insert("scheduleStatus".into(), Value::Array(status));
    }
    if let Some(email) = property.param("EMAIL") {
        participant.insert("email".into(), json!(email));
    }
    if let Some(language) = property.param("LANGUAGE") {
        participant.insert("language".into(), json!(language));
    }
}

fn rule_object(rule: &Rule, start: Option<&Time>, zones: &Zones) -> Value {
    let mut out = Object::new();
    out.insert("@type".into(), json!("RecurrenceRule"));
    out.insert("frequency".into(), json!(rule.frequency.as_str().to_ascii_lowercase()));
    if rule.interval != 1 {
        out.insert("interval".into(), json!(rule.interval));
    }
    for (name, value) in &rule.other {
        match name.as_str() {
            "RSCALE" => {
                out.insert("rscale".into(), json!(value.to_ascii_lowercase()));
            }
            "SKIP" => {
                out.insert("skip".into(), json!(value.to_ascii_lowercase()));
            }
            _ => {}
        }
    }
    if rule.week_start != jiff::civil::Weekday::Monday {
        out.insert("firstDayOfWeek".into(), json!(weekday_code(rule.week_start).to_ascii_lowercase()));
    }
    if !rule.by_day.is_empty() {
        let days: Vec<Value> = rule
            .by_day
            .iter()
            .map(|(nth, day)| {
                let mut entry = json!({ "@type": "NDay", "day": weekday_code(*day).to_ascii_lowercase() });
                if let Some(nth) = nth {
                    entry["nthOfPeriod"] = json!(nth);
                }
                entry
            })
            .collect();
        out.insert("byDay".into(), Value::Array(days));
    }
    if !rule.by_month_day.is_empty() {
        out.insert("byMonthDay".into(), json!(rule.by_month_day));
    }
    if !rule.by_month.is_empty() {
        out.insert("byMonth".into(), json!(rule.by_month.iter().map(|m| m.to_string()).collect::<Vec<_>>()));
    }
    for (key, values) in [
        ("byYearDay", json!(rule.by_year_day)),
        ("byWeekNo", json!(rule.by_week_no)),
        ("byHour", json!(rule.by_hour)),
        ("byMinute", json!(rule.by_minute)),
        ("bySecond", json!(rule.by_second)),
        ("bySetPosition", json!(rule.by_set_pos)),
    ] {
        if values.as_array().is_some_and(|values| !values.is_empty()) {
            out.insert(key.into(), values);
        }
    }
    if let Some(count) = rule.count {
        out.insert("count".into(), json!(count));
    }
    if let Some(until) = &rule.until {
        let local = match (until, start) {
            (Time::Date(date), _) => date.to_datetime(jiff::civil::Time::midnight()),
            (Time::Utc(_) | Time::Zoned(..), Some(start @ (Time::Zoned(..) | Time::Utc(_)))) => {
                let zone = start.zone(zones, &TimeZone::UTC);
                // A zone only the calendar defines is shown in UTC (see `local_and_zone`).
                let zone = match start {
                    Time::Zoned(_, tzid) if zones.iana_name(tzid).is_none() => TimeZone::UTC,
                    _ => zone,
                };
                zone.to_datetime(until.resolve(zones, &TimeZone::UTC))
            }
            (other, _) => other.civil(),
        };
        out.insert("until".into(), json!(format_local(local)));
    }
    Value::Object(out)
}

fn alert_object(component: &Component) -> Option<Object> {
    if !component.is("VALARM") {
        return None;
    }
    let action = component.text("ACTION").map(|a| a.trim().to_ascii_lowercase()).unwrap_or_else(|| "display".into());
    if !matches!(action.as_str(), "display" | "email" | "audio") {
        return None;
    }
    let trigger = component.property("TRIGGER")?;
    let mut alert = Object::new();
    alert.insert("@type".into(), json!("Alert"));
    if trigger.has_param_value("VALUE", "DATE-TIME")
        || trigger.value.trim().ends_with('Z') && !trigger.value.contains('P')
    {
        let when = trigger.time_value()?.resolve(&Zones::default(), &TimeZone::UTC);
        alert.insert("trigger".into(), json!({ "@type": "AbsoluteTrigger", "when": format_utc(when) }));
    } else {
        let offset = Duration::parse(&trigger.value)?;
        let mut trigger_object = json!({ "@type": "OffsetTrigger", "offset": offset.to_string() });
        if trigger.param("RELATED").is_some_and(|related| related.eq_ignore_ascii_case("END")) {
            trigger_object["relativeTo"] = json!("end");
        }
        alert.insert("trigger".into(), trigger_object);
    }
    if action == "email" {
        alert.insert("action".into(), json!("email"));
    }
    let mut extra = Vec::new();
    for property in &component.properties {
        match property.name.as_str() {
            "TRIGGER" => {}
            "ACTION" if action != "audio" => {}
            "ACKNOWLEDGED" => match property.time_value() {
                Some(time) => {
                    alert.insert(
                        "acknowledged".into(),
                        json!(format_utc(time.resolve(&Zones::default(), &TimeZone::UTC))),
                    );
                }
                None => extra.push(prop_json(property)),
            },
            _ => extra.push(prop_json(property)),
        }
    }
    if !extra.is_empty() {
        alert.insert("iCalProps".into(), Value::Array(extra));
    }
    if !component.components.is_empty() {
        return None;
    }
    Some(alert)
}

/// A property as kept in `iCalProps`: `[name, params, "unknown", value as written]`.
fn prop_json(property: &Property) -> Value {
    let mut params = Object::new();
    for param in &property.params {
        let value = if param.values.len() == 1 { json!(param.values[0]) } else { json!(param.values) };
        params.insert(param.name.to_ascii_lowercase(), value);
    }
    json!([property.name.to_ascii_lowercase(), params, "unknown", property.value])
}

/// A property kept in `iCalProps`, back.
fn prop_from_json(value: &Value) -> Option<Property> {
    let items = value.as_array()?;
    let name = items.first()?.as_str()?;
    let mut property = Property::new(name, items.get(3).and_then(Value::as_str).unwrap_or_default());
    if let Some(params) = items.get(1).and_then(Value::as_object) {
        for (param, value) in params {
            let values = match value {
                Value::Array(values) => values.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
                Value::String(value) => vec![value.clone()],
                _ => continue,
            };
            property.params.push(Param { name: param.to_ascii_uppercase(), values });
        }
    }
    Some(property)
}

// ---------------------------------------------------------------------------------------------------------------
// JSCalendar → iCalendar

/// JSCalendar objects (`Group`s opened) as one `VCALENDAR`, with the `VTIMEZONE` of each zone they use.
pub fn to_icalendar(objects: &[Object], prod_id: &str) -> Result<Component, Error> {
    let mut calendar = Component::calendar(prod_id);
    let mut zones: Vec<(String, Timestamp)> = Vec::new();
    let mut components = Vec::new();
    let mut method = None;
    for object in objects.iter().flat_map(entries) {
        if method.is_none() {
            method = object.get("method").and_then(Value::as_str).map(str::to_ascii_uppercase);
        }
        let built = object_components(&object)?;
        for (name, instant) in built.zones {
            match zones.iter_mut().find(|(known, _)| *known == name) {
                Some((_, earliest)) => *earliest = (*earliest).min(instant),
                None => zones.push((name, instant)),
            }
        }
        components.extend(built.components);
    }
    if let Some(method) = method {
        calendar.properties.push(Property::new("METHOD", method));
    }
    for (name, earliest) in zones {
        let from = earliest.checked_sub(jiff::SignedDuration::from_hours(24 * 7)).unwrap_or(earliest);
        if let Some(zone) = tz::vtimezone(&name, from, from) {
            calendar.components.push(zone);
        }
    }
    calendar.components.extend(components);
    Ok(calendar)
}

struct Built {
    components: Vec<Component>,
    /// The IANA zones used (not UTC), each with the earliest instant it is needed for.
    zones: Vec<(String, Timestamp)>,
}

/// How an object writes its times.
#[derive(Clone)]
struct Writer {
    /// The IANA name of the zone, `None` for floating; UTC is `Etc/UTC`.
    zone_name: Option<String>,
    zone: TimeZone,
    all_day: bool,
}

impl Writer {
    fn of(object: &Object) -> Result<Writer, Error> {
        let all_day = object.get("showWithoutTime").and_then(Value::as_bool).unwrap_or(false);
        let zone_name = match object.get("timeZone") {
            None | Some(Value::Null) => None,
            Some(Value::String(name)) if all_day => {
                let _ = name;
                None
            }
            Some(Value::String(name)) => {
                Some(tz::iana_name(name).ok_or_else(|| Error(format!("timeZone: unknown time zone {name}")))?)
            }
            Some(_) => return Err(Error("timeZone: a string".into())),
        };
        let zone = zone_name.as_deref().and_then(tz::iana).unwrap_or(TimeZone::UTC);
        Ok(Writer { zone_name, zone, all_day })
    }

    fn is_utc(&self) -> bool {
        self.zone_name.as_deref().is_some_and(time::is_utc_name)
    }

    fn time(&self, local: DateTime) -> Time {
        if self.all_day {
            return Time::Date(local.date());
        }
        match &self.zone_name {
            None => Time::Floating(local),
            Some(_) if self.is_utc() => Time::Utc(local),
            Some(name) => Time::Zoned(local, name.clone()),
        }
    }

    fn instant(&self, local: DateTime) -> Timestamp {
        time::to_timestamp(&self.zone, local)
    }
}

fn local_of(object: &Object, key: &str) -> Result<Option<DateTime>, Error> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => parse_local(text)
            .map(Some)
            .ok_or_else(|| Error(format!("{key}: a LocalDateTime, e.g. 2026-11-02T00:00:00"))),
        Some(_) => Err(Error(format!("{key}: a LocalDateTime"))),
    }
}

fn str_of<'a>(object: &'a Object, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn object_components(object: &Object) -> Result<Built, Error> {
    let kind = str_of(object, "@type").unwrap_or("Event");
    if kind != "Event" && kind != "Task" {
        return Err(Error(format!("@type: {kind} is not an Event or a Task")));
    }
    let mut object = object.clone();
    if !object.get("uid").is_some_and(Value::is_string) {
        object.insert("uid".into(), json!(new_uid()));
    }
    let writer = Writer::of(&object)?;
    let start = local_of(&object, "start")?;
    if kind == "Event" && start.is_none() {
        return Err(Error("start: an event needs one".into()));
    }
    let mut zones = Vec::new();
    if let (Some(name), Some(start)) = (&writer.zone_name, start)
        && !writer.is_utc()
    {
        zones.push((name.clone(), writer.instant(start)));
    }
    let mut master = component_of(&object, &writer, None)?;
    let mut components = Vec::new();
    // Recurrences.
    let rules: Vec<&Value> = match (object.get("recurrenceRule"), object.get("recurrenceRules")) {
        (Some(rule @ Value::Object(_)), _) => vec![rule],
        (_, Some(Value::Array(rules))) => rules.iter().collect(),
        _ => Vec::new(),
    };
    let mut parsed_rules = Vec::new();
    for rule in rules {
        let rule = rule_from(rule, &writer)?;
        master.properties.push(Property::new("RRULE", rule.to_string()));
        parsed_rules.push(rule);
    }
    if let Some(Value::Array(rules)) = object.get("excludedRecurrenceRules") {
        for rule in rules {
            master.properties.push(Property::new("EXRULE", rule_from(rule, &writer)?.to_string()));
        }
    }
    if let Some(Value::Object(overrides)) = object.get("recurrenceOverrides") {
        let mut base = object.clone();
        for key in NOT_PATCHED {
            if !matches!(key, "@type" | "uid" | "updated") {
                base.remove(key);
            }
        }
        let mut rdates = Vec::new();
        let mut exdates = Vec::new();
        for (key, patch) in overrides {
            let local =
                parse_local(key).ok_or_else(|| Error(format!("recurrenceOverrides: {key} is not a LocalDateTime")))?;
            let patch = patch.as_object().ok_or_else(|| Error(format!("recurrenceOverrides/{key}: an object")))?;
            let id = writer.time(local);
            if patch.get("excluded").and_then(Value::as_bool) == Some(true) {
                exdates.push(id);
                continue;
            }
            let from_rule =
                start.is_some_and(|start| is_occurrence(&parsed_rules, start, writer.all_day, local, &writer));
            if !from_rule {
                rdates.push(id.clone());
            }
            if patch.is_empty() {
                continue;
            }
            let mut instance = base.clone();
            instance.insert("start".into(), json!(key));
            jmap::patch(&mut instance, patch).map_err(|error| Error(format!("recurrenceOverrides/{key}: {error}")))?;
            let instance_writer = Writer::of(&instance)?;
            if let (Some(name), Some(at)) = (&instance_writer.zone_name, local_of(&instance, "start")?)
                && !instance_writer.is_utc()
            {
                zones.push((name.clone(), instance_writer.instant(at)));
            }
            components.push(component_of(&instance, &instance_writer, Some(&id))?);
        }
        add_times(&mut master, "RDATE", &rdates);
        add_times(&mut master, "EXDATE", &exdates);
    }
    if let Some(id) = str_of(&object, "recurrenceId") {
        let local = parse_local(id).ok_or_else(|| Error("recurrenceId: a LocalDateTime".into()))?;
        let at = master.properties.iter().position(|p| p.is("DTSTART")).unwrap_or(2);
        master.properties.insert(at, Property::time("RECURRENCE-ID", &writer.time(local)));
    }
    components.insert(0, master);
    Ok(Built { components, zones })
}

/// Times of the same kind in one property each (`EXDATE`, `RDATE`).
fn add_times(component: &mut Component, name: &str, times: &[Time]) {
    for time in times {
        component.properties.push(Property::time(name, time));
    }
}

fn is_occurrence(rules: &[Rule], start: DateTime, all_day: bool, local: DateTime, writer: &Writer) -> bool {
    if local == start {
        return true;
    }
    rules.iter().any(|rule| {
        let until = rule.until.as_ref().map(|until| match until {
            Time::Date(day) => day.at(23, 59, 59, 0),
            Time::Utc(_) => writer.zone.to_datetime(until.resolve(&Zones::default(), &TimeZone::UTC)),
            other => other.civil(),
        });
        rule.occurrences(start, all_day, until).take_while(|time| *time <= local).any(|time| time == local)
    })
}

fn rule_from(value: &Value, writer: &Writer) -> Result<Rule, Error> {
    let object = value.as_object().ok_or_else(|| Error("recurrenceRule: an object".into()))?;
    let invalid = |what: &str| Error(format!("recurrenceRule: {what}"));
    let frequency = str_of(object, "frequency").and_then(Frequency::parse).ok_or_else(|| invalid("frequency"))?;
    let mut rule = Rule::new(frequency);
    if let Some(interval) = object.get("interval").and_then(Value::as_u64) {
        rule.interval = u32::try_from(interval).ok().filter(|i| *i > 0).ok_or_else(|| invalid("interval"))?;
    }
    if let Some(count) = object.get("count").and_then(Value::as_u64) {
        rule.count = Some(u32::try_from(count).map_err(|_| invalid("count"))?);
    }
    if let Some(rscale) = str_of(object, "rscale").filter(|r| !r.eq_ignore_ascii_case("gregorian")) {
        rule.other.push(("RSCALE".into(), rscale.to_ascii_uppercase()));
    }
    if let Some(skip) = str_of(object, "skip").filter(|s| !s.eq_ignore_ascii_case("omit")) {
        rule.other.push(("SKIP".into(), skip.to_ascii_uppercase()));
    }
    if let Some(day) = str_of(object, "firstDayOfWeek") {
        rule.week_start = parse_weekday(day).ok_or_else(|| invalid("firstDayOfWeek"))?;
    }
    if let Some(Value::Array(days)) = object.get("byDay") {
        for day in days {
            let weekday =
                day.get("day").and_then(Value::as_str).and_then(parse_weekday).ok_or_else(|| invalid("byDay"))?;
            let nth = day.get("nthOfPeriod").and_then(Value::as_i64).map(|n| n as i16);
            rule.by_day.push((nth, weekday));
        }
    }
    fn numbers<T: TryFrom<i64>>(object: &Object, key: &str) -> Result<Vec<T>, Error> {
        match object.get(key) {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    let number = item.as_i64().or_else(|| item.as_str().and_then(|s| s.trim().parse().ok()));
                    number.and_then(|n| T::try_from(n).ok()).ok_or_else(|| Error(format!("recurrenceRule: {key}")))
                })
                .collect(),
            _ => Ok(Vec::new()),
        }
    }
    rule.by_month_day = numbers(object, "byMonthDay")?;
    rule.by_month = numbers(object, "byMonth")?;
    rule.by_year_day = numbers(object, "byYearDay")?;
    rule.by_week_no = numbers(object, "byWeekNo")?;
    rule.by_hour = numbers(object, "byHour")?;
    rule.by_minute = numbers(object, "byMinute")?;
    rule.by_second = numbers(object, "bySecond")?;
    rule.by_set_pos = numbers(object, "bySetPosition")?;
    if let Some(until) = str_of(object, "until") {
        let local = parse_local(until).ok_or_else(|| invalid("until"))?;
        // RFC 5545: with a zone, UNTIL is in UTC.
        rule.until = Some(if writer.all_day {
            Time::Date(local.date())
        } else if writer.zone_name.is_some() {
            Time::Utc(TimeZone::UTC.to_datetime(writer.instant(local)))
        } else {
            Time::Floating(local)
        });
    }
    Ok(rule)
}

/// A component of an object (the series, or an override with its recurrence id).
fn component_of(object: &Object, writer: &Writer, recurrence_id: Option<&Time>) -> Result<Component, Error> {
    let task = str_of(object, "@type") == Some("Task");
    let mut component = Component::new(if task { "VTODO" } else { "VEVENT" });
    let props = &mut component.properties;
    props.push(Property::text("UID", str_of(object, "uid").unwrap_or_default()));
    let stamp = str_of(object, "updated").and_then(parse_utc).unwrap_or_else(Timestamp::now);
    props.push(Property::new("DTSTAMP", format!("{}Z", time::format_date_time(TimeZone::UTC.to_datetime(stamp)))));
    if let Some(id) = recurrence_id {
        props.push(Property::time("RECURRENCE-ID", id));
    }
    let start = local_of(object, "start")?;
    if let Some(start) = start {
        props.push(Property::time("DTSTART", &writer.time(start)));
    }
    if task {
        if let Some(due) = local_of(object, "due")? {
            props.push(Property::time("DUE", &writer.time(due)));
        }
        if let Some(duration) = str_of(object, "estimatedDuration").and_then(Duration::parse) {
            props.push(Property::new("DURATION", duration.to_string()));
        }
    } else if let (Some(start), Some(duration)) = (start, object.get("duration")) {
        let duration = match duration {
            Value::String(text) => {
                Duration::parse(text).ok_or_else(|| Error("duration: an ISO 8601 duration".into()))?
            }
            Value::Null => Duration::ZERO,
            _ => return Err(Error("duration: a string".into())),
        };
        if duration.is_negative() {
            return Err(Error("duration: not negative".into()));
        }
        if !duration.is_zero() {
            let days =
                if writer.all_day { duration.days + (duration.seconds + 86_399) / 86_400 } else { duration.days };
            let seconds = if writer.all_day { 0 } else { duration.seconds };
            let end = time::add_civil(start, days, seconds).ok_or_else(|| Error("duration: too long".into()))?;
            props.push(Property::time("DTEND", &writer.time(end)));
        }
    }
    if let Some(title) = str_of(object, "title") {
        props.push(Property::text("SUMMARY", title));
    }
    if let Some(description) = str_of(object, "description") {
        props.push(Property::text("DESCRIPTION", description));
    }
    if let Some(Value::Object(locations)) = object.get("locations") {
        for location in locations.values() {
            if let Some(name) = location.get("name").and_then(Value::as_str) {
                props.push(Property::text("LOCATION", name));
            }
        }
        if let Some(geo) = locations
            .values()
            .find_map(|l| l.get("coordinates").and_then(Value::as_str))
            .and_then(|uri| uri.strip_prefix("geo:"))
            .and_then(|rest| rest.split(';').next())
            .and_then(|rest| rest.split_once(','))
        {
            props.push(Property::new("GEO", format!("{};{}", geo.0.trim(), geo.1.trim())));
        }
    }
    if let Some(Value::Object(locations)) = object.get("virtualLocations") {
        for location in locations.values() {
            let Some(uri) = location.get("uri").and_then(Value::as_str) else { continue };
            // RFC 7986, 5.11: CONFERENCE has no default value type.
            let mut property = Property::new("CONFERENCE", uri.trim()).with_param("VALUE", "URI");
            if let Some(Value::Object(features)) = location.get("features") {
                let features: Vec<String> = features
                    .iter()
                    .filter(|(_, on)| on.as_bool() == Some(true))
                    .map(|(f, _)| f.to_ascii_uppercase())
                    .collect();
                property.set_param_values("FEATURE", features);
            }
            if let Some(name) = location.get("name").and_then(Value::as_str) {
                property.set_param("LABEL", name);
            }
            props.push(property);
        }
    }
    let status_key = if task { "progress" } else { "status" };
    if let Some(status) = str_of(object, status_key) {
        props.push(Property::new("STATUS", status.to_ascii_uppercase()));
    }
    match str_of(object, "freeBusyStatus") {
        Some("free") => props.push(Property::new("TRANSP", "TRANSPARENT")),
        Some("busy") => props.push(Property::new("TRANSP", "OPAQUE")),
        _ => {}
    }
    match str_of(object, "privacy") {
        Some("public") => props.push(Property::new("CLASS", "PUBLIC")),
        Some("private") => props.push(Property::new("CLASS", "PRIVATE")),
        Some("secret") => props.push(Property::new("CLASS", "CONFIDENTIAL")),
        _ => {}
    }
    for (key, name) in [("sequence", "SEQUENCE"), ("priority", "PRIORITY"), ("percentComplete", "PERCENT-COMPLETE")] {
        if let Some(number) = object.get(key).and_then(Value::as_i64) {
            props.push(Property::new(name, number.to_string()));
        }
    }
    if let Some(created) = str_of(object, "created").and_then(parse_utc) {
        props
            .push(Property::new("CREATED", format!("{}Z", time::format_date_time(TimeZone::UTC.to_datetime(created)))));
    }
    if let Some(Value::Object(keywords)) = object.get("keywords") {
        let words: Vec<String> =
            keywords.iter().filter(|(_, on)| on.as_bool() == Some(true)).map(|(word, _)| escape(word)).collect();
        if !words.is_empty() {
            props.push(Property::new("CATEGORIES", words.join(",")));
        }
    }
    if let Some(color) = str_of(object, "color") {
        props.push(Property::text("COLOR", color));
    }
    participants_back(object, props);
    if let Some(Value::Object(links)) = object.get("links") {
        for link in links.values() {
            let Some(href) = link.get("href").and_then(Value::as_str) else { continue };
            let mut property = Property::new("ATTACH", href);
            if let Some(media) = link.get("contentType").and_then(Value::as_str) {
                property.set_param("FMTTYPE", media);
            }
            if let Some(title) = link.get("title").and_then(Value::as_str) {
                property.set_param("FILENAME", title);
            }
            props.push(property);
        }
    }
    if let Some(Value::Object(related)) = object.get("relatedTo") {
        for (uid, relation) in related {
            let kinds: Vec<String> = relation
                .get("relation")
                .and_then(Value::as_object)
                .map(|kinds| {
                    kinds
                        .iter()
                        .filter(|(_, on)| on.as_bool() == Some(true))
                        .map(|(k, _)| k.to_ascii_uppercase())
                        .collect()
                })
                .unwrap_or_default();
            if kinds.is_empty() {
                props.push(Property::text("RELATED-TO", uid));
            }
            for kind in kinds {
                props.push(Property::text("RELATED-TO", uid).with_param("RELTYPE", kind));
            }
        }
    }
    if let Some(Value::Array(extra)) = object.get("iCalProps") {
        props.extend(extra.iter().filter_map(prop_from_json));
    }
    if let Some(Value::Object(alerts)) = object.get("alerts") {
        for alert in alerts.values() {
            if let Some(alarm) = alarm_of(alert, object) {
                component.components.push(alarm);
            }
        }
    }
    if let Some(Value::Array(extra)) = object.get("iCalComponents") {
        for text in extra.iter().filter_map(Value::as_str) {
            if let Ok(parsed) = crate::content::parse_blocks(text) {
                component.components.extend(parsed.into_iter().map(Component::from_block));
            }
        }
    }
    Ok(component)
}

fn participants_back(object: &Object, props: &mut Vec<Property>) {
    let participants = object.get("participants").and_then(Value::as_object);
    let organizer_address = str_of(object, "organizerCalendarAddress")
        .map(str::to_owned)
        .or_else(|| {
            // RFC 8984's replyTo.
            object.get("replyTo").and_then(|r| r.get("imip")).and_then(Value::as_str).map(str::to_owned)
        })
        .or_else(|| {
            participants?.values().find_map(|p| {
                let owner = p.get("roles").and_then(|r| r.get("owner")).and_then(Value::as_bool) == Some(true);
                owner.then(|| p.get("calendarAddress").and_then(Value::as_str)).flatten().map(str::to_owned)
            })
        });
    let same = |a: &str, b: &str| {
        crate::content::strip_mailto(a.trim()).eq_ignore_ascii_case(crate::content::strip_mailto(b.trim()))
    };
    if let Some(address) = &organizer_address {
        let mut organizer = Property::new("ORGANIZER", address.trim());
        let owner = participants.and_then(|participants| {
            participants
                .values()
                .find(|p| p.get("calendarAddress").and_then(Value::as_str).is_some_and(|a| same(a, address)))
        });
        if let Some(owner) = owner {
            if let Some(name) = owner.get("name").and_then(Value::as_str) {
                organizer.set_param("CN", name);
            }
            if let Some(sent_by) = owner.get("sentBy").and_then(Value::as_str) {
                organizer.set_param("SENT-BY", sent_by);
            }
            let attends = owner
                .get("roles")
                .and_then(Value::as_object)
                .is_some_and(|roles| roles.iter().any(|(role, on)| role != "owner" && on.as_bool() == Some(true)));
            let agent = if attends { owner.get("organizerScheduleAgent") } else { owner.get("scheduleAgent") };
            if let Some(agent) = agent.and_then(Value::as_str) {
                organizer.set_param("SCHEDULE-AGENT", agent.to_ascii_uppercase());
            }
            if !attends && let Some(email) = owner.get("email").and_then(Value::as_str) {
                organizer.set_param("EMAIL", email);
            }
        }
        props.push(organizer);
    }
    let Some(participants) = participants else { return };
    for participant in participants.values() {
        let Some(address) = participant.get("calendarAddress").and_then(Value::as_str) else { continue };
        let roles = participant.get("roles").and_then(Value::as_object);
        let role = |name: &str| roles.and_then(|r| r.get(name)).and_then(Value::as_bool) == Some(true);
        let only_owner = roles.is_some_and(|roles| {
            roles.iter().filter(|(_, on)| on.as_bool() == Some(true)).all(|(role, _)| role == "owner")
        }) && role("owner");
        if only_owner {
            continue;
        }
        let mut attendee = Property::new("ATTENDEE", address.trim());
        if let Some(name) = participant.get("name").and_then(Value::as_str) {
            attendee.set_param("CN", name);
        }
        if let Some(kind) = participant.get("kind").and_then(Value::as_str) {
            attendee.set_param("CUTYPE", if kind == "location" { "ROOM".into() } else { kind.to_ascii_uppercase() });
        }
        let role_param = if role("chair") {
            Some("CHAIR")
        } else if role("optional") {
            Some("OPT-PARTICIPANT")
        } else if role("informational") && !role("attendee") {
            Some("NON-PARTICIPANT")
        } else {
            None
        };
        if let Some(role) = role_param {
            attendee.set_param("ROLE", role);
        }
        if let Some(status) = participant.get("participationStatus").and_then(Value::as_str) {
            attendee.set_param("PARTSTAT", status.to_ascii_uppercase());
        }
        if participant.get("expectReply").and_then(Value::as_bool) == Some(true) {
            attendee.set_param("RSVP", "TRUE");
        }
        for (key, param) in
            [("delegatedTo", "DELEGATED-TO"), ("delegatedFrom", "DELEGATED-FROM"), ("memberOf", "MEMBER")]
        {
            if let Some(Value::Object(map)) = participant.get(key) {
                let values: Vec<String> =
                    map.iter().filter(|(_, on)| on.as_bool() == Some(true)).map(|(a, _)| a.clone()).collect();
                attendee.set_param_values(param, values);
            }
        }
        for (key, param) in [("sentBy", "SENT-BY"), ("email", "EMAIL"), ("language", "LANGUAGE")] {
            if let Some(value) = participant.get(key).and_then(Value::as_str) {
                attendee.set_param(param, value);
            }
        }
        if let Some(agent) = participant.get("scheduleAgent").and_then(Value::as_str) {
            attendee.set_param("SCHEDULE-AGENT", agent.to_ascii_uppercase());
        }
        if participant.get("scheduleForceSend").and_then(Value::as_bool) == Some(true) {
            attendee.set_param("SCHEDULE-FORCE-SEND", "REQUEST");
        }
        if let Some(Value::Array(status)) = participant.get("scheduleStatus") {
            attendee.set_param_values(
                "SCHEDULE-STATUS",
                status.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect(),
            );
        }
        props.push(attendee);
    }
}

fn alarm_of(alert: &Value, object: &Object) -> Option<Component> {
    let alert = alert.as_object()?;
    let trigger = alert.get("trigger")?.as_object()?;
    let mut alarm = Component::new("VALARM");
    let extra: Vec<Property> = alert
        .get("iCalProps")
        .and_then(Value::as_array)
        .map(|e| e.iter().filter_map(prop_from_json).collect())
        .unwrap_or_default();
    let action = match str_of(alert, "action") {
        Some("email") => "EMAIL",
        _ if extra.iter().any(|p| p.is("ACTION")) => "",
        _ => "DISPLAY",
    };
    if !action.is_empty() {
        alarm.properties.push(Property::new("ACTION", action));
    }
    match str_of(trigger, "@type") {
        Some("AbsoluteTrigger") => {
            let when = trigger.get("when").and_then(Value::as_str).and_then(parse_utc)?;
            alarm.properties.push(
                Property::new("TRIGGER", format!("{}Z", time::format_date_time(TimeZone::UTC.to_datetime(when))))
                    .with_param("VALUE", "DATE-TIME"),
            );
        }
        _ => {
            let offset = trigger.get("offset").and_then(Value::as_str).and_then(Duration::parse)?;
            let mut property = Property::new("TRIGGER", offset.to_string());
            if str_of(trigger, "relativeTo") == Some("end") {
                property.set_param("RELATED", "END");
            }
            alarm.properties.push(property);
        }
    }
    if let Some(acknowledged) = str_of(alert, "acknowledged").and_then(parse_utc) {
        alarm.properties.push(Property::new(
            "ACKNOWLEDGED",
            format!("{}Z", time::format_date_time(TimeZone::UTC.to_datetime(acknowledged))),
        ));
    }
    let needs_description = action == "DISPLAY" || action == "EMAIL";
    let has_description = extra.iter().any(|p| p.is("DESCRIPTION"));
    alarm.properties.extend(extra);
    if needs_description && !has_description {
        alarm.properties.push(Property::text("DESCRIPTION", str_of(object, "title").unwrap_or("Reminder")));
    }
    if action == "EMAIL" && !alarm.properties.iter().any(|p| p.is("SUMMARY")) {
        alarm.properties.push(Property::text("SUMMARY", str_of(object, "title").unwrap_or("Reminder")));
    }
    Some(alarm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{expand, ical};

    fn round(text: &str) -> (Vec<Object>, Component) {
        let calendar = ical::parse(text).unwrap();
        let objects = from_icalendar(&calendar);
        let back = to_icalendar(&objects, "-//test//EN").unwrap();
        (objects, back)
    }

    #[test]
    fn an_event_and_its_overrides_go_both_ways() {
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\nBEGIN:VEVENT\r\nUID:s@example\r\n\
            DTSTAMP:20261001T080000Z\r\nDTSTART;TZID=Europe/Berlin:20261102T100000\r\nDTEND;TZID=Europe/Berlin:20261102T110000\r\n\
            RRULE:FREQ=WEEKLY;COUNT=4\r\nEXDATE;TZID=Europe/Berlin:20261116T100000\r\nSUMMARY:Weekly\r\nLOCATION:Room 1\r\n\
            ORGANIZER;CN=Alice:mailto:alice@example.org\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@example.org\r\n\
            ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION;ROLE=OPT-PARTICIPANT:mailto:bob@example.org\r\n\
            X-MOZ-GENERATION:3\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s@example\r\nDTSTAMP:20261001T080000Z\r\nRECURRENCE-ID;TZID=Europe/Berlin:20261109T100000\r\n\
            DTSTART;TZID=Europe/Berlin:20261110T110000\r\nDTEND;TZID=Europe/Berlin:20261110T120000\r\nSUMMARY:Moved\r\n\
            LOCATION:Room 1\r\nORGANIZER;CN=Alice:mailto:alice@example.org\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@example.org\r\n\
            ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION;ROLE=OPT-PARTICIPANT:mailto:bob@example.org\r\nX-MOZ-GENERATION:3\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Soon\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let (objects, back) = round(text);
        assert_eq!(objects.len(), 1);
        let event = &objects[0];
        assert_eq!(event["@type"], "Event");
        assert_eq!(event["start"], "2026-11-02T10:00:00");
        assert_eq!(event["timeZone"], "Europe/Berlin");
        assert_eq!(event["duration"], "PT1H");
        assert_eq!(event["recurrenceRule"], json!({ "@type": "RecurrenceRule", "frequency": "weekly", "count": 4 }));
        assert_eq!(event["organizerCalendarAddress"], "mailto:alice@example.org");
        let alice = &event["participants"]["alice-example-org"];
        assert_eq!(alice["roles"], json!({ "attendee": true, "owner": true }));
        assert_eq!(alice["name"], "Alice");
        let bob = &event["participants"]["bob-example-org"];
        assert_eq!(bob["expectReply"], true);
        assert_eq!(bob["roles"], json!({ "attendee": true, "optional": true }));
        assert_eq!(event["alerts"]["a1"]["trigger"]["offset"], "-PT15M");
        assert_eq!(event["iCalProps"], json!([["x-moz-generation", {}, "unknown", "3"]]));
        assert_eq!(
            event["recurrenceOverrides"],
            json!({
                "2026-11-16T10:00:00": { "excluded": true },
                "2026-11-09T10:00:00": { "start": "2026-11-10T11:00:00", "title": "Moved" },
            })
        );
        // Back: a time zone, an EXDATE and the override as a whole component.
        let text = back.to_string().replace("\r\n ", "");
        assert!(text.contains("BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin"), "{text}");
        assert!(text.contains("EXDATE;TZID=Europe/Berlin:20261116T100000"), "{text}");
        assert!(text.contains("RECURRENCE-ID;TZID=Europe/Berlin:20261109T100000"), "{text}");
        assert!(text.contains("DTEND;TZID=Europe/Berlin:20261110T120000"), "{text}");
        assert!(text.contains("ORGANIZER;CN=Alice:mailto:alice@example.org"), "{text}");
        assert!(
            text.contains("ATTENDEE;ROLE=OPT-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:bob@example.org"),
            "{text}"
        );
        assert!(text.contains("X-MOZ-GENERATION:3"), "{text}");
        // … and once more to JSCalendar, the same.
        assert_eq!(from_icalendar(&back)[0]["recurrenceOverrides"], event["recurrenceOverrides"]);
        let expansion = expand::expand(&back, &TimeZone::UTC, None, 10);
        assert_eq!(expansion.instances.len(), 3);
    }

    #[test]
    fn times_keep_their_kind() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261105T090000Z\r\nDURATION:PT1H\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:b\r\nDTSTART;VALUE=DATE:20261104\r\nRRULE:FREQ=YEARLY;UNTIL=20301104\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:c\r\nDTSTART:20261105T090000\r\nDTEND:20261106T100000\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:d\r\nDTSTART;TZID=America/New_York:20261101T090000\r\nRRULE:FREQ=DAILY;UNTIL=20261110T140000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let (objects, back) = round(text);
        assert_eq!(objects[0]["timeZone"], "Etc/UTC");
        assert_eq!(objects[1]["showWithoutTime"], true);
        assert_eq!(objects[1]["duration"], "P1D");
        assert_eq!(objects[1]["recurrenceRule"]["until"], "2030-11-04T00:00:00");
        assert!(objects[2].get("timeZone").is_none());
        assert_eq!(objects[2]["duration"], "P1DT1H");
        assert_eq!(objects[3]["recurrenceRule"]["until"], "2026-11-10T09:00:00");
        let text = back.to_string();
        assert!(text.contains("DTSTART:20261105T090000Z\r\nDTEND:20261105T100000Z"), "{text}");
        assert!(text.contains("DTSTART;VALUE=DATE:20261104\r\nDTEND;VALUE=DATE:20261105"), "{text}");
        assert!(text.contains("RRULE:FREQ=YEARLY;UNTIL=20301104"), "{text}");
        assert!(text.contains("DTSTART:20261105T090000\r\nDTEND:20261106T100000"), "{text}");
        assert!(text.contains("RRULE:FREQ=DAILY;UNTIL=20261110T140000Z"), "{text}");
        assert_eq!(text.matches("BEGIN:VTIMEZONE").count(), 1);
    }

    #[test]
    fn outlook_zones_become_iana_ones() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:W. Europe Standard Time\r\nBEGIN:STANDARD\r\nDTSTART:16010101T030000\r\n\
            TZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nRRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
            BEGIN:VEVENT\r\nUID:o\r\nDTSTART;TZID=W. Europe Standard Time:20261105T090000\r\n\
            DTEND;TZID=W. Europe Standard Time:20261105T093000\r\nX-MICROSOFT-CDO-BUSYSTATUS:BUSY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let (objects, back) = round(text);
        assert_eq!(objects[0]["timeZone"], "Europe/Berlin");
        assert_eq!(objects[0]["duration"], "PT30M");
        assert!(back.to_string().contains("DTSTART;TZID=Europe/Berlin:20261105T090000"));
        let custom = text.replace("W. Europe Standard Time", "Custom");
        let (objects, _) = round(&custom);
        assert_eq!(
            (objects[0]["start"].as_str(), objects[0]["timeZone"].as_str()),
            (Some("2026-11-05T08:00:00"), Some("Etc/UTC"))
        );
    }

    #[test]
    fn json_is_checked_and_completed() {
        let object = |value: Value| value.as_object().unwrap().clone();
        let made =
            to_icalendar(&[object(json!({ "@type": "Event", "title": "x", "start": "2026-11-02T10:00:00" }))], "p")
                .unwrap();
        let event = made.schedulable().next().unwrap();
        assert!(event.uid().is_some_and(|uid| uid.len() == 36));
        assert!(event.property("DTSTAMP").is_some());
        assert!(to_icalendar(&[object(json!({ "@type": "Event", "start": "2026-11-02" }))], "p").is_err());
        assert!(
            to_icalendar(
                &[object(json!({ "@type": "Event", "start": "2026-11-02T10:00:00", "timeZone": "Mars/Base" }))],
                "p"
            )
            .is_err()
        );
        assert!(to_icalendar(&[object(json!({ "@type": "Note" }))], "p").is_err());
        // An RDATE is an override without changes.
        let rdate =
            object(json!({ "@type": "Event", "uid": "r", "start": "2026-11-02T10:00:00", "timeZone": "Europe/Berlin",
            "recurrenceRule": { "frequency": "weekly" },
            "recurrenceOverrides": { "2026-11-04T15:00:00": {}, "2026-11-09T10:00:00": {} } }));
        let text = to_icalendar(&[rdate], "p").unwrap().to_string();
        assert!(text.contains("RDATE;TZID=Europe/Berlin:20261104T150000"), "{text}");
        assert!(!text.contains("20261109"), "{text}");
        // Tasks and their alerts, with the web app's nulls.
        let task = object(
            json!({ "@type": "Task", "uid": "t", "title": "Do", "due": "2026-11-05T12:00:00", "timeZone": "Europe/Berlin",
            "progress": "in-process", "percentComplete": 40, "description": null, "locations": null,
            "alerts": { "x": { "@type": "Alert", "trigger": { "@type": "OffsetTrigger", "offset": "-PT1H", "relativeTo": "end" } } } }),
        );
        let text = to_icalendar(&[task], "p").unwrap().to_string();
        assert!(text.contains("BEGIN:VTODO") && text.contains("DUE;TZID=Europe/Berlin:20261105T120000"), "{text}");
        assert!(text.contains("STATUS:IN-PROCESS") && text.contains("PERCENT-COMPLETE:40"), "{text}");
        assert!(text.contains("TRIGGER;RELATED=END:-PT1H") && text.contains("DESCRIPTION:Do"), "{text}");
        let back = from_icalendar(&ical::parse(&text).unwrap());
        assert_eq!(back[0]["due"], "2026-11-05T12:00:00");
        assert_eq!(back[0]["progress"], "in-process");
    }
}
