// SPDX-License-Identifier: MIT
//! Calendars over JMAP (draft-ietf-jmap-calendars): the calendars of every account the user reaches, the
//! instances of their events in a window of time, as JSCalendar; events made, changed and removed, and invitations
//! answered – with `sendSchedulingMessages`, so participants hear of it (iTIP).

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CALENDARS, Client, Error, Result, ids_of};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Calendar {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub is_visible: Option<bool>,
    #[serde(default)]
    pub my_rights: Option<CalendarRights>,
    /// The account it belongs to (not from the server).
    #[serde(skip)]
    pub account: String,
    /// The name of the account, for calendars shared with the user (not from the server).
    #[serde(skip)]
    pub shared: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CalendarRights {
    pub may_write_all: bool,
    #[serde(rename = "mayRSVP")]
    pub may_rsvp: bool,
}

impl Calendar {
    /// Whether events may be made in it; without rights given, yes.
    pub fn writable(&self) -> bool {
        self.my_rights.is_none_or(|rights| rights.may_write_all)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub calendar_address: Option<String>,
    #[serde(default)]
    pub participation_status: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Location {
    #[serde(default)]
    pub name: Option<String>,
}

/// An event, or one instance of a recurring one.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub id: String,
    /// For an instance of a recurring event: the event it is of – changes go there.
    #[serde(default)]
    pub base_event_id: Option<String>,
    /// For an instance: which one of its event's it is – where it would start but for an override.
    #[serde(default)]
    pub recurrence_id: Option<String>,
    /// For a recurring event: its instances changed or left out, by recurrence id (RFC 8984, 4.3.5).
    #[serde(default)]
    pub recurrence_overrides: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub organizer_calendar_address: Option<String>,
    /// `confirmed`, `tentative` or `cancelled` – an invitation the organizer called off stays, cancelled.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub calendar_ids: BTreeMap<String, bool>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub time_zone: Option<String>,
    #[serde(default)]
    pub duration: Option<String>,
    #[serde(default)]
    pub show_without_time: bool,
    #[serde(default)]
    pub utc_start: Option<String>,
    #[serde(default)]
    pub utc_end: Option<String>,
    #[serde(default)]
    pub recurrence_rule: Option<Value>,
    #[serde(default)]
    pub locations: Option<BTreeMap<String, Location>>,
    #[serde(default)]
    pub participants: Option<BTreeMap<String, Participant>>,
    #[serde(skip)]
    pub account: String,
}

impl Event {
    /// When it starts, in UTC: `utcStart`, or the start of an all-day event.
    pub fn starts(&self) -> Option<DateTime<Utc>> {
        if let Some(start) = self.utc_start.as_deref().and_then(|s| DateTime::parse_from_rfc3339(s).ok()) {
            return Some(start.with_timezone(&Utc));
        }
        let start = self.start.as_deref()?;
        chrono::NaiveDateTime::parse_from_str(start, "%Y-%m-%dT%H:%M:%S").ok().map(|naive| naive.and_utc())
    }

    pub fn ends(&self) -> Option<DateTime<Utc>> {
        self.utc_end.as_deref().and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|end| end.with_timezone(&Utc))
    }

    pub fn is_cancelled(&self) -> bool {
        self.status.as_deref() == Some("cancelled")
    }

    /// The id changes go to: the event an instance is of, or the event itself.
    pub fn event_id(&self) -> &str {
        self.base_event_id.as_deref().unwrap_or(&self.id)
    }

    /// The participant that is the user – by one of their addresses –, with its key.
    pub fn me<'a>(&'a self, addresses: &[String]) -> Option<(&'a str, &'a Participant)> {
        self.participants.as_ref()?.iter().map(|(key, p)| (key.as_str(), p)).find(|(_, participant)| {
            let address = participant.calendar_address.as_deref().unwrap_or_default();
            let address = address.strip_prefix("mailto:").unwrap_or(address);
            addresses.iter().any(|own| own.eq_ignore_ascii_case(address))
        })
    }

    /// Whether the user organizes it (or nobody does: an event without participants).
    pub fn organized_by(&self, addresses: &[String]) -> bool {
        match self.organizer_calendar_address.as_deref() {
            None => true,
            Some(organizer) => {
                let organizer = organizer.strip_prefix("mailto:").unwrap_or(organizer);
                addresses.iter().any(|own| own.eq_ignore_ascii_case(organizer))
            }
        }
    }

    pub fn location(&self) -> Option<String> {
        let names: Vec<_> = self.locations.as_ref()?.values().filter_map(|location| location.name.clone()).collect();
        (!names.is_empty()).then(|| names.join(", "))
    }
}

#[derive(Deserialize)]
struct List<T> {
    list: Vec<T>,
}

fn list<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> Result<Vec<T>> {
    let value = value.cloned().unwrap_or(json!({ "list": [] }));
    serde_json::from_value::<List<T>>(value).map(|list| list.list).map_err(|error| Error::Protocol(error.to_string()))
}

/// The user's calendars and those shared with them.
pub fn calendars(client: &Client) -> Result<Vec<Calendar>> {
    let mut out = Vec::new();
    for (id, account) in client.session.accounts_with(CALENDARS) {
        let result = client.call(&[CALENDARS], "Calendar/get", json!({ "accountId": id }))?;
        for mut calendar in list::<Calendar>(Some(&result))? {
            calendar.account = id.to_owned();
            calendar.shared = (!account.is_personal).then(|| account.name.clone());
            out.push(calendar);
        }
    }
    Ok(out)
}

fn utc(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// One event as stored – for an instance, the recurring event it is of.
pub fn event(client: &Client, account: &str, id: &str) -> Result<Option<Event>> {
    let result = client.call(&[CALENDARS], "CalendarEvent/get", json!({ "accountId": account, "ids": [id] }))?;
    Ok(list::<Event>(Some(&result))?.into_iter().next().map(|mut event| {
        event.account = account.to_owned();
        event
    }))
}

/// The instances of the events of `calendars` between `after` and `before`, by start.
pub fn instances(
    client: &Client,
    calendars: &[Calendar],
    after: DateTime<Utc>,
    before: DateTime<Utc>,
) -> Result<Vec<Event>> {
    let mut accounts: Vec<&str> = calendars.iter().map(|calendar| calendar.account.as_str()).collect();
    accounts.dedup();
    let mut out = Vec::new();
    for account in accounts {
        let visible: Vec<&str> = calendars
            .iter()
            .filter(|calendar| calendar.account == account && calendar.is_visible.unwrap_or(true))
            .map(|calendar| calendar.id.as_str())
            .collect();
        let responses = client.request(
            &[CALENDARS],
            vec![
                (
                    "CalendarEvent/query",
                    json!({
                        "accountId": account, "expandRecurrences": true,
                        "filter": { "after": utc(after), "before": utc(before) },
                    }),
                    "q",
                ),
                ("CalendarEvent/get", json!({ "accountId": account, "#ids": ids_of("q", "CalendarEvent/query") }), "g"),
            ],
        )?;
        for mut event in list::<Event>(responses.get("g"))? {
            if event.calendar_ids.keys().any(|id| visible.contains(&id.as_str())) {
                event.account = account.to_owned();
                out.push(event);
            }
        }
    }
    out.sort_by_key(Event::starts);
    Ok(out)
}

/// An ISO 8601 duration as JSCalendar writes it (`PT1H30M`, `P1D`, `P2W`, `P1DT2H`), in seconds.
pub fn parse_duration(text: &str) -> Option<i64> {
    let text = text.strip_prefix('P')?;
    let (date, time) = text.split_once('T').unwrap_or((text, ""));
    let mut seconds = 0i64;
    let mut take = |part: &str, units: &[(char, i64)]| -> Option<()> {
        let mut number = String::new();
        for c in part.chars() {
            if c.is_ascii_digit() {
                number.push(c);
            } else {
                let factor = units.iter().find(|(unit, _)| *unit == c)?.1;
                seconds += number.parse::<i64>().ok()? * factor;
                number.clear();
            }
        }
        number.is_empty().then_some(())
    };
    take(date, &[('W', 7 * 86_400), ('D', 86_400)])?;
    take(time, &[('H', 3_600), ('M', 60), ('S', 1)])?;
    Some(seconds)
}

/// Seconds as a JSCalendar duration: `PT1H30M`, `P1D`, `PT0M`.
pub fn format_duration(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (hours, minutes) = (rest / 3_600, rest % 3_600 / 60);
    let mut out = String::from("P");
    if days > 0 {
        out.push_str(&format!("{days}D"));
    }
    if hours > 0 || minutes > 0 || days == 0 {
        out.push('T');
        if hours > 0 {
            out.push_str(&format!("{hours}H"));
        }
        if minutes > 0 || hours == 0 {
            out.push_str(&format!("{minutes}M"));
        }
    }
    out
}

/// How often an event repeats, as the app offers it.
pub const FREQUENCIES: [&str; 4] = ["daily", "weekly", "monthly", "yearly"];

/// An event as the user writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventForm {
    pub title: String,
    pub all_day: bool,
    /// Local times in `time_zone`; for all-day events the days (the end is the last day).
    pub start: NaiveDateTime,
    pub end: NaiveDateTime,
    pub time_zone: Option<String>,
    pub location: String,
    pub description: String,
    /// Addresses of the people invited, besides the user.
    pub participants: Vec<String>,
    /// `daily`, `weekly`, `monthly`, `yearly` or none.
    pub repeat: Option<String>,
    /// For an event changed: the answers participants gave (address, status) and when it was – the answers stay
    /// while the time does (RFC 5546, 2.1.4: a new time asks again).
    pub answers: Vec<(String, String)>,
    pub was: Option<(NaiveDateTime, NaiveDateTime, bool)>,
}

impl EventForm {
    /// The form of an event, to change it.
    pub fn of(event: &Event, own: &[String]) -> Option<Self> {
        let start = NaiveDateTime::parse_from_str(event.start.as_deref()?, "%Y-%m-%dT%H:%M:%S").ok()?;
        let seconds = event.duration.as_deref().and_then(parse_duration).unwrap_or(if event.show_without_time {
            86_400
        } else {
            3_600
        });
        let mut end = start + chrono::Duration::seconds(seconds);
        if event.show_without_time {
            end -= chrono::Duration::days(1);
        }
        let participants = event
            .participants
            .iter()
            .flat_map(|map| map.values())
            .filter_map(|p| p.calendar_address.as_deref())
            .map(|address| address.strip_prefix("mailto:").unwrap_or(address).to_owned())
            .filter(|address| !own.iter().any(|o| o.eq_ignore_ascii_case(address)))
            .collect();
        let answers = event
            .participants
            .iter()
            .flat_map(|map| map.values())
            .filter_map(|p| {
                let address = p.calendar_address.as_deref()?;
                let address = address.strip_prefix("mailto:").unwrap_or(address).to_lowercase();
                Some((address, p.participation_status.clone()?))
            })
            .collect();
        let repeat = event
            .recurrence_rule
            .as_ref()
            .and_then(|rule| rule.get("frequency"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        Some(Self {
            title: event.title.clone().unwrap_or_default(),
            all_day: event.show_without_time,
            start,
            end,
            time_zone: event.time_zone.clone(),
            location: event.location().unwrap_or_default(),
            description: event.description.clone().unwrap_or_default(),
            participants,
            repeat,
            answers,
            was: Some((start, end, event.show_without_time)),
        })
    }

    /// The JSCalendar object (without `calendarIds`); `own` is the organizer's address.
    pub fn object(&self, own: &str) -> Value {
        let (start, seconds) = if self.all_day {
            let days = (self.end.date() - self.start.date()).num_days().max(0) + 1;
            (self.start.date().and_hms_opt(0, 0, 0).unwrap_or(self.start), days * 86_400)
        } else {
            (self.start, (self.end - self.start).num_seconds())
        };
        let mut value = json!({
            "@type": "Event",
            "title": self.title,
            "start": start.format("%Y-%m-%dT%H:%M:%S").to_string(),
            "duration": format_duration(seconds),
            "showWithoutTime": self.all_day,
            "timeZone": if self.all_day { Value::Null } else { json!(self.time_zone) },
            "description": if self.description.is_empty() { Value::Null } else { json!(self.description) },
            "locations": if self.location.is_empty() { Value::Null } else {
                json!({ "l1": { "@type": "Location", "name": self.location } })
            },
            "recurrenceRule": match &self.repeat {
                Some(frequency) => json!({ "@type": "RecurrenceRule", "frequency": frequency }),
                None => Value::Null,
            },
            "participants": Value::Null,
            "organizerCalendarAddress": Value::Null,
        });
        let others: Vec<String> = self
            .participants
            .iter()
            .map(|address| address.trim().to_lowercase())
            .filter(|address| !address.is_empty() && !address.eq_ignore_ascii_case(own))
            .collect();
        if !others.is_empty() {
            let mut participants = serde_json::Map::new();
            participants.insert(
                "p0".into(),
                json!({ "calendarAddress": format!("mailto:{own}"), "roles": { "owner": true, "attendee": true },
                        "participationStatus": "accepted" }),
            );
            let same_time = self.was == Some((self.start, self.end, self.all_day));
            for (index, address) in others.iter().enumerate() {
                let status = self
                    .answers
                    .iter()
                    .find(|(known, _)| same_time && known == address)
                    .map_or("needs-action", |(_, status)| status.as_str());
                participants.insert(
                    format!("p{}", index + 1),
                    json!({ "calendarAddress": format!("mailto:{address}"), "roles": { "attendee": true },
                            "participationStatus": status, "expectReply": true }),
                );
            }
            value["participants"] = Value::Object(participants);
            value["organizerCalendarAddress"] = json!(format!("mailto:{own}"));
        }
        value
    }
}

const SCHEDULE: &str = "sendSchedulingMessages";

/// Makes an event in a calendar; its id.
pub fn create(client: &Client, calendar: &Calendar, form: &EventForm, own: &str) -> Result<String> {
    let mut object = form.object(own);
    object["calendarIds"] = json!({ calendar.id.as_str(): true });
    let result = client.set(
        &[CALENDARS],
        "CalendarEvent",
        &calendar.account,
        json!({ "create": { "e": object } }),
        json!({ SCHEDULE: true }),
    )?;
    result
        .pointer("/created/e/id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Protocol("the event has no id".into()))
}

/// Changes an event (all instances of a recurring one), and moves it to `calendar`.
pub fn update(client: &Client, calendar: &Calendar, id: &str, form: &EventForm, own: &str) -> Result<()> {
    let mut object = form.object(own);
    object["calendarIds"] = json!({ calendar.id.as_str(): true });
    let change = json!({ "update": { id: object } });
    client.set(&[CALENDARS], "CalendarEvent", &calendar.account, change, json!({ SCHEDULE: true }))?;
    Ok(())
}

/// What an instance of a series may differ in from its series.
const OVERRIDDEN: [&str; 6] = ["title", "start", "duration", "showWithoutTime", "description", "locations"];

/// Changes one instance of `series`: its override in the event's `recurrenceOverrides`.
pub fn update_instance(
    client: &Client,
    series: &Event,
    recurrence_id: &str,
    form: &EventForm,
    own: &str,
) -> Result<()> {
    let whole = form.object(own);
    let mut patch: serde_json::Map<String, Value> =
        OVERRIDDEN.iter().map(|key| ((*key).to_owned(), whole[*key].clone())).collect();
    if whole["timeZone"] != json!(series.time_zone) {
        patch.insert("timeZone".into(), whole["timeZone"].clone());
    }
    override_instance(client, series, recurrence_id, Value::Object(patch))
}

/// Leaves one instance of `series` out.
pub fn destroy_instance(client: &Client, series: &Event, recurrence_id: &str) -> Result<()> {
    override_instance(client, series, recurrence_id, json!({ "excluded": true }))
}

fn override_instance(client: &Client, series: &Event, recurrence_id: &str, patch: Value) -> Result<()> {
    let mut overrides = series.recurrence_overrides.clone().unwrap_or_default();
    overrides.insert(recurrence_id.to_owned(), patch);
    let change = json!({ "update": { series.id.as_str(): { "recurrenceOverrides": overrides } } });
    client.set(&[CALENDARS], "CalendarEvent", &series.account, change, json!({ SCHEDULE: true }))?;
    Ok(())
}

/// Removes an event (all instances of a recurring one).
pub fn destroy(client: &Client, account: &str, id: &str) -> Result<()> {
    client.set(&[CALENDARS], "CalendarEvent", account, json!({ "destroy": [id] }), json!({ SCHEDULE: true }))?;
    Ok(())
}

/// Answers an invitation: the participant `key` (the user) gets `status` – `accepted`, `tentative` or `declined`.
pub fn answer(client: &Client, account: &str, id: &str, key: &str, status: &str) -> Result<()> {
    let path = format!("participants/{key}/participationStatus");
    let change = json!({ "update": { id: { path: status } } });
    client.set(&[CALENDARS], "CalendarEvent", account, change, json!({ SCHEDULE: true }))?;
    Ok(())
}

/// The time zone of this machine (IANA name), for the events the user makes.
pub fn local_time_zone() -> Option<String> {
    iana_time_zone::get_timezone().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("PT1H30M"), Some(5_400));
        assert_eq!(parse_duration("P1D"), Some(86_400));
        assert_eq!(parse_duration("P1W"), Some(604_800));
        assert_eq!(parse_duration("P1DT2H"), Some(93_600));
        assert_eq!(parse_duration("1H"), None);
        assert_eq!(parse_duration("PT1X"), None);
        assert_eq!(format_duration(5_400), "PT1H30M");
        assert_eq!(format_duration(3_600), "PT1H");
        assert_eq!(format_duration(172_800), "P2D");
        assert_eq!(format_duration(0), "PT0M");
    }

    #[test]
    fn forms() {
        let at = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap();
        let form = EventForm {
            title: "Plans".into(),
            all_day: false,
            start: at("2026-10-29 10:00"),
            end: at("2026-10-29 11:30"),
            time_zone: Some("Europe/Berlin".into()),
            location: "Room 1".into(),
            description: String::new(),
            participants: vec!["Bob@x.example".into(), "me@x.example".into()],
            repeat: Some("weekly".into()),
            answers: vec![("bob@x.example".into(), "accepted".into())],
            was: Some((at("2026-10-29 10:00"), at("2026-10-29 11:30"), false)),
        };
        // The time stays: Bob's answer too; a new time asks again.
        assert_eq!(form.object("me@x.example")["participants"]["p1"]["participationStatus"], "accepted");
        let moved = EventForm { start: at("2026-10-29 10:30"), ..form.clone() };
        assert_eq!(moved.object("me@x.example")["participants"]["p1"]["participationStatus"], "needs-action");
        let object = form.object("me@x.example");
        assert_eq!(object["start"], "2026-10-29T10:00:00");
        assert_eq!(object["duration"], "PT1H30M");
        assert_eq!(object["timeZone"], "Europe/Berlin");
        assert_eq!(object["recurrenceRule"]["frequency"], "weekly");
        assert_eq!(object["participants"]["p1"]["calendarAddress"], "mailto:bob@x.example");
        assert!(object["participants"].get("p2").is_none());
        assert_eq!(object["organizerCalendarAddress"], "mailto:me@x.example");
        let all_day = EventForm { all_day: true, end: at("2026-10-30 00:00"), participants: vec![], ..form };
        let object = all_day.object("me@x.example");
        assert_eq!((object["duration"].as_str(), object["timeZone"].clone()), (Some("P2D"), Value::Null));
        assert_eq!(object["participants"], Value::Null);
    }
}
