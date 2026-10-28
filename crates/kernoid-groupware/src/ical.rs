// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reading what clients send (RFC 0004, 3): an iCalendar object or a vCard, parsed by calcard, checked, and the
//! index kept in the clear worked out from it.

use calcard::{
    Entry, Parser,
    common::timezone::Tz,
    icalendar::{ICalendar, ICalendarComponentType, ICalendarProperty, dates::TimeOrDelta},
    vcard::{VCard, VCardProperty},
};
use chrono::{DateTime, Utc};

use crate::{GroupwareError, Result};

/// Largest iCalendar object or vCard accepted, in bytes (RFC 0004, 3).
pub const MAX_OBJECT_SIZE: usize = 1024 * 1024;

/// Most instances of a recurrence expanded for one object (RFC 0004, 3).
pub const MAX_INSTANCES: usize = 3000;

/// An event or task as a client sent it, with its index.
#[derive(Debug)]
pub struct ParsedEvent {
    pub ical: ICalendar,
    pub uid: String,
    /// `VEVENT`, `VTODO` or `VJOURNAL`.
    pub component: &'static str,
    /// From the start of the first instance to the end of the last; `None` above for a recurrence without end, and
    /// no span at all for an object without times (a task without dates).
    pub span: Option<(DateTime<Utc>, Option<DateTime<Utc>>)>,
    /// The organizer's address, lower case, without `mailto:`.
    pub organizer: Option<String>,
}

/// Parses and checks an iCalendar object for a calendar: one UID, one kind of component (RFC 4791, 4.1).
pub fn parse_event(text: &str, default_tz: Tz) -> Result<ParsedEvent> {
    if text.len() > MAX_OBJECT_SIZE {
        return Err(GroupwareError::TooLarge { limit: MAX_OBJECT_SIZE as u64 });
    }
    let ical = match Parser::new(text).entry() {
        Entry::ICalendar(ical) => ical,
        _ => return Err(GroupwareError::Invalid("not an iCalendar object".into())),
    };
    let mut uid: Option<&str> = None;
    let mut component = None;
    let mut organizer = None;
    for comp in &ical.components {
        let kind = match comp.component_type {
            ICalendarComponentType::VEvent => "VEVENT",
            ICalendarComponentType::VTodo => "VTODO",
            ICalendarComponentType::VJournal => "VJOURNAL",
            ICalendarComponentType::VFreebusy | ICalendarComponentType::VAvailability => {
                return Err(GroupwareError::Invalid("free/busy and availability are not stored".into()));
            }
            _ => continue,
        };
        if component.is_some_and(|known| known != kind) {
            return Err(GroupwareError::Invalid("an object holds one kind of component".into()));
        }
        component = Some(kind);
        match (uid, comp.uid()) {
            (_, None) => return Err(GroupwareError::Invalid("a component without UID".into())),
            (Some(known), Some(other)) if known != other => {
                return Err(GroupwareError::Invalid("an object holds one UID".into()));
            }
            (_, Some(other)) => uid = Some(other),
        }
        if organizer.is_none() {
            organizer = comp
                .property(&ICalendarProperty::Organizer)
                .and_then(|entry| entry.calendar_address())
                .map(|address| address.to_lowercase());
        }
    }
    let (Some(uid), Some(component)) = (uid, component) else {
        return Err(GroupwareError::Invalid("no event, task or journal entry".into()));
    };
    if uid.is_empty() || uid.len() > 255 {
        return Err(GroupwareError::Invalid("the UID must have 1 to 255 characters".into()));
    }
    let uid = uid.to_owned();
    let span = span(&ical, default_tz);
    Ok(ParsedEvent { ical, uid, component, span, organizer })
}

/// The time zone to expand an object's recurrences in. calcard 0.3.14 places the instances of a recurrence whose
/// start is in UTC (`…Z`, no `TZID`) in the default time zone, so that they move by an hour across a change of
/// daylight saving time; for such objects UTC is the default. OPEN: report to calcard.
pub fn expansion_tz(ical: &ICalendar, default_tz: Tz) -> Tz {
    use calcard::icalendar::{ICalendarParameterName, ICalendarValue};
    let utc_start = ical.components.iter().filter(|comp| comp.component_type.has_time_ranges()).any(|comp| {
        comp.property(&ICalendarProperty::Dtstart).is_some_and(|entry| {
            !entry.params.iter().any(|param| param.name == ICalendarParameterName::Tzid)
                && matches!(entry.values.first(), Some(ICalendarValue::PartialDateTime(date)) if date.tz_hour.is_some())
        })
    });
    if utc_start { Tz::UTC } else { default_tz }
}

/// The span of an object's instances (RFC 0004, 3).
pub fn span(ical: &ICalendar, default_tz: Tz) -> Option<(DateTime<Utc>, Option<DateTime<Utc>>)> {
    let expanded = ical.expand_dates(expansion_tz(ical, default_tz), MAX_INSTANCES);
    let endless = expanded.events.len() >= MAX_INSTANCES;
    let mut first: Option<DateTime<Utc>> = None;
    let mut last: Option<DateTime<Utc>> = None;
    for event in &expanded.events {
        let start = event.start.with_timezone(&Utc);
        let end = match &event.end {
            TimeOrDelta::Time(end) => end.with_timezone(&Utc),
            TimeOrDelta::Delta(delta) => start + *delta,
        };
        first = Some(first.map_or(start, |first| first.min(start)));
        last = Some(last.map_or(end, |last| last.max(end)));
    }
    let first = first?;
    Some((first, if endless { None } else { last.map(|last| last.max(first)) }))
}

/// The time zone named by a calendar, or UTC.
pub fn time_zone(name: Option<&str>) -> Tz {
    name.and_then(|name| name.parse::<chrono_tz::Tz>().ok()).map_or(Tz::UTC, Tz::from)
}

/// A contact as a client sent it, with its index.
#[derive(Debug)]
pub struct ParsedContact {
    pub card: VCard,
    pub uid: String,
    /// `individual`, `group`, `org`, `location` or another `KIND`, lower case.
    pub kind: String,
    /// Lower case.
    pub emails: Vec<String>,
}

/// Parses and checks a vCard for an address book: exactly one, with a UID (RFC 6352, 5.1).
pub fn parse_contact(text: &str) -> Result<ParsedContact> {
    if text.len() > MAX_OBJECT_SIZE {
        return Err(GroupwareError::TooLarge { limit: MAX_OBJECT_SIZE as u64 });
    }
    let mut parser = Parser::new(text);
    let card = match parser.entry() {
        Entry::VCard(card) => card,
        _ => return Err(GroupwareError::Invalid("not a vCard".into())),
    };
    if !matches!(parser.entry(), Entry::Eof) {
        return Err(GroupwareError::Invalid("a resource holds one vCard".into()));
    }
    let text_of = |property: &VCardProperty| {
        card.property(property).and_then(|entry| entry.values.first()).and_then(|value| value.as_text())
    };
    let uid = text_of(&VCardProperty::Uid)
        .map(str::to_owned)
        .ok_or_else(|| GroupwareError::Invalid("a vCard without UID".into()))?;
    if uid.is_empty() || uid.len() > 255 {
        return Err(GroupwareError::Invalid("the UID must have 1 to 255 characters".into()));
    }
    let kind = text_of(&VCardProperty::Kind).map_or_else(|| "individual".to_owned(), str::to_lowercase);
    let mut emails: Vec<String> = card
        .properties(&VCardProperty::Email)
        .filter_map(|entry| entry.values.first().and_then(|value| value.as_text()))
        .map(|email| email.trim().to_lowercase())
        .filter(|email| !email.is_empty())
        .collect();
    emails.sort();
    emails.dedup();
    Ok(ParsedContact { card, uid, kind, emails })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEEKLY: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:a@example\r\n\
        DTSTAMP:20261001T080000Z\r\nDTSTART:20261005T090000Z\r\nDTEND:20261005T100000Z\r\n\
        RRULE:FREQ=WEEKLY;COUNT=3\r\nORGANIZER:mailto:Alice@Example.org\r\nSUMMARY:Weekly\r\nEND:VEVENT\r\n\
        END:VCALENDAR\r\n";

    #[test]
    fn events_are_checked_and_indexed() {
        let event = parse_event(WEEKLY, Tz::UTC).unwrap();
        assert_eq!(event.uid, "a@example");
        assert_eq!(event.component, "VEVENT");
        assert_eq!(event.organizer.as_deref(), Some("alice@example.org"));
        let (start, end) = event.span.unwrap();
        assert_eq!(start.to_rfc3339(), "2026-10-05T09:00:00+00:00");
        assert_eq!(end.unwrap().to_rfc3339(), "2026-10-19T10:00:00+00:00");

        let endless = WEEKLY.replace(";COUNT=3", "");
        assert_eq!(parse_event(&endless, Tz::UTC).unwrap().span.unwrap().1, None);

        // A UTC start keeps its time across the change of daylight saving time on 2026-10-25.
        let berlin = time_zone(Some("Europe/Berlin"));
        let endless = parse_event(&WEEKLY.replace("COUNT=3", "COUNT=10"), berlin).unwrap();
        assert_eq!(endless.span.unwrap().1.unwrap().to_rfc3339(), "2026-12-07T10:00:00+00:00");

        let floating = WEEKLY.replace("T090000Z", "T090000").replace("T100000Z", "T100000");
        let start = parse_event(&floating, berlin).unwrap().span.unwrap().0;
        assert_eq!(start.to_rfc3339(), "2026-10-05T07:00:00+00:00");

        let two_uids = WEEKLY.replace(
            "END:VCALENDAR",
            "BEGIN:VEVENT\r\nUID:b@example\r\nDTSTART:20261005T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR",
        );
        assert!(matches!(parse_event(&two_uids, Tz::UTC), Err(GroupwareError::Invalid(_))));
        assert!(parse_event("BEGIN:VCARD\r\nEND:VCARD\r\n", Tz::UTC).is_err());
    }

    #[test]
    fn contacts_are_checked_and_indexed() {
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:1\r\nFN:Bob\r\nEMAIL:Bob@Example.org\r\n\
            EMAIL;TYPE=work:bob@work.example\r\nEND:VCARD\r\n";
        let contact = parse_contact(card).unwrap();
        assert_eq!(contact.uid, "urn:uuid:1");
        assert_eq!(contact.kind, "individual");
        assert_eq!(contact.emails, ["bob@example.org", "bob@work.example"]);
        assert!(parse_contact(&format!("{card}{card}")).is_err());
        assert!(parse_contact(&card.replace("UID:urn:uuid:1\r\n", "")).is_err());
    }
}
