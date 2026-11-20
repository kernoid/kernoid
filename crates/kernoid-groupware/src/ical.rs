// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reading what clients send (RFC 0004, 3): an iCalendar object or a vCard, parsed by kernoid-pim, checked, and the
//! index kept in the clear worked out from it.

use jiff::{Timestamp, tz::TimeZone};
use kernoid_pim::{
    Component, expand, ical,
    vcard::{self, VCard},
};

use crate::{GroupwareError, Result};

/// Largest iCalendar object or vCard accepted, in bytes (RFC 0004, 3).
pub const MAX_OBJECT_SIZE: usize = 1024 * 1024;

/// Most instances of a recurrence expanded for one object (RFC 0004, 3).
pub const MAX_INSTANCES: usize = 3000;

/// An event or task as a client sent it, with its index.
#[derive(Debug)]
pub struct ParsedEvent {
    pub ical: Component,
    pub uid: String,
    /// `VEVENT`, `VTODO` or `VJOURNAL`.
    pub component: &'static str,
    /// From the start of the first instance to the end of the last; `None` above for a recurrence without end, and
    /// no span at all for an object without times (a task without dates).
    pub span: Option<(Timestamp, Option<Timestamp>)>,
    /// The organizer's address, lower case, without `mailto:`.
    pub organizer: Option<String>,
}

/// Parses and checks an iCalendar object for a calendar: one UID, one kind of component (RFC 4791, 4.1).
pub fn parse_event(text: &str, default_tz: TimeZone) -> Result<ParsedEvent> {
    if text.len() > MAX_OBJECT_SIZE {
        return Err(GroupwareError::TooLarge { limit: MAX_OBJECT_SIZE as u64 });
    }
    let ical = ical::parse(text).map_err(|_| GroupwareError::Invalid("not an iCalendar object".into()))?;
    let mut uid: Option<String> = None;
    let mut component = None;
    let mut organizer = None;
    for comp in &ical.components {
        let kind = match comp.name.as_str() {
            "VEVENT" => "VEVENT",
            "VTODO" => "VTODO",
            "VJOURNAL" => "VJOURNAL",
            "VFREEBUSY" | "VAVAILABILITY" => {
                return Err(GroupwareError::Invalid("free/busy and availability are not stored".into()));
            }
            _ => continue,
        };
        if component.is_some_and(|known| known != kind) {
            return Err(GroupwareError::Invalid("an object holds one kind of component".into()));
        }
        component = Some(kind);
        match (&uid, comp.uid()) {
            (_, None) => return Err(GroupwareError::Invalid("a component without UID".into())),
            (Some(known), Some(other)) if *known != other => {
                return Err(GroupwareError::Invalid("an object holds one UID".into()));
            }
            (_, Some(other)) => uid = Some(other),
        }
        if organizer.is_none() {
            organizer =
                comp.property("ORGANIZER").and_then(|entry| entry.address()).map(|address| address.to_lowercase());
        }
    }
    let (Some(uid), Some(component)) = (uid, component) else {
        return Err(GroupwareError::Invalid("no event, task or journal entry".into()));
    };
    if uid.is_empty() || uid.len() > 255 {
        return Err(GroupwareError::Invalid("the UID must have 1 to 255 characters".into()));
    }
    let span = span(&ical, &default_tz);
    Ok(ParsedEvent { ical, uid, component, span, organizer })
}

/// The span of an object's instances (RFC 0004, 3).
pub fn span(ical: &Component, default_tz: &TimeZone) -> Option<(Timestamp, Option<Timestamp>)> {
    let expanded = expand::expand(ical, default_tz, None, MAX_INSTANCES);
    let first = expanded.instances.iter().map(|instance| instance.start).min()?;
    let last = expanded.instances.iter().map(|instance| instance.end).max().unwrap_or(first);
    Some((first, if expanded.complete { Some(last.max(first)) } else { None }))
}

/// The time zone named by a calendar, or UTC.
pub fn time_zone(name: Option<&str>) -> TimeZone {
    name.and_then(kernoid_pim::tz::iana).unwrap_or(TimeZone::UTC)
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
    let card = match vcard::parse_all(text) {
        Ok(mut cards) if cards.len() == 1 => cards.remove(0),
        Ok(cards) if cards.len() > 1 => return Err(GroupwareError::Invalid("a resource holds one vCard".into())),
        _ => return Err(GroupwareError::Invalid("not a vCard".into())),
    };
    let uid = card.uid().ok_or_else(|| GroupwareError::Invalid("a vCard without UID".into()))?;
    if uid.len() > 255 {
        return Err(GroupwareError::Invalid("the UID must have 1 to 255 characters".into()));
    }
    let kind = card
        .text("KIND")
        .or_else(|| card.text("X-ADDRESSBOOKSERVER-KIND"))
        .map_or_else(|| "individual".to_owned(), |kind| kind.trim().to_lowercase());
    let mut emails: Vec<String> = card
        .properties("EMAIL")
        .map(|entry| entry.as_text().trim().to_lowercase())
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
        let event = parse_event(WEEKLY, TimeZone::UTC).unwrap();
        assert_eq!(event.uid, "a@example");
        assert_eq!(event.component, "VEVENT");
        assert_eq!(event.organizer.as_deref(), Some("alice@example.org"));
        let (start, end) = event.span.unwrap();
        assert_eq!(start.to_string(), "2026-10-05T09:00:00Z");
        assert_eq!(end.unwrap().to_string(), "2026-10-19T10:00:00Z");

        let endless = WEEKLY.replace(";COUNT=3", "");
        assert_eq!(parse_event(&endless, TimeZone::UTC).unwrap().span.unwrap().1, None);

        // A UTC start keeps its time across the change of daylight saving time on 2026-10-25.
        let berlin = time_zone(Some("Europe/Berlin"));
        let endless = parse_event(&WEEKLY.replace("COUNT=3", "COUNT=10"), berlin.clone()).unwrap();
        assert_eq!(endless.span.unwrap().1.unwrap().to_string(), "2026-12-07T10:00:00Z");

        let floating = WEEKLY.replace("T090000Z", "T090000").replace("T100000Z", "T100000");
        let start = parse_event(&floating, berlin).unwrap().span.unwrap().0;
        assert_eq!(start.to_string(), "2026-10-05T07:00:00Z");

        let two_uids = WEEKLY.replace(
            "END:VCALENDAR",
            "BEGIN:VEVENT\r\nUID:b@example\r\nDTSTART:20261005T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR",
        );
        assert!(matches!(parse_event(&two_uids, TimeZone::UTC), Err(GroupwareError::Invalid(_))));
        assert!(parse_event("BEGIN:VCARD\r\nEND:VCARD\r\n", TimeZone::UTC).is_err());
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
