// SPDX-License-Identifier: AGPL-3.0-or-later
//! JSCalendar (RFC 8984) and JSContact (RFC 9553) as JMAP shows them (RFC 0004, 8.2): the stored iCalendar and vCard
//! converted by kernoid-pim, and back. Patches of `*/set` (RFC 8620, 5.3) apply to the JSON.

use kernoid_pim::{ical, jscalendar, jscontact, vcard};
use serde_json::{Map, Value};

/// A vCard as a JSContact Card object.
pub(crate) fn card_to_json(text: &str) -> Option<Map<String, Value>> {
    let card = vcard::parse(text).ok()?;
    Some(jscontact::from_vcard(&card))
}

/// The words of a vCard to search in: the text values of its properties, lower-cased – not the property names, nor
/// the values of UID, PRODID, REV and VERSION, which say nothing about the person, nor inline media.
pub(crate) fn card_text(text: &str) -> String {
    let Ok(card) = vcard::parse(text) else { return String::new() };
    let mut words = String::new();
    for property in &card.properties {
        if ["UID", "PRODID", "REV", "VERSION", "PHOTO", "LOGO", "SOUND", "KEY"].iter().any(|name| property.is(name)) {
            continue;
        }
        let fields: Vec<String> = property.fields().into_iter().filter(|field| !field.is_empty()).collect();
        words.push_str(&fields.join(" "));
        words.push('\n');
    }
    words.to_lowercase()
}

/// A JSContact Card object as a vCard 4.0.
pub(crate) fn json_to_card(object: &Map<String, Value>) -> Result<String, String> {
    let card = jscontact::to_vcard(object).map_err(|error| error.to_string())?;
    Ok(card.write(vcard::Version::V4_0))
}

/// An iCalendar object as a JSCalendar object (an Event, a Task, or a Group of them).
pub(crate) fn event_to_json(text: &str) -> Option<Map<String, Value>> {
    let calendar = ical::parse(text).ok()?;
    let mut objects = jscalendar::from_icalendar(&calendar);
    // One object holds one event and its exceptions (RFC 0004, 4): the event itself, not a group of one.
    match objects.len() {
        0 => None,
        1 => objects.pop(),
        _ => Some(jscalendar::group(objects, calendar.text("PRODID").as_deref())),
    }
}

/// A JSCalendar object (or a `Group`) as an iCalendar object.
pub(crate) fn json_to_event(object: &Map<String, Value>) -> Result<String, String> {
    // A start that is not a LocalDateTime is refused, not dropped.
    if let Some(start) = object.get("start")
        && !start.as_str().is_some_and(is_local_date_time)
    {
        return Err("start: a LocalDateTime, e.g. 2026-11-02T00:00:00".into());
    }
    let calendar = jscalendar::to_icalendar(std::slice::from_ref(object), kernoid_groupware::PROD_ID)
        .map_err(|error| error.to_string())?;
    Ok(calendar.to_string())
}

/// Applies a patch (RFC 8620, 5.3): keys are JSON pointers, `null` removes.
pub(crate) fn patch(object: &mut Map<String, Value>, patch: &Map<String, Value>) -> Result<(), String> {
    kernoid_pim::jmap::patch(object, patch).map_err(|error| error.to_string())
}

/// `YYYY-MM-DDTHH:MM:SS` with an optional fraction – JSCalendar's LocalDateTime (RFC 8984, 1.4.4).
fn is_local_date_time(text: &str) -> bool {
    let (main, fraction) = text.split_once('.').unwrap_or((text, ""));
    jiff::civil::DateTime::strptime("%Y-%m-%dT%H:%M:%S", main).is_ok() && fraction.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_must_be_a_local_date_time() {
        let event = |start: Value| {
            let mut object = Map::new();
            object.insert("@type".into(), "Event".into());
            object.insert("uid".into(), "u".into());
            object.insert("title".into(), "Holiday".into());
            object.insert("start".into(), start);
            object
        };
        assert!(json_to_event(&event("2026-11-02".into())).is_err());
        assert!(json_to_event(&event("2026-11-02T10:00:00Z".into())).is_err());
        assert!(json_to_event(&event(Value::Null)).is_err());
        assert!(json_to_event(&event("2026-11-02T00:00:00".into())).is_ok());
    }

    #[test]
    fn cards_and_events_go_both_ways() {
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:1\r\nFN:Carol Example\r\nEMAIL:carol@example.org\r\nEND:VCARD\r\n";
        let mut json = card_to_json(card).unwrap();
        assert_eq!(json["uid"], "urn:uuid:1");
        patch(&mut json, &serde_json::from_str::<Map<String, Value>>(r#"{"name/full": "Carol E."}"#).unwrap()).unwrap();
        let back = json_to_card(&json).unwrap();
        assert!(back.contains("FN:Carol E."), "{back}");

        let event = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTAMP:20261001T080000Z\r\n\
                     DTSTART:20261105T090000Z\r\nDURATION:PT1H\r\nSUMMARY:Meeting\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let json = event_to_json(event).unwrap();
        assert_eq!(json["@type"], "Event", "{json:?}");
        assert_eq!(json["title"], "Meeting");
        let back = json_to_event(&json).unwrap();
        assert!(back.contains("SUMMARY:Meeting") && back.contains("UID:a"), "{back}");
        assert!(back.contains("DTSTART:20261105T090000Z") && back.starts_with("BEGIN:VCALENDAR"), "{back}");
    }

    #[test]
    fn searches_values_not_property_names() {
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:carrot\r\nFN:Ada Lovelace\r\nN:Lovelace;Ada;;;\r\n\
                    EMAIL:ada@example.org\r\nEND:VCARD\r\n";
        let text = card_text(card);
        assert!(text.contains("ada lovelace") && text.contains("ada@example.org"));
        assert!(!text.contains("vcard") && !text.contains("carrot"));
    }

    #[test]
    fn a_virtual_location_is_written_as_a_conference_uri() {
        let object: Map<String, Value> = serde_json::from_str(
            r#"{"@type":"Event","uid":"c","start":"2026-11-02T10:00:00","timeZone":"Europe/Berlin","duration":"PT1H",
                "title":"Call","virtualLocations":{"v1":{"@type":"VirtualLocation","uri":"https://meet.example.org/room",
                "features":{"video":true}}}}"#,
        )
        .unwrap();
        let ical = json_to_event(&object).unwrap();
        // RFC 7986, 5.11: CONFERENCE has no default value type.
        let line = ical.lines().find(|line| line.starts_with("CONFERENCE")).unwrap();
        assert!(line.contains("VALUE=URI") && line.ends_with(":https://meet.example.org/room"), "{line}");
    }
}
