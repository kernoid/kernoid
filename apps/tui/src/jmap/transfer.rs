// SPDX-License-Identifier: MIT
//! `.ics` and `.vcf` files: events and contacts read from iCalendar and vCard and written to them – converted by
//! calcard, the library kernoid stores them with, to the JSCalendar and JSContact objects JMAP speaks.

use calcard::{Entry, Parser, jscalendar::JSCalendar, jscontact::JSContact, vcard::VCardVersion};
use serde_json::{Map, Value, json};

/// What the server sets: not taken from a file, nor written to one.
const SERVER_SET: [&str; 9] =
    ["id", "calendarIds", "addressBookIds", "utcStart", "utcEnd", "isDraft", "isOrigin", "baseEventId", "blobId"];

fn own_properties(mut object: Map<String, Value>) -> Map<String, Value> {
    for key in SERVER_SET {
        object.remove(key);
    }
    object
}

/// The events of an iCalendar text, as JSCalendar objects – an event with its exceptions is one.
pub fn events_from_ics(text: &str) -> Result<Vec<Map<String, Value>>, String> {
    let mut parser = Parser::new(text);
    let mut out = Vec::new();
    loop {
        match parser.entry() {
            Entry::ICalendar(ical) => {
                let calendar: JSCalendar<'static, String, String> = ical.into_jscalendar();
                let value = serde_json::to_value(&calendar.0).map_err(|error| error.to_string())?;
                match value {
                    // calcard gives a Group of what the file holds.
                    Value::Object(group) if group.get("@type").and_then(Value::as_str) == Some("Group") => {
                        let entries = group.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
                        out.extend(entries.into_iter().filter_map(|entry| match entry {
                            Value::Object(entry) if entry.get("@type").and_then(Value::as_str) == Some("Event") => {
                                Some(own_properties(entry))
                            }
                            _ => None,
                        }));
                    }
                    Value::Object(event) => out.push(own_properties(event)),
                    _ => {}
                }
            }
            Entry::Eof => break,
            Entry::VCard(_) => return Err("a vCard, not an iCalendar file".into()),
            other => return Err(format!("not an iCalendar file: {other:?}")),
        }
    }
    if out.is_empty() {
        return Err("no events in the file".into());
    }
    Ok(out)
}

/// Events as one iCalendar text. calcard converts times and time zones only inside a Group.
pub fn ics_from_events(events: &[Map<String, Value>]) -> Result<String, String> {
    let entries: Vec<Value> = events.iter().cloned().map(|event| Value::Object(own_properties(event))).collect();
    let group = json!({ "@type": "Group", "prodId": "-//kernoid//kernoid-tui//EN", "entries": entries });
    let text = serde_json::to_string(&group).map_err(|error| error.to_string())?;
    let calendar: JSCalendar<'_, String, String> = JSCalendar::parse(&text)?;
    Ok(calendar.into_icalendar().ok_or("not a calendar")?.to_string())
}

/// The contacts of a vCard text, as JSContact Card objects.
pub fn cards_from_vcf(text: &str) -> Result<Vec<Map<String, Value>>, String> {
    let mut parser = Parser::new(text);
    let mut out = Vec::new();
    loop {
        match parser.entry() {
            Entry::VCard(card) => {
                let card: JSContact<'static, String, String> = card.into_jscontact();
                if let Value::Object(card) = serde_json::to_value(&card.0).map_err(|error| error.to_string())? {
                    out.push(own_properties(card));
                }
            }
            Entry::Eof => break,
            Entry::ICalendar(_) => return Err("an iCalendar file, not a vCard".into()),
            other => return Err(format!("not a vCard file: {other:?}")),
        }
    }
    if out.is_empty() {
        return Err("no contacts in the file".into());
    }
    Ok(out)
}

/// Contacts as one vCard 4.0 text.
pub fn vcf_from_cards(cards: &[Map<String, Value>]) -> Result<String, String> {
    let mut out = String::new();
    for card in cards {
        let text = serde_json::to_string(&own_properties(card.clone())).map_err(|error| error.to_string())?;
        let card: JSContact<'_, String, String> = JSContact::parse(&text)?;
        card.into_vcard()
            .ok_or("not a contact card")?
            .write_to(&mut out, VCardVersion::V4_0)
            .map_err(|error| error.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:a@x\r\nDTSTART;TZID=Europe/Berlin:20261103T100000\r\nDURATION:PT1H\r\nSUMMARY:Plans\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:b@x\r\nDTSTART;VALUE=DATE:20261104\r\nSUMMARY:Holiday\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    const VCF: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Dora\r\nEMAIL;TYPE=work:dora@x.example\r\nEND:VCARD\r\nBEGIN:VCARD\r\nVERSION:4.0\r\nFN:Emil\r\nTEL:+49 30 1\r\nEND:VCARD\r\n";

    #[test]
    fn events_go_both_ways() {
        let events = events_from_ics(ICS).unwrap();
        let titles: Vec<&str> = events.iter().filter_map(|e| e.get("title").and_then(Value::as_str)).collect();
        assert_eq!(titles, ["Plans", "Holiday"]);
        assert_eq!(events[0]["start"], "2026-11-03T10:00:00");
        assert_eq!(events[0]["timeZone"], "Europe/Berlin");
        let written = ics_from_events(&events).unwrap();
        assert!(written.contains("SUMMARY:Plans") && written.contains("SUMMARY:Holiday"), "{written}");
        assert!(written.contains("DTSTART;TZID=Europe/Berlin:20261103T100000"), "{written}");
        assert_eq!(events_from_ics(&written).unwrap().len(), 2);
        assert!(events_from_ics(VCF).is_err());
    }

    #[test]
    fn contacts_go_both_ways() {
        let cards = cards_from_vcf(VCF).unwrap();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0]["name"]["full"], "Dora");
        let written = vcf_from_cards(&cards).unwrap();
        assert!(written.contains("FN:Dora") && written.contains("FN:Emil"), "{written}");
        assert!(written.contains("dora@x.example"), "{written}");
        assert_eq!(cards_from_vcf(&written).unwrap().len(), 2);
        assert!(cards_from_vcf(ICS).is_err());
    }
}
