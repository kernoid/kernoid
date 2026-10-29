// SPDX-License-Identifier: AGPL-3.0-or-later
//! JSCalendar (RFC 8984) and JSContact (RFC 9553) as JMAP shows them (RFC 0004, 8.2): the stored iCalendar and vCard
//! converted by calcard, and back. Patches of `*/set` (RFC 8620, 5.3) apply to the JSON.

use calcard::{
    Entry, Parser,
    jscalendar::JSCalendar,
    jscontact::JSContact,
    vcard::{VCardProperty, VCardValue, VCardVersion},
};
use serde_json::{Map, Value};

/// A vCard as a JSContact Card object.
pub(crate) fn card_to_json(text: &str) -> Option<Map<String, Value>> {
    let Entry::VCard(card) = Parser::new(text).entry() else { return None };
    let card: JSContact<'static, String, String> = card.into_jscontact();
    match serde_json::to_value(&card.0).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// The words of a vCard to search in: the text values of its properties, lower-cased – not the property names, nor
/// the values of UID, PRODID, REV and VERSION, which say nothing about the person.
pub(crate) fn card_text(text: &str) -> String {
    let Entry::VCard(card) = Parser::new(text).entry() else { return String::new() };
    let mut words = String::new();
    for entry in card.entries {
        if matches!(
            entry.name,
            VCardProperty::Uid | VCardProperty::Prodid | VCardProperty::Rev | VCardProperty::Version
        ) {
            continue;
        }
        for value in entry.values {
            match value {
                VCardValue::Text(text) => words.push_str(&text),
                VCardValue::Component(parts) => words.push_str(&parts.join(" ")),
                _ => continue,
            }
            words.push('\n');
        }
    }
    words.to_lowercase()
}

/// A JSContact Card object as a vCard 4.0.
pub(crate) fn json_to_card(object: &Map<String, Value>) -> Result<String, String> {
    let json = serde_json::to_string(object).map_err(|error| error.to_string())?;
    let card: JSContact<'_, String, String> = JSContact::parse(&json)?;
    let card = card.into_vcard().ok_or("not a contact card")?;
    let mut out = String::new();
    card.write_to(&mut out, VCardVersion::V4_0).map_err(|error| error.to_string())?;
    Ok(out)
}

/// An iCalendar object as a JSCalendar object (an Event, a Task, or a Group of them).
pub(crate) fn event_to_json(text: &str) -> Option<Map<String, Value>> {
    let Entry::ICalendar(ical) = Parser::new(text).entry() else { return None };
    let event: JSCalendar<'static, String, String> = ical.into_jscalendar();
    let mut map = match serde_json::to_value(&event.0).ok()? {
        Value::Object(map) => map,
        _ => return None,
    };
    // One object holds one event and its exceptions (RFC 0004, 4): the event itself, not a group of one.
    if map.get("@type").and_then(Value::as_str) == Some("Group")
        && let Some(Value::Array(entries)) = map.get("entries")
        && entries.len() == 1
        && let Some(Value::Object(entry)) = entries.first()
    {
        map = entry.clone();
    }
    Some(map)
}

/// A JSCalendar object as an iCalendar object. calcard converts times and time zones only inside a `Group`, so a
/// single event is wrapped in one.
pub(crate) fn json_to_event(object: &Map<String, Value>) -> Result<String, String> {
    let object = &with_override_durations(object);
    let wrapped;
    let object = if object.get("@type").and_then(Value::as_str) == Some("Group") {
        object
    } else {
        let mut group = Map::new();
        group.insert("@type".into(), Value::String("Group".into()));
        group.insert("prodId".into(), Value::String(kernoid_groupware::PROD_ID.into()));
        group.insert("entries".into(), Value::Array(vec![Value::Object(object.clone())]));
        wrapped = group;
        &wrapped
    };
    let json = serde_json::to_string(object).map_err(|error| error.to_string())?;
    let event: JSCalendar<'_, String, String> = JSCalendar::parse(&json)?;
    let ical = event.into_icalendar().ok_or("not a calendar object")?;
    Ok(ical.to_string())
}

/// The event with its duration in every override that does not leave its instance out and has none of its own.
/// calcard writes an override as a component of what it changes only, and an instance without `DURATION` or `DTEND`
/// ends with its day (RFC 5545, 3.6.1) – not as the series' instances do.
fn with_override_durations(object: &Map<String, Value>) -> Map<String, Value> {
    let mut object = object.clone();
    let Some(duration) = object.get("duration").cloned() else { return object };
    if let Some(Value::Object(overrides)) = object.get_mut("recurrenceOverrides") {
        for patch in overrides.values_mut().filter_map(Value::as_object_mut) {
            let excluded = patch.get("excluded").and_then(Value::as_bool).unwrap_or(false);
            if !excluded && !patch.contains_key("duration") {
                patch.insert("duration".into(), duration.clone());
            }
        }
    }
    object
}

/// Applies a patch (RFC 8620, 5.3): keys are JSON pointers, `null` removes.
pub(crate) fn patch(object: &mut Map<String, Value>, patch: &Map<String, Value>) -> Result<(), String> {
    for (path, value) in patch {
        let parts: Vec<String> = path.split('/').map(|part| part.replace("~1", "/").replace("~0", "~")).collect();
        let (last, parents) = parts.split_last().ok_or("an empty path")?;
        let mut current = &mut *object;
        for part in parents {
            current = match current.get_mut(part) {
                Some(Value::Object(next)) => next,
                _ => return Err(format!("{path}: no such object")),
            };
        }
        if value.is_null() {
            current.remove(last);
        } else {
            current.insert(last.clone(), value.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
