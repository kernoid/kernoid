// SPDX-License-Identifier: MIT
//! iCalendar objects (RFC 5545): a tree of components, each with its properties as written. [`parse`] reads one
//! `VCALENDAR`, [`parse_all`] every one of a file; `to_string` writes it back – folded, CRLF, what was not understood
//! unchanged.

use std::fmt;

use crate::content::{self, Block, Error, Property};

/// A component (`VCALENDAR`, `VEVENT`, `VALARM`, …): its name in upper case, its properties in order, the components
/// it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub properties: Vec<Property>,
    pub components: Vec<Component>,
}

/// The components that make an event, a task or a journal entry – what calendars store and scheduling sends.
pub const SCHEDULABLE: [&str; 3] = ["VEVENT", "VTODO", "VJOURNAL"];

impl Component {
    pub fn new(name: &str) -> Component {
        Component { name: name.to_ascii_uppercase(), properties: Vec::new(), components: Vec::new() }
    }

    /// A `VCALENDAR` with `VERSION:2.0` and a `PRODID`.
    pub fn calendar(prod_id: &str) -> Component {
        let mut calendar = Component::new("VCALENDAR");
        calendar.properties.push(Property::new("VERSION", "2.0"));
        calendar.properties.push(Property::text("PRODID", prod_id));
        calendar
    }

    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    /// Whether this is an event, a task or a journal entry.
    pub fn is_schedulable(&self) -> bool {
        SCHEDULABLE.iter().any(|name| self.is(name))
    }

    /// The first property of a name.
    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties.iter().find(|property| property.is(name))
    }

    pub fn property_mut(&mut self, name: &str) -> Option<&mut Property> {
        self.properties.iter_mut().find(|property| property.is(name))
    }

    /// Every property of a name.
    pub fn properties<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> + 'a {
        self.properties.iter().filter(move |property| property.is(name))
    }

    /// A property's value as text.
    pub fn text(&self, name: &str) -> Option<String> {
        self.property(name).map(Property::as_text)
    }

    /// The `UID`.
    pub fn uid(&self) -> Option<String> {
        self.text("UID").map(|uid| uid.trim().to_owned())
    }

    /// Replaces every property of the name with this one.
    pub fn set(&mut self, property: Property) {
        match self.properties.iter().position(|known| known.name == property.name) {
            Some(position) => {
                self.properties[position] = property.clone();
                let name = property.name;
                let mut seen = false;
                self.properties.retain(|known| {
                    if known.name != name {
                        return true;
                    }
                    let keep = !seen;
                    seen = true;
                    keep
                });
            }
            None => self.properties.push(property),
        }
    }

    /// Removes every property of a name.
    pub fn remove(&mut self, name: &str) {
        self.properties.retain(|property| !property.is(name));
    }

    /// The components of a name it holds.
    pub fn components<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Component> + 'a {
        self.components.iter().filter(move |component| component.is(name))
    }

    /// The events, tasks and journal entries it holds.
    pub fn schedulable(&self) -> impl Iterator<Item = &Component> {
        self.components.iter().filter(|component| component.is_schedulable())
    }

    pub fn schedulable_mut(&mut self) -> impl Iterator<Item = &mut Component> {
        self.components.iter_mut().filter(|component| component.is_schedulable())
    }

    /// `METHOD` of an iTIP object, in upper case.
    pub fn method(&self) -> Option<String> {
        self.property("METHOD").map(|method| method.as_text().trim().to_ascii_uppercase())
    }

    pub(crate) fn from_block(block: Block) -> Component {
        Component {
            name: block.name,
            properties: block.properties,
            components: block.blocks.into_iter().map(Component::from_block).collect(),
        }
    }

    fn write(&self, out: &mut String) {
        content::write_block(out, &self.name, &self.properties, |out| {
            for component in &self.components {
                component.write(out);
            }
        });
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

/// The one `VCALENDAR` of a text.
pub fn parse(text: &str) -> Result<Component, Error> {
    let mut all = parse_all(text)?;
    match all.len() {
        1 => Ok(all.remove(0)),
        0 => Err(Error("not an iCalendar object".into())),
        _ => Err(Error("more than one VCALENDAR".into())),
    }
}

/// Every `VCALENDAR` of a text; anything else at the top is an error.
pub fn parse_all(text: &str) -> Result<Vec<Component>, Error> {
    let blocks = content::parse_blocks(text)?;
    if blocks.iter().any(|block| block.name != "VCALENDAR") {
        return Err(Error("not an iCalendar object".into()));
    }
    Ok(blocks.into_iter().map(Component::from_block).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendars_go_through_unchanged() {
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\nX-WR-CALNAME:Work\r\nBEGIN:VEVENT\r\n\
            UID:1@example\r\nDTSTART;TZID=Europe/Berlin:20261105T090000\r\nSUMMARY:Plan\\, then act\r\n\
            X-MICROSOFT-CDO-BUSYSTATUS:BUSY\r\nATTENDEE;CN=\"Doe, Jane\";PARTSTAT=ACCEPTED:mailto:jane@example.org\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let calendar = parse(text).unwrap();
        assert_eq!(calendar.to_string(), text);
        let event = calendar.schedulable().next().unwrap();
        assert_eq!(event.text("SUMMARY").as_deref(), Some("Plan, then act"));
        assert_eq!(event.property("ATTENDEE").unwrap().param("CN"), Some("Doe, Jane"));
        assert_eq!(event.components("VALARM").count(), 1);
        assert!(parse("BEGIN:VCARD\r\nEND:VCARD\r\n").is_err());
        assert!(parse("").is_err());
        assert!(parse("not a calendar").is_err());
    }
}
