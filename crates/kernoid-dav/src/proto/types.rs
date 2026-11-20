// SPDX-License-Identifier: AGPL-3.0-or-later
//! Values shared by requests and responses: time ranges (RFC 4791, 9.9) and dead properties (RFC 4918, 4.2), which
//! kernoid keeps as clients set them.

use serde::{Deserialize, Serialize};

use super::{Error, xml::Element};

/// A time range in seconds since 1970; an open start is `i64::MIN`, an open end `i64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: i64,
    pub end: i64,
}

impl TimeRange {
    pub fn new(start: i64, end: i64) -> Self {
        Self { start, end }
    }

    /// Whether something from `start` to `end` overlaps the range (RFC 4791, 9.9). Something without length is in the
    /// range when it starts within it. To-dos (`is_todo`) follow the RFC's row for a start and a due date, which comes
    /// to the same.
    pub fn is_in_range(&self, is_todo: bool, start: i64, end: i64) -> bool {
        if is_todo {
            (self.start <= start || self.start < end) && (self.end > start || self.end >= end)
        } else if start == end {
            self.start <= start && self.end > start
        } else {
            self.start < end && self.end > start
        }
    }

    /// A `time-range`, `expand`, `limit-recurrence-set` or `limit-freebusy-set` element: `start` and `end` as UTC
    /// date-times (`20261201T000000Z`), at least one of them.
    pub fn from_element(element: &Element) -> Result<Self, Error> {
        let start = element.attr("start").map(parse_utc).transpose()?;
        let end = element.attr("end").map(parse_utc).transpose()?;
        if start.is_none() && end.is_none() {
            return Err(Error::Invalid("a time range needs a start or an end"));
        }
        let range = Self { start: start.unwrap_or(i64::MIN), end: end.unwrap_or(i64::MAX) };
        if range.start >= range.end {
            return Err(Error::Invalid("a time range must end after it starts"));
        }
        Ok(range)
    }
}

/// An iCalendar date-time in UTC (`YYYYMMDDTHHMMSSZ`); without `Z` it is taken as UTC too.
fn parse_utc(value: &str) -> Result<i64, Error> {
    let value = value.trim();
    let value = value.strip_suffix(['Z', 'z']).unwrap_or(value);
    let civil = jiff::civil::DateTime::strptime("%Y%m%dT%H%M%S", value)
        .map_err(|_| Error::Invalid("a time range's date-time is not in UTC form"))?;
    civil
        .to_zoned_datetime(jiff::tz::TimeZone::UTC)
        .map(|zoned| zoned.timestamp().as_second())
        .map_err(|_| Error::Invalid("a time range's date-time is out of range"))
}

/// A property kernoid does not know, as a client set it: its namespace, name and value as XML ([`Element::inner_xml`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadProperty {
    pub ns: String,
    pub name: String,
    pub xml: String,
}

/// The dead properties of a collection, stored as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(transparent)]
pub struct DeadProperties(pub Vec<DeadProperty>);

/// Apple's namespace of calendar properties, which `calendar-color` and `calendar-order` are in.
const APPLE_ICAL: &str = "http://apple.com/ns/ical/";

impl DeadProperties {
    /// The properties stored in `value`. Before kernoid 0.6 they were stored as a flat list of tags
    /// (`{"type": "ElementStart", "data": {"name", "attrs"}}`, `ElementEnd`, `Text`); those are read too. What cannot
    /// be read is no properties.
    pub fn from_stored(value: &serde_json::Value) -> Self {
        if let Ok(properties) = serde_json::from_value::<Vec<DeadProperty>>(value.clone()) {
            return Self(properties);
        }
        let Some(tags) = value.as_array() else { return Self::default() };
        let mut properties = Vec::new();
        let mut depth = 0usize;
        let mut current: Option<DeadProperty> = None;
        let mut names: Vec<String> = Vec::new();
        for tag in tags {
            let kind = tag.get("type").and_then(|kind| kind.as_str()).unwrap_or_default();
            let data = tag.get("data");
            match kind {
                "ElementStart" => {
                    let name =
                        data.and_then(|data| data.get("name")).and_then(|name| name.as_str()).unwrap_or_default();
                    let attrs = data.and_then(|data| data.get("attrs")).and_then(|attrs| attrs.as_str());
                    if depth == 0 {
                        let ns = attrs.and_then(legacy_namespace).unwrap_or_else(|| match name {
                            "calendar-color" | "calendar-order" => APPLE_ICAL.to_owned(),
                            _ => String::new(),
                        });
                        current = Some(DeadProperty { ns, name: name.to_owned(), xml: String::new() });
                    } else if let Some(property) = current.as_mut() {
                        property.xml.push('<');
                        property.xml.push_str(name);
                        if let Some(attrs) = attrs.filter(|attrs| !attrs.trim().is_empty()) {
                            property.xml.push(' ');
                            property.xml.push_str(attrs.trim());
                        }
                        property.xml.push('>');
                        names.push(name.to_owned());
                    }
                    depth += 1;
                }
                "ElementEnd" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        properties.extend(current.take());
                    } else if let (Some(property), Some(name)) = (current.as_mut(), names.pop()) {
                        property.xml.push_str("</");
                        property.xml.push_str(&name);
                        property.xml.push('>');
                    }
                }
                "Text" => {
                    if let (Some(property), Some(text)) = (current.as_mut(), data.and_then(|data| data.as_str())) {
                        property.xml.push_str(&quick_xml::escape::escape(text));
                    }
                }
                _ => {}
            }
        }
        Self(properties)
    }

    pub fn to_stored(&self) -> serde_json::Value {
        serde_json::to_value(&self.0).unwrap_or_default()
    }

    pub fn get(&self, ns: &str, name: &str) -> Option<&DeadProperty> {
        self.0.iter().find(|property| property.ns == ns && property.name == name)
    }

    /// Sets a property, replacing one of the same name.
    pub fn set(&mut self, ns: &str, name: &str, xml: String) {
        self.remove(ns, name);
        self.0.push(DeadProperty { ns: ns.to_owned(), name: name.to_owned(), xml });
    }

    pub fn remove(&mut self, ns: &str, name: &str) {
        self.0.retain(|property| property.ns != ns || property.name != name);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl DeadProperty {
    /// The value as text, when it is only text: Apple's colour and order.
    pub fn text(&self) -> Option<String> {
        let element = super::xml::parse(format!("<v>{}</v>", self.xml).as_bytes()).ok()?;
        element.elements().next().is_none().then(|| element.text().trim().to_owned())
    }
}

/// The namespace an `xmlns="…"` in stored attributes names.
fn legacy_namespace(attrs: &str) -> Option<String> {
    let start = attrs.find("xmlns=")? + "xmlns=".len();
    let quote = attrs[start..].chars().next().filter(|quote| *quote == '"' || *quote == '\'')?;
    let rest = &attrs[start + 1..];
    Some(rest[..rest.find(quote)?].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_overlap_as_rfc_4791_says() {
        let range = TimeRange::new(100, 200);
        assert!(range.is_in_range(false, 150, 250));
        assert!(!range.is_in_range(false, 200, 300));
        assert!(!range.is_in_range(false, 50, 100));
        assert!(range.is_in_range(false, 100, 100));
        assert!(!range.is_in_range(false, 200, 200));
        assert!(!range.is_in_range(true, 200, 300));
        assert!(!range.is_in_range(true, 50, 100));
        assert!(range.is_in_range(true, 100, 100));
        assert!(range.is_in_range(true, 150, 150));
    }

    #[test]
    fn ranges_from_elements() {
        let element = super::super::xml::parse(br#"<t start="20261201T000000Z" end="20261202T000000Z"/>"#).unwrap();
        assert_eq!(TimeRange::from_element(&element).unwrap(), TimeRange::new(1_796_083_200, 1_796_169_600));
        let open = super::super::xml::parse(br#"<t start="20261201T000000Z"/>"#).unwrap();
        assert_eq!(TimeRange::from_element(&open).unwrap().end, i64::MAX);
        for bad in [r#"<t/>"#, r#"<t start="2026-12-01"/>"#, r#"<t start="20261202T000000Z" end="20261201T000000Z"/>"#]
        {
            let element = super::super::xml::parse(bad.as_bytes()).unwrap();
            assert!(TimeRange::from_element(&element).is_err(), "{bad}");
        }
    }

    #[test]
    fn dead_properties_are_stored_and_read_back_also_from_before() {
        let mut properties = DeadProperties::default();
        properties.set(APPLE_ICAL, "calendar-color", "#3DDC97FF".into());
        properties.set("urn:x", "thing", "<a xmlns=\"urn:x\">1</a>".into());
        properties.set(APPLE_ICAL, "calendar-color", "#000000FF".into());
        let stored = properties.to_stored();
        let again = DeadProperties::from_stored(&stored);
        assert_eq!(again, properties);
        assert_eq!(again.get(APPLE_ICAL, "calendar-color").unwrap().text().as_deref(), Some("#000000FF"));
        assert_eq!(again.get("urn:x", "thing").unwrap().text(), None);

        let before = serde_json::json!([
            {"type": "ElementStart", "data": {"name": "calendar-color", "attrs": "xmlns=\"http://apple.com/ns/ical/\""}},
            {"type": "Text", "data": "#FF0000FF"},
            {"type": "ElementEnd"},
            {"type": "ElementStart", "data": {"name": "thing", "attrs": "xmlns=\"urn:x\""}},
            {"type": "ElementStart", "data": {"name": "a", "attrs": null}},
            {"type": "Text", "data": "1 & 2"},
            {"type": "ElementEnd"},
            {"type": "ElementEnd"},
        ]);
        let read = DeadProperties::from_stored(&before);
        assert_eq!(read.get(APPLE_ICAL, "calendar-color").unwrap().text().as_deref(), Some("#FF0000FF"));
        assert_eq!(read.get("urn:x", "thing").unwrap().xml, "<a>1 &amp; 2</a>");
        assert!(DeadProperties::from_stored(&serde_json::json!({"x": 1})).is_empty());
    }
}
