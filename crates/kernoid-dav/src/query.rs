// SPDX-License-Identifier: AGPL-3.0-or-later
//! The filters of CalDAV and CardDAV queries (RFC 4791, 9.7; RFC 6352, 10.5), the partial retrieval and expansion of
//! calendar data (RFC 4791, 9.6) and free/busy (7.10) – on kernoid-pim's objects, the instances expanded on the fly.
//!
//! The filters come flat from the protocol's parser – each with the path of components it is about – and all must
//! hold; an address book's are grouped by property, each group with its own `test`. Alarms are not matched by time
//! range (OPEN).

use std::collections::HashMap;

use jiff::{Timestamp, tz::TimeZone};
use kernoid_groupware::ical::MAX_INSTANCES;
use kernoid_pim::{
    Component, Property, Time, expand, ical,
    tz::{self, Zones},
    vcard::{VCard, Version},
};

use crate::proto::{
    names::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty, VCardParameterName},
    schema::{
        Collation, MatchType, TextMatch,
        property::{CalDavProperty, CalendarData, CalendarDataProperty, CardDavPropertyName, DavProperty},
        request::{CalendarQuery, Filter, FilterOp, PropFind, Timezone, VCardPropertyWithGroup},
    },
    types::TimeRange,
};

pub type CalendarFilter = Vec<Filter<Vec<ICalendarComponentType>, ICalendarProperty, ICalendarParameterName>>;
pub type AddressbookFilter = Vec<Filter<(), VCardPropertyWithGroup, VCardParameterName>>;

/// An instance of a component of an object (its index in the object's components, its times).
pub type Instance = expand::Instance;

/// Busy times by `FBTYPE`, in seconds since 1970.
pub type Busy = HashMap<String, Vec<(i64, i64)>>;

fn instant(seconds: i64) -> Timestamp {
    Timestamp::from_second(seconds).unwrap_or(if seconds < 0 { Timestamp::MIN } else { Timestamp::MAX })
}

fn bounds(range: &TimeRange) -> (Timestamp, Timestamp) {
    (instant(range.start), instant(range.end))
}

/// The instances of an object's components that meet `range` (or all, up to the limit).
pub fn instances(ical: &Component, default_tz: TimeZone, range: Option<TimeRange>) -> Vec<Instance> {
    expand::expand(ical, &default_tz, range.as_ref().map(bounds), MAX_INSTANCES).instances
}

fn widest(a: Option<TimeRange>, b: TimeRange) -> Option<TimeRange> {
    Some(match a {
        Some(a) => TimeRange { start: a.start.min(b.start), end: a.end.max(b.end) },
        None => b,
    })
}

/// The widest time range the filters of a query name.
pub fn filter_range(query: &CalendarQuery) -> Option<TimeRange> {
    query.filters.iter().fold(None, |range, filter| match filter {
        Filter::Component { op: FilterOp::TimeRange(time), .. } => widest(range, *time),
        _ => range,
    })
}

/// The range calendar data must be expanded over: the filters' and the calendar-data's own.
pub fn data_range(propfind: &PropFind, filter_range: Option<TimeRange>) -> Option<TimeRange> {
    let mut range = filter_range;
    if let PropFind::Prop(properties) | PropFind::AllProp(properties) = propfind {
        for property in properties {
            if let DavProperty::CalDav(CalDavProperty::CalendarData(data)) = property
                && let Some(own) = data.expand.or(data.limit_recurrence)
            {
                range = widest(range, own);
            }
        }
    }
    range
}

/// The time zone of a query: a `VTIMEZONE` or a zone's name.
pub fn parse_tz(tz: &Timezone) -> Option<TimeZone> {
    match tz {
        Timezone::Name(text) => {
            let calendar = ical::parse(text).ok()?;
            let tzid = calendar.components("VTIMEZONE").find_map(|zone| zone.text("TZID"))?;
            Zones::of(&calendar).get(&tzid)
        }
        Timezone::Id(name) => tz::iana(name),
        Timezone::None => None,
    }
}

/// The components a path names (`VCALENDAR`, `VEVENT`, `VALARM` …), with their index among the object's when they
/// are at the second level.
fn find_components<'x>(ical: &'x Component, path: &[ICalendarComponentType]) -> Vec<(Option<usize>, &'x Component)> {
    let Some((first, rest)) = path.split_first() else { return Vec::new() };
    if !ical.is(first.as_str()) {
        return Vec::new();
    }
    let mut current: Vec<(Option<usize>, &Component)> = vec![(None, ical)];
    for (depth, name) in rest.iter().enumerate() {
        current = current
            .into_iter()
            .flat_map(|(_, component)| {
                component
                    .components
                    .iter()
                    .enumerate()
                    .filter(|(_, inner)| inner.is(name.as_str()))
                    .map(move |(index, inner)| (if depth == 0 { Some(index) } else { None }, inner))
            })
            .collect();
    }
    current
}

/// Text compared as a `text-match` asks (RFC 4790 collations).
fn text_matches(text: &str, matcher: &TextMatch) -> bool {
    let (text, value) = match matcher.collation {
        Collation::Octet => (text.to_owned(), matcher.text.clone()),
        Collation::AsciiCasemap => (text.to_ascii_lowercase(), matcher.text.to_ascii_lowercase()),
        Collation::UnicodeCasemap => (text.to_lowercase(), matcher.text.to_lowercase()),
    };
    let found = match matcher.match_type {
        MatchType::Equals => text == value,
        MatchType::Contains => text.contains(&value),
        MatchType::StartsWith => text.starts_with(&value),
        MatchType::EndsWith => text.ends_with(&value),
    };
    found != matcher.negate
}

fn overlaps(start: i64, end: i64, range: &TimeRange) -> bool {
    start < range.end && (end > range.start || (start == end && start >= range.start))
}

/// Whether an object meets the filters of a `calendar-query` (RFC 4791, 9.7); `instances` are its instances over the
/// filters' range.
pub fn calendar_matches(
    ical: &Component,
    filters: &CalendarFilter,
    instances: &[Instance],
    default_tz: TimeZone,
) -> bool {
    let zones = Zones::of(ical);
    filters.iter().all(|filter| match filter {
        Filter::AnyOf | Filter::AllOf => true,
        Filter::Component { comp, op } => {
            let found = find_components(ical, comp);
            match op {
                FilterOp::Exists => !found.is_empty(),
                FilterOp::Undefined => found.is_empty(),
                FilterOp::TimeRange(range) => found.iter().any(|(index, component)| match index {
                    Some(index) if component.is_schedulable() => instances.iter().any(|instance| {
                        instance.component == *index
                            && overlaps(instance.start.as_second(), instance.end.as_second(), range)
                    }),
                    // Alarms and other components: not by time (OPEN).
                    _ => true,
                }),
                FilterOp::TextMatch(_) => false,
            }
        }
        Filter::Property { comp, prop, op } => {
            let found = find_components(ical, comp);
            let mut properties = found.iter().flat_map(|(_, component)| component.properties(prop.as_str()));
            match op {
                FilterOp::Exists => properties.next().is_some(),
                FilterOp::Undefined => {
                    !found.is_empty() && found.iter().all(|(_, component)| component.property(prop.as_str()).is_none())
                }
                FilterOp::TextMatch(matcher) => {
                    properties.any(|property| text_matches(&property_text(property), matcher))
                }
                FilterOp::TimeRange(range) => properties.any(|property| {
                    property.time_values().iter().any(|time| {
                        let at = time.resolve(&zones, &default_tz).as_second();
                        at >= range.start && at < range.end
                    })
                }),
            }
        }
        Filter::Parameter { comp, prop, param, op } => {
            let found = find_components(ical, comp);
            let mut properties = found.iter().flat_map(|(_, component)| component.properties(prop.as_str()));
            match op {
                FilterOp::Exists => properties.any(|property| property.param(param.as_str()).is_some()),
                FilterOp::Undefined => properties.all(|property| property.param(param.as_str()).is_none()),
                FilterOp::TextMatch(matcher) => properties
                    .any(|property| property.param_values(param.as_str()).any(|value| text_matches(value, matcher))),
                FilterOp::TimeRange(_) => false,
            }
        }
    })
}

/// A property's value as a text match sees it.
fn property_text(property: &Property) -> String {
    if property.is("ORGANIZER") || property.is("ATTENDEE") || property.is("URL") {
        return property.value.trim().to_owned();
    }
    property.as_text()
}

/// The time an instance had in its series, in UTC.
fn utc_property(name: &str, time: Timestamp, all_day: bool) -> Property {
    let civil = TimeZone::UTC.to_datetime(time);
    if all_day {
        return Property::time(name, &Time::Date(civil.date()));
    }
    Property::time(name, &Time::Utc(civil))
}

/// The calendar data of an object as a `calendar-data` element asks for it (RFC 4791, 9.6): only some components
/// and properties, recurrences expanded or limited. `None` when it would hold more instances than allowed.
pub fn serialize_ical(
    ical: &Component,
    data: &CalendarData,
    instances: &mut [Instance],
    instances_limit: &mut usize,
) -> Option<String> {
    let zones = Zones::of(ical);
    let mut out = ical.clone();
    if let Some(range) = data.expand {
        let chosen: Vec<&Instance> = instances
            .iter()
            .filter(|instance| overlaps(instance.start.as_second(), instance.end.as_second(), &range))
            .collect();
        if chosen.len() > *instances_limit {
            return None;
        }
        *instances_limit -= chosen.len();
        out.components = Vec::new();
        for instance in chosen {
            let Some(source) = ical.components.get(instance.component) else { continue };
            let mut component = source.clone();
            for name in ["RRULE", "RDATE", "EXDATE", "EXRULE", "DTSTART", "DTEND", "DURATION", "RECURRENCE-ID"] {
                component.remove(name);
            }
            let mut head = Vec::new();
            if let Some(id) = &instance.recurrence_id {
                let id = id.resolve(&zones, &TimeZone::UTC);
                head.push(utc_property("RECURRENCE-ID", id, instance.all_day));
            }
            head.push(utc_property("DTSTART", instance.start, instance.all_day));
            if instance.end > instance.start {
                head.push(utc_property(
                    if source.is("VTODO") { "DUE" } else { "DTEND" },
                    instance.end,
                    instance.all_day,
                ));
                if source.is("VTODO") {
                    component.remove("DUE");
                }
            }
            let at = component.properties.iter().position(|p| p.is("UID")).map_or(0, |p| p + 1);
            component.properties.splice(at..at, head);
            out.components.push(component);
        }
    } else if let Some(range) = data.limit_recurrence {
        // The series, and the overrides that meet the range.
        let keep: Vec<usize> = instances
            .iter()
            .filter(|instance| overlaps(instance.start.as_second(), instance.end.as_second(), &range))
            .map(|instance| instance.component)
            .collect();
        out.components = ical
            .components
            .iter()
            .enumerate()
            .filter(|(index, component)| {
                !component.is_schedulable() || component.property("RECURRENCE-ID").is_none() || keep.contains(index)
            })
            .map(|(_, component)| component.clone())
            .collect();
    }
    if !data.properties.is_empty() {
        select(&mut out, &data.properties, true);
    }
    Some(out.to_string())
}

/// Leaves only the components and properties asked for.
fn select(component: &mut Component, wanted: &[CalendarDataProperty], root: bool) {
    let entries: Vec<_> =
        wanted.iter().filter(|entry| entry.component.as_ref().is_some_and(|c| component.is(c.as_str()))).collect();
    let all = entries.iter().any(|entry| entry.name.is_none());
    if !root && !all {
        let names: Vec<(&str, bool)> = entries
            .iter()
            .filter_map(|entry| entry.name.as_ref().map(|name| (name.as_str(), entry.no_value)))
            .collect();
        component.properties.retain(|property| names.iter().any(|(name, _)| property.is(name)));
        for property in &mut component.properties {
            if names.iter().any(|(name, no_value)| *no_value && property.is(name)) {
                property.value.clear();
            }
        }
    }
    component
        .components
        .retain(|inner| wanted.iter().any(|entry| entry.component.as_ref().is_some_and(|c| inner.is(c.as_str()))));
    for inner in &mut component.components {
        select(inner, wanted, false);
    }
}

fn card_properties<'x>(card: &'x VCard, prop: &VCardPropertyWithGroup) -> impl Iterator<Item = &'x Property> {
    card.properties.iter().filter(move |property| {
        property.is(prop.name.as_str())
            && prop
                .group
                .as_ref()
                .is_none_or(|group| property.group.as_ref().is_some_and(|own| own.eq_ignore_ascii_case(group)))
    })
}

/// Whether a vCard meets the filters of an `addressbook-query` (RFC 6352, 8.6).
pub fn vcard_matches(card: &VCard, filters: &AddressbookFilter) -> bool {
    let mut all_of = false;
    let mut start = 0;
    match filters.first() {
        Some(Filter::AllOf) => {
            all_of = true;
            start = 1;
        }
        Some(Filter::AnyOf) => start = 1,
        _ => {}
    }
    // Groups: a prop-filter's conditions, each with its own test (a marker before them).
    let mut groups: Vec<(bool, Option<&VCardPropertyWithGroup>, Vec<bool>)> = Vec::new();
    for filter in &filters[start..] {
        let (prop, result) = match filter {
            Filter::AllOf | Filter::AnyOf => {
                groups.push((matches!(filter, Filter::AllOf), None, Vec::new()));
                continue;
            }
            Filter::Component { .. } => continue,
            Filter::Property { prop, op, .. } => {
                let mut properties = card_properties(card, prop);
                let result = match op {
                    FilterOp::Exists => properties.next().is_some(),
                    FilterOp::Undefined => properties.next().is_none(),
                    FilterOp::TextMatch(matcher) => {
                        properties.any(|property| text_matches(&property.as_text(), matcher))
                    }
                    FilterOp::TimeRange(_) => false,
                };
                (prop, result)
            }
            Filter::Parameter { prop, param, op, .. } => {
                let mut properties = card_properties(card, prop);
                let result = match op {
                    FilterOp::Exists => properties.any(|property| property.param(param.as_str()).is_some()),
                    FilterOp::Undefined => properties.all(|property| property.param(param.as_str()).is_none()),
                    FilterOp::TextMatch(matcher) => properties.any(|property| {
                        property.param_values(param.as_str()).any(|value| text_matches(value, matcher))
                    }),
                    FilterOp::TimeRange(_) => false,
                };
                (prop, result)
            }
        };
        match groups.last_mut() {
            Some((_, own @ None, results)) => {
                *own = Some(prop);
                results.push(result);
            }
            Some((_, Some(own), results)) if *own == prop => results.push(result),
            _ => groups.push((false, Some(prop), vec![result])),
        }
    }
    let results = groups
        .into_iter()
        .filter(|(_, _, results)| !results.is_empty())
        .map(|(all, _, results)| if all { results.iter().all(|r| *r) } else { results.iter().any(|r| *r) });
    let results: Vec<bool> = results.collect();
    if results.is_empty() {
        return true;
    }
    if all_of { results.iter().all(|r| *r) } else { results.iter().any(|r| *r) }
}

/// A vCard with only the properties an `address-data` element asks for (RFC 6352, 10.4), in the version asked for.
pub fn serialize_vcard(card: &VCard, props: &[CardDavPropertyName], version: Version) -> String {
    let mut out = card.clone();
    if !props.is_empty() {
        out.properties.retain(|property| {
            props.iter().any(|wanted| {
                property.is(wanted.name.as_str())
                    && wanted.group.as_ref().is_none_or(|group| property.group.as_deref() == Some(group))
            })
        });
        for property in &mut out.properties {
            if props.iter().any(|wanted| wanted.no_value && property.is(wanted.name.as_str())) {
                property.value.clear();
            }
        }
    }
    out.write(version)
}

/// What an object adds to free/busy over `range` (RFC 4791, 7.10): its opaque events that are not cancelled, by
/// type, and the periods of its `VFREEBUSY` components.
pub fn busy_times(ical: &Component, instances: &[Instance], range: &TimeRange, busy: &mut Busy) {
    for instance in instances {
        let Some(component) = ical.components.get(instance.component) else { continue };
        if !component.is("VEVENT") {
            continue;
        }
        let value = |name: &str| component.text(name).map(|v| v.trim().to_ascii_uppercase());
        if value("TRANSP").as_deref() == Some("TRANSPARENT") || value("STATUS").as_deref() == Some("CANCELLED") {
            continue;
        }
        let kind = if value("STATUS").as_deref() == Some("TENTATIVE") { "BUSY-TENTATIVE" } else { "BUSY" };
        let (start, end) = (instance.start.as_second().max(range.start), instance.end.as_second().min(range.end));
        if start < end {
            busy.entry(kind.to_owned()).or_default().push((start, end));
        }
    }
    let zones = Zones::of(ical);
    for component in ical.components("VFREEBUSY") {
        for property in component.properties("FREEBUSY") {
            let kind = property.param("FBTYPE").unwrap_or("BUSY").to_ascii_uppercase();
            if kind == "FREE" {
                continue;
            }
            for period in property.value.split(',') {
                let Some((from, to)) = period.split_once('/') else { continue };
                let Some(start) = Time::parse(from, None, false).map(|t| t.resolve(&zones, &TimeZone::UTC)) else {
                    continue;
                };
                let end = kernoid_pim::Duration::parse(to)
                    .map(|duration| start.as_second() + duration.days * 86_400 + duration.seconds)
                    .or_else(|| Time::parse(to, None, false).map(|t| t.resolve(&zones, &TimeZone::UTC).as_second()));
                let Some(end) = end else { continue };
                let (start, end) = (start.as_second().max(range.start), end.min(range.end));
                if start < end {
                    busy.entry(kind.clone()).or_default().push((start, end));
                }
            }
        }
    }
}

fn merge_intervals(mut intervals: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    intervals.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for (start, end) in intervals {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn utc_text(seconds: i64) -> String {
    Time::Utc(TimeZone::UTC.to_datetime(instant(seconds))).format()
}

/// A `VFREEBUSY` object for `range` from busy times (RFC 4791, 7.10; RFC 6638, 5).
pub fn freebusy_object(range: &TimeRange, busy: Busy, extra: Vec<Property>) -> Component {
    let mut calendar = Component::calendar(crate::PROD_ID);
    let mut freebusy = Component::new("VFREEBUSY");
    freebusy.properties.push(Property::new("DTSTAMP", utc_text(Timestamp::now().as_second())));
    if range.start != i64::MIN {
        freebusy.properties.push(Property::new("DTSTART", utc_text(range.start)));
    }
    if range.end != i64::MAX {
        freebusy.properties.push(Property::new("DTEND", utc_text(range.end)));
    }
    freebusy.properties.extend(extra);
    let mut kinds: Vec<(String, Vec<(i64, i64)>)> = busy.into_iter().collect();
    kinds.sort();
    for (kind, intervals) in kinds {
        let periods: Vec<String> = merge_intervals(intervals)
            .into_iter()
            .map(|(start, end)| format!("{}/{}", utc_text(start), utc_text(end)))
            .collect();
        if !periods.is_empty() {
            freebusy.properties.push(Property::new("FREEBUSY", periods.join(",")).with_param("FBTYPE", kind));
        }
    }
    calendar.components.push(freebusy);
    calendar
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEEKLY: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:t\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nBEGIN:STANDARD\r\n\
        DTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\n\
        UID:w\r\nDTSTART;TZID=Europe/Berlin:20261102T100000\r\nDURATION:PT1H\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\n\
        SUMMARY:Weekly\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@example.org\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\n\
        TRIGGER:-PT5M\r\nDESCRIPTION:x\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    fn names(path: &[&str]) -> Vec<ICalendarComponentType> {
        path.iter().map(|name| ICalendarComponentType::new(name)).collect()
    }

    fn matcher(value: &str) -> TextMatch {
        TextMatch {
            match_type: MatchType::Contains,
            text: value.into(),
            collation: Collation::AsciiCasemap,
            negate: false,
        }
    }

    #[test]
    fn filters_match_components_properties_and_parameters() {
        let ical = ical::parse(WEEKLY).unwrap();
        let range = TimeRange::new(1_763_000_000, 1_764_000_000);
        let found = instances(&ical, TimeZone::UTC, Some(TimeRange::new(i64::MIN, i64::MAX)));
        assert_eq!(found.len(), 4);
        let check = |filters: CalendarFilter| calendar_matches(&ical, &filters, &found, TimeZone::UTC);
        assert!(check(vec![Filter::Component { comp: names(&["VCALENDAR", "VEVENT"]), op: FilterOp::Exists }]));
        assert!(!check(vec![Filter::Component { comp: names(&["VCALENDAR", "VTODO"]), op: FilterOp::Exists }]));
        assert!(check(vec![Filter::Property {
            comp: names(&["VCALENDAR", "VEVENT"]),
            prop: ICalendarProperty::new("SUMMARY"),
            op: FilterOp::TextMatch(matcher("week")),
        }]));
        assert!(check(vec![Filter::Parameter {
            comp: names(&["VCALENDAR", "VEVENT"]),
            prop: ICalendarProperty::new("ATTENDEE"),
            param: ICalendarParameterName::new("PARTSTAT"),
            op: FilterOp::TextMatch(matcher("accepted")),
        }]));
        assert!(check(vec![Filter::Property {
            comp: names(&["VCALENDAR", "VEVENT"]),
            prop: ICalendarProperty::new("LOCATION"),
            op: FilterOp::Undefined,
        }]));
        // 2026-11-16 10:00 Berlin is an instance; a range without one is not met.
        let at = |from: &str, to: &str| {
            TimeRange::new(
                kernoid_pim::time::parse_utc(from).unwrap().as_second(),
                kernoid_pim::time::parse_utc(to).unwrap().as_second(),
            )
        };
        let hit = at("2026-11-16T08:30:00Z", "2026-11-16T09:30:00Z");
        let miss = at("2026-11-17T00:00:00Z", "2026-11-23T00:00:00Z");
        assert!(check(vec![Filter::Component { comp: names(&["VCALENDAR", "VEVENT"]), op: FilterOp::TimeRange(hit) }]));
        assert!(!check(vec![Filter::Component {
            comp: names(&["VCALENDAR", "VEVENT"]),
            op: FilterOp::TimeRange(miss)
        }]));
        let _ = range;
    }

    #[test]
    fn a_query_names_its_time_zone() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Custom\r\nBEGIN:STANDARD\r\nDTSTART:19700101T000000\r\n\
            TZOFFSETFROM:+0530\r\nTZOFFSETTO:+0530\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\nEND:VCALENDAR\r\n";
        let zone = parse_tz(&Timezone::Name(text.into())).unwrap();
        assert_eq!(zone.to_offset(Timestamp::UNIX_EPOCH).seconds(), 19_800);
        assert!(parse_tz(&Timezone::Id("Europe/Berlin".into())).is_some());
        assert!(parse_tz(&Timezone::Name("not a calendar".into())).is_none());
    }

    #[test]
    fn calendar_data_is_expanded_and_selected() {
        let ical = ical::parse(WEEKLY).unwrap();
        let range = TimeRange::new(
            kernoid_pim::time::parse_utc("2026-11-08T00:00:00Z").unwrap().as_second(),
            kernoid_pim::time::parse_utc("2026-11-20T00:00:00Z").unwrap().as_second(),
        );
        let mut found = instances(&ical, TimeZone::UTC, Some(range));
        let data = CalendarData { expand: Some(range), ..CalendarData::default() };
        let mut limit = 10;
        let text = serialize_ical(&ical, &data, &mut found, &mut limit).unwrap();
        assert_eq!(text.matches("RECURRENCE-ID:").count(), 2, "{text}");
        assert!(
            text.contains("RECURRENCE-ID:20261109T090000Z\r\nDTSTART:20261109T090000Z\r\nDTEND:20261109T100000Z"),
            "{text}"
        );
        assert!(!text.contains("RRULE") && !text.contains("VTIMEZONE"), "{text}");
        assert_eq!(limit, 8);
        let mut small = 1;
        assert!(serialize_ical(&ical, &data, &mut found, &mut small).is_none());

        let summary = CalendarData {
            properties: vec![
                CalendarDataProperty {
                    component: Some(ICalendarComponentType::new("VEVENT")),
                    name: Some(ICalendarProperty::new("SUMMARY")),
                    no_value: false,
                },
                CalendarDataProperty {
                    component: Some(ICalendarComponentType::new("VEVENT")),
                    name: Some(ICalendarProperty::new("UID")),
                    no_value: false,
                },
            ],
            ..CalendarData::default()
        };
        let text = serialize_ical(&ical, &summary, &mut found, &mut limit).unwrap();
        assert!(
            text.contains("SUMMARY:Weekly")
                && text.contains("UID:w")
                && !text.contains("DTSTART")
                && !text.contains("VALARM"),
            "{text}"
        );
        assert!(text.contains("VERSION:2.0"), "{text}");
    }

    #[test]
    fn free_busy_merges_and_skips_free_time() {
        let ical = ical::parse(WEEKLY).unwrap();
        let range = TimeRange::new(i64::MIN, i64::MAX);
        let found = instances(&ical, TimeZone::UTC, Some(range));
        let window = TimeRange::new(
            kernoid_pim::time::parse_utc("2026-11-02T00:00:00Z").unwrap().as_second(),
            kernoid_pim::time::parse_utc("2026-11-10T00:00:00Z").unwrap().as_second(),
        );
        let mut busy = Busy::new();
        busy_times(&ical, &found, &window, &mut busy);
        let text = freebusy_object(&window, busy, vec![]).to_string().replace("\r\n ", "");
        assert!(
            text.contains("FREEBUSY;FBTYPE=BUSY:20261102T090000Z/20261102T100000Z,20261109T090000Z/20261109T100000Z"),
            "{text}"
        );
        let free = ical::parse(&WEEKLY.replace("SUMMARY", "TRANSP:TRANSPARENT\r\nSUMMARY")).unwrap();
        let mut busy = Busy::new();
        busy_times(&free, &found, &window, &mut busy);
        assert!(busy.is_empty());
    }

    #[test]
    fn address_book_filters_group_by_property() {
        let card = kernoid_pim::vcard::parse(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c\r\nFN:Carol Example\r\nEMAIL;TYPE=work:carol@example.org\r\nEND:VCARD\r\n",
        )
        .unwrap();
        let prop =
            |name: &str| VCardPropertyWithGroup { name: crate::proto::names::VCardProperty::new(name), group: None };
        let text = |name: &str, value: &str| Filter::Property {
            comp: (),
            prop: prop(name),
            op: FilterOp::TextMatch(matcher(value)),
        };
        assert!(vcard_matches(&card, &vec![text("EMAIL", "carol")]));
        assert!(!vcard_matches(&card, &vec![text("EMAIL", "dave")]));
        assert!(vcard_matches(&card, &vec![Filter::AnyOf, text("EMAIL", "dave"), text("FN", "carol")]));
        assert!(!vcard_matches(&card, &vec![Filter::AllOf, text("EMAIL", "dave"), text("FN", "carol")]));
        // A prop-filter's own test: all of its text matches, or any.
        let both = |test| vec![Filter::AnyOf, test, text("EMAIL", "carol"), text("EMAIL", "dave")];
        assert!(!vcard_matches(&card, &both(Filter::AllOf)));
        assert!(vcard_matches(&card, &both(Filter::AnyOf)));
        // An empty prop-filter: the property is there.
        let exists = |name: &str| Filter::Property { comp: (), prop: prop(name), op: FilterOp::Exists };
        assert!(vcard_matches(&card, &vec![Filter::AnyOf, Filter::AnyOf, exists("EMAIL")]));
        assert!(!vcard_matches(&card, &vec![Filter::AnyOf, Filter::AnyOf, exists("TEL")]));
        let typed = Filter::Parameter {
            comp: (),
            prop: prop("EMAIL"),
            param: VCardParameterName::new("TYPE"),
            op: FilterOp::TextMatch(matcher("work")),
        };
        assert!(vcard_matches(&card, &vec![typed]));
        let only_fn = serialize_vcard(
            &card,
            &[CardDavPropertyName {
                group: None,
                name: crate::proto::names::VCardProperty::new("FN"),
                no_value: false,
            }],
            Version::V3_0,
        );
        assert!(
            only_fn.contains("VERSION:3.0") && only_fn.contains("FN:Carol Example") && !only_fn.contains("EMAIL"),
            "{only_fn}"
        );
    }
}
