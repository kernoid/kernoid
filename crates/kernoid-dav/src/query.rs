/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The filters of CalDAV and CardDAV queries, the partial retrieval and expansion of calendar data, and free/busy
//! (RFC 0004, 8.1). Derived from Stalwart's `crates/dav/src/calendar/query.rs`, `card/query.rs` and
//! `calendar/freebusy.rs` (v0.16.27): rewritten for the parsed – not archived – calcard objects and for instances
//! expanded on the fly instead of Stalwart's stored index. Alarms are not matched by time range (OPEN).

use std::{collections::HashMap, fmt::Write, str::FromStr};

use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarFreeBusyType,
        ICalendarParameter, ICalendarParameterName, ICalendarPeriod, ICalendarProperty, ICalendarStatus,
        ICalendarTransparency, ICalendarValue, dates::TimeOrDelta,
    },
    vcard::{VCard, VCardEntry, VCardParameterName, VCardProperty, VCardVersion},
};
use kernoid_groupware::ical::MAX_INSTANCES;

use crate::proto::{
    schema::{
        property::{CalDavProperty, CalendarData, CardDavPropertyName, DavProperty},
        request::{CalendarQuery, Filter, FilterOp, PropFind, Timezone, VCardPropertyWithGroup},
    },
    types::TimeRange,
};

pub type CalendarFilter = Vec<Filter<Vec<ICalendarComponentType>, ICalendarProperty, ICalendarParameterName>>;
pub type AddressbookFilter = Vec<Filter<(), VCardPropertyWithGroup, VCardParameterName>>;

/// An instance of a component: its index in the object and its times in seconds since 1970.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instance {
    pub comp_id: u32,
    pub start: i64,
    pub end: i64,
}

/// The instances of an object's components that meet `range` (or all, up to the limit).
pub fn instances(ical: &ICalendar, default_tz: Tz, range: Option<TimeRange>) -> Vec<Instance> {
    let expanded = ical.expand_dates(kernoid_groupware::ical::expansion_tz(ical, default_tz), MAX_INSTANCES);
    expanded
        .events
        .into_iter()
        .map(|event| {
            let start = event.start.timestamp();
            let end = match event.end {
                TimeOrDelta::Time(end) => end.timestamp(),
                TimeOrDelta::Delta(delta) => start + delta.num_seconds(),
            };
            Instance { comp_id: event.comp_id, start, end: end.max(start) }
        })
        .filter(|instance| range.is_none_or(|range| range.is_in_range(false, instance.start, instance.end)))
        .collect()
}

/// The widest time range the filters of a query name.
pub fn filter_range(query: &CalendarQuery) -> Option<TimeRange> {
    let mut range = TimeRange { start: i64::MAX, end: i64::MIN };
    for filter in &query.filters {
        let op = match filter {
            Filter::Component { op, .. } => op,
            Filter::Property { op, .. } => op,
            Filter::Parameter { op, .. } => op,
            _ => continue,
        };
        if let FilterOp::TimeRange(date_range) = op {
            range.start = range.start.min(date_range.start);
            range.end = range.end.max(date_range.end);
        }
    }
    (range.start != i64::MAX).then_some(range)
}

/// The range calendar data must be expanded over: the filters' and the calendar-data's own.
pub fn data_range(propfind: &PropFind, filter_range: Option<TimeRange>) -> Option<TimeRange> {
    let props = match propfind {
        PropFind::AllProp(props) | PropFind::Prop(props) => props,
        PropFind::PropName => &[][..],
    };
    for prop in props {
        if let DavProperty::CalDav(CalDavProperty::CalendarData(data)) = prop {
            let mut range = filter_range.unwrap_or(TimeRange { start: i64::MAX, end: i64::MIN });
            for data_range in [&data.expand, &data.limit_recurrence, &data.limit_freebusy].into_iter().flatten() {
                range.start = range.start.min(data_range.start);
                range.end = range.end.max(data_range.end);
            }
            return (range.start != i64::MAX).then_some(range);
        }
    }
    filter_range
}

pub fn parse_tz(tz: &Timezone) -> Option<Tz> {
    match tz {
        Timezone::Name(value) | Timezone::Id(value) => Tz::from_str(value).ok(),
        Timezone::None => None,
    }
}

fn find_components<'x>(
    ical: &'x ICalendar,
    comp: &[ICalendarComponentType],
) -> impl Iterator<Item = (usize, &'x ICalendarComponent)> {
    let comp = comp.last().unwrap_or(&ICalendarComponentType::VCalendar);
    ical.components
        .iter()
        .enumerate()
        .filter(move |(_, entry)| comp == &ICalendarComponentType::VCalendar || &entry.component_type == comp)
}

fn tz_id(entry: &ICalendarEntry) -> Option<&str> {
    entry.params.iter().find(|param| param.name == ICalendarParameterName::Tzid).and_then(|param| param.value.as_text())
}

/// Whether an object meets the filters of a `calendar-query` (RFC 4791, 9.7); `instances` are its instances over the
/// filters' range.
pub fn calendar_matches(ical: &ICalendar, filters: &CalendarFilter, instances: &[Instance], default_tz: Tz) -> bool {
    let mut is_all = true;
    let mut matches_one = false;

    for filter in filters {
        let result = match filter {
            Filter::AnyOf => {
                is_all = false;
                continue;
            }
            Filter::AllOf => {
                is_all = true;
                continue;
            }
            Filter::Property { prop, op, comp } => {
                let mut properties = find_components(ical, comp)
                    .flat_map(|(_, comp)| comp.entries.iter().filter(move |entry| &entry.name == prop))
                    .peekable();
                if properties.peek().is_some() {
                    properties.any(|entry| match op {
                        FilterOp::Exists => true,
                        FilterOp::Undefined => false,
                        FilterOp::TextMatch(text_match) => entry
                            .values
                            .iter()
                            .any(|value| value.as_text().is_some_and(|text| text_match.matches(text))),
                        FilterOp::TimeRange(range) => {
                            if let Some(ICalendarValue::PartialDateTime(date)) = entry.values.first() {
                                let tz = tz_id(entry).and_then(|tz_id| Tz::from_str(tz_id).ok()).unwrap_or(default_tz);
                                date.to_date_time().and_then(|date| date.to_date_time_with_tz(tz)).is_some_and(|date| {
                                    let timestamp = date.timestamp();
                                    // RFC4791#9.9: start <= DTSTART AND end > DTSTART
                                    range.start <= timestamp && range.end > timestamp
                                })
                            } else {
                                false
                            }
                        }
                    })
                } else {
                    matches!(op, FilterOp::Undefined)
                }
            }
            Filter::Parameter { prop, param, op, comp } => {
                let mut parameters = find_components(ical, comp)
                    .flat_map(|(_, comp)| {
                        comp.entries
                            .iter()
                            .filter(move |entry| &entry.name == prop)
                            .filter_map(move |entry| entry.params.iter().find(|p| p.name == *param))
                    })
                    .peekable();
                if parameters.peek().is_some() {
                    parameters.any(|entry| match op {
                        FilterOp::Exists => true,
                        FilterOp::Undefined => false,
                        FilterOp::TextMatch(text_match) => {
                            entry.value.as_text().is_some_and(|text| text_match.matches(text))
                        }
                        FilterOp::TimeRange(_) => false,
                    })
                } else {
                    matches!(op, FilterOp::Undefined)
                }
            }
            Filter::Component { comp, op } => match op {
                FilterOp::Exists => find_components(ical, comp).next().is_some(),
                FilterOp::Undefined => find_components(ical, comp).next().is_none(),
                FilterOp::TimeRange(range) => {
                    if matches!(comp.last(), Some(ICalendarComponentType::VAlarm)) {
                        false
                    } else {
                        let matching: HashMap<u32, &ICalendarComponentType> =
                            find_components(ical, comp).map(|(id, comp)| (id as u32, &comp.component_type)).collect();
                        !matching.is_empty()
                            && instances.iter().any(|instance| {
                                matching.get(&instance.comp_id).is_some_and(|kind| {
                                    range.is_in_range(
                                        **kind == ICalendarComponentType::VTodo,
                                        instance.start,
                                        instance.end,
                                    )
                                })
                            })
                    }
                }
                FilterOp::TextMatch(_) => false,
            },
        };
        if result {
            matches_one = true;
        } else if is_all {
            return false;
        }
    }

    is_all || matches_one
}

fn write_entry(out: &mut String, entry: &ICalendarEntry, with_value: bool) {
    if with_value {
        let _ = entry.write_to(out);
    } else {
        let empty = ICalendarEntry { name: entry.name.clone(), params: entry.params.clone(), values: Vec::new() };
        let _ = empty.write_to(out);
    }
}

/// The calendar data of an object as a `calendar-data` element asks for it (RFC 4791, 9.6): only some components
/// and properties, recurrences expanded or limited. `None` when it would hold more instances than allowed.
pub fn serialize_ical(
    ical: &ICalendar,
    data: &CalendarData,
    instances: &mut [Instance],
    instances_limit: &mut usize,
) -> Option<String> {
    let mut out = String::with_capacity(512);
    let root = [0u32];
    let mut component_iter = root.iter();
    let mut component_stack: Vec<(&ICalendarComponent, std::slice::Iter<'_, u32>)> = Vec::with_capacity(4);

    if data.expand.is_some() {
        instances.sort_unstable_by_key(|instance| instance.start);
    }

    loop {
        if let Some(component_id) = component_iter.next() {
            let component_id = *component_id;
            let component = ical.components.get(component_id as usize)?;

            // Limit recurrence overrides
            if let Some(limit_recurrence) = &data.limit_recurrence
                && component.is_recurrence_override()
                && !instances.iter().any(|instance| {
                    instance.comp_id == component_id
                        && limit_recurrence.is_in_range(
                            component.component_type == ICalendarComponentType::VTodo,
                            instance.start,
                            instance.end,
                        )
                })
            {
                continue;
            }

            let mut entries = component
                .entries
                .iter()
                .filter_map(|entry| {
                    if data.properties.is_empty() || component.component_type == ICalendarComponentType::VCalendar {
                        Some((entry, true))
                    } else {
                        data.properties
                            .iter()
                            .find(|prop| {
                                prop.component.as_ref().is_none_or(|comp| {
                                    comp == &component.component_type
                                        || component_stack.iter().any(|(parent, _)| comp == &parent.component_type)
                                }) && prop.name.as_ref().is_none_or(|name| name == &entry.name)
                            })
                            .map(|prop| (entry, !prop.no_value))
                    }
                })
                .peekable();

            let component_name = component.component_type.as_str();
            if let Some(expand) = &data.expand.filter(|_| component.component_type.has_time_ranges()) {
                // Expand recurrences into one component per instance
                let is_recurrent = component.is_recurrent();
                let is_recurrent_or_override = is_recurrent || component.is_recurrence_override();
                let is_todo = component.component_type == ICalendarComponentType::VTodo;
                let mut has_duration = false;
                let entries = entries
                    .filter(|(entry, _)| match &entry.name {
                        ICalendarProperty::Dtstart
                        | ICalendarProperty::Dtend
                        | ICalendarProperty::Exdate
                        | ICalendarProperty::Exrule
                        | ICalendarProperty::Rdate
                        | ICalendarProperty::Rrule
                        | ICalendarProperty::RecurrenceId => false,
                        ICalendarProperty::Due | ICalendarProperty::Completed | ICalendarProperty::Created => {
                            is_recurrent
                        }
                        ICalendarProperty::Duration => {
                            has_duration = true;
                            true
                        }
                        _ => true,
                    })
                    .collect::<Vec<_>>();
                for instance in instances.iter() {
                    if instance.comp_id == component_id
                        && (!is_recurrent_or_override || expand.is_in_range(is_todo, instance.start, instance.end))
                    {
                        if *instances_limit == 0 {
                            return None;
                        }
                        *instances_limit -= 1;
                        let _ = write!(&mut out, "BEGIN:{component_name}\r\n");
                        let mut entry = ICalendarEntry {
                            name: ICalendarProperty::Dtstart,
                            params: vec![],
                            values: vec![ICalendarValue::PartialDateTime(Box::new(
                                PartialDateTime::from_utc_timestamp(instance.start),
                            ))],
                        };
                        let _ = entry.write_to(&mut out);
                        if is_recurrent_or_override {
                            entry.name = ICalendarProperty::RecurrenceId;
                            let _ = entry.write_to(&mut out);
                        }
                        if !has_duration {
                            entry.name = ICalendarProperty::Dtend;
                            entry.values = vec![ICalendarValue::PartialDateTime(Box::new(
                                PartialDateTime::from_utc_timestamp(instance.end),
                            ))];
                            let _ = entry.write_to(&mut out);
                        }
                        for (entry, with_value) in &entries {
                            write_entry(&mut out, entry, *with_value);
                        }
                        let _ = write!(&mut out, "END:{component_name}\r\n");
                    }
                }
            } else if entries.peek().is_some()
                || (component.component_type == ICalendarComponentType::VCalendar
                    && !component.component_ids.is_empty())
            {
                let _ = write!(&mut out, "BEGIN:{component_name}\r\n");
                for (entry, with_value) in entries {
                    write_entry(&mut out, entry, with_value);
                }
                if !component.component_ids.is_empty() {
                    component_stack.push((component, component_iter));
                    component_iter = component.component_ids.iter();
                } else {
                    let _ = write!(&mut out, "END:{component_name}\r\n");
                }
            }
        } else if let Some((component, iter)) = component_stack.pop() {
            let _ = write!(&mut out, "END:{}\r\n", component.component_type.as_str());
            component_iter = iter;
        } else {
            break;
        }
    }

    Some(out)
}

fn find_card_properties<'x>(card: &'x VCard, prop: &VCardPropertyWithGroup) -> impl Iterator<Item = &'x VCardEntry> {
    card.entries.iter().filter(move |entry| entry.name == prop.name && entry.group == prop.group)
}

/// Whether a vCard meets the filters of an `addressbook-query` (RFC 6352, 8.6).
pub fn vcard_matches(card: &VCard, filters: &AddressbookFilter) -> bool {
    let mut is_all = true;
    let mut matches_one = false;

    for filter in filters {
        let result = match filter {
            Filter::AnyOf => {
                is_all = false;
                continue;
            }
            Filter::AllOf => {
                is_all = true;
                continue;
            }
            Filter::Property { prop, op, .. } => {
                let mut properties = find_card_properties(card, prop).peekable();
                if properties.peek().is_some() {
                    properties.any(|entry| match op {
                        FilterOp::Exists => true,
                        FilterOp::Undefined => false,
                        FilterOp::TextMatch(text_match) => entry
                            .values
                            .iter()
                            .any(|value| value.as_text().is_some_and(|text| text_match.matches(text))),
                        FilterOp::TimeRange(_) => false,
                    })
                } else {
                    matches!(op, FilterOp::Undefined)
                }
            }
            Filter::Parameter { prop, param, op, .. } => {
                let mut parameters = find_card_properties(card, prop)
                    .filter_map(|entry| entry.params.iter().find(|p| p.name == *param))
                    .peekable();
                if parameters.peek().is_some() {
                    parameters.any(|entry| match op {
                        FilterOp::Exists => true,
                        FilterOp::Undefined => false,
                        FilterOp::TextMatch(text_match) => {
                            entry.value.as_text().is_some_and(|text| text_match.matches(text))
                        }
                        FilterOp::TimeRange(_) => false,
                    })
                } else {
                    matches!(op, FilterOp::Undefined)
                }
            }
            Filter::Component { .. } => continue,
        };
        if result {
            matches_one = true;
        } else if is_all {
            return false;
        }
    }

    is_all || matches_one
}

/// A vCard with only the properties an `address-data` element asks for (RFC 6352, 10.4), in the version asked for.
pub fn serialize_vcard(card: &VCard, props: &[CardDavPropertyName], version: VCardVersion) -> String {
    let mut out = String::with_capacity(256);
    if props.is_empty() {
        let _ = card.write_to(&mut out, version);
        return out;
    }
    let is_v4 = matches!(version, VCardVersion::V4_0);
    let _ = write!(&mut out, "BEGIN:VCARD\r\n");
    for entry in &card.entries {
        if let Some(item) = props.iter().find(|item| entry.name == item.name && entry.group == item.group) {
            if item.name == VCardProperty::Version {
                let _ = write!(&mut out, "VERSION:{version}\r\n");
            } else if item.no_value {
                let empty = VCardEntry { values: Vec::new(), ..entry.clone() };
                let _ = empty.write_to(&mut out, is_v4);
            } else {
                let _ = entry.write_to(&mut out, is_v4);
            }
        }
    }
    let _ = write!(&mut out, "END:VCARD\r\n");
    out
}

/// What an object adds to free/busy over `range` (RFC 4791, 7.10): its opaque events that are not cancelled, by
/// type.
pub fn busy_times(
    ical: &ICalendar,
    instances: &[Instance],
    range: &TimeRange,
    busy: &mut HashMap<ICalendarFreeBusyType, Vec<(i64, i64)>>,
) {
    for (component_id, component) in ical.components.iter().enumerate() {
        if component.component_type != ICalendarComponentType::VEvent
            || component.transparency().is_some_and(|t| t != &ICalendarTransparency::Opaque)
        {
            continue;
        }
        let fbtype = match component.status() {
            Some(ICalendarStatus::Cancelled) => continue,
            Some(ICalendarStatus::Tentative) => ICalendarFreeBusyType::BusyTentative,
            _ => ICalendarFreeBusyType::Busy,
        };
        for instance in instances {
            if instance.comp_id == component_id as u32 && range.is_in_range(false, instance.start, instance.end) {
                busy.entry(fbtype.clone())
                    .or_default()
                    .push((instance.start.max(range.start), instance.end.min(range.end)));
            }
        }
    }
}

fn merge_intervals(mut intervals: Vec<(i64, i64)>) -> Vec<ICalendarValue> {
    intervals.sort_unstable_by_key(|interval| interval.0);
    let mut merged: Vec<(i64, i64)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
        .into_iter()
        .map(|(start, end)| {
            ICalendarValue::Period(ICalendarPeriod::Range {
                start: PartialDateTime::from_utc_timestamp(start),
                end: PartialDateTime::from_utc_timestamp(end),
            })
        })
        .collect()
}

/// A `VFREEBUSY` object for `range` from busy times (RFC 4791, 7.10; RFC 6638, 5).
pub fn freebusy_object(
    range: &TimeRange,
    busy: HashMap<ICalendarFreeBusyType, Vec<(i64, i64)>>,
    extra: Vec<ICalendarEntry>,
) -> ICalendar {
    let time =
        |timestamp: i64| ICalendarValue::PartialDateTime(Box::new(PartialDateTime::from_utc_timestamp(timestamp)));
    let mut entries = vec![
        ICalendarEntry {
            name: ICalendarProperty::Dtstamp,
            params: vec![],
            values: vec![time(chrono::Utc::now().timestamp())],
        },
        ICalendarEntry { name: ICalendarProperty::Dtstart, params: vec![], values: vec![time(range.start)] },
        ICalendarEntry { name: ICalendarProperty::Dtend, params: vec![], values: vec![time(range.end)] },
    ];
    entries.extend(extra);
    let mut busy: Vec<_> = busy.into_iter().collect();
    busy.sort_by_key(|(fbtype, _)| format!("{fbtype:?}"));
    for (fbtype, intervals) in busy {
        entries.push(ICalendarEntry {
            name: ICalendarProperty::Freebusy,
            params: vec![ICalendarParameter::fbtype(fbtype)],
            values: merge_intervals(intervals),
        });
    }
    ICalendar {
        components: vec![
            ICalendarComponent {
                component_type: ICalendarComponentType::VCalendar,
                entries: vec![
                    ICalendarEntry {
                        name: ICalendarProperty::Version,
                        params: vec![],
                        values: vec![ICalendarValue::Text("2.0".into())],
                    },
                    ICalendarEntry {
                        name: ICalendarProperty::Prodid,
                        params: vec![],
                        values: vec![ICalendarValue::Text(crate::PROD_ID.into())],
                    },
                ],
                component_ids: vec![1],
            },
            ICalendarComponent { component_type: ICalendarComponentType::VFreebusy, entries, component_ids: vec![] },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calcard::{Entry, Parser};

    fn parse(text: &str) -> ICalendar {
        match Parser::new(text).entry() {
            Entry::ICalendar(ical) => ical,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn instances_expand_and_free_busy_merges() {
        let ical = parse(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261005T090000Z\r\nDURATION:PT2H\r\n\
             RRULE:FREQ=DAILY;COUNT=3\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let day = 86_400;
        let start = 1_791_190_800; // 2026-10-05T09:00:00Z
        let range = TimeRange::new(start + day - 3600, start + 3 * day);
        let found = instances(&ical, Tz::UTC, Some(range));
        assert_eq!(found.iter().map(|i| i.start).collect::<Vec<_>>(), [start + day, start + 2 * day]);

        let mut busy = HashMap::new();
        busy_times(&ical, &found, &range, &mut busy);
        busy_times(&ical, &found, &range, &mut busy);
        let object = freebusy_object(&range, busy, Vec::new()).to_string().replace("\r\n ", "");
        assert!(
            object.contains("FREEBUSY;FBTYPE=BUSY:20261006T090000Z/20261006T110000Z,20261007T090000Z/20261007T110000Z"),
            "{object}"
        );
    }
}
