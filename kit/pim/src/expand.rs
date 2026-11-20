// SPDX-License-Identifier: MIT
//! The instances of an iCalendar object (RFC 5545, 3.8.5): each series' start, its `RRULE`s and `RDATE`s less its
//! `EXDATE`s, the instances an override (a component with `RECURRENCE-ID`) replaces in its place. Times are resolved
//! through the calendar's time zones; floating times and dates in the zone the caller gives.
//!
//! An instance lasts as its series does: `DTEND` (or `DUE`) less `DTSTART` – the same exact time for every instance –,
//! or `DURATION` – days of the calendar and exact seconds –, else a day for a date and nothing for a date-time. An
//! override without an end of its own lasts as its series. `RANGE=THISANDFUTURE` is read as this instance only (OPEN).

use std::collections::HashSet;

use jiff::{
    Timestamp,
    civil::{Date, DateTime},
    tz::TimeZone,
};

use crate::{
    content::Property,
    ical::Component,
    recur::Rule,
    time::{Duration, Time, to_timestamp},
    tz::Zones,
};

/// An instance of an event, task or journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// The component it comes from: its index in the calendar's components.
    pub component: usize,
    /// The time the series gives this instance (`RECURRENCE-ID`); `None` for what does not repeat.
    pub recurrence_id: Option<Time>,
    pub start: Timestamp,
    pub end: Timestamp,
    /// A date, not a date-time.
    pub all_day: bool,
}

/// The instances of an object, by start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expansion {
    pub instances: Vec<Instance>,
    /// Every instance (in the range) is there – not cut off at the limit.
    pub complete: bool,
}

/// The time a component starts: `DTSTART`, or a task's `DUE`.
pub fn start_of(component: &Component) -> Option<Time> {
    component
        .property("DTSTART")
        .and_then(Property::time_value)
        .or_else(|| if component.is("VTODO") { component.property("DUE").and_then(Property::time_value) } else { None })
}

/// How long a component lasts (see the module).
pub fn duration_of(component: &Component, zones: &Zones, default: &TimeZone) -> Duration {
    let Some(start) = component.property("DTSTART").and_then(Property::time_value) else { return Duration::ZERO };
    let end_name = if component.is("VTODO") { "DUE" } else { "DTEND" };
    if let Some(end) = component.property(end_name).and_then(Property::time_value) {
        if let (Time::Date(from), Time::Date(to)) = (&start, &end) {
            return Duration::days((crate::time::day_number(*to) - crate::time::day_number(*from)).max(0));
        }
        let seconds = end.resolve(zones, default).as_second() - start.resolve(zones, default).as_second();
        return Duration::seconds(seconds.max(0));
    }
    if let Some(duration) = component.property("DURATION").and_then(|duration| Duration::parse(&duration.value))
        && !duration.is_negative()
    {
        return duration;
    }
    if start.is_date() { Duration::days(1) } else { Duration::ZERO }
}

/// Whether an instance from `start` to `end` meets a range (RFC 4791, 9.9): it overlaps, or a moment in it.
pub fn overlaps(start: Timestamp, end: Timestamp, range: Option<(Timestamp, Timestamp)>) -> bool {
    match range {
        None => true,
        Some((from, to)) => start < to && (end > from || (start == end && start >= from)),
    }
}

/// The instances of the events, tasks and journal entries of a calendar that meet `range`, by start; at most `limit`.
pub fn expand(
    calendar: &Component,
    default: &TimeZone,
    range: Option<(Timestamp, Timestamp)>,
    limit: usize,
) -> Expansion {
    let zones = Zones::of(calendar);
    let mut out = Expansion { instances: Vec::new(), complete: true };
    let components: Vec<(usize, &Component)> =
        calendar.components.iter().enumerate().filter(|(_, component)| component.is_schedulable()).collect();
    let mut overridden: Vec<(String, Timestamp)> = Vec::new();
    for (_, component) in &components {
        if let (Some(uid), Some(id)) =
            (component.uid(), component.property("RECURRENCE-ID").and_then(Property::time_value))
        {
            overridden.push((uid, id.resolve(&zones, default)));
        }
    }
    for (index, component) in &components {
        let recurrence_id = component.property("RECURRENCE-ID").and_then(Property::time_value);
        let Some(start) = start_of(component).or_else(|| recurrence_id.clone()) else { continue };
        let duration = match recurrence_id {
            // An override without an end of its own lasts as its series.
            Some(_) if !has_end(component) => masters(&components, component)
                .map(|master| duration_of(master, &zones, default))
                .unwrap_or_else(|| duration_of(component, &zones, default)),
            _ => duration_of(component, &zones, default),
        };
        let zone = start.zone(&zones, default);
        let all_day = start.is_date();
        if recurrence_id.is_some() || !repeats(component) {
            let instant = to_timestamp(&zone, start.civil());
            let end = duration.end_of(&zone, start.civil()).max(instant);
            if overlaps(instant, end, range) {
                out.instances.push(Instance { component: *index, recurrence_id, start: instant, end, all_day });
            }
            continue;
        }
        let uid = component.uid().unwrap_or_default();
        let replaced: HashSet<Timestamp> =
            overridden.iter().filter(|(of, _)| *of == uid).map(|(_, instant)| *instant).collect();
        let mut excluded_instants = HashSet::new();
        let mut excluded_days: HashSet<Date> = HashSet::new();
        for time in component.properties("EXDATE").flat_map(Property::time_values) {
            match time {
                Time::Date(day) if !all_day => {
                    excluded_days.insert(day);
                }
                time => {
                    excluded_instants.insert(time.resolve(&zones, default));
                }
            }
        }
        let mut from_series = 0;
        for occurrence in occurrences(component, &start, &zones, default) {
            let civil = occurrence.civil;
            let instant = to_timestamp(&zone, civil);
            if let Some((_, to)) = range
                && instant >= to
            {
                break;
            }
            if replaced.contains(&instant)
                || excluded_instants.contains(&instant)
                || excluded_days.contains(&civil.date())
            {
                continue;
            }
            let end = occurrence.duration.unwrap_or(duration).end_of(&zone, civil).max(instant);
            if !overlaps(instant, end, range) {
                continue;
            }
            // Each series gives at most `limit` instances – its earliest; the others are not cut short by it.
            if from_series >= limit {
                out.complete = false;
                break;
            }
            from_series += 1;
            out.instances.push(Instance {
                component: *index,
                recurrence_id: Some(start.with_civil(civil)),
                start: instant,
                end,
                all_day,
            });
        }
    }
    out.instances.sort_by_key(|instance| (instance.start, instance.component));
    if out.instances.len() > limit {
        out.instances.truncate(limit);
        out.complete = false;
    }
    out
}

/// Whether a component repeats (`RRULE` or `RDATE`).
pub fn repeats(component: &Component) -> bool {
    component.property("RRULE").is_some() || component.property("RDATE").is_some()
}

fn has_end(component: &Component) -> bool {
    component.property("DTEND").is_some()
        || component.property("DURATION").is_some()
        || component.property("DUE").is_some()
}

fn masters<'a>(components: &'a [(usize, &'a Component)], of: &Component) -> Option<&'a Component> {
    let uid = of.uid()?;
    components
        .iter()
        .map(|(_, component)| *component)
        .find(|component| component.property("RECURRENCE-ID").is_none() && component.uid().as_deref() == Some(&uid))
}

/// An occurrence of a series: its local start, and its own duration (an `RDATE` period).
#[derive(Debug, Clone, Copy)]
struct Occurrence {
    civil: DateTime,
    duration: Option<Duration>,
}

/// The occurrences of a series in order, its rules and dates merged, each once.
fn occurrences<'a>(
    component: &'a Component,
    start: &'a Time,
    zones: &'a Zones,
    default: &'a TimeZone,
) -> impl Iterator<Item = Occurrence> + 'a {
    let zone = start.zone(zones, default);
    let rules: Vec<Rule> = component.properties("RRULE").filter_map(|rule| rule.value.parse().ok()).collect();
    // The start in its own frame; RDATEs moved into it.
    let mut dates: Vec<Occurrence> = vec![Occurrence { civil: start.civil(), duration: None }];
    for rdate in component.properties("RDATE") {
        let period = rdate.param("VALUE").is_some_and(|value| value.eq_ignore_ascii_case("PERIOD"));
        for item in rdate.value.split(',') {
            let (first, second) = match item.split_once('/') {
                Some((first, second)) => (first, Some(second)),
                None => (item, None),
            };
            let Some(time) = Time::parse(
                first,
                rdate.param("TZID"),
                rdate.param("VALUE").is_some_and(|v| v.eq_ignore_ascii_case("DATE")),
            ) else {
                continue;
            };
            let instant = time.resolve(zones, default);
            let civil = if start.is_date() { time.civil().date().at(0, 0, 0, 0) } else { zone.to_datetime(instant) };
            let duration = second.filter(|_| period || second.is_some()).and_then(|second| {
                Duration::parse(second).or_else(|| {
                    let end = Time::parse(second, rdate.param("TZID"), false)?.resolve(zones, default);
                    Some(Duration::seconds((end.as_second() - instant.as_second()).max(0)))
                })
            });
            dates.push(Occurrence { civil, duration });
        }
    }
    dates.sort_by_key(|occurrence| occurrence.civil);
    let until_of = |rule: &Rule| {
        rule.until.as_ref().map(|until| match until {
            Time::Date(day) => day.at(23, 59, 59, 0),
            Time::Utc(_) | Time::Zoned(..) if !start.is_date() => zone.to_datetime(until.resolve(zones, default)),
            other => other.civil(),
        })
    };
    let mut streams: Vec<Box<dyn Iterator<Item = Occurrence> + 'a>> = Vec::new();
    streams.push(Box::new(dates.into_iter()));
    let start_civil = start.civil();
    let date_only = start.is_date();
    for rule in rules {
        let until = until_of(&rule);
        streams.push(Box::new(
            rule.into_occurrences(start_civil, date_only, until).map(|civil| Occurrence { civil, duration: None }),
        ));
    }
    Merge { streams: streams.into_iter().map(|s| s.peekable()).collect(), last: None }
}

/// Sorted streams merged, each time once.
struct Merge<'a> {
    streams: Vec<std::iter::Peekable<Box<dyn Iterator<Item = Occurrence> + 'a>>>,
    last: Option<DateTime>,
}

impl Iterator for Merge<'_> {
    type Item = Occurrence;

    fn next(&mut self) -> Option<Occurrence> {
        loop {
            let mut best: Option<(usize, DateTime)> = None;
            for (index, stream) in self.streams.iter_mut().enumerate() {
                if let Some(next) = stream.peek()
                    && best.is_none_or(|(_, time)| next.civil < time)
                {
                    best = Some((index, next.civil));
                }
            }
            let (index, _) = best?;
            let next = self.streams[index].next()?;
            if self.last == Some(next.civil) {
                continue;
            }
            self.last = Some(next.civil);
            return Some(next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ical, time::format_utc};

    fn instances(text: &str, zone: &str, range: Option<(&str, &str)>, limit: usize) -> (Vec<(String, String)>, bool) {
        let calendar = ical::parse(text).unwrap();
        let zone = TimeZone::get(zone).unwrap();
        let range = range.map(|(a, b)| (crate::time::parse_utc(a).unwrap(), crate::time::parse_utc(b).unwrap()));
        let expansion = expand(&calendar, &zone, range, limit);
        (expansion.instances.iter().map(|i| (format_utc(i.start), format_utc(i.end))).collect(), expansion.complete)
    }

    fn event(lines: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:t\r\nBEGIN:VEVENT\r\nUID:a\r\n{lines}END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    #[test]
    fn a_series_keeps_its_local_time_across_daylight_saving() {
        let text =
            event("DTSTART;TZID=Europe/Berlin:20261020T090000\r\nDURATION:PT1H\r\nRRULE:FREQ=WEEKLY;COUNT=3\r\n");
        let (found, complete) = instances(&text, "UTC", None, 100);
        assert!(complete);
        assert_eq!(
            found,
            [
                ("2026-10-20T07:00:00Z".into(), "2026-10-20T08:00:00Z".into()),
                ("2026-10-27T08:00:00Z".into(), "2026-10-27T09:00:00Z".into()),
                ("2026-11-03T08:00:00Z".into(), "2026-11-03T09:00:00Z".into()),
            ]
        );
        // A UTC start stays in UTC, whatever the default zone.
        let utc = event("DTSTART:20261020T090000Z\r\nDURATION:PT1H\r\nRRULE:FREQ=WEEKLY;COUNT=2\r\n");
        let (found, _) = instances(&utc, "Europe/Berlin", None, 100);
        assert_eq!(found[1].0, "2026-10-27T09:00:00Z");
    }

    #[test]
    fn a_time_the_clocks_skip_moves_on() {
        let text = event("DTSTART;TZID=Europe/Berlin:20260328T023000\r\nRRULE:FREQ=DAILY;COUNT=2\r\n");
        let (found, _) = instances(&text, "UTC", None, 10);
        assert_eq!(found[0].0, "2026-03-28T01:30:00Z");
        assert_eq!(found[1].0, "2026-03-29T01:30:00Z"); // 03:30 summer time
    }

    #[test]
    fn exceptions_overrides_and_dates() {
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:t\r\nBEGIN:VEVENT\r\nUID:a\r\n\
            DTSTART;TZID=Europe/Berlin:20261102T100000\r\nDTEND;TZID=Europe/Berlin:20261102T110000\r\n\
            RRULE:FREQ=WEEKLY;COUNT=4\r\nEXDATE:20261116T090000Z\r\nRDATE;TZID=Europe/Berlin:20261104T150000\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:a\r\nRECURRENCE-ID;TZID=Europe/Berlin:20261109T100000\r\n\
            DTSTART;TZID=Europe/Berlin:20261110T110000\r\nSUMMARY:Moved\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let (found, _) = instances(text, "UTC", None, 10);
        let starts: Vec<&str> = found.iter().map(|(start, _)| start.as_str()).collect();
        assert_eq!(
            starts,
            ["2026-11-02T09:00:00Z", "2026-11-04T14:00:00Z", "2026-11-10T10:00:00Z", "2026-11-23T09:00:00Z"]
        );
        // The moved instance lasts as its series.
        assert_eq!(found[2].1, "2026-11-10T11:00:00Z");
        let calendar = ical::parse(text).unwrap();
        let expansion = expand(&calendar, &TimeZone::UTC, None, 10);
        assert_eq!(expansion.instances[2].component, 1);
        assert_eq!(expansion.instances[2].recurrence_id.as_ref().unwrap().format(), "20261109T100000");
    }

    #[test]
    fn an_override_of_an_endless_series_is_not_cut_off_by_the_limit() {
        // The override of the first instance comes after its endless series in the file; with a limit, the series
        // must not use it up before the override is read.
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:t\r\nBEGIN:VEVENT\r\nUID:a\r\n\
            DTSTART;TZID=Europe/Berlin:20261121T090000\r\nDTEND;TZID=Europe/Berlin:20261121T100000\r\n\
            RRULE:FREQ=WEEKLY\r\nSUMMARY:Serie\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:a\r\n\
            RECURRENCE-ID;TZID=Europe/Berlin:20261121T090000\r\nDTSTART;TZID=Europe/Berlin:20261121T090000\r\n\
            DTEND;TZID=Europe/Berlin:20261121T100000\r\nSUMMARY:Einmal\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let calendar = ical::parse(text).unwrap();
        let expansion = expand(&calendar, &TimeZone::UTC, None, 3);
        assert!(!expansion.complete);
        let found: Vec<(usize, String)> =
            expansion.instances.iter().map(|i| (i.component, format_utc(i.start))).collect();
        assert_eq!(
            found,
            [
                (1, "2026-11-21T08:00:00Z".to_owned()),
                (0, "2026-11-28T08:00:00Z".to_owned()),
                (0, "2026-12-05T08:00:00Z".to_owned()),
            ]
        );
    }

    #[test]
    fn ranges_limits_and_all_day_events() {
        let endless = event("DTSTART:20261005T090000Z\r\nDTEND:20261005T100000Z\r\nRRULE:FREQ=WEEKLY\r\n");
        let (found, complete) = instances(&endless, "UTC", None, 10);
        assert_eq!((found.len(), complete), (10, false));
        let (found, complete) = instances(&endless, "UTC", Some(("2026-12-01T00:00:00Z", "2026-12-15T00:00:00Z")), 10);
        assert_eq!((found.len(), complete), (2, true));
        assert_eq!(found[0].0, "2026-12-07T09:00:00Z");

        let day = event("DTSTART;VALUE=DATE:20261105\r\nRRULE:FREQ=YEARLY;UNTIL=20281105\r\n");
        let (found, _) = instances(&day, "Europe/Berlin", None, 10);
        assert_eq!(
            found,
            [
                ("2026-11-04T23:00:00Z".into(), "2026-11-05T23:00:00Z".into()),
                ("2027-11-04T23:00:00Z".into(), "2027-11-05T23:00:00Z".into()),
                ("2028-11-04T23:00:00Z".into(), "2028-11-05T23:00:00Z".into()),
            ]
        );
        // Floating times are in the zone given; UNTIL in UTC against a zoned start is an instant.
        let floating = event("DTSTART:20261005T090000\r\n");
        assert_eq!(instances(&floating, "Europe/Berlin", None, 10).0[0].0, "2026-10-05T07:00:00Z");
        let until =
            event("DTSTART;TZID=America/New_York:20261101T090000\r\nRRULE:FREQ=DAILY;UNTIL=20261103T140000Z\r\n");
        assert_eq!(instances(&until, "UTC", None, 10).0.len(), 3);
        let before =
            event("DTSTART;TZID=America/New_York:20261101T090000\r\nRRULE:FREQ=DAILY;UNTIL=20261103T135959Z\r\n");
        assert_eq!(instances(&before, "UTC", None, 10).0.len(), 2);
    }

    #[test]
    fn tasks_and_unknown_zones() {
        let task = "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t\r\nDUE:20261105T120000Z\r\nEND:VTODO\r\n\
            BEGIN:VTODO\r\nUID:u\r\nSUMMARY:no dates\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        let (found, _) = instances(task, "UTC", None, 10);
        assert_eq!(found, [("2026-11-05T12:00:00Z".into(), "2026-11-05T12:00:00Z".into())]);
        let outlook = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:o\r\nDTSTART;TZID=W. Europe Standard Time:20261105T090000\r\n\
            DTEND;TZID=W. Europe Standard Time:20261105T093000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(
            instances(outlook, "UTC", None, 10).0[0],
            ("2026-11-05T08:00:00Z".into(), "2026-11-05T08:30:00Z".into())
        );
    }
}
