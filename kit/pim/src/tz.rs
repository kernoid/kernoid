// SPDX-License-Identifier: MIT
//! Time zones: what a `TZID` names (RFC 5545, 3.2.19) and `VTIMEZONE` components (3.6.5).
//!
//! A `TZID` is resolved, in this order, as an IANA name; as an IANA name behind a prefix (`/mozilla.org/…/Europe/Berlin`,
//! `/freeassociation.sourceforge.net/Tzfile/…`); as a Windows name (`W. Europe Standard Time`, as Outlook and Exchange
//! write, after the territory-neutral mappings of CLDR's `windowsZones`); through `X-LIC-LOCATION`; and last from the
//! rules of the calendar's own `VTIMEZONE` – its current standard and daylight observances as a POSIX rule, or its
//! offset. Historic rules of an unknown zone are not kept (OPEN).
//!
//! [`vtimezone`] writes the `VTIMEZONE` of an IANA zone: its transitions over a span, yearly ones as `RRULE`s.

use std::collections::HashMap;

use jiff::{Timestamp, tz::TimeZone};

use crate::{
    content::Property,
    ical::Component,
    recur::{Frequency, Rule},
    time::{self, Time, format_offset, parse_offset},
};

/// The time zones a calendar's `VTIMEZONE`s define, by `TZID`.
#[derive(Debug, Clone, Default)]
pub struct Zones {
    zones: HashMap<String, TimeZone>,
}

impl Zones {
    /// The zones of a `VCALENDAR` (or of the components given).
    pub fn of(calendar: &Component) -> Zones {
        let mut zones = HashMap::new();
        for component in calendar.components.iter().filter(|component| component.is("VTIMEZONE")) {
            let Some(tzid) = component.property("TZID").map(|tzid| tzid.as_text()) else { continue };
            let zone = iana(&tzid)
                .or_else(|| component.property("X-LIC-LOCATION").and_then(|location| iana(&location.as_text())))
                .or_else(|| from_rules(component));
            if let Some(zone) = zone {
                zones.insert(tzid, zone);
            }
        }
        Zones { zones }
    }

    /// The zone a `TZID` names: the calendar's own definition, or what the name says.
    pub fn get(&self, tzid: &str) -> Option<TimeZone> {
        self.zones.get(tzid).cloned().or_else(|| iana(tzid))
    }

    /// The IANA name of the zone a `TZID` names, if it has one.
    pub fn iana_name(&self, tzid: &str) -> Option<String> {
        match self.zones.get(tzid) {
            Some(zone) => zone.iana_name().map(str::to_owned),
            None => iana_name(tzid),
        }
    }
}

/// The IANA zone a name means – an IANA name, one behind a prefix, a Windows name; `None` for anything else.
pub fn iana(name: &str) -> Option<TimeZone> {
    let name = name.trim().trim_matches('"').trim();
    if name.is_empty() {
        return None;
    }
    if time::is_utc_name(name) {
        return Some(TimeZone::UTC);
    }
    if name.contains('/')
        && let Ok(zone) = TimeZone::get(name)
    {
        return Some(zone);
    }
    // A prefix: try the last segments, longest first.
    let segments: Vec<&str> = name.split('/').filter(|segment| !segment.is_empty()).collect();
    for start in 1..segments.len().saturating_sub(1) {
        let candidate = segments[start..].join("/");
        if let Ok(zone) = TimeZone::get(&candidate) {
            return Some(zone);
        }
    }
    if let Some(iana) = windows(name) {
        return TimeZone::get(iana).ok();
    }
    // Names without an area (`GB`, `Japan`, `EST5EDT`) last: they are less likely meant.
    TimeZone::get(name).ok()
}

/// The IANA name of what a name means.
pub fn iana_name(name: &str) -> Option<String> {
    let zone = iana(name)?;
    if zone == TimeZone::UTC {
        return Some("Etc/UTC".into());
    }
    zone.iana_name().map(str::to_owned)
}

/// A zone from a `VTIMEZONE`'s rules: the current standard and daylight observances, or the current offset.
fn from_rules(component: &Component) -> Option<TimeZone> {
    struct Observance {
        daylight: bool,
        start: jiff::civil::DateTime,
        offset: i32,
        rule: Option<Rule>,
    }
    let observances: Vec<Observance> = component
        .components
        .iter()
        .filter(|part| part.is("STANDARD") || part.is("DAYLIGHT"))
        .filter_map(|part| {
            Some(Observance {
                daylight: part.is("DAYLIGHT"),
                start: part.property("DTSTART")?.time_value()?.civil(),
                offset: parse_offset(&part.property("TZOFFSETTO")?.value)?,
                rule: part.property("RRULE").and_then(|rule| rule.value.parse().ok()),
            })
        })
        .collect();
    let latest = |daylight: bool| {
        observances
            .iter()
            .filter(|o| o.daylight == daylight)
            .max_by_key(|o| (o.rule.is_some() && o.rule.as_ref().is_some_and(|r| r.until.is_none()), o.start))
    };
    let standard = latest(false);
    let daylight = latest(true);
    if let (Some(standard), Some(daylight)) = (standard, daylight)
        && let (Some(std_rule), Some(dst_rule)) = (&standard.rule, &daylight.rule)
        && std_rule.until.is_none()
        && dst_rule.until.is_none()
        && let (Some(to_std), Some(to_dst)) =
            (posix_date(std_rule, standard.start), posix_date(dst_rule, daylight.start))
    {
        let posix =
            format!("<STD>{}<DST>{},{to_dst},{to_std}", posix_offset(standard.offset), posix_offset(daylight.offset));
        if let Ok(zone) = TimeZone::posix(&posix) {
            return Some(zone);
        }
    }
    let current = observances.iter().max_by_key(|o| o.start)?;
    let offset =
        standard.map_or(current.offset, |standard| if daylight.is_some() { standard.offset } else { current.offset });
    jiff::tz::Offset::from_seconds(offset).ok().map(TimeZone::fixed)
}

/// POSIX writes offsets west of Greenwich as positive.
fn posix_offset(seconds: i32) -> String {
    let west = -seconds;
    let sign = if west < 0 { "-" } else { "" };
    let abs = west.abs();
    format!("{sign}{}:{:02}:{:02}", abs / 3600, abs % 3600 / 60, abs % 60)
}

/// `Mm.n.d/time` of a yearly rule on the nth (or last) weekday of a month.
fn posix_date(rule: &Rule, start: jiff::civil::DateTime) -> Option<String> {
    if rule.frequency != Frequency::Yearly || rule.by_month.len() > 1 {
        return None;
    }
    let month = rule.by_month.first().copied().unwrap_or(start.month() as u8);
    let (nth, weekday) = match rule.by_day.as_slice() {
        [(Some(nth), weekday)] => (*nth, *weekday),
        // `BYDAY=SU;BYMONTHDAY=8,9,…,14`: the second Sunday.
        [(None, weekday)] if !rule.by_month_day.is_empty() => {
            let first = *rule.by_month_day.iter().min()?;
            if first < 0 { (-1, *weekday) } else { (i16::from((first - 1) / 7 + 1), *weekday) }
        }
        _ => return None,
    };
    let week = match nth {
        -1 => 5,
        1..=4 => nth,
        _ => return None,
    };
    Some(format!(
        "M{month}.{week}.{}/{}:{:02}:{:02}",
        weekday.to_sunday_zero_offset(),
        start.hour(),
        start.minute(),
        start.second()
    ))
}

/// The `VTIMEZONE` of an IANA zone over `from` to `to`: the observance in effect at `from` and each transition after,
/// those that repeat every year as one observance with an `RRULE` (open when it goes on to the end).
pub fn vtimezone(name: &str, from: Timestamp, to: Timestamp) -> Option<Component> {
    let zone = iana(name)?;
    let tzid = if zone == TimeZone::UTC { "Etc/UTC".to_owned() } else { zone.iana_name().unwrap_or(name).to_owned() };
    let to = to.max(from.checked_add(jiff::SignedDuration::from_hours(24 * 366 * 3)).unwrap_or(to));
    struct Transition {
        at: Timestamp,
        from: i32,
        to: i32,
        daylight: bool,
        abbreviation: String,
        onset: jiff::civil::DateTime,
    }
    let mut transitions = Vec::new();
    let previous = zone.preceding(from).next();
    let mut list: Vec<(Timestamp, i32, bool, String)> = Vec::new();
    if let Some(previous) = &previous {
        list.push((
            previous.timestamp(),
            previous.offset().seconds(),
            previous.dst().is_dst(),
            previous.abbreviation().to_owned(),
        ));
    }
    for transition in zone.following(from) {
        if transition.timestamp() > to {
            break;
        }
        list.push((
            transition.timestamp(),
            transition.offset().seconds(),
            transition.dst().is_dst(),
            transition.abbreviation().to_owned(),
        ));
    }
    for (at, offset, daylight, abbreviation) in list {
        let before = at.checked_sub(jiff::SignedDuration::from_secs(1)).unwrap_or(at);
        let from_offset = zone.to_offset(before).seconds();
        let onset = jiff::tz::Offset::from_seconds(from_offset).ok()?.to_datetime(at);
        transitions.push(Transition { at, from: from_offset, to: offset, daylight, abbreviation, onset });
    }
    let mut out = Component::new("VTIMEZONE");
    out.properties.push(Property::text("TZID", &tzid));
    if transitions.is_empty() {
        let offset = zone.to_offset(from).seconds();
        let mut standard = Component::new("STANDARD");
        standard.properties.push(Property::new("DTSTART", "19700101T000000"));
        standard.properties.push(Property::new("TZOFFSETFROM", format_offset(offset)));
        standard.properties.push(Property::new("TZOFFSETTO", format_offset(offset)));
        out.components.push(standard);
        return Some(out);
    }
    let last_year = jiff::tz::TimeZone::UTC.to_datetime(to).year();
    // The key of a yearly transition: the same change on the same weekday of the same week of the same month.
    let key = |t: &Transition| {
        let date = t.onset.date();
        let days = date.days_in_month();
        let nth: i16 = if date.day() > days - 7 { -1 } else { i16::from((date.day() - 1) / 7 + 1) };
        (t.daylight, t.from, t.to, t.abbreviation.clone(), date.month(), date.weekday(), nth, t.onset.time())
    };
    let mut used = vec![false; transitions.len()];
    for first in 0..transitions.len() {
        if used[first] {
            continue;
        }
        used[first] = true;
        let first_key = key(&transitions[first]);
        let mut run = vec![first];
        let mut year = transitions[first].onset.year();
        for next in first + 1..transitions.len() {
            if !used[next] && transitions[next].onset.year() == year + 1 && key(&transitions[next]) == first_key {
                used[next] = true;
                run.push(next);
                year += 1;
            }
        }
        let start = &transitions[first];
        let last = &transitions[*run.last().expect("one")];
        let mut observance = Component::new(if start.daylight { "DAYLIGHT" } else { "STANDARD" });
        observance.properties.push(Property::new("DTSTART", time::format_date_time(start.onset)));
        observance.properties.push(Property::new("TZOFFSETFROM", format_offset(start.from)));
        observance.properties.push(Property::new("TZOFFSETTO", format_offset(start.to)));
        if !start.abbreviation.is_empty() && !start.abbreviation.starts_with(['+', '-']) {
            observance.properties.push(Property::text("TZNAME", &start.abbreviation));
        }
        if run.len() > 1 {
            let (_, _, _, _, month, weekday, nth, _) = first_key;
            let mut rule = Rule::new(Frequency::Yearly);
            rule.by_month = vec![month as u8];
            rule.by_day = vec![(Some(nth), weekday)];
            if last.onset.year() < last_year - 1 {
                rule.until = Some(Time::Utc(TimeZone::UTC.to_datetime(last.at)));
            }
            observance.properties.push(Property::new("RRULE", rule.to_string()));
        }
        out.components.push(observance);
    }
    Some(out)
}

/// The IANA zone of a Windows time zone name (CLDR `windowsZones`, territory 001).
fn windows(name: &str) -> Option<&'static str> {
    const ZONES: &[(&str, &str)] = &[
        ("Dateline Standard Time", "Etc/GMT+12"),
        ("UTC-11", "Etc/GMT+11"),
        ("Aleutian Standard Time", "America/Adak"),
        ("Hawaiian Standard Time", "Pacific/Honolulu"),
        ("Marquesas Standard Time", "Pacific/Marquesas"),
        ("Alaskan Standard Time", "America/Anchorage"),
        ("UTC-09", "Etc/GMT+9"),
        ("Pacific Standard Time (Mexico)", "America/Tijuana"),
        ("UTC-08", "Etc/GMT+8"),
        ("Pacific Standard Time", "America/Los_Angeles"),
        ("US Mountain Standard Time", "America/Phoenix"),
        ("Mountain Standard Time (Mexico)", "America/Mazatlan"),
        ("Mountain Standard Time", "America/Denver"),
        ("Yukon Standard Time", "America/Whitehorse"),
        ("Central America Standard Time", "America/Guatemala"),
        ("Central Standard Time", "America/Chicago"),
        ("Easter Island Standard Time", "Pacific/Easter"),
        ("Central Standard Time (Mexico)", "America/Mexico_City"),
        ("Canada Central Standard Time", "America/Regina"),
        ("SA Pacific Standard Time", "America/Bogota"),
        ("Eastern Standard Time (Mexico)", "America/Cancun"),
        ("Eastern Standard Time", "America/New_York"),
        ("Haiti Standard Time", "America/Port-au-Prince"),
        ("Cuba Standard Time", "America/Havana"),
        ("US Eastern Standard Time", "America/Indianapolis"),
        ("Turks And Caicos Standard Time", "America/Grand_Turk"),
        ("Paraguay Standard Time", "America/Asuncion"),
        ("Atlantic Standard Time", "America/Halifax"),
        ("Venezuela Standard Time", "America/Caracas"),
        ("Central Brazilian Standard Time", "America/Cuiaba"),
        ("SA Western Standard Time", "America/La_Paz"),
        ("Pacific SA Standard Time", "America/Santiago"),
        ("Newfoundland Standard Time", "America/St_Johns"),
        ("Tocantins Standard Time", "America/Araguaina"),
        ("E. South America Standard Time", "America/Sao_Paulo"),
        ("SA Eastern Standard Time", "America/Cayenne"),
        ("Argentina Standard Time", "America/Buenos_Aires"),
        ("Greenland Standard Time", "America/Godthab"),
        ("Montevideo Standard Time", "America/Montevideo"),
        ("Magallanes Standard Time", "America/Punta_Arenas"),
        ("Saint Pierre Standard Time", "America/Miquelon"),
        ("Bahia Standard Time", "America/Bahia"),
        ("UTC-02", "Etc/GMT+2"),
        ("Mid-Atlantic Standard Time", "Etc/GMT+2"),
        ("Azores Standard Time", "Atlantic/Azores"),
        ("Cape Verde Standard Time", "Atlantic/Cape_Verde"),
        ("UTC", "Etc/UTC"),
        ("Coordinated Universal Time", "Etc/UTC"),
        ("GMT Standard Time", "Europe/London"),
        ("Greenwich Standard Time", "Atlantic/Reykjavik"),
        ("Sao Tome Standard Time", "Africa/Sao_Tome"),
        ("Morocco Standard Time", "Africa/Casablanca"),
        ("W. Europe Standard Time", "Europe/Berlin"),
        ("Central Europe Standard Time", "Europe/Budapest"),
        ("Romance Standard Time", "Europe/Paris"),
        ("Central European Standard Time", "Europe/Warsaw"),
        ("W. Central Africa Standard Time", "Africa/Lagos"),
        ("Jordan Standard Time", "Asia/Amman"),
        ("GTB Standard Time", "Europe/Bucharest"),
        ("Middle East Standard Time", "Asia/Beirut"),
        ("Egypt Standard Time", "Africa/Cairo"),
        ("E. Europe Standard Time", "Europe/Chisinau"),
        ("Syria Standard Time", "Asia/Damascus"),
        ("West Bank Standard Time", "Asia/Hebron"),
        ("South Africa Standard Time", "Africa/Johannesburg"),
        ("FLE Standard Time", "Europe/Kiev"),
        ("Israel Standard Time", "Asia/Jerusalem"),
        ("South Sudan Standard Time", "Africa/Juba"),
        ("Kaliningrad Standard Time", "Europe/Kaliningrad"),
        ("Sudan Standard Time", "Africa/Khartoum"),
        ("Libya Standard Time", "Africa/Tripoli"),
        ("Namibia Standard Time", "Africa/Windhoek"),
        ("Arabic Standard Time", "Asia/Baghdad"),
        ("Turkey Standard Time", "Europe/Istanbul"),
        ("Arab Standard Time", "Asia/Riyadh"),
        ("Belarus Standard Time", "Europe/Minsk"),
        ("Russian Standard Time", "Europe/Moscow"),
        ("E. Africa Standard Time", "Africa/Nairobi"),
        ("Volgograd Standard Time", "Europe/Volgograd"),
        ("Iran Standard Time", "Asia/Tehran"),
        ("Arabian Standard Time", "Asia/Dubai"),
        ("Astrakhan Standard Time", "Europe/Astrakhan"),
        ("Azerbaijan Standard Time", "Asia/Baku"),
        ("Russia Time Zone 3", "Europe/Samara"),
        ("Mauritius Standard Time", "Indian/Mauritius"),
        ("Saratov Standard Time", "Europe/Saratov"),
        ("Georgian Standard Time", "Asia/Tbilisi"),
        ("Caucasus Standard Time", "Asia/Yerevan"),
        ("Afghanistan Standard Time", "Asia/Kabul"),
        ("West Asia Standard Time", "Asia/Tashkent"),
        ("Qyzylorda Standard Time", "Asia/Qyzylorda"),
        ("Ekaterinburg Standard Time", "Asia/Yekaterinburg"),
        ("Pakistan Standard Time", "Asia/Karachi"),
        ("India Standard Time", "Asia/Calcutta"),
        ("Sri Lanka Standard Time", "Asia/Colombo"),
        ("Nepal Standard Time", "Asia/Katmandu"),
        ("Central Asia Standard Time", "Asia/Bishkek"),
        ("Bangladesh Standard Time", "Asia/Dhaka"),
        ("Omsk Standard Time", "Asia/Omsk"),
        ("Myanmar Standard Time", "Asia/Rangoon"),
        ("SE Asia Standard Time", "Asia/Bangkok"),
        ("Altai Standard Time", "Asia/Barnaul"),
        ("W. Mongolia Standard Time", "Asia/Hovd"),
        ("North Asia Standard Time", "Asia/Krasnoyarsk"),
        ("N. Central Asia Standard Time", "Asia/Novosibirsk"),
        ("Tomsk Standard Time", "Asia/Tomsk"),
        ("China Standard Time", "Asia/Shanghai"),
        ("North Asia East Standard Time", "Asia/Irkutsk"),
        ("Singapore Standard Time", "Asia/Singapore"),
        ("W. Australia Standard Time", "Australia/Perth"),
        ("Taipei Standard Time", "Asia/Taipei"),
        ("Ulaanbaatar Standard Time", "Asia/Ulaanbaatar"),
        ("Aus Central W. Standard Time", "Australia/Eucla"),
        ("Transbaikal Standard Time", "Asia/Chita"),
        ("Tokyo Standard Time", "Asia/Tokyo"),
        ("North Korea Standard Time", "Asia/Pyongyang"),
        ("Korea Standard Time", "Asia/Seoul"),
        ("Yakutsk Standard Time", "Asia/Yakutsk"),
        ("Cen. Australia Standard Time", "Australia/Adelaide"),
        ("AUS Central Standard Time", "Australia/Darwin"),
        ("E. Australia Standard Time", "Australia/Brisbane"),
        ("AUS Eastern Standard Time", "Australia/Sydney"),
        ("West Pacific Standard Time", "Pacific/Port_Moresby"),
        ("Tasmania Standard Time", "Australia/Hobart"),
        ("Vladivostok Standard Time", "Asia/Vladivostok"),
        ("Lord Howe Standard Time", "Australia/Lord_Howe"),
        ("Bougainville Standard Time", "Pacific/Bougainville"),
        ("Russia Time Zone 10", "Asia/Srednekolymsk"),
        ("Magadan Standard Time", "Asia/Magadan"),
        ("Norfolk Standard Time", "Pacific/Norfolk"),
        ("Sakhalin Standard Time", "Asia/Sakhalin"),
        ("Central Pacific Standard Time", "Pacific/Guadalcanal"),
        ("Russia Time Zone 11", "Asia/Kamchatka"),
        ("New Zealand Standard Time", "Pacific/Auckland"),
        ("UTC+12", "Etc/GMT-12"),
        ("Fiji Standard Time", "Pacific/Fiji"),
        ("Chatham Islands Standard Time", "Pacific/Chatham"),
        ("UTC+13", "Etc/GMT-13"),
        ("Tonga Standard Time", "Pacific/Tongatapu"),
        ("Samoa Standard Time", "Pacific/Apia"),
        ("Line Islands Standard Time", "Pacific/Kiritimati"),
    ];
    ZONES.iter().find(|(windows, _)| windows.eq_ignore_ascii_case(name)).map(|(_, iana)| *iana)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ical;

    fn utc(text: &str) -> Timestamp {
        time::parse_utc(text).unwrap()
    }

    #[test]
    fn names_resolve_to_iana_zones() {
        assert_eq!(iana_name("Europe/Berlin").as_deref(), Some("Europe/Berlin"));
        assert_eq!(iana_name("/mozilla.org/20050126_1/Europe/Berlin").as_deref(), Some("Europe/Berlin"));
        assert_eq!(
            iana_name("/freeassociation.sourceforge.net/Tzfile/America/New_York").as_deref(),
            Some("America/New_York")
        );
        assert_eq!(iana_name("W. Europe Standard Time").as_deref(), Some("Europe/Berlin"));
        assert_eq!(iana_name("\"Pacific Standard Time\"").as_deref(), Some("America/Los_Angeles"));
        assert_eq!(iana_name("UTC").as_deref(), Some("Etc/UTC"));
        assert!(iana("Mars/Base").is_none());
        assert!(iana("Customized Time Zone").is_none());
    }

    #[test]
    fn an_unknown_zone_takes_its_rules_from_its_vtimezone() {
        let text = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Customized Time Zone\r\nBEGIN:STANDARD\r\n\
            DTSTART:16010101T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nRRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\n\
            END:STANDARD\r\nBEGIN:DAYLIGHT\r\nDTSTART:16010101T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\n\
            RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\nEND:DAYLIGHT\r\nEND:VTIMEZONE\r\nEND:VCALENDAR\r\n";
        let calendar = ical::parse(text).unwrap();
        let zones = Zones::of(&calendar);
        let zone = zones.get("Customized Time Zone").unwrap();
        assert_eq!(zone.to_offset(utc("2026-07-01T00:00:00Z")).seconds(), 7200);
        assert_eq!(zone.to_offset(utc("2026-12-01T00:00:00Z")).seconds(), 3600);
        assert_eq!(zone.to_offset(utc("2026-03-29T00:59:59Z")).seconds(), 3600);
        assert_eq!(zone.to_offset(utc("2026-03-29T01:00:00Z")).seconds(), 7200);

        let fixed = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Somewhere\r\nBEGIN:STANDARD\r\nDTSTART:19700101T000000\r\n\
            TZOFFSETFROM:+0530\r\nTZOFFSETTO:+0530\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\nEND:VCALENDAR\r\n";
        let zones = Zones::of(&ical::parse(fixed).unwrap());
        assert_eq!(zones.get("Somewhere").unwrap().to_offset(utc("2026-07-01T00:00:00Z")).seconds(), 19800);
    }

    #[test]
    fn vtimezones_are_written_with_yearly_rules() {
        let zone = vtimezone("Europe/Berlin", utc("2026-01-01T00:00:00Z"), utc("2030-01-01T00:00:00Z")).unwrap();
        let text = zone.to_string();
        assert!(text.contains("TZID:Europe/Berlin"), "{text}");
        assert!(text.contains("RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU"), "{text}");
        assert!(text.contains("RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU"), "{text}");
        assert!(text.contains("DTSTART:20260329T020000"), "{text}");
        assert!(!text.contains("UNTIL"), "{text}");
        // Read back as a zone of its own, it keeps the clocks.
        let calendar =
            ical::parse(&format!("BEGIN:VCALENDAR\r\n{}END:VCALENDAR\r\n", text.replace("Europe/Berlin", "Mine")))
                .unwrap();
        let mine = Zones::of(&calendar).get("Mine").unwrap();
        assert_eq!(mine.to_offset(utc("2035-07-01T00:00:00Z")).seconds(), 7200);
        assert_eq!(mine.to_offset(utc("2035-01-01T00:00:00Z")).seconds(), 3600);

        let tokyo =
            vtimezone("Asia/Tokyo", utc("2026-01-01T00:00:00Z"), utc("2027-01-01T00:00:00Z")).unwrap().to_string();
        assert!(tokyo.contains("TZOFFSETTO:+0900") && !tokyo.contains("RRULE"), "{tokyo}");
        assert!(vtimezone("Mars/Base", utc("2026-01-01T00:00:00Z"), utc("2027-01-01T00:00:00Z")).is_none());
    }
}
