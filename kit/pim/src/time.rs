// SPDX-License-Identifier: MIT
//! Times and durations as iCalendar writes them (RFC 5545, 3.3.4–3.3.6, 3.3.9, 3.3.14): dates, date-times that float,
//! are in UTC or in a named time zone, durations of nominal days and exact seconds, and UTC offsets.

use std::fmt;

use jiff::{
    Timestamp,
    civil::{Date, DateTime},
    tz::TimeZone,
};

use crate::tz::Zones;

/// A date or date-time value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Time {
    /// `VALUE=DATE`: a day, all day long.
    Date(Date),
    /// A local time in whatever time zone the reader is (or the calendar's).
    Floating(DateTime),
    /// A time in UTC (`…Z`).
    Utc(DateTime),
    /// A local time in the time zone a `TZID` names.
    Zoned(DateTime, String),
}

impl Time {
    /// Reads a value: `20261105`, `20261105T090000`, `20261105T090000Z`; `tzid` from the property, `date` when it
    /// says `VALUE=DATE`. A date-time with a `TZID` of UTC's names is UTC.
    pub fn parse(value: &str, tzid: Option<&str>, date: bool) -> Option<Time> {
        let value = value.trim();
        if date || value.len() == 8 {
            return parse_date(value.get(..8)?).map(Time::Date);
        }
        let (main, utc) = match value.strip_suffix(['Z', 'z']) {
            Some(main) => (main, true),
            None => (value, false),
        };
        let (day, time) = main.split_once(['T', 't'])?;
        let day = parse_date(day)?;
        if time.len() < 4 || !time.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let hour: i8 = time.get(0..2)?.parse().ok()?;
        let minute: i8 = time.get(2..4)?.parse().ok()?;
        // A leap second (60) reads as the last second of its minute.
        let second: i8 = time.get(4..6).map_or(Some(0), |s| s.parse().ok())?.min(59);
        let civil = day.at(hour.min(23), minute.min(59), second, 0);
        if utc {
            return Some(Time::Utc(civil));
        }
        match tzid.map(str::trim).filter(|tzid| !tzid.is_empty()) {
            Some(tzid) if is_utc_name(tzid) => Some(Time::Utc(civil)),
            Some(tzid) => Some(Time::Zoned(civil, tzid.to_owned())),
            None => Some(Time::Floating(civil)),
        }
    }

    /// The value as iCalendar writes it.
    pub fn format(&self) -> String {
        match self {
            Time::Date(date) => format_date(*date),
            Time::Floating(time) | Time::Zoned(time, _) => format_date_time(*time),
            Time::Utc(time) => format!("{}Z", format_date_time(*time)),
        }
    }

    /// The local date and time (a date at midnight).
    pub fn civil(&self) -> DateTime {
        match self {
            Time::Date(date) => date.to_datetime(jiff::civil::Time::midnight()),
            Time::Floating(time) | Time::Utc(time) | Time::Zoned(time, _) => *time,
        }
    }

    pub fn is_date(&self) -> bool {
        matches!(self, Time::Date(_))
    }

    pub fn tzid(&self) -> Option<&str> {
        match self {
            Time::Zoned(_, tzid) => Some(tzid),
            _ => None,
        }
    }

    /// The time zone this time is read in: UTC, its `TZID` resolved, or `default` (floating times and dates, and a
    /// `TZID` nothing resolves).
    pub fn zone(&self, zones: &Zones, default: &TimeZone) -> TimeZone {
        match self {
            Time::Utc(_) => TimeZone::UTC,
            Time::Zoned(_, tzid) => zones.get(tzid).unwrap_or_else(|| default.clone()),
            _ => default.clone(),
        }
    }

    /// The instant this time names.
    pub fn resolve(&self, zones: &Zones, default: &TimeZone) -> Timestamp {
        to_timestamp(&self.zone(zones, default), self.civil())
    }

    /// The same kind of time (date, floating, UTC or zoned the same) at another local date-time.
    pub fn with_civil(&self, civil: DateTime) -> Time {
        match self {
            Time::Date(_) => Time::Date(civil.date()),
            Time::Floating(_) => Time::Floating(civil),
            Time::Utc(_) => Time::Utc(civil),
            Time::Zoned(_, tzid) => Time::Zoned(civil, tzid.clone()),
        }
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format())
    }
}

/// Whether a time zone name means UTC.
pub fn is_utc_name(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "UTC"
            | "Z"
            | "GMT"
            | "ETC/UTC"
            | "ETC/GMT"
            | "ETC/ZULU"
            | "ETC/UCT"
            | "UCT"
            | "ZULU"
            | "UNIVERSAL"
            | "ETC/UNIVERSAL"
    )
}

/// A local time in a time zone as an instant; a time a change of clocks skipped moves on by the gap, a time that
/// happens twice is the first (RFC 5545, 3.3.5).
pub fn to_timestamp(zone: &TimeZone, civil: DateTime) -> Timestamp {
    zone.to_ambiguous_timestamp(civil).compatible().unwrap_or_else(|_| {
        jiff::tz::Offset::UTC.to_timestamp(civil).unwrap_or(if civil.year() < 0 {
            Timestamp::MIN
        } else {
            Timestamp::MAX
        })
    })
}

fn parse_date(value: &str) -> Option<Date> {
    if value.len() != 8 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Date::new(value[0..4].parse().ok()?, value[4..6].parse().ok()?, value[6..8].parse().ok()?).ok()
}

pub(crate) fn format_date(date: Date) -> String {
    format!("{:04}{:02}{:02}", date.year(), date.month(), date.day())
}

pub(crate) fn format_date_time(time: DateTime) -> String {
    format!("{}T{:02}{:02}{:02}", format_date(time.date()), time.hour(), time.minute(), time.second())
}

/// A local date-time as JSCalendar writes it (`2026-11-05T09:00:00`, RFC 8984, 1.4.4).
pub fn format_local(time: DateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

/// An instant as JSCalendar's and JMAP's `UTCDateTime` (`2026-11-05T09:00:00Z`).
pub fn format_utc(time: Timestamp) -> String {
    format!("{}Z", format_local(TimeZone::UTC.to_datetime(time)))
}

/// A JSCalendar `LocalDateTime` (`YYYY-MM-DDTHH:MM:SS`, a fraction allowed and dropped).
pub fn parse_local(text: &str) -> Option<DateTime> {
    let main = text
        .split_once('.')
        .map_or(text, |(main, fraction)| if fraction.bytes().all(|b| b.is_ascii_digit()) { main } else { text });
    if main.len() != 19 {
        return None;
    }
    DateTime::strptime("%Y-%m-%dT%H:%M:%S", main).ok()
}

/// A JSCalendar `UTCDateTime` (`…Z`).
pub fn parse_utc(text: &str) -> Option<Timestamp> {
    let main = text.strip_suffix(['Z', 'z'])?;
    let civil = parse_local(main)?;
    jiff::tz::Offset::UTC.to_timestamp(civil).ok()
}

/// The day number of a date: days since 1970-01-01.
pub(crate) fn day_number(date: Date) -> i64 {
    // Howard Hinnant's days_from_civil.
    let (y, m, d) = (date.year() as i64, date.month() as i64, date.day() as i64);
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day number; `None` outside the years -9999 to 9999.
pub(crate) fn date_of(days: i64) -> Option<Date> {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    Date::new(i16::try_from(y).ok()?, m as i8, d as i8).ok()
}

/// A local date-time moved by days and seconds; `None` past the years jiff knows.
pub(crate) fn add_civil(time: DateTime, days: i64, seconds: i64) -> Option<DateTime> {
    let total = time.hour() as i64 * 3600 + time.minute() as i64 * 60 + time.second() as i64 + seconds;
    let day = day_number(time.date()) + days + total.div_euclid(86_400);
    let rest = total.rem_euclid(86_400);
    Some(date_of(day)?.at((rest / 3600) as i8, (rest % 3600 / 60) as i8, (rest % 60) as i8, 0))
}

/// A duration: nominal days (a day is a day of the calendar, whatever the clocks do) and exact seconds, both of the
/// same sign (RFC 5545, 3.3.6; RFC 8984, 1.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Duration {
    pub days: i64,
    pub seconds: i64,
}

impl Duration {
    pub const ZERO: Duration = Duration { days: 0, seconds: 0 };

    pub fn days(days: i64) -> Self {
        Duration { days, seconds: 0 }
    }

    pub fn seconds(seconds: i64) -> Self {
        Duration { days: 0, seconds }
    }

    /// Reads `P1W`, `-PT15M`, `P1DT2H30M`; lenient about what follows the rules (`PT1H0M0S`, `P1W2D`).
    pub fn parse(text: &str) -> Option<Duration> {
        let text = text.trim();
        let (negative, rest) = match text.as_bytes().first()? {
            b'-' => (true, &text[1..]),
            b'+' => (false, &text[1..]),
            _ => (false, text),
        };
        let rest = rest.strip_prefix(['P', 'p'])?;
        let mut days = 0i64;
        let mut seconds = 0i64;
        let mut number = String::new();
        let mut in_time = false;
        let mut any = false;
        for c in rest.chars() {
            match c.to_ascii_uppercase() {
                '0'..='9' => number.push(c),
                'T' if number.is_empty() => in_time = true,
                unit => {
                    let value: i64 = number.parse().ok()?;
                    number.clear();
                    any = true;
                    match (unit, in_time) {
                        ('W', false) => days += value * 7,
                        ('D', false) => days += value,
                        ('H', true) => seconds += value * 3600,
                        ('M', true) => seconds += value * 60,
                        ('S', true) => seconds += value,
                        _ => return None,
                    }
                }
            }
        }
        if !number.is_empty() || !any {
            return None;
        }
        Some(if negative { Duration { days: -days, seconds: -seconds } } else { Duration { days, seconds } })
    }

    pub fn is_negative(&self) -> bool {
        self.days < 0 || self.seconds < 0
    }

    pub fn is_zero(&self) -> bool {
        self.days == 0 && self.seconds == 0
    }

    /// The end of a span that starts at `start` (a local time in `zone`) and lasts this long: days on the calendar,
    /// then seconds on the clock.
    pub fn end_of(&self, zone: &TimeZone, start: DateTime) -> Timestamp {
        let day = add_civil(start, self.days, 0).unwrap_or(start);
        let instant = to_timestamp(zone, day);
        instant.checked_add(jiff::SignedDuration::from_secs(self.seconds)).unwrap_or(instant)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let negative = self.is_negative();
        let days = self.days.abs();
        let seconds = self.seconds.abs();
        if negative {
            f.write_str("-")?;
        }
        f.write_str("P")?;
        if seconds == 0 && days != 0 && days % 7 == 0 {
            return write!(f, "{}W", days / 7);
        }
        if days != 0 {
            write!(f, "{days}D")?;
        }
        if seconds != 0 || days == 0 {
            f.write_str("T")?;
            let (h, m, s) = (seconds / 3600, seconds % 3600 / 60, seconds % 60);
            if h != 0 {
                write!(f, "{h}H")?;
            }
            if m != 0 {
                write!(f, "{m}M")?;
            }
            if s != 0 || seconds == 0 {
                write!(f, "{s}S")?;
            }
        }
        Ok(())
    }
}

/// A UTC offset (`+0100`, `-053000`) in seconds.
pub fn parse_offset(text: &str) -> Option<i32> {
    let text = text.trim();
    let (sign, digits) = match text.as_bytes().first()? {
        b'+' => (1, &text[1..]),
        b'-' => (-1, &text[1..]),
        _ => (1, text),
    };
    let digits: String = digits.chars().filter(|c| *c != ':').collect();
    if !(digits.len() == 4 || digits.len() == 6) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i32 = digits[0..2].parse().ok()?;
    let minutes: i32 = digits[2..4].parse().ok()?;
    let seconds: i32 = digits.get(4..6).map_or(Some(0), |s| s.parse().ok())?;
    Some(sign * (hours * 3600 + minutes * 60 + seconds))
}

/// A UTC offset as iCalendar writes it.
pub fn format_offset(seconds: i32) -> String {
    let sign = if seconds < 0 { '-' } else { '+' };
    let abs = seconds.abs();
    let (h, m, s) = (abs / 3600, abs % 3600 / 60, abs % 60);
    if s == 0 { format!("{sign}{h:02}{m:02}") } else { format!("{sign}{h:02}{m:02}{s:02}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_parse_and_format() {
        assert_eq!(Time::parse("20261105", None, false), Some(Time::Date(jiff::civil::date(2026, 11, 5))));
        let utc = Time::parse("20261105T090000Z", Some("Europe/Berlin"), false).unwrap();
        assert_eq!(utc, Time::Utc(jiff::civil::datetime(2026, 11, 5, 9, 0, 0, 0)));
        assert_eq!(utc.format(), "20261105T090000Z");
        let zoned = Time::parse("20261105T0900", Some("Europe/Berlin"), false).unwrap();
        assert_eq!(zoned.format(), "20261105T090000");
        assert_eq!(zoned.tzid(), Some("Europe/Berlin"));
        assert!(matches!(Time::parse("20261105T090000", Some("UTC"), false), Some(Time::Utc(_))));
        assert!(Time::parse("2026-11-05", None, false).is_none());
        assert!(Time::parse("20261105T090000", None, true).unwrap().is_date());
    }

    #[test]
    fn durations_read_and_write() {
        for (text, days, seconds, back) in [
            ("PT1H", 0, 3600, "PT1H"),
            ("-PT15M", 0, -900, "-PT15M"),
            ("P1W", 7, 0, "P1W"),
            ("P1DT2H30M", 1, 9000, "P1DT2H30M"),
            ("PT1H0M0S", 0, 3600, "PT1H"),
            ("P0D", 0, 0, "PT0S"),
            ("P1W2D", 9, 0, "P9D"),
        ] {
            let duration = Duration::parse(text).unwrap();
            assert_eq!((duration.days, duration.seconds), (days, seconds), "{text}");
            assert_eq!(duration.to_string(), back);
        }
        assert!(Duration::parse("P").is_none());
        assert!(Duration::parse("1H").is_none());
        assert!(Duration::parse("PT1D").is_none());
    }

    #[test]
    fn a_day_is_a_day_of_the_calendar() {
        let berlin = TimeZone::get("Europe/Berlin").unwrap();
        let start = jiff::civil::datetime(2026, 10, 24, 10, 0, 0, 0);
        let day = Duration::days(1).end_of(&berlin, start);
        let hours = Duration::seconds(24 * 3600).end_of(&berlin, start);
        assert_eq!(format_utc(day), "2026-10-25T09:00:00Z");
        assert_eq!(format_utc(hours), "2026-10-25T08:00:00Z");
    }

    #[test]
    fn day_numbers_go_both_ways() {
        for date in [jiff::civil::date(1970, 1, 1), jiff::civil::date(2000, 2, 29), jiff::civil::date(1600, 12, 31)] {
            assert_eq!(date_of(day_number(date)), Some(date));
        }
        assert_eq!(day_number(jiff::civil::date(1970, 1, 2)), 1);
        assert_eq!(parse_offset("-0530"), Some(-19800));
        assert_eq!(format_offset(3600), "+0100");
        assert_eq!(parse_local("2026-11-02T09:00:00.5").map(format_local).as_deref(), Some("2026-11-02T09:00:00"));
        assert!(parse_local("2026-11-02").is_none());
    }
}
