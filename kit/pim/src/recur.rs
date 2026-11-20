// SPDX-License-Identifier: MIT
//! Recurrence rules (RFC 5545, 3.3.10): reading and writing `RRULE` values, and the occurrences a rule gives from a
//! start – in local time, the caller puts them in their time zone.
//!
//! Each period of the frequency (a year, a month, a week, …, every `INTERVAL`th) gives the local times its `BYxxx`
//! parts allow – a part finer than the frequency picks out of the period, a coarser one limits it (the table in
//! 3.3.10) – sorted, then `BYSETPOS` takes from them. The start is always the first occurrence and counts for `COUNT`.
//! `RSCALE` and `SKIP` (RFC 7529) are kept when written but not applied (OPEN): the Gregorian calendar only.

use std::{fmt, str::FromStr};

use jiff::civil::{Date, DateTime, Weekday};

use crate::time::{Time, date_of, day_number};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Frequency {
    Secondly,
    Minutely,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

impl Frequency {
    pub fn as_str(self) -> &'static str {
        match self {
            Frequency::Secondly => "SECONDLY",
            Frequency::Minutely => "MINUTELY",
            Frequency::Hourly => "HOURLY",
            Frequency::Daily => "DAILY",
            Frequency::Weekly => "WEEKLY",
            Frequency::Monthly => "MONTHLY",
            Frequency::Yearly => "YEARLY",
        }
    }

    pub fn parse(text: &str) -> Option<Frequency> {
        Some(match text.to_ascii_uppercase().as_str() {
            "SECONDLY" => Frequency::Secondly,
            "MINUTELY" => Frequency::Minutely,
            "HOURLY" => Frequency::Hourly,
            "DAILY" => Frequency::Daily,
            "WEEKLY" => Frequency::Weekly,
            "MONTHLY" => Frequency::Monthly,
            "YEARLY" => Frequency::Yearly,
            _ => return None,
        })
    }
}

/// A recurrence rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub frequency: Frequency,
    pub interval: u32,
    pub count: Option<u32>,
    /// Inclusive; a date, a floating or a UTC time.
    pub until: Option<Time>,
    pub by_second: Vec<u8>,
    pub by_minute: Vec<u8>,
    pub by_hour: Vec<u8>,
    /// Weekdays, each with an optional ordinal (`-1SU`: the last Sunday).
    pub by_day: Vec<(Option<i16>, Weekday)>,
    pub by_month_day: Vec<i8>,
    pub by_year_day: Vec<i16>,
    pub by_week_no: Vec<i8>,
    pub by_month: Vec<u8>,
    pub by_set_pos: Vec<i32>,
    pub week_start: Weekday,
    /// Parts not understood (`RSCALE`, `SKIP`, `X-…`), kept as written.
    pub other: Vec<(String, String)>,
}

impl Rule {
    pub fn new(frequency: Frequency) -> Rule {
        Rule {
            frequency,
            interval: 1,
            count: None,
            until: None,
            by_second: Vec::new(),
            by_minute: Vec::new(),
            by_hour: Vec::new(),
            by_day: Vec::new(),
            by_month_day: Vec::new(),
            by_year_day: Vec::new(),
            by_week_no: Vec::new(),
            by_month: Vec::new(),
            by_set_pos: Vec::new(),
            week_start: Weekday::Monday,
            other: Vec::new(),
        }
    }

    /// Whether the rule ends (by `COUNT` or `UNTIL`).
    pub fn is_bounded(&self) -> bool {
        self.count.is_some() || self.until.is_some()
    }

    /// The occurrences from `start` (a local time; a date when `date_only`), in order, the start first; `until` as a
    /// local time in the start's zone, which the caller works out (`UNTIL` in UTC is an instant).
    pub fn occurrences(&self, start: DateTime, date_only: bool, until: Option<DateTime>) -> Occurrences<'_> {
        Occurrences::new(std::borrow::Cow::Borrowed(self), start, date_only, until)
    }

    /// The same, owning the rule.
    pub fn into_occurrences(self, start: DateTime, date_only: bool, until: Option<DateTime>) -> Occurrences<'static> {
        Occurrences::new(std::borrow::Cow::Owned(self), start, date_only, until)
    }
}

impl<'r> Occurrences<'r> {
    fn new(rule: std::borrow::Cow<'r, Rule>, start: DateTime, date_only: bool, until: Option<DateTime>) -> Self {
        Occurrences {
            rule,
            start,
            date_only,
            until,
            period: 0,
            buffer: Vec::new(),
            emitted: 0,
            empty: 0,
            started: false,
            done: false,
        }
    }
}

pub fn weekday_code(day: Weekday) -> &'static str {
    match day {
        Weekday::Monday => "MO",
        Weekday::Tuesday => "TU",
        Weekday::Wednesday => "WE",
        Weekday::Thursday => "TH",
        Weekday::Friday => "FR",
        Weekday::Saturday => "SA",
        Weekday::Sunday => "SU",
    }
}

pub fn parse_weekday(code: &str) -> Option<Weekday> {
    Some(match code.to_ascii_uppercase().as_str() {
        "MO" => Weekday::Monday,
        "TU" => Weekday::Tuesday,
        "WE" => Weekday::Wednesday,
        "TH" => Weekday::Thursday,
        "FR" => Weekday::Friday,
        "SA" => Weekday::Saturday,
        "SU" => Weekday::Sunday,
        _ => return None,
    })
}

/// Why a rule could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError(pub String);

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "recurrence rule: {}", self.0)
    }
}

impl std::error::Error for RuleError {}

fn list<T: FromStr>(value: &str, range: std::ops::RangeInclusive<i64>, zero: bool) -> Result<Vec<T>, RuleError> {
    value
        .split(',')
        .map(|item| {
            let number: i64 = item.trim().parse().map_err(|_| RuleError(format!("not a number: {item}")))?;
            if !range.contains(&number.abs()) && !(zero && number == 0) || (!zero && number == 0) {
                return Err(RuleError(format!("out of range: {item}")));
            }
            number.to_string().parse().map_err(|_| RuleError(format!("out of range: {item}")))
        })
        .collect()
}

impl FromStr for Rule {
    type Err = RuleError;

    fn from_str(text: &str) -> Result<Rule, RuleError> {
        let mut rule = Rule::new(Frequency::Yearly);
        let mut frequency = None;
        for part in text.trim().trim_start_matches("RRULE:").split(';').filter(|part| !part.trim().is_empty()) {
            let (name, value) = part.split_once('=').ok_or_else(|| RuleError(format!("not a part: {part}")))?;
            let value = value.trim();
            match name.trim().to_ascii_uppercase().as_str() {
                "FREQ" => frequency = Some(Frequency::parse(value).ok_or_else(|| RuleError(format!("FREQ={value}")))?),
                "INTERVAL" => {
                    rule.interval =
                        value.parse().ok().filter(|n| *n > 0).ok_or_else(|| RuleError(format!("INTERVAL={value}")))?
                }
                "COUNT" => rule.count = Some(value.parse().map_err(|_| RuleError(format!("COUNT={value}")))?),
                "UNTIL" => {
                    rule.until =
                        Some(Time::parse(value, None, false).ok_or_else(|| RuleError(format!("UNTIL={value}")))?)
                }
                "BYSECOND" => rule.by_second = list::<u8>(value, 0..=60, true)?,
                "BYMINUTE" => rule.by_minute = list::<u8>(value, 0..=59, true)?,
                "BYHOUR" => rule.by_hour = list::<u8>(value, 0..=23, true)?,
                "BYMONTHDAY" => rule.by_month_day = list::<i8>(value, 1..=31, false)?,
                "BYYEARDAY" => rule.by_year_day = list::<i16>(value, 1..=366, false)?,
                "BYWEEKNO" => rule.by_week_no = list::<i8>(value, 1..=53, false)?,
                "BYMONTH" => {
                    // A leap month of RFC 7529 (`5L`) is not of the Gregorian calendar.
                    rule.by_month = list::<u8>(value, 1..=12, false)?;
                }
                "BYSETPOS" => rule.by_set_pos = list::<i32>(value, 1..=366, false)?,
                "WKST" => rule.week_start = parse_weekday(value).ok_or_else(|| RuleError(format!("WKST={value}")))?,
                "BYDAY" => {
                    rule.by_day = value
                        .split(',')
                        .map(|item| {
                            let item = item.trim();
                            if item.len() < 2 {
                                return Err(RuleError(format!("BYDAY={item}")));
                            }
                            let (nth, day) = item.split_at(item.len() - 2);
                            let day = parse_weekday(day).ok_or_else(|| RuleError(format!("BYDAY={item}")))?;
                            let nth = match nth.trim_start_matches('+') {
                                "" => None,
                                n => Some(
                                    n.parse::<i16>()
                                        .ok()
                                        .filter(|n| *n != 0 && n.abs() <= 53)
                                        .ok_or_else(|| RuleError(format!("BYDAY={item}")))?,
                                ),
                            };
                            Ok((nth, day))
                        })
                        .collect::<Result<_, _>>()?;
                }
                other => rule.other.push((other.to_owned(), value.to_owned())),
            }
        }
        rule.frequency = frequency.ok_or_else(|| RuleError("no FREQ".into()))?;
        Ok(rule)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn join<T: fmt::Display>(values: &[T]) -> String {
            values.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
        }
        write!(f, "FREQ={}", self.frequency.as_str())?;
        for (name, value) in self.other.iter().filter(|(name, _)| name == "RSCALE") {
            write!(f, ";{name}={value}")?;
        }
        if let Some(until) = &self.until {
            write!(f, ";UNTIL={}", until.format())?;
        }
        if let Some(count) = self.count {
            write!(f, ";COUNT={count}")?;
        }
        if self.interval != 1 {
            write!(f, ";INTERVAL={}", self.interval)?;
        }
        for (name, values) in
            [("BYSECOND", join(&self.by_second)), ("BYMINUTE", join(&self.by_minute)), ("BYHOUR", join(&self.by_hour))]
        {
            if !values.is_empty() {
                write!(f, ";{name}={values}")?;
            }
        }
        if !self.by_month.is_empty() {
            write!(f, ";BYMONTH={}", join(&self.by_month))?;
        }
        if !self.by_day.is_empty() {
            let days: Vec<String> = self
                .by_day
                .iter()
                .map(|(nth, day)| format!("{}{}", nth.map(|n| n.to_string()).unwrap_or_default(), weekday_code(*day)))
                .collect();
            write!(f, ";BYDAY={}", days.join(","))?;
        }
        for (name, values) in [
            ("BYMONTHDAY", join(&self.by_month_day)),
            ("BYYEARDAY", join(&self.by_year_day)),
            ("BYWEEKNO", join(&self.by_week_no)),
            ("BYSETPOS", join(&self.by_set_pos)),
        ] {
            if !values.is_empty() {
                write!(f, ";{name}={values}")?;
            }
        }
        if self.week_start != Weekday::Monday {
            write!(f, ";WKST={}", weekday_code(self.week_start))?;
        }
        for (name, value) in self.other.iter().filter(|(name, _)| name != "RSCALE") {
            write!(f, ";{name}={value}")?;
        }
        Ok(())
    }
}

/// Periods without an occurrence after which a rule is taken to give no more (e.g. `BYMONTHDAY=30;BYMONTH=2`).
const MAX_EMPTY_PERIODS: u32 = 10_000;

/// The occurrences of a rule, in order.
#[derive(Debug)]
pub struct Occurrences<'r> {
    rule: std::borrow::Cow<'r, Rule>,
    start: DateTime,
    date_only: bool,
    until: Option<DateTime>,
    period: i64,
    buffer: Vec<DateTime>,
    emitted: u64,
    empty: u32,
    started: bool,
    done: bool,
}

impl Iterator for Occurrences<'_> {
    type Item = DateTime;

    fn next(&mut self) -> Option<DateTime> {
        if self.done {
            return None;
        }
        if self.rule.count.is_some_and(|count| self.emitted >= u64::from(count)) {
            self.done = true;
            return None;
        }
        if !self.started {
            self.started = true;
            self.emitted += 1;
            return Some(self.start);
        }
        loop {
            if let Some(next) = self.buffer.pop() {
                if next <= self.start {
                    continue;
                }
                if let Some(until) = self.until
                    && next > until
                {
                    self.done = true;
                    return None;
                }
                self.emitted += 1;
                return Some(next);
            }
            let limit = if self.rule.frequency < Frequency::Daily { MAX_EMPTY_PERIODS * 10 } else { MAX_EMPTY_PERIODS };
            if self.empty > limit {
                self.done = true;
                return None;
            }
            let Some(mut set) = self.period_set(self.period) else {
                self.done = true;
                return None;
            };
            if set.is_empty() {
                self.empty += 1;
                self.period = self.skip_after(self.period).unwrap_or(self.period + 1);
                continue;
            }
            self.period += 1;
            self.empty = 0;
            set.reverse();
            self.buffer = set;
        }
    }
}

impl Occurrences<'_> {
    /// The next period worth trying after an empty one of a frequency below a day: the first of the next day when
    /// the day is not wanted, of the next hour when the hour is not.
    fn skip_after(&self, index: i64) -> Option<i64> {
        let unit = match self.rule.frequency {
            Frequency::Hourly => 3600,
            Frequency::Minutely => 60,
            Frequency::Secondly => 1,
            _ => return None,
        };
        let step = unit * i64::from(self.rule.interval);
        let at = crate::time::add_civil(self.start, 0, index.checked_mul(step)?)?;
        let into_day = i64::from(at.hour()) * 3600 + i64::from(at.minute()) * 60 + i64::from(at.second());
        let gap = if !self.day_ok(at.date(), false) {
            86_400 - into_day
        } else if !self.rule.by_hour.is_empty() && !self.rule.by_hour.contains(&(at.hour() as u8)) {
            3600 - into_day % 3600
        } else {
            return None;
        };
        Some(index + ((gap + step - 1) / step).max(1))
    }

    /// The occurrences of one period (the `index`th from the start's), sorted, `BYSETPOS` applied; `None` past the
    /// years there are.
    fn period_set(&self, index: i64) -> Option<Vec<DateTime>> {
        let rule = &*self.rule;
        let step = index.checked_mul(i64::from(rule.interval))?;
        let start = self.start;
        let days: Vec<Date> = match rule.frequency {
            Frequency::Yearly => {
                let year = i16::try_from(i64::from(start.year()) + step).ok().filter(|y| *y <= 9999)?;
                self.year_days(year)
            }
            Frequency::Monthly => {
                let months = i64::from(start.year()) * 12 + i64::from(start.month()) - 1 + step;
                let year = i16::try_from(months.div_euclid(12)).ok().filter(|y| *y <= 9999)?;
                let month = (months.rem_euclid(12) + 1) as i8;
                self.month_days(year, month)
            }
            Frequency::Weekly => {
                let offset =
                    (7 + start.weekday().to_monday_zero_offset() - rule.week_start.to_monday_zero_offset()) % 7;
                let first = day_number(start.date()) - i64::from(offset) + step * 7;
                let week: Vec<Date> = (0..7).filter_map(|d| date_of(first + d)).collect();
                if week.is_empty() {
                    return None;
                }
                let wanted: Vec<Weekday> = if rule.by_day.is_empty() {
                    vec![start.weekday()]
                } else {
                    rule.by_day.iter().map(|(_, day)| *day).collect()
                };
                week.into_iter().filter(|day| wanted.contains(&day.weekday()) && self.month_ok(*day)).collect()
            }
            Frequency::Daily => {
                let day = date_of(day_number(start.date()) + step)?;
                if self.day_ok(day, false) { vec![day] } else { vec![] }
            }
            Frequency::Hourly | Frequency::Minutely | Frequency::Secondly => {
                let unit = match rule.frequency {
                    Frequency::Hourly => 3600,
                    Frequency::Minutely => 60,
                    _ => 1,
                };
                let at = crate::time::add_civil(start, 0, step.checked_mul(unit)?)?;
                if at.year() > 9999 || !self.day_ok(at.date(), false) {
                    return Some(vec![]);
                }
                let hour_ok = rule.by_hour.is_empty() || rule.by_hour.contains(&(at.hour() as u8));
                let minute_ok = rule.frequency == Frequency::Hourly
                    || rule.by_minute.is_empty()
                    || rule.by_minute.contains(&(at.minute() as u8));
                let second_ok = rule.frequency != Frequency::Secondly
                    || rule.by_second.is_empty()
                    || rule.by_second.contains(&(at.second() as u8));
                if !(hour_ok && minute_ok && second_ok) {
                    return Some(vec![]);
                }
                let minutes = if rule.frequency == Frequency::Hourly { self.minutes() } else { vec![at.minute()] };
                let seconds = if rule.frequency == Frequency::Secondly { vec![at.second()] } else { self.seconds() };
                let mut out = Vec::new();
                for minute in &minutes {
                    for second in &seconds {
                        out.push(at.date().at(at.hour(), *minute, *second, 0));
                    }
                }
                return Some(self.set_positions(out));
            }
        };
        let mut out = Vec::new();
        if self.date_only {
            out.extend(days.into_iter().map(|day| day.at(0, 0, 0, 0)));
        } else {
            let hours = self.hours();
            let minutes = self.minutes();
            let seconds = self.seconds();
            for day in days {
                for hour in &hours {
                    for minute in &minutes {
                        for second in &seconds {
                            out.push(day.at(*hour, *minute, *second, 0));
                        }
                    }
                }
            }
        }
        Some(self.set_positions(out))
    }

    fn hours(&self) -> Vec<i8> {
        if self.rule.by_hour.is_empty() {
            vec![self.start.hour()]
        } else {
            sorted(self.rule.by_hour.iter().map(|h| *h as i8))
        }
    }

    fn minutes(&self) -> Vec<i8> {
        if self.rule.by_minute.is_empty() {
            vec![self.start.minute()]
        } else {
            sorted(self.rule.by_minute.iter().map(|m| *m as i8))
        }
    }

    fn seconds(&self) -> Vec<i8> {
        if self.rule.by_second.is_empty() {
            vec![self.start.second()]
        } else {
            sorted(self.rule.by_second.iter().map(|s| (*s).min(59) as i8))
        }
    }

    fn set_positions(&self, mut set: Vec<DateTime>) -> Vec<DateTime> {
        set.sort();
        set.dedup();
        if self.rule.by_set_pos.is_empty() {
            return set;
        }
        let len = set.len() as i64;
        let mut out: Vec<DateTime> = self
            .rule
            .by_set_pos
            .iter()
            .filter_map(|pos| {
                let index = if *pos > 0 { i64::from(*pos) - 1 } else { len + i64::from(*pos) };
                (0..len).contains(&index).then(|| set[index as usize])
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn month_ok(&self, day: Date) -> bool {
        self.rule.by_month.is_empty() || self.rule.by_month.contains(&(day.month() as u8))
    }

    /// Whether a day passes the day parts that limit (`BYMONTH`, `BYYEARDAY`, `BYMONTHDAY`, `BYDAY` – without
    /// ordinals, they make no sense there).
    fn day_ok(&self, day: Date, _: bool) -> bool {
        let rule = &*self.rule;
        self.month_ok(day)
            && (rule.by_year_day.is_empty() || rule.by_year_day.iter().any(|n| year_day_matches(day, *n)))
            && (rule.by_month_day.is_empty() || rule.by_month_day.iter().any(|n| month_day_matches(day, *n)))
            && (rule.by_day.is_empty() || rule.by_day.iter().any(|(_, weekday)| *weekday == day.weekday()))
    }

    fn month_days(&self, year: i16, month: i8) -> Vec<Date> {
        let rule = &*self.rule;
        if !rule.by_month.is_empty() && !rule.by_month.contains(&(month as u8)) {
            return Vec::new();
        }
        let Ok(first) = Date::new(year, month, 1) else { return Vec::new() };
        let length = first.days_in_month();
        let no_day_parts = rule.by_month_day.is_empty() && rule.by_day.is_empty() && rule.by_year_day.is_empty();
        (1..=length)
            .filter_map(|d| Date::new(year, month, d).ok())
            .filter(|day| {
                if no_day_parts {
                    return day.day() == self.start.day();
                }
                (rule.by_month_day.is_empty() || rule.by_month_day.iter().any(|n| month_day_matches(*day, *n)))
                    && (rule.by_year_day.is_empty() || rule.by_year_day.iter().any(|n| year_day_matches(*day, *n)))
                    && (rule.by_day.is_empty() || rule.by_day.iter().any(|(nth, wd)| weekday_in_month(*day, *nth, *wd)))
            })
            .collect()
    }

    fn year_days(&self, year: i16) -> Vec<Date> {
        let rule = &*self.rule;
        let no_day_parts = rule.by_week_no.is_empty()
            && rule.by_year_day.is_empty()
            && rule.by_month_day.is_empty()
            && rule.by_day.is_empty();
        if no_day_parts {
            // The start's day, in the months asked for or the start's.
            let months: Vec<i8> = if rule.by_month.is_empty() {
                vec![self.start.month()]
            } else {
                sorted(rule.by_month.iter().map(|m| *m as i8))
            };
            return months.into_iter().filter_map(|month| Date::new(year, month, self.start.day()).ok()).collect();
        }
        let candidates: Vec<Date> = if rule.by_week_no.is_empty() {
            let Ok(first) = Date::new(year, 1, 1) else { return Vec::new() };
            let first = day_number(first);
            (0..i64::from(Date::new(year, 1, 1).map(|d| d.days_in_year()).unwrap_or(365)))
                .filter_map(|d| date_of(first + d))
                .collect()
        } else {
            let mut days = Vec::new();
            let weeks = weeks_in_year(year, rule.week_start);
            let week_one = week_one_start(year, rule.week_start);
            for n in &rule.by_week_no {
                let n = if *n > 0 { i64::from(*n) } else { weeks + i64::from(*n) + 1 };
                if n < 1 || n > weeks {
                    continue;
                }
                days.extend((0..7).filter_map(|d| date_of(week_one + (n - 1) * 7 + d)));
            }
            days.sort();
            days.dedup();
            days
        };
        let ordinals_in_month = !rule.by_month.is_empty();
        candidates
            .into_iter()
            .filter(|day| {
                self.month_ok(*day)
                    && (rule.by_year_day.is_empty() || rule.by_year_day.iter().any(|n| year_day_matches(*day, *n)))
                    && (rule.by_month_day.is_empty() || rule.by_month_day.iter().any(|n| month_day_matches(*day, *n)))
                    && (rule.by_day.is_empty()
                        || rule.by_day.iter().any(|(nth, wd)| match nth {
                            _ if !rule.by_week_no.is_empty() => *wd == day.weekday(),
                            Some(_) if ordinals_in_month => weekday_in_month(*day, *nth, *wd),
                            Some(_) => weekday_in_year(*day, *nth, *wd),
                            None => *wd == day.weekday(),
                        }))
            })
            .collect()
    }
}

fn sorted(values: impl Iterator<Item = i8>) -> Vec<i8> {
    let mut out: Vec<i8> = values.collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn month_day_matches(day: Date, n: i8) -> bool {
    if n > 0 { day.day() == n } else { day.days_in_month() + 1 + n == day.day() }
}

fn year_day_matches(day: Date, n: i16) -> bool {
    if n > 0 { day.day_of_year() == n } else { day.days_in_year() + 1 + n == day.day_of_year() }
}

fn weekday_in_month(day: Date, nth: Option<i16>, weekday: Weekday) -> bool {
    if day.weekday() != weekday {
        return false;
    }
    match nth {
        None => true,
        Some(n) if n > 0 => i16::from((day.day() - 1) / 7 + 1) == n,
        Some(n) => i16::from((day.days_in_month() - day.day()) / 7 + 1) == -n,
    }
}

fn weekday_in_year(day: Date, nth: Option<i16>, weekday: Weekday) -> bool {
    if day.weekday() != weekday {
        return false;
    }
    match nth {
        None => true,
        Some(n) if n > 0 => (day.day_of_year() - 1) / 7 + 1 == n,
        Some(n) => (day.days_in_year() - day.day_of_year()) / 7 + 1 == -n,
    }
}

/// The day number of the first day of week 1 of a year: the week (starting on `week_start`) that has at least four
/// days of the year (RFC 5545, 3.3.10, `BYWEEKNO`).
fn week_one_start(year: i16, week_start: Weekday) -> i64 {
    let Ok(january) = Date::new(year, 1, 1) else { return 0 };
    let first = day_number(january);
    let offset = i64::from((7 + january.weekday().to_monday_zero_offset() - week_start.to_monday_zero_offset()) % 7);
    let week_begin = first - offset;
    if offset <= 3 { week_begin } else { week_begin + 7 }
}

fn weeks_in_year(year: i16, week_start: Weekday) -> i64 {
    (week_one_start(year.saturating_add(1), week_start) - week_one_start(year, week_start)) / 7
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(text: &str) -> DateTime {
        Time::parse(text, None, false).unwrap().civil()
    }

    fn run(rule: &str, start: &str, take: usize) -> Vec<String> {
        let rule: Rule = rule.parse().unwrap();
        let until = rule.until.as_ref().map(|until| match until {
            Time::Date(date) => date.at(23, 59, 59, 0),
            other => other.civil(),
        });
        let date_only = start.len() == 8;
        rule.occurrences(dt(start), date_only, until)
            .take(take)
            .map(
                |time| {
                    if date_only { crate::time::format_date(time.date()) } else { crate::time::format_date_time(time) }
                },
            )
            .collect()
    }

    #[test]
    fn rules_read_and_write() {
        let text = "FREQ=MONTHLY;UNTIL=20271231T235959Z;INTERVAL=2;BYDAY=-1SU,2MO;BYSETPOS=1;WKST=SU";
        let rule: Rule = text.parse().unwrap();
        assert_eq!(rule.interval, 2);
        assert_eq!(rule.by_day, [(Some(-1), Weekday::Sunday), (Some(2), Weekday::Monday)]);
        assert_eq!(
            rule.to_string(),
            "FREQ=MONTHLY;UNTIL=20271231T235959Z;INTERVAL=2;BYDAY=-1SU,2MO;BYSETPOS=1;WKST=SU"
        );
        assert!("FREQ=WEEKLY;BYDAY=XX".parse::<Rule>().is_err());
        assert!("BYDAY=MO".parse::<Rule>().is_err());
        assert!("FREQ=DAILY;INTERVAL=0".parse::<Rule>().is_err());
        assert_eq!("FREQ=DAILY;X-NAME=1".parse::<Rule>().unwrap().to_string(), "FREQ=DAILY;X-NAME=1");
    }

    // The examples of RFC 5545, 3.8.5.3, in local time.
    #[test]
    fn the_examples_of_the_rfc() {
        assert_eq!(run("FREQ=DAILY;COUNT=10", "19970902T090000", 20).len(), 10);
        assert_eq!(run("FREQ=DAILY;UNTIL=19971224T000000Z", "19970902T090000", 200).last().unwrap(), "19971223T090000");
        assert_eq!(
            run("FREQ=DAILY;INTERVAL=10;COUNT=5", "19970902T090000", 10),
            ["19970902T090000", "19970912T090000", "19970922T090000", "19971002T090000", "19971012T090000"]
        );
        // Every day in January, for 3 years.
        let january =
            run("FREQ=YEARLY;UNTIL=20000131T140000Z;BYMONTH=1;BYDAY=SU,MO,TU,WE,TH,FR,SA", "19980101T090000", 200);
        assert_eq!(january.len(), 93);
        assert_eq!(january.last().unwrap(), "20000131T090000");
        // Weekly on Tuesday and Thursday for five weeks.
        assert_eq!(
            run("FREQ=WEEKLY;COUNT=10;WKST=SU;BYDAY=TU,TH", "19970902T090000", 20)[..4],
            ["19970902T090000", "19970904T090000", "19970909T090000", "19970911T090000"]
        );
        // Every other week on Monday, Wednesday and Friday.
        assert_eq!(
            run("FREQ=WEEKLY;INTERVAL=2;UNTIL=19971224T000000Z;WKST=SU;BYDAY=MO,WE,FR", "19970901T090000", 100).len(),
            25
        );
        // WKST matters: MO starts the week, then SU.
        assert_eq!(
            run("FREQ=WEEKLY;INTERVAL=2;COUNT=4;BYDAY=TU,SU;WKST=MO", "19970805T090000", 10),
            ["19970805T090000", "19970810T090000", "19970819T090000", "19970824T090000"]
        );
        assert_eq!(
            run("FREQ=WEEKLY;INTERVAL=2;COUNT=4;BYDAY=TU,SU;WKST=SU", "19970805T090000", 10),
            ["19970805T090000", "19970817T090000", "19970819T090000", "19970831T090000"]
        );
        // Monthly on the first Friday for 10 occurrences.
        assert_eq!(
            run("FREQ=MONTHLY;COUNT=10;BYDAY=1FR", "19970905T090000", 20)[..3],
            ["19970905T090000", "19971003T090000", "19971107T090000"]
        );
        // Monthly on the second-to-last Monday for 6 months.
        assert_eq!(
            run("FREQ=MONTHLY;COUNT=6;BYDAY=-2MO", "19970922T090000", 10),
            [
                "19970922T090000",
                "19971020T090000",
                "19971117T090000",
                "19971222T090000",
                "19980119T090000",
                "19980216T090000"
            ]
        );
        // Monthly on the third-to-the-last day of the month.
        assert_eq!(
            run("FREQ=MONTHLY;BYMONTHDAY=-3", "19970928T090000", 4),
            ["19970928T090000", "19971029T090000", "19971128T090000", "19971229T090000"]
        );
        // Every year on the 1st, 100th and 200th day.
        assert_eq!(
            run("FREQ=YEARLY;INTERVAL=3;COUNT=10;BYYEARDAY=1,100,200", "19970101T090000", 20)[..4],
            ["19970101T090000", "19970410T090000", "19970719T090000", "20000101T090000"]
        );
        // Every 20th Monday of the year.
        assert_eq!(
            run("FREQ=YEARLY;BYDAY=20MO", "19970519T090000", 3),
            ["19970519T090000", "19980518T090000", "19990517T090000"]
        );
        // Monday of week number 20 (where the default start of the week is Monday).
        assert_eq!(
            run("FREQ=YEARLY;BYWEEKNO=20;BYDAY=MO", "19970512T090000", 3),
            ["19970512T090000", "19980511T090000", "19990517T090000"]
        );
        // Every Thursday in March.
        assert_eq!(
            run("FREQ=YEARLY;BYMONTH=3;BYDAY=TH", "19970313T090000", 4),
            ["19970313T090000", "19970320T090000", "19970327T090000", "19980305T090000"]
        );
        // Every Friday the 13th.
        assert_eq!(
            run("FREQ=MONTHLY;BYDAY=FR;BYMONTHDAY=13", "19970902T090000", 3),
            ["19970902T090000", "19980213T090000", "19980313T090000"]
        );
        // The first Saturday that follows the first Sunday of the month.
        assert_eq!(
            run("FREQ=MONTHLY;BYDAY=SA;BYMONTHDAY=7,8,9,10,11,12,13", "19970913T090000", 3),
            ["19970913T090000", "19971011T090000", "19971108T090000"]
        );
        // US presidential elections.
        assert_eq!(
            run("FREQ=YEARLY;INTERVAL=4;BYMONTH=11;BYDAY=TU;BYMONTHDAY=2,3,4,5,6,7,8", "19961105T090000", 3),
            ["19961105T090000", "20001107T090000", "20041102T090000"]
        );
        // The third instance of Tuesday, Wednesday or Thursday, for the next 3 months.
        assert_eq!(
            run("FREQ=MONTHLY;COUNT=3;BYDAY=TU,WE,TH;BYSETPOS=3", "19970904T090000", 5),
            ["19970904T090000", "19971007T090000", "19971106T090000"]
        );
        // The second-to-last weekday of the month.
        assert_eq!(
            run("FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-2", "19970929T090000", 3),
            ["19970929T090000", "19971030T090000", "19971127T090000"]
        );
        // Every 3 hours from 9:00 to 17:00 on one day.
        assert_eq!(
            run("FREQ=HOURLY;INTERVAL=3;UNTIL=19970902T170000Z", "19970902T090000", 10),
            ["19970902T090000", "19970902T120000", "19970902T150000"]
        );
        // Every 20 minutes from 9:00 to 16:40 every day.
        let minutes = run("FREQ=DAILY;BYHOUR=9,10,11,12,13,14,15,16;BYMINUTE=0,20,40", "19970902T090000", 30);
        assert_eq!(minutes[..4], ["19970902T090000", "19970902T092000", "19970902T094000", "19970902T100000"]);
        assert_eq!(minutes[24], "19970903T090000");
        let same = run("FREQ=MINUTELY;INTERVAL=20;BYHOUR=9,10,11,12,13,14,15,16", "19970902T090000", 30);
        assert_eq!(minutes, same);
        // An invalid date (30 February) is left out; the 15th and 30th otherwise.
        assert_eq!(
            run("FREQ=MONTHLY;BYMONTHDAY=15,30;COUNT=5", "20070115T090000", 10),
            ["20070115T090000", "20070130T090000", "20070215T090000", "20070315T090000", "20070330T090000"]
        );
    }

    #[test]
    fn edge_cases() {
        // A yearly rule on 29 February comes every four years.
        assert_eq!(run("FREQ=YEARLY", "20240229", 3), ["20240229", "20280229", "20320229"]);
        // A rule that never matches ends.
        assert_eq!(run("FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=30", "20240101", 5), ["20240101"]);
        // Week 1 may start in the year before.
        assert_eq!(run("FREQ=YEARLY;BYWEEKNO=1;BYDAY=MO;COUNT=3", "20241230", 5), ["20241230", "20251229", "20270104"]);
        // UNTIL as a date includes that day.
        assert_eq!(run("FREQ=DAILY;UNTIL=20261103", "20261101T100000", 9).len(), 3);
        // The last day of each month, and the monthly default of a start on the 31st skips short months.
        assert_eq!(run("FREQ=MONTHLY;BYMONTHDAY=-1", "20260131", 3), ["20260131", "20260228", "20260331"]);
        assert_eq!(run("FREQ=MONTHLY", "20260131", 3), ["20260131", "20260331", "20260531"]);
    }
}
