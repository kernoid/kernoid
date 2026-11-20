// SPDX-License-Identifier: MIT
//! Dates (RFC 5322, 3.3, with the obsolete forms of 4.3): read as mail programs write them – without a weekday,
//! with two-digit years, without seconds, with zone names or none, in asctime's order, or as ISO 8601 – and written.

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

/// A date and time with the offset of its zone from UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// Minutes east of UTC.
    pub offset: i16,
}

/// Days since 1970-01-01 of a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => 29,
        2 => 28,
        _ => 0,
    }
}

impl DateTime {
    /// The instant in UTC.
    pub fn from_timestamp(timestamp: i64) -> Self {
        let (year, month, day) = civil_from_days(timestamp.div_euclid(86_400));
        let seconds = timestamp.rem_euclid(86_400);
        Self {
            year: year.clamp(0, 9999) as u16,
            month: month as u8,
            day: day as u8,
            hour: (seconds / 3600) as u8,
            minute: (seconds % 3600 / 60) as u8,
            second: (seconds % 60) as u8,
            offset: 0,
        }
    }

    /// The instant in the zone `offset` minutes east of UTC.
    pub fn from_timestamp_in(timestamp: i64, offset: i16) -> Self {
        Self { offset, ..Self::from_timestamp(timestamp + i64::from(offset) * 60) }
    }

    /// Now, in UTC.
    pub fn now() -> Self {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs() as i64);
        Self::from_timestamp(seconds)
    }

    /// Seconds since the epoch.
    pub fn to_timestamp(&self) -> i64 {
        days_from_civil(i64::from(self.year), i64::from(self.month), i64::from(self.day)) * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
            - i64::from(self.offset) * 60
    }

    /// Whether each field is in its range.
    pub fn is_valid(&self) -> bool {
        (1..=12).contains(&self.month)
            && (1..=days_in_month(self.year, self.month)).contains(&self.day)
            && self.hour < 24
            && self.minute < 60
            && self.second < 61
            && self.offset.abs() < 24 * 60
    }

    fn zone(&self, colon: bool) -> String {
        let sign = if self.offset < 0 { '-' } else { '+' };
        let (hours, minutes) = (self.offset.unsigned_abs() / 60, self.offset.unsigned_abs() % 60);
        if colon { format!("{sign}{hours:02}:{minutes:02}") } else { format!("{sign}{hours:02}{minutes:02}") }
    }

    /// RFC 3339 in the date's own zone (`Z` for UTC).
    pub fn to_rfc3339(&self) -> String {
        let zone = if self.offset == 0 { "Z".to_owned() } else { self.zone(true) };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{zone}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// RFC 5322's form: `Sat, 24 Oct 2026 08:30:00 +0200`.
    pub fn to_rfc822(&self) -> String {
        let days = days_from_civil(i64::from(self.year), i64::from(self.month), i64::from(self.day));
        format!(
            "{}, {} {} {:04} {:02}:{:02}:{:02} {}",
            WEEKDAYS[days.rem_euclid(7) as usize],
            self.day,
            MONTHS[usize::from(self.month.clamp(1, 12)) - 1],
            self.year,
            self.hour,
            self.minute,
            self.second,
            self.zone(false)
        )
    }
}

/// The offset of a zone name, in minutes (RFC 5322, 4.3, and names mail programs write).
fn zone_name(name: &str) -> Option<i16> {
    Some(match name.to_ascii_uppercase().as_str() {
        "UT" | "UTC" | "GMT" | "Z" | "WET" => 0,
        "EDT" => -4 * 60,
        "EST" | "CDT" => -5 * 60,
        "CST" | "MDT" => -6 * 60,
        "MST" | "PDT" => -7 * 60,
        "PST" => -8 * 60,
        "CET" | "MET" | "MEZ" | "BST" | "WEST" => 60,
        "CEST" | "MEST" | "MESZ" | "EET" => 120,
        "EEST" | "MSK" => 180,
        "JST" | "KST" => 540,
        "IST" => 330,
        // Military zones are to be read as unknown (RFC 5322, 4.3).
        letter if letter.len() == 1 && letter.chars().all(|c| c.is_ascii_alphabetic()) => 0,
        _ => return None,
    })
}

/// `+hhmm`, `-hh:mm`, `+h`, after an optional `GMT`/`UTC`.
fn numeric_zone(text: &str) -> Option<i16> {
    let text = text.strip_prefix("GMT").or_else(|| text.strip_prefix("UTC")).unwrap_or(text);
    let (sign, digits) = match text.as_bytes().first()? {
        b'+' => (1, &text[1..]),
        b'-' => (-1, &text[1..]),
        _ => return None,
    };
    let digits: String = digits.chars().filter(|c| *c != ':').collect();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.len() > 4 {
        return None;
    }
    let (hours, minutes) = match digits.len() {
        1 | 2 => (digits.parse::<i16>().ok()?, 0),
        3 => (digits[..1].parse::<i16>().ok()?, digits[1..].parse::<i16>().ok()?),
        _ => (digits[..2].parse::<i16>().ok()?, digits[2..].parse::<i16>().ok()?),
    };
    Some(sign * (hours * 60 + minutes))
}

fn month(name: &str) -> Option<u8> {
    let name = name.get(..3)?;
    MONTHS.iter().position(|m| m.eq_ignore_ascii_case(name)).map(|i| i as u8 + 1)
}

fn time(text: &str) -> Option<(u8, u8, u8)> {
    let mut parts = text.split(':');
    let hour = parts.next()?.parse().ok()?;
    let minute = parts.next()?.parse().ok()?;
    let second = match parts.next() {
        Some(second) => second.split('.').next()?.parse().ok()?,
        None => 0,
    };
    parts.next().is_none().then_some((hour, minute, second))
}

/// ISO 8601 / RFC 3339: `2026-10-24T08:30:00+02:00`, `2026-10-24 08:30:00Z`.
fn iso(text: &str) -> Option<DateTime> {
    let text = text.trim();
    let date = text.get(..10)?;
    let mut fields = date.split('-');
    let year = fields.next()?.parse().ok()?;
    let month = fields.next()?.parse().ok()?;
    let day = fields.next()?.parse().ok()?;
    let rest = text[10..].trim_start_matches(['T', 't', ' ']);
    let zone_at = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
    let (hour, minute, second) = if rest.is_empty() { (0, 0, 0) } else { time(&rest[..zone_at])? };
    let zone = rest[zone_at..].trim();
    let offset = match zone {
        "" | "Z" | "z" => 0,
        zone => numeric_zone(zone)?,
    };
    let date = DateTime { year, month, day, hour, minute, second, offset };
    date.is_valid().then_some(date)
}

/// Reads a date; `None` unless it names a valid day and time.
pub fn parse(text: &str) -> Option<DateTime> {
    // Comments go: `+0200 (CEST)`.
    let mut cleaned = String::with_capacity(text.len());
    let mut depth = 0;
    for c in text.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            c if depth == 0 => cleaned.push(c),
            _ => {}
        }
    }
    let cleaned = cleaned.trim();
    if cleaned.as_bytes().get(4) == Some(&b'-')
        && cleaned.as_bytes().get(..4).is_some_and(|y| y.iter().all(u8::is_ascii_digit))
    {
        return iso(cleaned);
    }
    let (mut day, mut month_number, mut year, mut clock, mut offset) = (None, None, None, None, None);
    let mut numbers = Vec::new();
    for token in cleaned.split(|c: char| c.is_whitespace() || c == ',').filter(|t| !t.is_empty()) {
        if token.contains(':') && token.as_bytes()[0].is_ascii_digit() && clock.is_none() {
            // `08:30:00+0200` written together.
            let at = token.find(['+', '-']).unwrap_or(token.len());
            clock = Some(time(&token[..at])?);
            if at < token.len() {
                offset = numeric_zone(&token[at..]);
            }
        } else if token.bytes().all(|b| b.is_ascii_digit()) {
            numbers.push(token);
        } else if let Some(zone) = numeric_zone(token) {
            offset = offset.or(Some(zone));
        } else if let Some(m) = month(token).filter(|_| month_number.is_none() && token.len() >= 3) {
            if token.len() == 3 || MONTH_NAMES.iter().any(|name| name.eq_ignore_ascii_case(token)) {
                month_number = Some(m);
            }
        } else if clock.is_some()
            && let Some(zone) = zone_name(token)
        {
            offset = offset.or(Some(zone));
        } else if let Some((d, m)) = token.split_once('-').and_then(|(d, rest)| Some((d, month(rest)?))) {
            // `24-Oct-2026`.
            month_number = Some(m);
            numbers.push(d);
            if let Some(y) = token.rsplit('-').next().filter(|y| y.bytes().all(|b| b.is_ascii_digit())) {
                numbers.push(y);
            }
        }
    }
    for number in numbers {
        let value: u32 = number.parse().ok()?;
        if day.is_none() && number.len() <= 2 && (1..=31).contains(&value) {
            day = Some(value as u8);
        } else if year.is_none() {
            year = Some(match (number.len(), value) {
                (1 | 2, v) if v < 50 => 2000 + v,
                (1 | 2, v) => 1900 + v,
                (3, v) => 1900 + v,
                (_, v) => v,
            });
        }
    }
    let (hour, minute, second) = clock?;
    let date = DateTime {
        year: u16::try_from(year?).ok()?,
        month: month_number?,
        day: day?,
        hour,
        minute,
        second: second.min(59),
        offset: offset.unwrap_or(0),
    };
    date.is_valid().then_some(date)
}

const MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Option<i64> {
        parse(text).map(|date| date.to_timestamp())
    }

    #[test]
    fn dates_of_rfc_5322() {
        assert_eq!(at("Fri, 21 Nov 1997 09:55:06 -0600"), Some(880_127_706));
        assert_eq!(at("Tue, 1 Jul 2003 10:52:37 +0200"), Some(1_057_049_557));
        assert_eq!(
            at(
                "Thu,\r\n      13\r\n        Feb\r\n          1969\r\n      23:32\r\n               -0330 (Newfoundland Time)"
            ),
            Some(-27_723_480)
        );
        assert_eq!(at("21 Nov 97 09:55:06 GMT"), Some(880_106_106));
        assert_eq!(at("Tue, 1 Apr 1997 09:06:31 -0800"), Some(859_914_391));
        let date = parse("Sat, 24 Oct 2026 08:30:00\r\n +0200").unwrap();
        assert_eq!(date.offset, 120);
        assert_eq!(date.to_rfc3339(), "2026-10-24T08:30:00+02:00");
        assert_eq!(date.to_rfc822(), "Sat, 24 Oct 2026 08:30:00 +0200");
        assert_eq!(DateTime::from_timestamp(date.to_timestamp()).to_rfc3339(), "2026-10-24T06:30:00Z");
    }

    #[test]
    fn dates_as_mail_programs_write_them() {
        let utc = |text: &str| parse(text).map(|d| DateTime::from_timestamp(d.to_timestamp()).to_rfc3339());
        assert_eq!(utc("24 Oct 2026 08:30 +0200").as_deref(), Some("2026-10-24T06:30:00Z"));
        assert_eq!(utc("Sat, 24 Oct 2026 08:30:00").as_deref(), Some("2026-10-24T08:30:00Z"));
        assert_eq!(utc("Sat, 24 Oct 2026 08:30:00 CEST").as_deref(), Some("2026-10-24T06:30:00Z"));
        assert_eq!(utc("Sat Oct 24 08:30:00 2026").as_deref(), Some("2026-10-24T08:30:00Z"));
        assert_eq!(utc("Saturday, 24 October 2026 08:30:00 GMT+0200").as_deref(), Some("2026-10-24T06:30:00Z"));
        assert_eq!(utc("2026-10-24T08:30:00+02:00").as_deref(), Some("2026-10-24T06:30:00Z"));
        assert_eq!(utc("24-Oct-2026 08:30:00 -0000").as_deref(), Some("2026-10-24T08:30:00Z"));
        assert_eq!(utc("Sat, 24 Oct 2026 08:30:00 +02:00").as_deref(), Some("2026-10-24T06:30:00Z"));
        for broken in ["", "yesterday", "31 Feb 2026 10:00:00 +0000", "24 Oct 2026", "24 Foo 2026 10:00:00", "x 99:99"]
        {
            assert_eq!(parse(broken), None, "{broken}");
        }
    }

    #[test]
    fn timestamps_both_ways() {
        for timestamp in [0, 951_782_400, 1_700_000_000, -2_208_988_800, 4_102_444_800] {
            assert_eq!(DateTime::from_timestamp(timestamp).to_timestamp(), timestamp);
        }
        let date = DateTime::from_timestamp_in(1_700_000_000, -300);
        assert_eq!(date.to_rfc822(), "Tue, 14 Nov 2023 17:13:20 -0500");
        assert_eq!(date.to_timestamp(), 1_700_000_000);
        assert!(DateTime::now().is_valid());
    }
}
