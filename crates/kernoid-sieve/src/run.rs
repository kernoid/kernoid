// SPDX-License-Identifier: AGPL-3.0-or-later
//! Running a compiled script on a message (RFC 5228, 2.10): the commands in order, the implicit keep, the actions
//! taken – within the limits.

use std::collections::HashMap;

use mail_parser::DateTime;
use sha2::{Digest, Sha256};

use crate::{
    Context, Environment, Limits, Outcome, RuntimeError, Script,
    compile::{AddressPart, Command, DatePart, DuplicateSource, FlagOp, Test, Zone},
    matching::{MatchType, Matcher},
    message::{Mail, domain, local_part, single_address},
    strings::{Part, Value, truncate},
    vacation,
};

/// What a script decided to do with the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Into the inbox, with these flags (`imap4flags`).
    Keep {
        flags: Vec<String>,
    },
    /// Into `mailbox` (`create`: made if it is missing, RFC 5490); `copy` (RFC 3894) did not cancel the implicit
    /// keep.
    FileInto {
        mailbox: String,
        flags: Vec<String>,
        create: bool,
        copy: bool,
    },
    /// The message, unchanged, to `address`.
    Redirect {
        address: String,
        copy: bool,
    },
    /// Refuse the message (RFC 5429): `extended` for `ereject`, which should refuse it in the SMTP session.
    Reject {
        reason: String,
        extended: bool,
    },
    Vacation(Vacation),
    Notify(Notify),
}

/// A vacation reply to send (RFC 5230) – unless one with the same key went to the same sender within `seconds`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vacation {
    pub to: String,
    /// The sender and the vacation's handle, for remembering the reply.
    pub key: String,
    pub seconds: u64,
    /// The reply, ready to send from an empty envelope sender.
    pub message: Vec<u8>,
}

/// A notification (RFC 5435).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub method: String,
    pub from: Option<String>,
    /// 1 (high) to 3 (low), 2 without one.
    pub importance: u8,
    pub options: Vec<String>,
    pub message: Option<String>,
}

struct Run<'r> {
    limits: Limits,
    mail: Mail<'r>,
    context: &'r Context<'r>,
    environment: &'r mut dyn Environment,
    variables: HashMap<String, String>,
    /// `${0}` to `${9}` of the last successful `:matches`.
    matches: Vec<String>,
    /// The internal variable of `imap4flags`.
    flags: Vec<String>,
    actions: Vec<Action>,
    implicit_keep: bool,
    spent: u64,
    redirects: usize,
    vacation: bool,
}

pub(crate) fn run(
    script: &Script,
    message: &[u8],
    context: &Context<'_>,
    environment: &mut dyn Environment,
) -> Result<Outcome, RuntimeError> {
    let mut run = Run {
        limits: script.limits,
        mail: Mail::new(message),
        context,
        environment,
        variables: HashMap::new(),
        matches: Vec::new(),
        flags: Vec::new(),
        actions: Vec::new(),
        implicit_keep: true,
        spent: 0,
        redirects: 0,
        vacation: false,
    };
    run.block(&script.commands)?;
    if run.implicit_keep {
        let flags = run.flags.clone();
        run.actions.push(Action::Keep { flags });
    }
    Ok(Outcome { actions: run.actions })
}

fn error(message: impl Into<String>) -> RuntimeError {
    RuntimeError { message: message.into() }
}

/// The flags in `strings`, each of which may hold several separated by spaces; each once, ignoring case.
fn flag_list<'a>(strings: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut flags: Vec<String> = Vec::new();
    for flag in strings.into_iter().flat_map(str::split_whitespace) {
        if !flags.iter().any(|known| known.eq_ignore_ascii_case(flag)) {
            flags.push(flag.to_owned());
        }
    }
    flags
}

fn address_part(address: &str, part: AddressPart) -> Option<&str> {
    let has_at = address.contains('@');
    match part {
        AddressPart::All => Some(address),
        AddressPart::LocalPart => has_at.then(|| local_part(address)),
        AddressPart::Domain => has_at.then(|| domain(address)),
        AddressPart::User => has_at.then(|| {
            let local = local_part(address);
            local.split_once('+').map_or(local, |(user, _)| user)
        }),
        AddressPart::Detail => {
            if has_at {
                local_part(address).split_once('+').map(|(_, detail)| detail)
            } else {
                None
            }
        }
    }
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// The part of the instant `timestamp` (seconds since the epoch) in a zone `offset` seconds east of UTC (RFC 5260,
/// 4.2).
fn date_part(timestamp: i64, offset: i64, part: DatePart) -> String {
    let local = timestamp.saturating_add(offset);
    let date = DateTime::from_timestamp(local);
    let days = local.div_euclid(86_400);
    let sign = if offset < 0 { '-' } else { '+' };
    let (zone_hours, zone_minutes) = (offset.unsigned_abs() / 3600, (offset.unsigned_abs() % 3600) / 60);
    let weekday = usize::try_from((days + 4).rem_euclid(7)).unwrap_or_default();
    let (y, mo, d, h, mi, s) = (date.year, date.month, date.day, date.hour, date.minute, date.second);
    match part {
        DatePart::Year => format!("{y:04}"),
        DatePart::Month => format!("{mo:02}"),
        DatePart::Day => format!("{d:02}"),
        DatePart::Date => format!("{y:04}-{mo:02}-{d:02}"),
        // The Modified Julian Day: days since 1858-11-17; 1970-01-01 is day 40587.
        DatePart::Julian => (days + 40_587).to_string(),
        DatePart::Hour => format!("{h:02}"),
        DatePart::Minute => format!("{mi:02}"),
        DatePart::Second => format!("{s:02}"),
        DatePart::Time => format!("{h:02}:{mi:02}:{s:02}"),
        DatePart::Iso8601 => {
            format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{sign}{zone_hours:02}:{zone_minutes:02}")
        }
        DatePart::Std11 => format!(
            "{}, {d:02} {} {y:04} {h:02}:{mi:02}:{s:02} {sign}{zone_hours:02}{zone_minutes:02}",
            WEEKDAYS[weekday],
            MONTHS[usize::from(mo.clamp(1, 12)) - 1]
        ),
        DatePart::Zone => format!("{sign}{zone_hours:02}{zone_minutes:02}"),
        DatePart::Weekday => weekday.to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_mailto(uri: &str) -> bool {
    crate::compile::valid_uri(uri) && uri.get(..7).is_some_and(|scheme| scheme.eq_ignore_ascii_case("mailto:"))
}

impl Run<'_> {
    fn charge(&mut self, cost: u64) -> Result<(), RuntimeError> {
        self.spent = self.spent.saturating_add(cost);
        if self.spent > self.limits.max_instructions {
            return Err(error("the script did too much work"));
        }
        Ok(())
    }

    fn push(&mut self, action: Action) -> Result<(), RuntimeError> {
        if self.actions.len() >= self.limits.max_actions {
            return Err(error("the script took too many actions"));
        }
        self.actions.push(action);
        Ok(())
    }

    fn expand(&self, value: &Value) -> String {
        let parts = match value {
            Value::Constant(text) => return text.clone(),
            Value::Template(parts) => parts,
        };
        let mut out = String::new();
        for part in parts {
            out.push_str(match part {
                Part::Text(text) => text,
                Part::Variable(name) => self.variables.get(name).map_or("", String::as_str),
                Part::Match(n) => self.matches.get(*n).map_or("", String::as_str),
            });
            if out.len() > self.limits.max_string_size {
                return truncate(out, self.limits.max_string_size);
            }
        }
        out
    }

    fn expand_all(&self, values: &[Value]) -> Vec<String> {
        values.iter().map(|value| self.expand(value)).collect()
    }

    /// Runs `commands`; `true` if one said stop.
    fn block(&mut self, commands: &[Command]) -> Result<bool, RuntimeError> {
        for command in commands {
            self.charge(1)?;
            if self.command(command)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn command(&mut self, command: &Command) -> Result<bool, RuntimeError> {
        match command {
            Command::If { branches, otherwise } => {
                for (test, block) in branches {
                    if self.test(test)? {
                        return self.block(block);
                    }
                }
                if let Some(block) = otherwise {
                    return self.block(block);
                }
            }
            Command::Stop => return Ok(true),
            Command::Keep { flags } => {
                let flags = self.flags_of(flags.as_deref());
                self.push(Action::Keep { flags })?;
                self.implicit_keep = false;
            }
            Command::Discard => self.implicit_keep = false,
            Command::FileInto { mailbox, flags, create, copy } => {
                let mailbox = self.expand(mailbox);
                if mailbox.is_empty() {
                    return Err(error("fileinto: the mailbox has no name"));
                }
                let flags = self.flags_of(flags.as_deref());
                self.push(Action::FileInto { mailbox, flags, create: *create, copy: *copy })?;
                if !copy {
                    self.implicit_keep = false;
                }
            }
            Command::Redirect { address, copy } => {
                let address = self.expand(address);
                let Some((_, address)) = single_address(&address) else {
                    return Err(error(format!("redirect: \"{address}\" is not a valid address")));
                };
                let again = self.actions.iter().any(|action| {
                    matches!(action, Action::Redirect { address: known, .. } if known.eq_ignore_ascii_case(&address))
                });
                if !again {
                    if self.redirects >= self.limits.max_redirects {
                        return Err(error("the script redirected too often"));
                    }
                    self.redirects += 1;
                    self.push(Action::Redirect { address, copy: *copy })?;
                }
                if !copy {
                    self.implicit_keep = false;
                }
            }
            Command::Reject { reason, extended } => {
                let reason = self.expand(reason);
                self.push(Action::Reject { reason, extended: *extended })?;
                self.implicit_keep = false;
            }
            Command::Vacation(command) => {
                if self.vacation {
                    return Err(error("vacation may run only once"));
                }
                self.vacation = true;
                let request = vacation::Request {
                    reason: self.expand(&command.reason),
                    subject: command.subject.as_ref().map(|subject| self.expand(subject)),
                    from: command.from.as_ref().map(|from| self.expand(from)),
                    addresses: self.expand_all(&command.addresses),
                    mime: command.mime,
                    handle: command.handle.as_ref().map(|handle| self.expand(handle)),
                    seconds: command.seconds,
                };
                self.charge(10)?;
                if let Some(reply) = vacation::respond(&self.mail, self.context, request) {
                    self.push(Action::Vacation(reply))?;
                }
            }
            Command::Set { name, value, modifiers } => {
                let mut value = self.expand(value);
                for modifier in modifiers {
                    value = modifier.apply(value);
                }
                self.set_variable(name, value)?;
            }
            Command::Flags { op, variable, flags } => {
                let given = self.expand_all(flags);
                let given = flag_list(given.iter().map(String::as_str));
                let current = match variable {
                    Some(name) => flag_list(self.variables.get(name).map(String::as_str)),
                    None => self.flags.clone(),
                };
                let changed = match op {
                    FlagOp::Set => given,
                    FlagOp::Add => flag_list(current.iter().chain(&given).map(String::as_str)),
                    FlagOp::Remove => current
                        .into_iter()
                        .filter(|flag| !given.iter().any(|gone| gone.eq_ignore_ascii_case(flag)))
                        .collect(),
                };
                match variable {
                    Some(name) => self.set_variable(name, changed.join(" "))?,
                    None => self.flags = changed,
                }
            }
            Command::Notify(notify) => {
                let method = self.expand(&notify.method);
                let importance = notify
                    .importance
                    .as_ref()
                    .map(|importance| self.expand(importance))
                    .and_then(|importance| importance.parse().ok())
                    .filter(|importance| (1..=3).contains(importance))
                    .unwrap_or(2);
                let action = Action::Notify(Notify {
                    method,
                    from: notify.from.as_ref().map(|from| self.expand(from)),
                    importance,
                    options: self.expand_all(&notify.options),
                    message: notify.message.as_ref().map(|message| self.expand(message)),
                });
                self.push(action)?;
            }
        }
        Ok(false)
    }

    fn set_variable(&mut self, name: &str, value: String) -> Result<(), RuntimeError> {
        if !self.variables.contains_key(name) && self.variables.len() >= self.limits.max_variables {
            return Err(error("the script set too many variables"));
        }
        self.charge(1 + value.len() as u64 / 256)?;
        self.variables.insert(name.to_owned(), truncate(value, self.limits.max_variable_size));
        Ok(())
    }

    /// The flags of `:flags`, or the internal variable's without it.
    fn flags_of(&self, flags: Option<&[Value]>) -> Vec<String> {
        match flags {
            Some(flags) => {
                let flags = self.expand_all(flags);
                flag_list(flags.iter().map(String::as_str))
            }
            None => self.flags.clone(),
        }
    }

    /// Whether any value matches any key; the keys are filled in first. `:count` counts the values.
    fn compare(&mut self, values: &[String], keys: &[Value], matcher: &Matcher) -> Result<bool, RuntimeError> {
        let keys = self.expand_all(keys);
        if let MatchType::Count(_) = matcher.kind {
            self.charge(keys.len() as u64)?;
            return Ok(keys.iter().any(|key| matcher.count(values.len(), key)));
        }
        let matches = matcher.kind == MatchType::Matches;
        for value in values {
            for key in &keys {
                let cost = if matches {
                    1 + (value.len() as u64).saturating_mul(key.len() as u64) / 1024
                } else {
                    1 + (value.len() + key.len()) as u64 / 256
                };
                self.charge(cost)?;
                let mut captures = matches.then(Vec::new);
                if matcher.matches(value, key, &mut captures) {
                    if let Some(captures) = captures {
                        self.matches = captures;
                    }
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn zone(&self, zone: Zone) -> Option<i64> {
        match zone {
            Zone::Local => Some(i64::from(self.context.zone)),
            Zone::Fixed(offset) => Some(i64::from(offset)),
            Zone::Original => None,
        }
    }

    fn test(&mut self, test: &Test) -> Result<bool, RuntimeError> {
        self.charge(1)?;
        Ok(match test {
            Test::True => true,
            Test::False => false,
            Test::Not(test) => !self.test(test)?,
            Test::AllOf(tests) => {
                for test in tests {
                    if !self.test(test)? {
                        return Ok(false);
                    }
                }
                true
            }
            Test::AnyOf(tests) => {
                for test in tests {
                    if self.test(test)? {
                        return Ok(true);
                    }
                }
                false
            }
            Test::Exists(names) => self.expand_all(names).iter().all(|name| self.mail.exists(name)),
            Test::Size { over, limit } => {
                let size = self.mail.size() as u64;
                if *over { size > *limit } else { size < *limit }
            }
            Test::Header { names, keys, matcher, index } => {
                let values: Vec<String> =
                    self.expand_all(names).iter().flat_map(|name| self.mail.header_values(name, *index)).collect();
                self.compare(&values, keys, matcher)?
            }
            Test::Address { names, keys, matcher, part, index } => {
                let values: Vec<String> = self
                    .expand_all(names)
                    .iter()
                    .flat_map(|name| self.mail.addresses(name, *index))
                    .filter_map(|address| address_part(&address, *part).map(str::to_owned))
                    .collect();
                self.compare(&values, keys, matcher)?
            }
            Test::Envelope { parts, keys, matcher, part } => {
                let values: Vec<String> = self
                    .expand_all(parts)
                    .iter()
                    .filter_map(|name| match name.to_ascii_lowercase().as_str() {
                        "from" => Some(self.context.envelope_from),
                        "to" => Some(self.context.envelope_to),
                        _ => None,
                    })
                    .filter_map(|address| address_part(address, *part).map(str::to_owned))
                    .collect();
                self.compare(&values, keys, matcher)?
            }
            Test::Body { transform, keys, matcher } => {
                let values = self.mail.body(transform);
                self.charge(values.iter().map(|value| value.len() as u64 / 1024).sum())?;
                self.compare(&values, keys, matcher)?
            }
            Test::String { sources, keys, matcher } => {
                let mut values = self.expand_all(sources);
                if let MatchType::Count(_) = matcher.kind {
                    values.retain(|value| !value.is_empty());
                }
                self.compare(&values, keys, matcher)?
            }
            Test::HasFlag { variables, keys, matcher } => {
                let values = if variables.is_empty() {
                    self.flags.clone()
                } else {
                    flag_list(variables.iter().filter_map(|name| self.variables.get(name)).map(String::as_str))
                };
                let keys = flag_list(self.expand_all(keys).iter().map(String::as_str));
                let keys: Vec<Value> = keys.into_iter().map(Value::Constant).collect();
                self.compare(&values, &keys, matcher)?
            }
            Test::Date { name, part, zone, keys, matcher, index } => {
                let name = self.expand(name);
                let zone = self.zone(*zone);
                let values: Vec<String> = self
                    .mail
                    .dates(&name, *index)
                    .iter()
                    .map(|date| {
                        let original = i64::from(date.tz_hour) * 3600 + i64::from(date.tz_minute) * 60;
                        let original = if date.tz_before_gmt { -original } else { original };
                        date_part(date.to_timestamp(), zone.unwrap_or(original), *part)
                    })
                    .collect();
                self.compare(&values, keys, matcher)?
            }
            Test::CurrentDate { part, zone, keys, matcher } => {
                let value = date_part(self.context.now, self.zone(*zone).unwrap_or_default(), *part);
                self.compare(&[value], keys, matcher)?
            }
            Test::MailboxExists(names) => {
                self.expand_all(names).iter().all(|name| self.environment.mailbox_exists(name))
            }
            Test::Duplicate { handle, source, seconds, last } => {
                let id = match source {
                    DuplicateSource::UniqueId(id) => Some(self.expand(id)),
                    DuplicateSource::Header(name) => {
                        let name = self.expand(name);
                        self.mail.header_values(&name, None).into_iter().next()
                    }
                };
                let Some(id) = id.filter(|id| !id.is_empty()) else {
                    return Ok(false);
                };
                let mut hash = Sha256::new();
                hash.update(handle.as_ref().map(|handle| self.expand(handle)).unwrap_or_default().as_bytes());
                hash.update([0]);
                hash.update(id.as_bytes());
                let key = format!("duplicate:{}", hex(&hash.finalize()[..16]));
                self.environment.duplicate(&key, *seconds, *last)
            }
            Test::ValidNotifyMethod(uris) => self.expand_all(uris).iter().all(|uri| is_mailto(uri)),
            Test::NotifyMethodCapability { uri, capability, keys, matcher } => {
                let uri = self.expand(uri);
                let capability = self.expand(capability);
                if !is_mailto(&uri) || !capability.eq_ignore_ascii_case("online") {
                    return Ok(false);
                }
                // Whether a mail is read at once cannot be known.
                self.compare(&["maybe".to_owned()], keys, matcher)?
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_parts() {
        assert_eq!(address_part("ken+sieve@example.org", AddressPart::All), Some("ken+sieve@example.org"));
        assert_eq!(address_part("ken+sieve@example.org", AddressPart::LocalPart), Some("ken+sieve"));
        assert_eq!(address_part("ken+sieve@example.org", AddressPart::Domain), Some("example.org"));
        assert_eq!(address_part("ken+sieve@example.org", AddressPart::User), Some("ken"));
        assert_eq!(address_part("ken+sieve@example.org", AddressPart::Detail), Some("sieve"));
        assert_eq!(address_part("ken@example.org", AddressPart::Detail), None);
        assert_eq!(address_part("ken+@example.org", AddressPart::Detail), Some(""));
        assert_eq!(address_part("", AddressPart::All), Some(""));
        assert_eq!(address_part("", AddressPart::Domain), None);
    }

    #[test]
    fn date_parts() {
        // 2008-01-18 15:30:20 UTC, a Friday.
        let at = 1_200_670_220;
        let part = |offset, part| date_part(at, offset, part);
        assert_eq!(part(0, DatePart::Year), "2008");
        assert_eq!(part(0, DatePart::Month), "01");
        assert_eq!(part(0, DatePart::Day), "18");
        assert_eq!(part(0, DatePart::Date), "2008-01-18");
        assert_eq!(part(0, DatePart::Julian), "54483");
        assert_eq!(part(0, DatePart::Hour), "15");
        assert_eq!(part(0, DatePart::Minute), "30");
        assert_eq!(part(0, DatePart::Second), "20");
        assert_eq!(part(0, DatePart::Time), "15:30:20");
        assert_eq!(part(0, DatePart::Weekday), "5");
        assert_eq!(part(0, DatePart::Zone), "+0000");
        assert_eq!(part(-8 * 3600, DatePart::Iso8601), "2008-01-18T07:30:20-08:00");
        assert_eq!(part(-8 * 3600, DatePart::Std11), "Fri, 18 Jan 2008 07:30:20 -0800");
        assert_eq!(part(9 * 3600, DatePart::Date), "2008-01-19");
        assert_eq!(part(9 * 3600, DatePart::Weekday), "6");
        assert_eq!(part(5 * 3600 + 30 * 60, DatePart::Zone), "+0530");
    }

    #[test]
    fn flag_lists() {
        assert_eq!(flag_list(["\\Seen \\Flagged", "\\seen", "$Work"]), ["\\Seen", "\\Flagged", "$Work"]);
        assert!(flag_list(["  "]).is_empty());
    }
}
