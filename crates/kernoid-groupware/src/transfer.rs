// SPDX-License-Identifier: AGPL-3.0-or-later
//! Whole calendars and address books in and out (RFC 0004, 9): one iCalendar file (`.ics`) with every event of a
//! calendar, one vCard file (`.vcf`) with every contact of an address book. An import splits the file by UID into
//! objects and stores each as a client would; one that is there already is replaced.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::{Expect, Groupware, GroupwareError, Result};

/// What an import did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Imported {
    pub stored: usize,
    /// Objects that could not be stored, with why.
    pub refused: Vec<(String, String)>,
}

/// The top-level blocks of a text in iCalendar or vCard syntax: each `BEGIN:x` … `END:x` at depth `depth`, with its
/// lines as they are (folded lines stay with theirs).
fn blocks(text: &str, depth: usize) -> Vec<(String, Vec<&str>)> {
    let mut out = Vec::new();
    let mut level = 0usize;
    let mut current: Option<(String, Vec<&str>)> = None;
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\r', '\n']);
        let upper = bare.to_ascii_uppercase();
        if let Some(name) = upper.strip_prefix("BEGIN:") {
            if level == depth {
                current = Some((name.to_owned(), Vec::new()));
            }
            level += 1;
        }
        if let Some((_, lines)) = current.as_mut() {
            lines.push(line);
        }
        if upper.starts_with("END:") {
            level = level.saturating_sub(1);
            if level == depth
                && let Some(block) = current.take()
            {
                out.push(block);
            }
        }
    }
    out
}

/// A property's value in a block's own lines (not in nested components), unfolded.
fn property(lines: &[&str], name: &str) -> Option<String> {
    let mut depth = 0usize;
    let mut found: Option<String> = None;
    for line in lines {
        let bare = line.trim_end_matches(['\r', '\n']);
        if let Some(value) = found.as_mut() {
            if let Some(rest) = bare.strip_prefix([' ', '\t']) {
                value.push_str(rest);
                continue;
            }
            return found;
        }
        let upper = bare.to_ascii_uppercase();
        if upper.starts_with("BEGIN:") {
            depth += 1;
        } else if upper.starts_with("END:") {
            depth = depth.saturating_sub(1);
        } else if depth == 1 {
            let (key, value) = bare.split_once(':')?;
            if key.split(';').next().is_some_and(|key| key.eq_ignore_ascii_case(name)) {
                found = Some(value.to_owned());
            }
        }
    }
    found
}

fn crlf(lines: &[&str], out: &mut String) {
    for line in lines {
        let bare = line.trim_end_matches(['\r', '\n']);
        out.push_str(bare);
        out.push_str("\r\n");
    }
}

impl Groupware {
    /// Every event of a calendar in one iCalendar object; time zones once each.
    pub async fn export_calendar(&self, account: Uuid, calendar: Uuid) -> Result<String> {
        self.calendar(account, calendar).await?;
        let ids: Vec<Uuid> = self.events(account, calendar).await?.into_iter().map(|event| event.id).collect();
        let mut out = format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:{}\r\n", crate::PROD_ID);
        let mut zones = BTreeMap::new();
        let mut components = String::new();
        for (_, text) in self.event_data(account, &ids).await? {
            for calendar in blocks(&text, 0) {
                let inner = calendar.1.join("");
                for (name, lines) in blocks(&inner, 1) {
                    if name == "VTIMEZONE" {
                        let tzid = property(&lines, "TZID").unwrap_or_default();
                        zones.entry(tzid).or_insert_with(|| {
                            let mut block = String::new();
                            crlf(&lines, &mut block);
                            block
                        });
                    } else {
                        crlf(&lines, &mut components);
                    }
                }
            }
        }
        for zone in zones.into_values() {
            out.push_str(&zone);
        }
        out.push_str(&components);
        out.push_str("END:VCALENDAR\r\n");
        Ok(out)
    }

    /// Stores the events of an iCalendar file in a calendar, one object per UID with the time zones it may need.
    pub async fn import_calendar(&self, account: Uuid, calendar: Uuid, text: &str) -> Result<Imported> {
        self.calendar(account, calendar).await?;
        let mut zones = String::new();
        let mut by_uid: BTreeMap<String, String> = BTreeMap::new();
        let mut imported = Imported::default();
        for calendar_block in blocks(text, 0).into_iter().filter(|(name, _)| name == "VCALENDAR") {
            let inner = calendar_block.1.join("");
            for (name, lines) in blocks(&inner, 1) {
                match name.as_str() {
                    "VTIMEZONE" => crlf(&lines, &mut zones),
                    "VEVENT" | "VTODO" | "VJOURNAL" => match property(&lines, "UID") {
                        Some(uid) => crlf(&lines, by_uid.entry(uid).or_default()),
                        None => imported.refused.push((name, "no UID".into())),
                    },
                    _ => {}
                }
            }
        }
        if by_uid.is_empty() && imported.refused.is_empty() {
            return Err(GroupwareError::Invalid("no events in the file".into()));
        }
        for (uid, components) in by_uid {
            let object = format!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:{}\r\n{zones}{components}END:VCALENDAR\r\n",
                crate::PROD_ID
            );
            let existing =
                self.events_by_uid(account, &uid).await?.into_iter().find(|event| event.calendar == calendar);
            let result = match existing {
                Some(event) => self.replace_event(account, event.id, &object, false).await.map(|_| ()),
                None => self.create_event(account, calendar, &object).await.map(|_| ()),
            };
            match result {
                Ok(()) => imported.stored += 1,
                Err(error @ (GroupwareError::Invalid(_) | GroupwareError::TooLarge { .. })) => {
                    imported.refused.push((uid, error.to_string()));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(imported)
    }

    /// Every contact of an address book in one vCard file.
    pub async fn export_addressbook(&self, account: Uuid, addressbook: Uuid) -> Result<String> {
        self.addressbook(account, addressbook).await?;
        let ids: Vec<Uuid> =
            self.contacts(account, Some(addressbook)).await?.into_iter().map(|contact| contact.id).collect();
        let mut out = String::new();
        for (_, text) in self.contact_data(account, &ids).await? {
            for (_, lines) in blocks(&text, 0) {
                crlf(&lines, &mut out);
            }
        }
        Ok(out)
    }

    /// Stores the vCards of a file in an address book; one without a UID gets one.
    pub async fn import_addressbook(&self, account: Uuid, addressbook: Uuid, text: &str) -> Result<Imported> {
        self.addressbook(account, addressbook).await?;
        let mut imported = Imported::default();
        let cards = blocks(text, 0);
        if cards.is_empty() {
            return Err(GroupwareError::Invalid("no contacts in the file".into()));
        }
        for (name, lines) in cards {
            if name != "VCARD" {
                continue;
            }
            let mut card = String::new();
            crlf(&lines, &mut card);
            let uid = match property(&lines, "UID") {
                Some(uid) => uid,
                None => {
                    let uid = format!("urn:uuid:{}", Uuid::now_v7());
                    card = card.replacen("\r\n", &format!("\r\nUID:{uid}\r\n"), 1);
                    uid
                }
            };
            let name = crate::resource_name(&uid, Uuid::now_v7(), "vcf");
            let existing =
                self.contacts(account, Some(addressbook)).await?.into_iter().find(|contact| contact.uid == uid);
            let result = match existing {
                Some(contact) => self.replace_contact(account, contact.id, &card).await.map(|_| ()),
                None => self.put_contact(account, addressbook, &name, &card, Expect::New).await.map(|_| ()),
            };
            match result {
                Ok(()) => imported.stored += 1,
                Err(
                    error @ (GroupwareError::Invalid(_)
                    | GroupwareError::TooLarge { .. }
                    | GroupwareError::PreconditionFailed),
                ) => {
                    imported.refused.push((uid, error.to_string()));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(imported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_and_properties_are_found() {
        let text = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:a\r\n b\r\nSUMMARY:x\r\nBEGIN:VALARM\r\nUID:inner\r\n\
                    END:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let outer = blocks(text, 0);
        assert_eq!(outer.len(), 1);
        let joined = outer[0].1.join("");
        let inner = blocks(&joined, 1);
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].0, "VEVENT");
        assert_eq!(property(&inner[0].1, "UID").as_deref(), Some("ab"));
    }
}
