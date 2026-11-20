// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SEARCH` (RFC 9051, 6.4.4) with ESEARCH, SEARCHRES, WITHIN and CONDSTORE's `MODSEQ`, evaluated in kernoid on the
//! selected mailbox: text through the full-text index (RFC 0002, 13.1), addresses, subject and dates from the summary
//! in PostgreSQL; only `HEADER` reads the messages.

use std::collections::{HashMap, HashSet};

use jiff::Timestamp;
use kernoid_mail::{AddressInfo, EmailInfo};
use mail_parser::{Address, HeaderValue, Message, MessageParser};
use uuid::Uuid;

use crate::{
    flags,
    proto::{
        request::{ResultOption, Search, SearchKey},
        response::Status,
        sequence,
    },
    selected::Selected,
    session::{Session, mail_error},
};

/// Calls `test` on every key that is not `AND`, `OR` or `NOT`.
fn any_leaf(key: &SearchKey, test: &impl Fn(&SearchKey) -> bool) -> bool {
    match key {
        SearchKey::And(keys) => keys.iter().any(|key| any_leaf(key, test)),
        SearchKey::Or(first, second) => any_leaf(first, test) || any_leaf(second, test),
        SearchKey::Not(key) => any_leaf(key, test),
        leaf => test(leaf),
    }
}

/// Only `HEADER` reads the messages.
fn needs_message(key: &SearchKey) -> bool {
    any_leaf(key, &|key| matches!(key, SearchKey::Header(..)))
}

/// What the summary in PostgreSQL answers.
fn needs_summary(key: &SearchKey) -> bool {
    any_leaf(key, &|key| {
        matches!(
            key,
            SearchKey::Bcc(_)
                | SearchKey::Cc(_)
                | SearchKey::From(_)
                | SearchKey::SentBefore(_)
                | SearchKey::SentOn(_)
                | SearchKey::SentSince(_)
                | SearchKey::Subject(_)
                | SearchKey::Text(_)
                | SearchKey::To(_)
        )
    })
}

/// The values of `BODY` and `TEXT`, for the index.
fn texts(key: &SearchKey, out: &mut Vec<String>) {
    match key {
        SearchKey::And(keys) => keys.iter().for_each(|key| texts(key, out)),
        SearchKey::Or(first, second) => {
            texts(first, out);
            texts(second, out);
        }
        SearchKey::Not(key) => texts(key, out),
        SearchKey::Body(text) | SearchKey::Text(text) => out.push(text.clone()),
        _ => {}
    }
}

fn uses_modseq(key: &SearchKey) -> bool {
    any_leaf(key, &|key| matches!(key, SearchKey::ModSeq(_)))
}

/// A header's decoded text: addresses as `name <address>`.
fn header_text(message: &Message<'_>, name: &str) -> Option<String> {
    let mut texts = Vec::new();
    for header in message.headers().iter().filter(|header| header.raw_name().eq_ignore_ascii_case(name)) {
        texts.push(match header.value() {
            HeaderValue::Text(text) => text.to_string(),
            HeaderValue::TextList(list) => list.iter().collect::<Vec<_>>().join(" "),
            HeaderValue::Address(address) => address
                .iter()
                .flat_map(|item| match item {
                    Address::Mailbox(mailbox) => vec![mailbox],
                    Address::Group(group) => group.mailboxes().collect(),
                })
                .map(|mailbox| {
                    format!("{} <{}>", mailbox.name().unwrap_or_default(), mailbox.address().unwrap_or_default())
                })
                .collect::<Vec<_>>()
                .join(", "),
            _ => String::from_utf8_lossy(header.raw_value()).into_owned(),
        });
    }
    (!texts.is_empty()).then(|| texts.join("\n"))
}

fn contains(haystack: Option<String>, needle: &str) -> bool {
    haystack.is_some_and(|haystack| haystack.to_lowercase().contains(&needle.to_lowercase()))
}

/// Whether an address list has `needle` in a name or an address.
fn in_addresses(list: &[AddressInfo], needle: &str) -> bool {
    let needle = needle.to_lowercase();
    list.iter().any(|address| {
        address.email.to_lowercase().contains(&needle)
            || address.name.as_deref().is_some_and(|name| name.to_lowercase().contains(&needle))
    })
}

fn day(timestamp: i64) -> i64 {
    timestamp.div_euclid(86_400)
}

struct Candidate<'x> {
    position: usize,
    entry: &'x kernoid_mail::MailboxEntry,
    info: Option<&'x EmailInfo>,
    message: Option<&'x Message<'x>>,
    saved: bool,
    /// The emails whose text has the words of each `BODY` and `TEXT`.
    found: &'x HashMap<String, HashSet<Uuid>>,
}

fn matches(key: &SearchKey, candidate: &Candidate<'_>, selected: &Selected) -> bool {
    let entry = candidate.entry;
    let has = |keyword: &str| entry.keywords.iter().any(|k| k == keyword);
    let received = entry.received_at.as_second();
    let sent = || candidate.info.and_then(|info| info.sent_at).map(|at| at.as_second());
    let summary = |test: &dyn Fn(&EmailInfo) -> bool| candidate.info.is_some_and(test);
    let in_body = |text: &str| candidate.found.get(text).is_some_and(|ids| ids.contains(&entry.email));
    let subject = |info: &EmailInfo, needle: &str| {
        info.subject.as_deref().unwrap_or_default().to_lowercase().contains(&needle.to_lowercase())
    };
    let header = |name: &str, needle: &str| {
        candidate.message.is_some_and(|message| contains(header_text(message, name), needle))
    };
    let older_than =
        |seconds: u64| Timestamp::now().as_second().saturating_sub(i64::try_from(seconds).unwrap_or(i64::MAX));
    match key {
        SearchKey::And(keys) => keys.iter().all(|key| matches(key, candidate, selected)),
        SearchKey::Or(first, second) => matches(first, candidate, selected) || matches(second, candidate, selected),
        SearchKey::Not(key) => !matches(key, candidate, selected),
        SearchKey::All => true,
        SearchKey::Sequence(set) => {
            set.contains(candidate.position as u32 + 1, selected.entries.len() as u32, candidate.saved)
        }
        SearchKey::Uid(set) => {
            set.contains(entry.uid, selected.entries.last().map_or(0, |entry| entry.uid), candidate.saved)
        }
        SearchKey::Answered => has("$answered"),
        SearchKey::Unanswered => !has("$answered"),
        SearchKey::Deleted => has("$deleted"),
        SearchKey::Undeleted => !has("$deleted"),
        SearchKey::Draft => has("$draft"),
        SearchKey::Undraft => !has("$draft"),
        SearchKey::Flagged => has("$flagged"),
        SearchKey::Unflagged => !has("$flagged"),
        SearchKey::Seen => has("$seen"),
        SearchKey::Unseen => !has("$seen"),
        SearchKey::Keyword(flag) => flags::keyword(flag).is_some_and(|keyword| has(keyword.as_str())),
        SearchKey::Unkeyword(flag) => flags::keyword(flag).is_none_or(|keyword| !has(keyword.as_str())),
        // kernoid keeps no `\Recent`.
        SearchKey::Recent | SearchKey::New => false,
        SearchKey::Old => true,
        SearchKey::Before(date) => day(received) < day(*date),
        SearchKey::On(date) => day(received) == day(*date),
        SearchKey::Since(date) => day(received) >= day(*date),
        SearchKey::SentBefore(date) => sent().is_some_and(|sent| day(sent) < day(*date)),
        SearchKey::SentOn(date) => sent().is_some_and(|sent| day(sent) == day(*date)),
        SearchKey::SentSince(date) => sent().is_some_and(|sent| day(sent) >= day(*date)),
        SearchKey::Older(seconds) => received <= older_than(*seconds),
        SearchKey::Younger(seconds) => received >= older_than(*seconds),
        SearchKey::Larger(size) => entry.size > *size,
        SearchKey::Smaller(size) => entry.size < *size,
        SearchKey::ModSeq(modseq) => entry.modseq >= *modseq,
        SearchKey::From(needle) => {
            summary(&|info| in_addresses(&info.from, needle) || in_addresses(&info.sender, needle))
        }
        SearchKey::To(needle) => summary(&|info| in_addresses(&info.to, needle)),
        SearchKey::Cc(needle) => summary(&|info| in_addresses(&info.cc, needle)),
        SearchKey::Bcc(needle) => summary(&|info| in_addresses(&info.bcc, needle)),
        SearchKey::Subject(needle) => summary(&|info| subject(info, needle)),
        SearchKey::Header(name, needle) if needle.is_empty() => candidate
            .message
            .is_some_and(|message| message.headers().iter().any(|h| h.raw_name().eq_ignore_ascii_case(name))),
        SearchKey::Header(name, needle) => header(name, needle),
        SearchKey::Body(needle) => in_body(needle),
        SearchKey::Text(needle) => {
            in_body(needle)
                || summary(&|info| {
                    subject(info, needle)
                        || [&info.from, &info.sender, &info.to, &info.cc, &info.bcc]
                            .iter()
                            .any(|list| in_addresses(list, needle))
                })
        }
    }
}

impl Session {
    /// The positions of the selected mailbox's messages that match `filter`, and whether it asked for `MODSEQ`.
    pub(crate) async fn matching(&mut self, key: &SearchKey) -> Result<(Selected, Vec<usize>, bool), Box<Status>> {
        let Some(selected) = self.selected.clone() else {
            return Err(Box::new(Status::bad("No mailbox selected")));
        };
        let account = selected.owner;
        let with_messages = needs_message(key);
        let mail = &self.inner.mail;
        let mut words = Vec::new();
        texts(key, &mut words);
        let mut in_text = HashMap::new();
        for text in words {
            if let std::collections::hash_map::Entry::Vacant(slot) = in_text.entry(text) {
                match mail.search_text(account, slot.key()).await {
                    Ok(ids) => {
                        slot.insert(ids);
                    }
                    Err(error) => return Err(Box::new(mail_error(error))),
                }
            }
        }
        let infos: HashMap<Uuid, EmailInfo> = if needs_summary(key) {
            let ids: Vec<Uuid> = selected.entries.iter().map(|entry| entry.email).collect();
            match mail.emails(account, &ids).await {
                Ok(infos) => infos.into_iter().map(|info| (info.id, info)).collect(),
                Err(error) => return Err(Box::new(mail_error(error))),
            }
        } else {
            HashMap::new()
        };
        let mut found = Vec::new();
        for (position, entry) in selected.entries.iter().enumerate() {
            let raw = if with_messages {
                match mail.raw_email(account, entry.email).await {
                    Ok(raw) => Some(raw),
                    Err(kernoid_mail::MailError::NotFound(_)) => continue,
                    Err(error) => return Err(Box::new(mail_error(error))),
                }
            } else {
                None
            };
            let message = raw.as_deref().and_then(|raw| MessageParser::new().parse(raw));
            let candidate = Candidate {
                position,
                entry,
                info: infos.get(&entry.email),
                message: message.as_ref(),
                saved: selected.saved.contains(&entry.uid),
                found: &in_text,
            };
            if matches(key, &candidate, &selected) {
                found.push(position);
            }
        }
        let modseq = uses_modseq(key);
        Ok((selected, found, modseq))
    }

    pub(crate) async fn search(&mut self, search: Search, is_uid: bool) -> Status {
        let (selected, found, modseq) = match self.matching(&search.key).await {
            Ok(matched) => matched,
            Err(response) => return *response,
        };
        let ids: Vec<u32> = found
            .iter()
            .map(|&position| if is_uid { selected.entries[position].uid } else { position as u32 + 1 })
            .collect();
        let highest_modseq =
            if modseq { found.iter().map(|&position| selected.entries[position].modseq).max() } else { None };
        let options = search.options.clone().unwrap_or_default();
        if options.contains(&ResultOption::Save) {
            let uids = found.iter().map(|&position| selected.entries[position].uid).collect();
            if let Some(selected) = &mut self.selected {
                selected.saved = uids;
            }
            // RFC 5182, 2.1: `SAVE` alone returns nothing.
            if options.len() == 1 {
                return Status::done();
            }
        }
        // ESEARCH when asked for it, and always in IMAP4rev2 (RFC 9051, 7.3.4).
        if search.options.is_none() && !self.rev2 {
            let mut line = String::from("* SEARCH");
            for id in &ids {
                line.push_str(&format!(" {id}"));
            }
            if let Some(modseq) = highest_modseq.filter(|_| !ids.is_empty()) {
                line.push_str(&format!(" (MODSEQ {modseq})"));
            }
            line.push_str("\r\n");
            self.write(line);
            return Status::done();
        }
        let wants = |option: ResultOption| options.contains(&option);
        let all = options.iter().all(|option| *option == ResultOption::Save) || wants(ResultOption::All);
        let tag = self.tag.clone();
        let line = esearch(&tag, is_uid, |line| {
            if wants(ResultOption::Min)
                && let Some(min) = ids.iter().min()
            {
                line.push_str(&format!(" MIN {min}"));
            }
            if wants(ResultOption::Max)
                && let Some(max) = ids.iter().max()
            {
                line.push_str(&format!(" MAX {max}"));
            }
            if wants(ResultOption::Count) {
                line.push_str(&format!(" COUNT {}", ids.len()));
            }
            if all && !ids.is_empty() {
                line.push_str(&format!(" ALL {}", sequence::compact(&ids)));
            }
            if let Some(modseq) = highest_modseq.filter(|_| !ids.is_empty()) {
                line.push_str(&format!(" MODSEQ {modseq}"));
            }
        });
        self.write(line);
        Status::done()
    }
}

/// `* ESEARCH (TAG "a") [UID] …` (RFC 4731).
pub(crate) fn esearch(tag: &str, is_uid: bool, items: impl FnOnce(&mut String)) -> String {
    let mut line = String::from("* ESEARCH (TAG ");
    let mut quoted = Vec::new();
    crate::proto::response::string(&mut quoted, tag.as_bytes(), false);
    line.push_str(&String::from_utf8_lossy(&quoted));
    line.push(')');
    if is_uid {
        line.push_str(" UID");
    }
    items(&mut line);
    line.push_str("\r\n");
    line
}
