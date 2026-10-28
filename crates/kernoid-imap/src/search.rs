// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SEARCH` (RFC 9051, 6.4.4) with ESEARCH, SEARCHRES, WITHIN and CONDSTORE's `MODSEQ`, evaluated in kernoid on the
//! selected mailbox: text through the full-text index (RFC 0002, 13.1), addresses, subject and dates from the summary
//! in PostgreSQL; only `HEADER` reads the messages.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use kernoid_mail::{AddressInfo, EmailInfo};
use mail_parser::{Address, HeaderValue, Message, MessageParser};
use uuid::Uuid;

use crate::{
    flags,
    proto::{
        Command, StatusResponse,
        protocol::search::{self, Filter, ResultOption},
    },
    selected::Selected,
    session::{Session, mail_error},
};

enum Node {
    Leaf(Filter),
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Vec<Node>),
}

/// The parser's filters are prefix operators closed by `End`; the top level is an `AND`.
fn tree(filters: &mut impl Iterator<Item = Filter>) -> Vec<Node> {
    let mut nodes = Vec::new();
    while let Some(filter) = filters.next() {
        nodes.push(match filter {
            Filter::End => break,
            Filter::And => Node::And(tree(filters)),
            Filter::Or => Node::Or(tree(filters)),
            Filter::Not => Node::Not(tree(filters)),
            leaf => Node::Leaf(leaf),
        });
    }
    nodes
}

fn any_leaf(nodes: &[Node], test: &impl Fn(&Filter) -> bool) -> bool {
    nodes.iter().any(|node| match node {
        Node::And(children) | Node::Or(children) | Node::Not(children) => any_leaf(children, test),
        Node::Leaf(filter) => test(filter),
    })
}

/// Only `HEADER` reads the messages.
fn needs_message(nodes: &[Node]) -> bool {
    any_leaf(nodes, &|filter| matches!(filter, Filter::Header(..)))
}

/// What the summary in PostgreSQL answers.
fn needs_summary(nodes: &[Node]) -> bool {
    any_leaf(nodes, &|filter| {
        matches!(
            filter,
            Filter::Bcc(_)
                | Filter::Cc(_)
                | Filter::From(_)
                | Filter::SentBefore(_)
                | Filter::SentOn(_)
                | Filter::SentSince(_)
                | Filter::Subject(_)
                | Filter::Text(_)
                | Filter::To(_)
        )
    })
}

/// The values of `BODY` and `TEXT`, for the index.
fn texts(nodes: &[Node], out: &mut Vec<String>) {
    for node in nodes {
        match node {
            Node::And(children) | Node::Or(children) | Node::Not(children) => texts(children, out),
            Node::Leaf(Filter::Body(text) | Filter::Text(text)) => out.push(text.clone()),
            Node::Leaf(_) => {}
        }
    }
}

fn uses_modseq(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| match node {
        Node::And(children) | Node::Or(children) | Node::Not(children) => uses_modseq(children),
        Node::Leaf(filter) => matches!(filter, Filter::ModSeq(_)),
    })
}

/// A header's decoded text: addresses as `name <address>`.
fn header_text(message: &Message<'_>, name: &str) -> Option<String> {
    let mut texts = Vec::new();
    for header in message.parts.first()?.headers.iter().filter(|header| header.name.as_str().eq_ignore_ascii_case(name))
    {
        texts.push(match &header.value {
            HeaderValue::Text(text) => text.to_string(),
            HeaderValue::TextList(list) => list.join(" "),
            HeaderValue::Address(address) => {
                let one = |addr: &mail_parser::Addr<'_>| {
                    format!(
                        "{} <{}>",
                        addr.name.as_deref().unwrap_or_default(),
                        addr.address.as_deref().unwrap_or_default()
                    )
                };
                match address {
                    Address::List(list) => list.iter().map(one).collect::<Vec<_>>().join(", "),
                    Address::Group(groups) => {
                        groups.iter().flat_map(|group| group.addresses.iter().map(one)).collect::<Vec<_>>().join(", ")
                    }
                }
            }
            _ => String::from_utf8_lossy(
                message.raw_message.get(header.offset_start as usize..header.offset_end as usize).unwrap_or_default(),
            )
            .into_owned(),
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

fn matches(nodes: &[Node], candidate: &Candidate<'_>, selected: &Selected) -> bool {
    nodes.iter().all(|node| node_matches(node, candidate, selected))
}

fn node_matches(node: &Node, candidate: &Candidate<'_>, selected: &Selected) -> bool {
    let entry = candidate.entry;
    let has = |keyword: &str| entry.keywords.iter().any(|k| k == keyword);
    let received = entry.received_at.timestamp();
    let sent = || candidate.info.and_then(|info| info.sent_at).map(|at| at.timestamp());
    let summary = |test: &dyn Fn(&EmailInfo) -> bool| candidate.info.is_some_and(test);
    let in_body = |text: &str| candidate.found.get(text).is_some_and(|ids| ids.contains(&entry.email));
    let subject = |info: &EmailInfo, needle: &str| {
        info.subject.as_deref().unwrap_or_default().to_lowercase().contains(&needle.to_lowercase())
    };
    let header = |name: &str, needle: &str| {
        candidate.message.is_some_and(|message| contains(header_text(message, name), needle))
    };
    match node {
        Node::And(children) => matches(children, candidate, selected),
        Node::Or(children) => children.iter().any(|child| node_matches(child, candidate, selected)),
        Node::Not(children) => !matches(children, candidate, selected),
        Node::Leaf(filter) => match filter {
            Filter::All => true,
            Filter::Sequence(sequence, is_uid) => {
                let (value, max) = if *is_uid {
                    (entry.uid, selected.entries.last().map_or(0, |entry| entry.uid))
                } else {
                    (candidate.position as u32 + 1, selected.entries.len() as u32)
                };
                crate::selected::in_set(sequence, value, max, candidate.saved)
            }
            Filter::Answered => has("$answered"),
            Filter::Unanswered => !has("$answered"),
            Filter::Deleted => has("$deleted"),
            Filter::Undeleted => !has("$deleted"),
            Filter::Draft => has("$draft"),
            Filter::Undraft => !has("$draft"),
            Filter::Flagged => has("$flagged"),
            Filter::Unflagged => !has("$flagged"),
            Filter::Seen => has("$seen"),
            Filter::Unseen => !has("$seen"),
            Filter::Keyword(flag) => flags::keyword(flag).is_some_and(|keyword| has(keyword.as_str())),
            Filter::Unkeyword(flag) => flags::keyword(flag).is_none_or(|keyword| !has(keyword.as_str())),
            // kernoid keeps no `\Recent`.
            Filter::Recent | Filter::New => false,
            Filter::Old => true,
            Filter::Before(date) => day(received) < day(*date),
            Filter::On(date) => day(received) == day(*date),
            Filter::Since(date) => day(received) >= day(*date),
            Filter::SentBefore(date) => sent().is_some_and(|sent| day(sent) < day(*date)),
            Filter::SentOn(date) => sent().is_some_and(|sent| day(sent) == day(*date)),
            Filter::SentSince(date) => sent().is_some_and(|sent| day(sent) >= day(*date)),
            Filter::Older(seconds) => received <= Utc::now().timestamp() - i64::from(*seconds),
            Filter::Younger(seconds) => received >= Utc::now().timestamp() - i64::from(*seconds),
            Filter::Larger(size) => entry.size > u64::from(*size),
            Filter::Smaller(size) => entry.size < u64::from(*size),
            Filter::ModSeq((modseq, _)) => entry.modseq >= *modseq,
            Filter::UidAfter(uid) => entry.uid > *uid,
            Filter::UidBefore(uid) => entry.uid < *uid,
            Filter::EmailId(id) => entry.email.to_string() == *id,
            Filter::ThreadId(id) => entry.thread.to_string() == *id,
            Filter::From(needle) => {
                summary(&|info| in_addresses(&info.from, needle) || in_addresses(&info.sender, needle))
            }
            Filter::To(needle) => summary(&|info| in_addresses(&info.to, needle)),
            Filter::Cc(needle) => summary(&|info| in_addresses(&info.cc, needle)),
            Filter::Bcc(needle) => summary(&|info| in_addresses(&info.bcc, needle)),
            Filter::Subject(needle) => summary(&|info| subject(info, needle)),
            Filter::Header(name, needle) if needle.is_empty() => candidate
                .message
                .and_then(|message| message.parts.first())
                .is_some_and(|root| root.headers.iter().any(|h| h.name.as_str().eq_ignore_ascii_case(name))),
            Filter::Header(name, needle) => header(name, needle),
            Filter::Body(needle) => in_body(needle),
            Filter::Text(needle) => {
                in_body(needle)
                    || summary(&|info| {
                        subject(info, needle)
                            || [&info.from, &info.sender, &info.to, &info.cc, &info.bcc]
                                .iter()
                                .any(|list| in_addresses(list, needle))
                    })
            }
            Filter::And | Filter::Or | Filter::Not | Filter::End => true,
        },
    }
}

impl Session {
    pub(crate) async fn search(&mut self, arguments: search::Arguments, is_uid: bool) -> StatusResponse {
        let command = Command::Search(is_uid);
        let Some(selected) = self.selected.clone() else { return StatusResponse::bad("No mailbox selected") };
        let account = selected.owner;
        let nodes = tree(&mut arguments.filter.into_iter());
        let with_messages = needs_message(&nodes);
        let mail = &self.inner.mail;
        let mut words = Vec::new();
        texts(&nodes, &mut words);
        let mut in_text = HashMap::new();
        for text in words {
            if let std::collections::hash_map::Entry::Vacant(slot) = in_text.entry(text) {
                match mail.search_text(account, slot.key()).await {
                    Ok(ids) => {
                        slot.insert(ids);
                    }
                    Err(error) => return mail_error(error),
                }
            }
        }
        let infos: HashMap<Uuid, EmailInfo> = if needs_summary(&nodes) {
            let ids: Vec<Uuid> = selected.entries.iter().map(|entry| entry.email).collect();
            match mail.emails(account, &ids).await {
                Ok(infos) => infos.into_iter().map(|info| (info.id, info)).collect(),
                Err(error) => return mail_error(error),
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
                    Err(error) => return mail_error(error),
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
            if matches(&nodes, &candidate, &selected) {
                found.push(position);
            }
        }
        let ids: Vec<u32> = found
            .iter()
            .map(|&position| if is_uid { selected.entries[position].uid } else { position as u32 + 1 })
            .collect();
        let highest_modseq = if uses_modseq(&nodes) {
            found.iter().map(|&position| selected.entries[position].modseq).max()
        } else {
            None
        };
        let options = arguments.result_options;
        if options.contains(&ResultOption::Save) {
            let uids = found.iter().map(|&position| selected.entries[position].uid).collect();
            if let Some(selected) = &mut self.selected {
                selected.saved = uids;
            }
            // RFC 5182, 2.1: `SAVE` alone returns nothing.
            if options.len() == 1 {
                return StatusResponse::completed(command);
            }
        }
        let wants = |option: ResultOption| options.is_empty() || options.contains(&option);
        let response = search::Response {
            is_uid,
            is_esearch: arguments.is_esearch,
            is_sort: false,
            min: (arguments.is_esearch && options.contains(&ResultOption::Min)).then(|| ids.first().copied()).flatten(),
            max: (arguments.is_esearch && options.contains(&ResultOption::Max)).then(|| ids.last().copied()).flatten(),
            count: (arguments.is_esearch && options.contains(&ResultOption::Count)).then_some(ids.len() as u32),
            ids: if !arguments.is_esearch || wants(ResultOption::All) { ids } else { Vec::new() },
            highest_modseq,
        };
        self.write(response.serialize(&arguments.tag));
        StatusResponse::completed(command)
    }
}
