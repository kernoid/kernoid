// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SORT` and `THREAD` (RFC 5256) and the quota of the account (`GETQUOTA`, `GETQUOTAROOT`, RFC 9208) – on the
//! selected mailbox, from the summaries in PostgreSQL. `THREAD=REFERENCES` uses kernoid's threads (RFC 0002, 5): the
//! messages of one thread, oldest first, as one chain; `ORDEREDSUBJECT` groups by base subject.

use std::{cmp::Ordering, collections::HashMap};

use kernoid_mail::{AddressInfo, EmailInfo};
use uuid::Uuid;

use crate::{
    proto::{
        request::{Search, SortCriterion, SortKey, ThreadAlgorithm},
        response::{self, Status},
        sequence,
    },
    search::esearch,
    selected::Selected,
    session::{Session, mail_error},
};

/// The subject without `Re:`, `Fwd:`, `[list]` prefixes and `(fwd)` suffixes, in lower case (RFC 5256, 2.1).
pub(crate) fn base_subject(subject: &str) -> String {
    let mut subject = subject.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    loop {
        let before = subject.clone();
        while let Some(rest) = subject.strip_suffix("(fwd)") {
            subject = rest.trim_end().to_owned();
        }
        loop {
            let trimmed = subject.trim_start();
            let rest = if let Some(rest) = trimmed.strip_prefix('[').and_then(|r| r.split_once(']')).map(|(_, r)| r) {
                // A blob only counts if something follows it.
                if rest.trim().is_empty() { break } else { rest }
            } else if let Some(rest) = ["re", "fwd", "fw"].iter().find_map(|word| {
                trimmed.strip_prefix(word).and_then(|r| {
                    let r = r.trim_start();
                    let r = if r.starts_with('[') { r.split_once(']').map_or(r, |(_, r)| r) } else { r };
                    r.strip_prefix(':')
                })
            }) {
                rest
            } else {
                break;
            };
            subject = rest.trim_start().to_owned();
        }
        if let Some(inner) = subject.strip_prefix("[fwd:").and_then(|r| r.strip_suffix(']')) {
            subject = inner.trim().to_owned();
        }
        if subject == before {
            return subject;
        }
    }
}

fn first_address(list: &[AddressInfo]) -> String {
    list.first().map(|address| address.email.split('@').next().unwrap_or_default().to_lowercase()).unwrap_or_default()
}

fn first_display(list: &[AddressInfo]) -> String {
    list.first()
        .map(|address| {
            address.name.clone().filter(|name| !name.trim().is_empty()).unwrap_or_else(|| address.email.clone())
        })
        .unwrap_or_default()
        .to_lowercase()
}

fn compare(sort: SortKey, a: &EmailInfo, b: &EmailInfo) -> Ordering {
    match sort {
        SortKey::Arrival => a.received_at.cmp(&b.received_at),
        SortKey::Date => a.sent_at.unwrap_or(a.received_at).cmp(&b.sent_at.unwrap_or(b.received_at)),
        SortKey::Size => a.size.cmp(&b.size),
        SortKey::Subject => base_subject(a.subject.as_deref().unwrap_or_default())
            .cmp(&base_subject(b.subject.as_deref().unwrap_or_default())),
        SortKey::From => first_address(&a.from).cmp(&first_address(&b.from)),
        SortKey::To => first_address(&a.to).cmp(&first_address(&b.to)),
        SortKey::Cc => first_address(&a.cc).cmp(&first_address(&b.cc)),
        SortKey::DisplayFrom => first_display(&a.from).cmp(&first_display(&b.from)),
        SortKey::DisplayTo => first_display(&a.to).cmp(&first_display(&b.to)),
    }
}

/// Positions in the order of `comparators`; ties keep the mailbox's order (RFC 5256, 3).
fn sorted(
    positions: &mut [usize],
    comparators: &[SortCriterion],
    infos: &HashMap<Uuid, EmailInfo>,
    selected: &Selected,
) {
    positions.sort_by(|&a, &b| {
        let (Some(first), Some(second)) =
            (infos.get(&selected.entries[a].email), infos.get(&selected.entries[b].email))
        else {
            return a.cmp(&b);
        };
        for comparator in comparators {
            let order = compare(comparator.key, first, second);
            let order = if comparator.reverse { order.reverse() } else { order };
            if order != Ordering::Equal {
                return order;
            }
        }
        a.cmp(&b)
    });
}

impl Session {
    async fn summaries(
        &mut self,
        selected: &Selected,
        positions: &[usize],
    ) -> Result<HashMap<Uuid, EmailInfo>, Box<Status>> {
        let ids: Vec<Uuid> = positions.iter().map(|&position| selected.entries[position].email).collect();
        match self.inner.mail.emails(selected.owner, &ids).await {
            Ok(infos) => Ok(infos.into_iter().map(|info| (info.id, info)).collect()),
            Err(error) => Err(Box::new(mail_error(error))),
        }
    }

    fn number(selected: &Selected, position: usize, is_uid: bool) -> u32 {
        if is_uid { selected.entries[position].uid } else { position as u32 + 1 }
    }

    pub(crate) async fn sort(&mut self, criteria: &[SortCriterion], search: Search, is_uid: bool) -> Status {
        let (selected, mut found, _) = match self.matching(&search.key).await {
            Ok(matched) => matched,
            Err(response) => return *response,
        };
        let infos = match self.summaries(&selected, &found).await {
            Ok(infos) => infos,
            Err(response) => return *response,
        };
        sorted(&mut found, criteria, &infos, &selected);
        let ids: Vec<u32> = found.iter().map(|&position| Self::number(&selected, position, is_uid)).collect();
        let line = if search.options.is_some() {
            // ESORT's result (RFC 5267): the numbers in their order.
            let tag = self.tag.clone();
            esearch(&tag, is_uid, |line| {
                if !ids.is_empty() {
                    line.push_str(&format!(" ALL {}", sequence::ordered(&ids)));
                }
            })
        } else {
            let mut line = String::from("* SORT");
            for id in &ids {
                line.push_str(&format!(" {id}"));
            }
            line + "\r\n"
        };
        self.write(line);
        Status::done()
    }

    pub(crate) async fn thread(&mut self, algorithm: ThreadAlgorithm, search: Search, is_uid: bool) -> Status {
        let (selected, found, _) = match self.matching(&search.key).await {
            Ok(matched) => matched,
            Err(response) => return *response,
        };
        let infos = match self.summaries(&selected, &found).await {
            Ok(infos) => infos,
            Err(response) => return *response,
        };
        // Messages grouped – by kernoid's thread, or by base subject –, each group oldest first, the groups by their
        // first message.
        let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for &position in &found {
            let entry = &selected.entries[position];
            let key = match algorithm {
                ThreadAlgorithm::References => entry.thread.to_string(),
                ThreadAlgorithm::OrderedSubject => {
                    base_subject(infos.get(&entry.email).and_then(|info| info.subject.as_deref()).unwrap_or_default())
                }
            };
            match index.get(&key) {
                Some(&group) => groups[group].1.push(position),
                None => {
                    index.insert(key.clone(), groups.len());
                    groups.push((key, vec![position]));
                }
            }
        }
        let by_date = [SortCriterion { key: SortKey::Date, reverse: false }];
        for (_, members) in &mut groups {
            sorted(members, &by_date, &infos, &selected);
        }
        groups.sort_by(|(_, a), (_, b)| {
            let first = |members: &[usize]| {
                infos.get(&selected.entries[members[0]].email).map(|info| info.sent_at.unwrap_or(info.received_at))
            };
            first(a).cmp(&first(b)).then(a[0].cmp(&b[0]))
        });
        let mut line = String::from("* THREAD ");
        for (_, members) in groups {
            let numbers: Vec<String> =
                members.into_iter().map(|position| Self::number(&selected, position, is_uid).to_string()).collect();
            line.push_str(&format!("({})", numbers.join(" ")));
        }
        line.truncate(line.trim_end().len());
        line.push_str("\r\n");
        self.write(line);
        Status::done()
    }

    /// The account's quota: one root, `""`, for all its mailboxes – `(STORAGE used total)` in KiB (RFC 9208); `None`
    /// without a quota, when the mailboxes have no root.
    async fn quota_resources(&mut self) -> Result<Option<String>, Box<Status>> {
        let account = self.account();
        let (used, quota) = self.inner.mail.quota(account).await.map_err(|error| Box::new(mail_error(error)))?;
        Ok(quota.map(|total| format!("(STORAGE {} {})", used / 1024, total / 1024)))
    }

    pub(crate) async fn get_quota_root(&mut self, mailbox: &str) -> Status {
        let resources = match self.quota_resources().await {
            Ok(resources) => resources,
            Err(response) => return *response,
        };
        let mut out = b"* QUOTAROOT ".to_vec();
        response::mailbox(&mut out, mailbox, self.utf8);
        if let Some(resources) = &resources {
            out.extend_from_slice(format!(" \"\"\r\n* QUOTA \"\" {resources}").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        self.write(out);
        Status::done()
    }

    pub(crate) async fn get_quota(&mut self, root: &str) -> Status {
        match self.quota_resources().await {
            Ok(Some(resources)) if root.is_empty() => {
                self.write(format!("* QUOTA \"\" {resources}\r\n"));
                Status::done()
            }
            Ok(_) => Status::no("No such quota root"),
            Err(response) => *response,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::base_subject;

    #[test]
    fn base_subjects_drop_replies_and_forwards() {
        assert_eq!(base_subject("Re: Lunch"), "lunch");
        assert_eq!(base_subject("RE: Fwd: [team] Re:  Lunch   plans (fwd)"), "lunch plans");
        assert_eq!(base_subject("[Fwd: Lunch]"), "lunch");
        assert_eq!(base_subject("Re[2]: Lunch"), "lunch");
        assert_eq!(base_subject("[only a blob]"), "[only a blob]");
        assert_eq!(base_subject(""), "");
    }
}
