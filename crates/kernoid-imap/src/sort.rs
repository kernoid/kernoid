// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SORT` and `THREAD` (RFC 5256) and the quota of the account (`GETQUOTA`, `GETQUOTAROOT`, RFC 9208) – on the
//! selected mailbox, from the summaries in PostgreSQL. `THREAD=REFERENCES` uses kernoid's threads (RFC 0002, 5): the
//! messages of one thread, oldest first, as one chain; `ORDEREDSUBJECT` groups by base subject.

use std::{cmp::Ordering, collections::HashMap};

use kernoid_mail::{AddressInfo, EmailInfo};
use uuid::Uuid;

use crate::{
    proto::{
        Command, StatusResponse,
        protocol::{
            ImapResponse,
            capability::QuotaResourceName,
            quota::{self, QuotaItem, QuotaResource},
            search::{self, Comparator, Sort},
            thread::{self, Algorithm},
        },
    },
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

fn compare(sort: &Sort, a: &EmailInfo, b: &EmailInfo) -> Ordering {
    match sort {
        Sort::Arrival => a.received_at.cmp(&b.received_at),
        Sort::Date => a.sent_at.unwrap_or(a.received_at).cmp(&b.sent_at.unwrap_or(b.received_at)),
        Sort::Size => a.size.cmp(&b.size),
        Sort::Subject => base_subject(a.subject.as_deref().unwrap_or_default())
            .cmp(&base_subject(b.subject.as_deref().unwrap_or_default())),
        Sort::From => first_address(&a.from).cmp(&first_address(&b.from)),
        Sort::To => first_address(&a.to).cmp(&first_address(&b.to)),
        Sort::Cc => first_address(&a.cc).cmp(&first_address(&b.cc)),
        Sort::DisplayFrom => first_display(&a.from).cmp(&first_display(&b.from)),
        Sort::DisplayTo => first_display(&a.to).cmp(&first_display(&b.to)),
    }
}

/// Positions in the order of `comparators`; ties keep the mailbox's order (RFC 5256, 3).
fn sorted(positions: &mut [usize], comparators: &[Comparator], infos: &HashMap<Uuid, EmailInfo>, selected: &Selected) {
    positions.sort_by(|&a, &b| {
        let (Some(first), Some(second)) =
            (infos.get(&selected.entries[a].email), infos.get(&selected.entries[b].email))
        else {
            return a.cmp(&b);
        };
        for comparator in comparators {
            let order = compare(&comparator.sort, first, second);
            let order = if comparator.ascending { order } else { order.reverse() };
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
    ) -> Result<HashMap<Uuid, EmailInfo>, Box<StatusResponse>> {
        let ids: Vec<Uuid> = positions.iter().map(|&position| selected.entries[position].email).collect();
        match self.inner.mail.emails(selected.owner, &ids).await {
            Ok(infos) => Ok(infos.into_iter().map(|info| (info.id, info)).collect()),
            Err(error) => Err(Box::new(mail_error(error))),
        }
    }

    fn number(selected: &Selected, position: usize, is_uid: bool) -> u32 {
        if is_uid { selected.entries[position].uid } else { position as u32 + 1 }
    }

    pub(crate) async fn sort(&mut self, arguments: search::Arguments, is_uid: bool) -> StatusResponse {
        let command = Command::Sort(is_uid);
        let comparators = arguments.sort.clone().unwrap_or_default();
        let (selected, mut found, _) = match self.matching(arguments.filter).await {
            Ok(matched) => matched,
            Err(response) => return *response,
        };
        let infos = match self.summaries(&selected, &found).await {
            Ok(infos) => infos,
            Err(response) => return *response,
        };
        sorted(&mut found, &comparators, &infos, &selected);
        let response = search::Response {
            is_uid,
            is_esearch: arguments.is_esearch,
            is_sort: true,
            ids: found.iter().map(|&position| Self::number(&selected, position, is_uid)).collect(),
            min: None,
            max: None,
            count: None,
            highest_modseq: None,
        };
        self.write(response.serialize(&arguments.tag));
        StatusResponse::completed(command)
    }

    pub(crate) async fn thread(&mut self, arguments: thread::Arguments, is_uid: bool) -> StatusResponse {
        let command = Command::Thread(is_uid);
        let (selected, found, _) = match self.matching(arguments.filter).await {
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
            let key = match arguments.algorithm {
                Algorithm::References => entry.thread.to_string(),
                Algorithm::OrderedSubject => {
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
        let by_date = [Comparator { sort: Sort::Date, ascending: true }];
        for (_, members) in &mut groups {
            sorted(members, &by_date, &infos, &selected);
        }
        groups.sort_by(|(_, a), (_, b)| {
            let first = |members: &[usize]| {
                infos.get(&selected.entries[members[0]].email).map(|info| info.sent_at.unwrap_or(info.received_at))
            };
            first(a).cmp(&first(b)).then(a[0].cmp(&b[0]))
        });
        let response = thread::Response {
            is_uid,
            threads: groups
                .into_iter()
                .map(|(_, members)| {
                    members.into_iter().map(|position| Self::number(&selected, position, is_uid)).collect()
                })
                .collect(),
        };
        self.write(response.serialize());
        StatusResponse::completed(command)
    }

    /// The account's quota: one root, `""`, for all its mailboxes – STORAGE in KiB (RFC 9208). Without a quota the
    /// mailboxes have no root.
    async fn quota_item(&mut self) -> Result<Option<QuotaItem>, Box<StatusResponse>> {
        let Some(account) = self.account else {
            return Err(Box::new(StatusResponse::no("Log in first")));
        };
        let (used, quota) = self.inner.mail.quota(account).await.map_err(|error| Box::new(mail_error(error)))?;
        Ok(quota.map(|total| QuotaItem {
            name: String::new(),
            resources: vec![QuotaResource {
                resource: QuotaResourceName::Storage,
                total: total / 1024,
                used: used / 1024,
            }],
        }))
    }

    pub(crate) async fn get_quota_root(&mut self, arguments: quota::Arguments) -> StatusResponse {
        let item = match self.quota_item().await {
            Ok(item) => item,
            Err(response) => return *response,
        };
        let mut root = vec![arguments.name];
        if item.is_some() {
            root.push(String::new());
        }
        let response = quota::Response { quota_root_items: root, quota_items: item.into_iter().collect() };
        self.write(response.serialize());
        StatusResponse::completed(Command::GetQuotaRoot)
    }

    pub(crate) async fn get_quota(&mut self, arguments: quota::Arguments) -> StatusResponse {
        match self.quota_item().await {
            Ok(Some(item)) if arguments.name.is_empty() => {
                let response = quota::Response { quota_root_items: Vec::new(), quota_items: vec![item] };
                self.write(response.serialize());
                StatusResponse::completed(Command::GetQuota)
            }
            Ok(_) => StatusResponse::no("No such quota root"),
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
