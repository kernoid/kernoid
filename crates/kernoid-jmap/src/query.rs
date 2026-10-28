// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Email/query` (RFC 8621, 4.4): filters and sorts over what PostgreSQL holds of the account's emails, in kernoid;
//! `body` and `text` use the full-text index (RFC 0002, 13.1). `header` is refused as unsupported.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use chrono::{DateTime, Utc};
use kernoid_mail::{AddressInfo, EmailInfo};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::request::{Context, MethodError, MethodResult};

pub(crate) const SORT_PROPERTIES: [&str; 9] = [
    "receivedAt",
    "sentAt",
    "size",
    "from",
    "to",
    "subject",
    "hasKeyword",
    "allInThreadHaveKeyword",
    "someInThreadHaveKeyword",
];

/// The keywords of each thread's emails, for the thread conditions.
type Threads = HashMap<Uuid, Vec<Vec<String>>>;

/// The emails whose text has the words of each `body` and `text` condition, looked up before the filter runs.
type Found = HashMap<String, HashSet<Uuid>>;

/// The values of the `body` and `text` conditions of a filter.
fn text_conditions(filter: &Value, out: &mut Vec<String>) {
    if let Some(conditions) = filter.get("conditions").and_then(Value::as_array) {
        for condition in conditions {
            text_conditions(condition, out);
        }
    }
    for key in ["body", "text"] {
        if let Some(value) = filter.get(key).and_then(Value::as_str) {
            out.push(value.to_owned());
        }
    }
}

fn date(value: &Value) -> Result<DateTime<Utc>, MethodError> {
    value
        .as_str()
        .and_then(|date| DateTime::parse_from_rfc3339(date).ok())
        .map(|date| date.with_timezone(&Utc))
        .ok_or_else(|| MethodError::invalid("a date is UTCDate"))
}

fn contains(list: &[AddressInfo], needle: &str) -> bool {
    list.iter().any(|address| {
        address.email.to_lowercase().contains(needle)
            || address.name.as_deref().is_some_and(|name| name.to_lowercase().contains(needle))
    })
}

fn keyword(value: &Value) -> Result<String, MethodError> {
    value.as_str().map(str::to_lowercase).ok_or_else(|| MethodError::invalid("a keyword is a string"))
}

impl Context<'_> {
    fn matches(
        &self,
        email: &EmailInfo,
        filter: &Value,
        threads: &Threads,
        found: &Found,
    ) -> Result<bool, MethodError> {
        let filter = filter.as_object().ok_or_else(|| MethodError::invalid("a filter is an object"))?;
        if let Some(operator) = filter.get("operator") {
            let conditions = filter
                .get("conditions")
                .and_then(Value::as_array)
                .ok_or_else(|| MethodError::invalid("an operator needs conditions"))?;
            let mut results = Vec::with_capacity(conditions.len());
            for condition in conditions {
                results.push(self.matches(email, condition, threads, found)?);
            }
            return match operator.as_str() {
                Some("AND") => Ok(results.iter().all(|result| *result)),
                Some("OR") => Ok(results.iter().any(|result| *result)),
                Some("NOT") => Ok(!results.iter().any(|result| *result)),
                _ => Err(MethodError::invalid("operator is AND, OR or NOT")),
            };
        }
        let thread = threads.get(&email.thread_id).map(Vec::as_slice).unwrap_or_default();
        for (key, value) in filter {
            let text = || value.as_str().map(str::to_lowercase).unwrap_or_default();
            let in_body =
                || value.as_str().and_then(|value| found.get(value)).is_some_and(|ids| ids.contains(&email.id));
            let matched = match key.as_str() {
                "inMailbox" => {
                    let mailbox = value.as_str().and_then(|id| self.id(id));
                    email.mailboxes.iter().any(|(id, _)| Some(*id) == mailbox)
                }
                "inMailboxOtherThan" => {
                    let excluded: Vec<Uuid> = value
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|id| id.as_str().and_then(|id| self.id(id)))
                        .collect();
                    email.mailboxes.iter().any(|(id, _)| !excluded.contains(id))
                }
                "before" => email.received_at < date(value)?,
                "after" => email.received_at >= date(value)?,
                "minSize" => email.size >= value.as_u64().unwrap_or(0),
                "maxSize" => email.size < value.as_u64().unwrap_or(u64::MAX),
                "hasKeyword" => email.keywords.contains(&keyword(value)?),
                "notKeyword" => !email.keywords.contains(&keyword(value)?),
                "allInThreadHaveKeyword" => {
                    let keyword = keyword(value)?;
                    thread.iter().all(|keywords| keywords.contains(&keyword))
                }
                "someInThreadHaveKeyword" => {
                    let keyword = keyword(value)?;
                    thread.iter().any(|keywords| keywords.contains(&keyword))
                }
                "noneInThreadHaveKeyword" => {
                    let keyword = keyword(value)?;
                    !thread.iter().any(|keywords| keywords.contains(&keyword))
                }
                "hasAttachment" => email.has_attachment == value.as_bool().unwrap_or(true),
                "from" => contains(&email.from, &text()),
                "to" => contains(&email.to, &text()),
                "cc" => contains(&email.cc, &text()),
                "bcc" => contains(&email.bcc, &text()),
                "subject" => email.subject.as_deref().unwrap_or_default().to_lowercase().contains(&text()),
                "text" => {
                    let needle = text();
                    [&email.from, &email.to, &email.cc, &email.bcc].iter().any(|list| contains(list, &needle))
                        || email.subject.as_deref().unwrap_or_default().to_lowercase().contains(&needle)
                        || in_body()
                }
                "body" => in_body(),
                "header" => {
                    return Err(MethodError::new("unsupportedFilter", "kernoid does not filter by any header yet"));
                }
                other => return Err(MethodError::new("unsupportedFilter", format!("no filter {other}"))),
            };
            if !matched {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub async fn email_query(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let mail = self.jmap.mail();
        let mut all = mail.emails(account, &mail.email_ids(account).await?).await?;
        if !access.owned {
            all.retain(|email| crate::blob::readable(email, &access));
        }
        let mut threads: Threads = HashMap::new();
        for email in &all {
            threads.entry(email.thread_id).or_default().push(email.keywords.clone());
        }
        let mut found = Found::new();
        if let Some(filter) = args.get("filter") {
            let mut texts = Vec::new();
            text_conditions(filter, &mut texts);
            for text in texts {
                if let std::collections::hash_map::Entry::Vacant(slot) = found.entry(text) {
                    let ids = mail.search_text(account, slot.key()).await?;
                    slot.insert(ids);
                }
            }
        }
        let mut emails = Vec::with_capacity(all.len());
        for email in &all {
            if match args.get("filter") {
                None | Some(Value::Null) => true,
                Some(filter) => self.matches(email, filter, &threads, &found)?,
            } {
                emails.push(email);
            }
        }

        let comparators: Vec<(String, bool, Option<String>)> = match args.get("sort") {
            Some(Value::Array(sort)) => sort
                .iter()
                .map(|comparator| {
                    let property = comparator.get("property").and_then(Value::as_str).unwrap_or_default().to_owned();
                    if !SORT_PROPERTIES.contains(&property.as_str()) {
                        return Err(MethodError::new("unsupportedSort", format!("cannot sort by {property}")));
                    }
                    let ascending = comparator.get("isAscending").and_then(Value::as_bool).unwrap_or(true);
                    let keyword = comparator.get("keyword").and_then(Value::as_str).map(str::to_lowercase);
                    Ok((property, ascending, keyword))
                })
                .collect::<Result<_, _>>()?,
            _ => vec![("receivedAt".into(), false, None)],
        };
        let first = |list: &[AddressInfo]| {
            list.first().map(|address| address.name.clone().unwrap_or_else(|| address.email.clone()).to_lowercase())
        };
        emails.sort_by(|a, b| {
            for (property, ascending, keyword) in &comparators {
                let has = |email: &EmailInfo, scope: &str| {
                    let keyword = keyword.clone().unwrap_or_default();
                    let thread = threads.get(&email.thread_id).map(Vec::as_slice).unwrap_or_default();
                    match scope {
                        "all" => thread.iter().all(|keywords| keywords.contains(&keyword)),
                        "some" => thread.iter().any(|keywords| keywords.contains(&keyword)),
                        _ => email.keywords.contains(&keyword),
                    }
                };
                let order = match property.as_str() {
                    "receivedAt" => a.received_at.cmp(&b.received_at),
                    "sentAt" => a.sent_at.cmp(&b.sent_at),
                    "size" => a.size.cmp(&b.size),
                    "from" => first(&a.from).cmp(&first(&b.from)),
                    "to" => first(&a.to).cmp(&first(&b.to)),
                    "subject" => {
                        a.subject.as_deref().map(str::to_lowercase).cmp(&b.subject.as_deref().map(str::to_lowercase))
                    }
                    "hasKeyword" => has(a, "one").cmp(&has(b, "one")),
                    "allInThreadHaveKeyword" => has(a, "all").cmp(&has(b, "all")),
                    "someInThreadHaveKeyword" => has(a, "some").cmp(&has(b, "some")),
                    _ => Ordering::Equal,
                };
                let order = if *ascending { order } else { order.reverse() };
                if order != Ordering::Equal {
                    return order;
                }
            }
            b.id.cmp(&a.id)
        });
        if args.get("collapseThreads").and_then(Value::as_bool).unwrap_or(false) {
            let mut seen = std::collections::HashSet::new();
            emails.retain(|email| seen.insert(email.thread_id));
        }

        let total = emails.len();
        let start = match args.get("anchor").and_then(Value::as_str) {
            Some(anchor) => {
                let anchor = self.id(anchor);
                let index = emails
                    .iter()
                    .position(|email| Some(email.id) == anchor)
                    .ok_or_else(|| MethodError::new("anchorNotFound", "the anchor is not in the results"))?;
                let offset = args.get("anchorOffset").and_then(Value::as_i64).unwrap_or(0);
                (index as i64 + offset).clamp(0, total as i64) as usize
            }
            None => {
                let position = args.get("position").and_then(Value::as_i64).unwrap_or(0);
                if position < 0 {
                    total.saturating_sub(position.unsigned_abs() as usize)
                } else {
                    (position as usize).min(total)
                }
            }
        };
        let limit = args.get("limit").and_then(Value::as_u64).map_or(usize::MAX, |limit| limit as usize);
        let ids: Vec<String> = emails.iter().skip(start).take(limit).map(|email| email.id.to_string()).collect();
        let state = mail.state(account).await?;
        let mut response = json!({
            "accountId": account.to_string(),
            "queryState": state.to_string(),
            "canCalculateChanges": false,
            "position": start,
            "ids": ids,
        });
        if args.get("calculateTotal").and_then(Value::as_bool).unwrap_or(false) {
            response["total"] = json!(total);
        }
        Ok(vec![("Email/query".into(), response)])
    }
}
