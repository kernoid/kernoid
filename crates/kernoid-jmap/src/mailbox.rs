// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Mailbox/get`, `/query` and `/set` (RFC 8621, 2).

use kernoid_mail::{Access, MailError, MailboxInfo, MailboxUpdate, NewMailbox, Rights, Role};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    MAX_OBJECTS_IN_SET,
    request::{Context, MethodError, MethodResult},
};

/// A `SetError` (RFC 8620, 5.3) for what the store refused.
pub(crate) fn set_error(error: &MailError) -> Value {
    if matches!(error, MailError::Store(_) | MailError::Blob(_)) {
        return internal_error(error);
    }
    let kind = match error {
        MailError::NotFound(_) => "notFound",
        MailError::Invalid(_) | MailError::Exists(_) | MailError::Unparsable => "invalidProperties",
        MailError::MailboxHasChild => "mailboxHasChild",
        MailError::MailboxHasEmail => "mailboxHasEmail",
        MailError::OverQuota => "overQuota",
        MailError::TooLarge { .. } => "tooLarge",
        _ => "forbidden",
    };
    json!({ "type": kind, "description": error.to_string() })
}

/// A failure of the database or object storage, for a `*/set` (RFC 8620, 5.3): logged, never shown to the client.
pub(crate) fn internal_error(error: &dyn std::fmt::Display) -> Value {
    tracing::warn!(%error, "a JMAP change failed");
    json!({ "type": "forbidden", "description": "the server could not make the change" })
}

pub(crate) fn invalid_properties(description: impl Into<String>) -> Value {
    json!({ "type": "invalidProperties", "description": description.into() })
}

/// The ids a `*/get` asks for; `None` for all.
pub(crate) fn ids(args: &Map<String, Value>) -> Result<Option<Vec<String>>, MethodError> {
    match args.get("ids") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(ids)) => Ok(Some(
            ids.iter()
                .map(|id| id.as_str().map(str::to_owned).ok_or_else(|| MethodError::invalid("ids are strings")))
                .collect::<Result<_, _>>()?,
        )),
        Some(_) => Err(MethodError::invalid("ids is a list")),
    }
}

/// The properties a `*/get` asks for, or `default`.
pub(crate) fn properties(args: &Map<String, Value>, key: &str, default: &[&str]) -> Vec<String> {
    match args.get(key) {
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        _ => default.iter().map(|property| (*property).to_owned()).collect(),
    }
}

/// Checks `ifInState`.
pub(crate) fn if_in_state(args: &Map<String, Value>, state: u64) -> Result<(), MethodError> {
    match args.get("ifInState").and_then(Value::as_str) {
        Some(expected) if expected != state.to_string() => Err(MethodError::new("stateMismatch", "the state moved on")),
        _ => Ok(()),
    }
}

const PROPERTIES: [&str; 11] = [
    "id",
    "name",
    "parentId",
    "role",
    "sortOrder",
    "totalEmails",
    "unreadEmails",
    "totalThreads",
    "unreadThreads",
    "myRights",
    "isSubscribed",
];

/// `myRights` (RFC 8621, 2) from the caller's rights (RFC 0002, 12.2).
fn rights(mailbox: &MailboxInfo, access: &Access) -> Value {
    let inbox = mailbox.role == Some(Role::Inbox);
    let rights = access.mailbox(mailbox.id);
    json!({
        "mayReadItems": rights.contains(Rights::READ),
        "mayAddItems": rights.contains(Rights::INSERT),
        "mayRemoveItems": rights.contains(Rights::DELETE | Rights::EXPUNGE),
        "maySetSeen": rights.contains(Rights::SEEN),
        "maySetKeywords": rights.contains(Rights::WRITE),
        "mayCreateChild": rights.contains(Rights::CREATE),
        "mayRename": rights.contains(Rights::DELETE_MAILBOX),
        "mayDelete": !inbox && rights.contains(Rights::DELETE_MAILBOX),
        "maySubmit": access.send_as,
    })
}

/// The mailboxes of the store the caller may see.
pub(crate) fn visible(mailboxes: Vec<MailboxInfo>, access: &Access) -> Vec<MailboxInfo> {
    mailboxes.into_iter().filter(|mailbox| access.mailbox(mailbox.id).contains(Rights::LOOKUP)).collect()
}

fn forbidden(description: &str) -> Value {
    json!({ "type": "forbidden", "description": description })
}

fn object(mailbox: &MailboxInfo, access: &Access, properties: &[String]) -> Value {
    let mut out = Map::new();
    for property in properties {
        let value = match property.as_str() {
            "id" => json!(mailbox.id.to_string()),
            "name" => json!(mailbox.name),
            "parentId" => json!(mailbox.parent_id.map(|id| id.to_string())),
            "role" => json!(mailbox.role.map(Role::as_str)),
            "sortOrder" => json!(mailbox.sort_order),
            "totalEmails" => json!(mailbox.total_emails),
            "unreadEmails" => json!(mailbox.unread_emails),
            "totalThreads" => json!(mailbox.total_threads),
            "unreadThreads" => json!(mailbox.unread_threads),
            "myRights" => rights(mailbox, access),
            "isSubscribed" => json!(mailbox.is_subscribed),
            _ => continue,
        };
        out.insert(property.clone(), value);
    }
    out.insert("id".into(), json!(mailbox.id.to_string()));
    Value::Object(out)
}

fn role(value: &Value) -> Result<Option<Role>, String> {
    match value {
        Value::Null => Ok(None),
        Value::String(role) => Role::parse(role).map(Some).ok_or_else(|| format!("kernoid has no role {role:?}")),
        _ => Err("role is a string or null".into()),
    }
}

impl Context<'_> {
    pub async fn mailbox_get(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let wanted = ids(&args)?;
        let properties = properties(&args, "properties", &PROPERTIES);
        let mailboxes = visible(self.jmap.mail().mailboxes(account).await?, &access);
        let state = self.jmap.mail().state(account).await?;
        let (list, not_found): (Vec<Value>, Vec<String>) = match wanted {
            None => (mailboxes.iter().map(|mailbox| object(mailbox, &access, &properties)).collect(), Vec::new()),
            Some(ids) => {
                let mut list = Vec::new();
                let mut not_found = Vec::new();
                for id in ids {
                    match self.id(&id).and_then(|id| mailboxes.iter().find(|mailbox| mailbox.id == id)) {
                        Some(mailbox) => list.push(object(mailbox, &access, &properties)),
                        None => not_found.push(id),
                    }
                }
                (list, not_found)
            }
        };
        Ok(vec![(
            "Mailbox/get".into(),
            json!({ "accountId": account.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    pub async fn mailbox_query(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let mut mailboxes = visible(self.jmap.mail().mailboxes(account).await?, &access);
        if let Some(Value::Object(filter)) = args.get("filter") {
            for (key, value) in filter {
                match key.as_str() {
                    "parentId" => {
                        let parent = value.as_str().and_then(|id| self.id(id));
                        mailboxes.retain(|mailbox| mailbox.parent_id == parent);
                    }
                    "name" => {
                        let name = value.as_str().unwrap_or_default().to_lowercase();
                        mailboxes.retain(|mailbox| mailbox.name.to_lowercase().contains(&name));
                    }
                    "role" => {
                        let wanted = role(value).map_err(MethodError::invalid)?;
                        mailboxes.retain(|mailbox| mailbox.role == wanted);
                    }
                    "hasAnyRole" => {
                        let wanted = value.as_bool().unwrap_or(true);
                        mailboxes.retain(|mailbox| mailbox.role.is_some() == wanted);
                    }
                    "isSubscribed" => {
                        let wanted = value.as_bool().unwrap_or(true);
                        mailboxes.retain(|mailbox| mailbox.is_subscribed == wanted);
                    }
                    other => return Err(MethodError::new("unsupportedFilter", format!("no filter {other}"))),
                }
            }
        }
        if let Some(Value::Array(sort)) = args.get("sort") {
            for comparator in sort.iter().rev() {
                let ascending = comparator.get("isAscending").and_then(Value::as_bool).unwrap_or(true);
                match comparator.get("property").and_then(Value::as_str) {
                    Some("name") => mailboxes.sort_by_key(|mailbox| mailbox.name.to_lowercase()),
                    Some("sortOrder") => mailboxes.sort_by_key(|mailbox| mailbox.sort_order),
                    other => return Err(MethodError::new("unsupportedSort", format!("cannot sort by {other:?}"))),
                }
                if !ascending {
                    mailboxes.reverse();
                }
            }
        }
        let total = mailboxes.len();
        let position = args.get("position").and_then(Value::as_i64).unwrap_or(0);
        let start =
            if position < 0 { total.saturating_sub(position.unsigned_abs() as usize) } else { position as usize };
        let limit = args.get("limit").and_then(Value::as_u64).map_or(usize::MAX, |limit| limit as usize);
        let ids: Vec<String> = mailboxes.iter().skip(start).take(limit).map(|mailbox| mailbox.id.to_string()).collect();
        let state = self.jmap.mail().state(account).await?;
        let mut response = json!({
            "accountId": account.to_string(),
            "queryState": state.to_string(),
            "canCalculateChanges": false,
            "position": start.min(total),
            "ids": ids,
        });
        if args.get("calculateTotal").and_then(Value::as_bool).unwrap_or(false) {
            response["total"] = json!(total);
        }
        Ok(vec![("Mailbox/query".into(), response)])
    }

    pub async fn mailbox_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let mail = self.jmap.mail().clone();
        let old_state = mail.state(account).await?;
        if_in_state(&args, old_state)?;
        let count = ["create", "update"]
            .iter()
            .filter_map(|key| args.get(*key).and_then(Value::as_object).map(Map::len))
            .sum::<usize>()
            + args.get("destroy").and_then(Value::as_array).map_or(0, Vec::len);
        if count > MAX_OBJECTS_IN_SET {
            return Err(MethodError::new("requestTooLarge", "too many objects"));
        }
        let (mut created, mut not_created) = (Map::new(), Map::new());
        if let Some(Value::Object(create)) = args.get("create") {
            // Parents first: a create may name another one of this request as its parent (`#creation`), and JSON
            // objects keep no order.
            let mut pending: Vec<(&String, &Value)> = create.iter().collect();
            let mut ordered = Vec::with_capacity(pending.len());
            let mut known: std::collections::HashSet<&str> = std::collections::HashSet::new();
            while !pending.is_empty() {
                let before = pending.len();
                pending.retain(|(creation, value)| {
                    let parent = value.get("parentId").and_then(Value::as_str).and_then(|id| id.strip_prefix('#'));
                    match parent {
                        Some(parent) if create.contains_key(parent) && !known.contains(parent) => true,
                        _ => {
                            known.insert(creation.as_str());
                            ordered.push((*creation, *value));
                            false
                        }
                    }
                });
                if pending.len() == before {
                    // A cycle: what is left fails on its unknown parent.
                    ordered.append(&mut pending);
                }
            }
            for (creation, value) in ordered {
                let new = match self.new_mailbox(value) {
                    Ok(new) => new,
                    Err(error) => {
                        not_created.insert(creation.clone(), invalid_properties(error));
                        continue;
                    }
                };
                let may = match new.parent_id {
                    Some(parent) => access.mailbox(parent).contains(Rights::CREATE),
                    None => access.store.contains(Rights::CREATE),
                };
                if !may || (!access.owned && new.role.is_some()) {
                    not_created.insert(creation.clone(), forbidden("no right to create this mailbox"));
                    continue;
                }
                match mail.create_mailbox(account, new).await {
                    Ok(id) => {
                        self.created.insert(creation.clone(), id.to_string());
                        created.insert(
                            creation.clone(),
                            json!({ "id": id.to_string(), "totalEmails": 0, "unreadEmails": 0, "totalThreads": 0, "unreadThreads": 0, "isSubscribed": value.get("isSubscribed").and_then(Value::as_bool).unwrap_or(false) }),
                        );
                    }
                    Err(error) => {
                        not_created.insert(creation.clone(), set_error(&error));
                    }
                }
            }
        }
        let (mut updated, mut not_updated) = (Map::new(), Map::new());
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, patch) in update {
                let Some(mailbox) = self.id(id) else {
                    not_updated.insert(id.clone(), json!({ "type": "notFound" }));
                    continue;
                };
                let change = match self.mailbox_update(patch) {
                    Ok(change) => change,
                    Err(error) => {
                        not_updated.insert(id.clone(), invalid_properties(error));
                        continue;
                    }
                };
                // Others change a mailbox only with `x`, move it only where they may create, and leave roles and
                // subscriptions to the owner.
                let may = access.owned
                    || (access.mailbox(mailbox).contains(Rights::DELETE_MAILBOX)
                        && change.role.is_none()
                        && change.is_subscribed.is_none()
                        && match change.parent_id {
                            Some(Some(parent)) => access.mailbox(parent).contains(Rights::CREATE),
                            Some(None) => access.store.contains(Rights::CREATE),
                            None => true,
                        });
                if !may {
                    not_updated.insert(id.clone(), forbidden("no right to change this mailbox"));
                    continue;
                }
                match mail.update_mailbox(account, mailbox, change).await {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), set_error(&error));
                    }
                }
            }
        }
        let remove_emails = args.get("onDestroyRemoveEmails").and_then(Value::as_bool).unwrap_or(false);
        let (mut destroyed, mut not_destroyed) = (Vec::new(), Map::new());
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy.iter().filter_map(Value::as_str) {
                let result = match self.id(id) {
                    Some(mailbox) if !access.mailbox(mailbox).contains(Rights::DELETE_MAILBOX) => {
                        not_destroyed.insert(id.to_owned(), forbidden("no right to delete this mailbox"));
                        continue;
                    }
                    Some(mailbox) => mail.destroy_mailbox(account, mailbox, remove_emails).await,
                    None => Err(MailError::NotFound("the mailbox")),
                };
                match result {
                    Ok(()) => destroyed.push(json!(id)),
                    Err(error) => {
                        not_destroyed.insert(id.to_owned(), set_error(&error));
                    }
                }
            }
        }
        let new_state = mail.state(account).await?;
        Ok(vec![(
            "Mailbox/set".into(),
            json!({
                "accountId": account.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": created, "updated": updated, "destroyed": destroyed,
                "notCreated": not_created, "notUpdated": not_updated, "notDestroyed": not_destroyed,
            }),
        )])
    }

    fn new_mailbox(&self, value: &Value) -> Result<NewMailbox, String> {
        let name = value.get("name").and_then(Value::as_str).ok_or("name is required")?.to_owned();
        let parent_id = match value.get("parentId") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) => Some(self.id(id).ok_or("no such parent")?),
            Some(_) => return Err("parentId is a string or null".into()),
        };
        Ok(NewMailbox {
            parent_id,
            name,
            role: role(value.get("role").unwrap_or(&Value::Null))?,
            sort_order: value.get("sortOrder").and_then(Value::as_u64).unwrap_or(0) as u32,
            is_subscribed: value.get("isSubscribed").and_then(Value::as_bool).unwrap_or(false),
        })
    }

    fn mailbox_update(&self, patch: &Value) -> Result<MailboxUpdate, String> {
        let patch = patch.as_object().ok_or("a patch is an object")?;
        let mut update = MailboxUpdate::default();
        for (key, value) in patch {
            match key.as_str() {
                "name" => update.name = Some(value.as_str().ok_or("name is a string")?.to_owned()),
                "parentId" => {
                    update.parent_id = Some(match value.as_str() {
                        Some(id) => Some(self.id(id).ok_or("no such parent")?),
                        None => None,
                    })
                }
                "role" => update.role = Some(role(value)?),
                "sortOrder" => update.sort_order = Some(value.as_u64().ok_or("sortOrder is a number")? as u32),
                "isSubscribed" => update.is_subscribed = Some(value.as_bool().ok_or("isSubscribed is true or false")?),
                other => return Err(format!("{other} cannot be changed")),
            }
        }
        Ok(update)
    }
}

/// The id of a mailbox, as JMAP writes it.
pub(crate) fn mailbox_ids(ids: &[(Uuid, u32)]) -> Value {
    Value::Object(ids.iter().map(|(id, _)| (id.to_string(), Value::Bool(true))).collect())
}
