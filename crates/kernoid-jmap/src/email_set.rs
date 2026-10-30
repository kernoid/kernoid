// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Email/set` and `Email/import` (RFC 8621, 4.6 and 4.8): new emails – built with mail-builder from JSON, or
//! imported from a blob – keywords and mailboxes changed, emails destroyed.

use std::collections::BTreeSet;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use kernoid_mail::{Access, EmailInfo, Keyword, MailError, NewEmail, Rights};
use mail_builder::{
    MessageBuilder,
    headers::{address::Address, date::Date},
    mime::MimePart,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    MAX_OBJECTS_IN_SET,
    blob::BlobId,
    mailbox::{if_in_state, invalid_properties, set_error},
    request::{Context, MethodError, MethodResult},
};

fn keyword_list(value: &Value) -> Result<Vec<Keyword>, String> {
    let map = value.as_object().ok_or("keywords is an object")?;
    map.iter()
        .filter(|(_, set)| set.as_bool() == Some(true))
        .map(|(keyword, _)| Keyword::parse(keyword).map_err(|error| error.to_string()))
        .collect()
}

fn received_at(value: Option<&Value>) -> Result<Option<DateTime<Utc>>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(date)) => DateTime::parse_from_rfc3339(date)
            .map(|date| Some(date.with_timezone(&Utc)))
            .map_err(|_| "receivedAt is a UTCDate".into()),
        Some(_) => Err("receivedAt is a UTCDate".into()),
    }
}

fn addresses(value: Option<&Value>) -> Result<Option<Address<'static>>, String> {
    let Some(Value::Array(list)) = value else { return Ok(None) };
    let mut out = Vec::new();
    for entry in list {
        let email = entry.get("email").and_then(Value::as_str).ok_or("an address needs email")?.to_owned();
        let name = entry.get("name").and_then(Value::as_str).map(str::to_owned);
        out.push(Address::new_address(name, email));
    }
    Ok(if out.is_empty() { None } else { Some(Address::new_list(out)) })
}

impl Context<'_> {
    fn mailbox_set_of(&self, value: Option<&Value>) -> Result<Vec<Uuid>, String> {
        let map = value.and_then(Value::as_object).ok_or("mailboxIds is required")?;
        map.iter()
            .filter(|(_, set)| set.as_bool() == Some(true))
            .map(|(id, _)| self.id(id).ok_or_else(|| format!("no mailbox {id}")))
            .collect()
    }

    /// The raw message for an `Email/set` create (RFC 8621, 4.6).
    async fn build(&self, access: &Access, object: &Map<String, Value>) -> Result<Vec<u8>, String> {
        let mut builder = MessageBuilder::new();
        if let Some(from) = addresses(object.get("from"))? {
            builder = builder.from(from);
        }
        if let Some(to) = addresses(object.get("to"))? {
            builder = builder.to(to);
        }
        if let Some(cc) = addresses(object.get("cc"))? {
            builder = builder.cc(cc);
        }
        if let Some(bcc) = addresses(object.get("bcc"))? {
            builder = builder.bcc(bcc);
        }
        if let Some(reply_to) = addresses(object.get("replyTo"))? {
            builder = builder.reply_to(reply_to);
        }
        if let Some(sender) = addresses(object.get("sender"))? {
            builder = builder.sender(sender);
        }
        if let Some(subject) = object.get("subject").and_then(Value::as_str) {
            builder = builder.subject(subject.to_owned());
        }
        let sent = match object.get("sentAt").and_then(Value::as_str) {
            Some(date) => DateTime::parse_from_rfc3339(date).map_err(|_| "sentAt is a date")?.timestamp(),
            None => Utc::now().timestamp(),
        };
        builder = builder.date(Date::new(sent));
        let ids = |key: &str| -> Vec<String> {
            object
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        };
        match ids("messageId").first() {
            Some(id) => builder = builder.message_id(id.clone()),
            None => builder = builder.message_id(format!("{}@kernoid", Uuid::now_v7())),
        }
        if let Some(id) = ids("inReplyTo").first() {
            builder = builder.in_reply_to(id.clone());
        }
        let references = ids("references");
        if !references.is_empty() {
            builder = builder.references(references);
        }
        let values = object.get("bodyValues").and_then(Value::as_object);
        let value_of = |part: &Value| -> Result<String, String> {
            let id = part.get("partId").and_then(Value::as_str).ok_or("a body part needs partId")?;
            values
                .and_then(|values| values.get(id))
                .and_then(|value| value.get("value"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("no bodyValue {id}"))
        };
        if let Some(part) = object.get("textBody").and_then(Value::as_array).and_then(|list| list.first()) {
            builder = builder.text_body(value_of(part)?);
        }
        if let Some(part) = object.get("htmlBody").and_then(Value::as_array).and_then(|list| list.first()) {
            builder = builder.html_body(value_of(part)?);
        }
        for attachment in object.get("attachments").and_then(Value::as_array).into_iter().flatten() {
            let blob = attachment.get("blobId").and_then(Value::as_str).ok_or("an attachment needs blobId")?;
            let content = self.jmap.blob_bytes(access, blob).await.ok_or_else(|| format!("no blob {blob}"))?;
            let kind = attachment.get("type").and_then(Value::as_str).unwrap_or("application/octet-stream").to_owned();
            let name = attachment.get("name").and_then(Value::as_str).unwrap_or("attachment").to_owned();
            match attachment.get("cid").and_then(Value::as_str) {
                Some(cid) if attachment.get("disposition").and_then(Value::as_str) == Some("inline") => {
                    builder = builder.inline(kind, cid.to_owned(), content.to_vec());
                }
                _ => builder = builder.attachment(kind, name, content.to_vec()),
            }
        }
        if object.get("textBody").is_none() && object.get("htmlBody").is_none() && object.get("attachments").is_none() {
            builder = builder.body(MimePart::new("text/plain", ""));
        }
        builder.write_to_vec().map_err(|error| error.to_string())
    }

    pub async fn email_set(&mut self, args: Map<String, Value>) -> MethodResult {
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
            for (creation, object) in create {
                let Some(object) = object.as_object() else {
                    not_created.insert(creation.clone(), invalid_properties("an email is an object"));
                    continue;
                };
                let prepared = async {
                    let mailbox_ids = self.mailbox_set_of(object.get("mailboxIds"))?;
                    let keywords = match object.get("keywords") {
                        Some(value) => keyword_list(value)?,
                        None => Vec::new(),
                    };
                    let received_at = received_at(object.get("receivedAt"))?;
                    if let Some(mailbox) = mailbox_ids.iter().find(|m| !access.mailbox(**m).contains(Rights::INSERT)) {
                        return Err(format!("no right to add emails to mailbox {mailbox}"));
                    }
                    let keywords = allowed_keywords(keywords, &mailbox_ids, &access);
                    let raw = self.build(&access, object).await?;
                    Ok::<_, String>((NewEmail { mailbox_ids, keywords, received_at }, raw))
                }
                .await;
                let (new, raw) = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        not_created.insert(creation.clone(), invalid_properties(error));
                        continue;
                    }
                };
                match mail.import_email(account, Bytes::from(raw), new).await {
                    Ok(imported) => {
                        self.created.insert(creation.clone(), imported.id.to_string());
                        created.insert(
                            creation.clone(),
                            json!({
                                "id": imported.id.to_string(),
                                "blobId": BlobId::Email(imported.id).to_string(),
                                "threadId": imported.thread_id.to_string(),
                                "size": imported.size,
                            }),
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
                let result = match (self.id(id), patch.as_object()) {
                    (Some(email), Some(patch)) => self.update_email(&access, email, patch).await,
                    _ => Err(json!({ "type": "notFound" })),
                };
                match result {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), error);
                    }
                }
            }
        }

        let (mut destroyed, mut not_destroyed) = (Vec::new(), Map::new());
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy.iter().filter_map(Value::as_str) {
                let result = match self.id(id) {
                    Some(email) => match self.removable(&access, email).await {
                        Ok(true) => mail.destroy_email(account, email).await,
                        Ok(false) => {
                            not_destroyed.insert(id.to_owned(), forbidden("no right to delete this email"));
                            continue;
                        }
                        Err(error) => Err(error),
                    },
                    None => Err(MailError::NotFound("the email")),
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
            "Email/set".into(),
            json!({
                "accountId": account.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": created, "updated": updated, "destroyed": destroyed,
                "notCreated": not_created, "notUpdated": not_updated, "notDestroyed": not_destroyed,
            }),
        )])
    }

    /// A patch of keywords and mailboxes (RFC 8620, 5.3 and RFC 8621, 4.6); other properties are immutable.
    pub(crate) async fn update_email(
        &self,
        access: &Access,
        email: Uuid,
        patch: &Map<String, Value>,
    ) -> Result<(), Value> {
        let account = access.owner;
        let mail = self.jmap.mail();
        // What others may do depends on the mailboxes the email is in (RFC 0002, 12.2).
        let current = if access.owned {
            None
        } else {
            let info = mail.email(account, email).await.map_err(|error| set_error(&error))?;
            if !crate::blob::readable(&info, access) {
                return Err(json!({ "type": "notFound" }));
            }
            Some(info)
        };
        let (mut add, mut remove, mut keywords) = (Vec::new(), Vec::new(), None);
        let mut mailboxes: Option<BTreeSet<Uuid>> = None;
        let mut mailbox_patch: Vec<(Uuid, bool)> = Vec::new();
        for (key, value) in patch {
            if key == "keywords" {
                keywords = Some(keyword_list(value).map_err(invalid_properties)?);
            } else if let Some(keyword) = key.strip_prefix("keywords/") {
                let keyword = Keyword::parse(keyword).map_err(|error| invalid_properties(error.to_string()))?;
                match value {
                    Value::Bool(true) => add.push(keyword),
                    Value::Null | Value::Bool(false) => remove.push(keyword),
                    _ => return Err(json!({ "type": "invalidPatch" })),
                }
            } else if key == "mailboxIds" {
                mailboxes = Some(self.mailbox_set_of(Some(value)).map_err(invalid_properties)?.into_iter().collect());
            } else if let Some(mailbox) = key.strip_prefix("mailboxIds/") {
                let mailbox = self.id(mailbox).ok_or_else(|| invalid_properties(format!("no mailbox {mailbox}")))?;
                mailbox_patch.push((mailbox, value.as_bool() == Some(true)));
            } else {
                return Err(invalid_properties(format!("{key} cannot be changed")));
            }
        }
        if let Some(info) = &current {
            let rights = email_rights(info, access);
            let before: BTreeSet<&str> = info.keywords.iter().map(String::as_str).collect();
            let changed: Vec<&str> = match &keywords {
                Some(keywords) => {
                    let after: BTreeSet<&str> = keywords.iter().map(Keyword::as_str).collect();
                    before.symmetric_difference(&after).copied().collect()
                }
                None => add.iter().chain(&remove).map(Keyword::as_str).collect(),
            };
            if let Some(keyword) = changed.iter().find(|keyword| !rights.contains(keyword_right(keyword))) {
                return Err(forbidden(&format!("no right to change {keyword}")));
            }
        }
        if let Some(keywords) = keywords {
            mail.set_keywords(account, email, &keywords).await.map_err(|error| set_error(&error))?;
        }
        if !add.is_empty() || !remove.is_empty() {
            mail.update_keywords(account, email, &add, &remove).await.map_err(|error| set_error(&error))?;
        }
        if mailboxes.is_some() || !mailbox_patch.is_empty() {
            let mut set = match mailboxes {
                Some(set) => set,
                None => mail
                    .email(account, email)
                    .await
                    .map_err(|error| set_error(&error))?
                    .mailboxes
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect(),
            };
            for (mailbox, keep) in mailbox_patch {
                if keep {
                    set.insert(mailbox);
                } else {
                    set.remove(&mailbox);
                }
            }
            if let Some(info) = &current {
                let before: BTreeSet<Uuid> = info.mailboxes.iter().map(|(id, _)| *id).collect();
                let entering = set.difference(&before).find(|m| !access.mailbox(**m).contains(Rights::INSERT));
                let leaving =
                    before.difference(&set).find(|m| !access.mailbox(**m).contains(Rights::DELETE | Rights::EXPUNGE));
                if entering.is_some() || leaving.is_some() {
                    return Err(forbidden("no right to move the email there"));
                }
            }
            let set: Vec<Uuid> = set.into_iter().collect();
            mail.set_mailboxes(account, email, &set).await.map_err(|error| set_error(&error))?;
        }
        Ok(())
    }

    /// Whether the caller may destroy an email: it may remove it from every mailbox it is in.
    async fn removable(&self, access: &Access, email: Uuid) -> Result<bool, MailError> {
        if access.owned {
            return Ok(true);
        }
        let info = self.jmap.mail().email(access.owner, email).await?;
        Ok(crate::blob::readable(&info, access)
            && info
                .mailboxes
                .iter()
                .all(|(mailbox, _)| access.mailbox(*mailbox).contains(Rights::DELETE | Rights::EXPUNGE)))
    }

    pub async fn email_import(&mut self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let mail = self.jmap.mail().clone();
        let old_state = mail.state(account).await?;
        if_in_state(&args, old_state)?;
        let emails =
            args.get("emails").and_then(Value::as_object).ok_or_else(|| MethodError::invalid("emails is required"))?;
        if emails.len() > MAX_OBJECTS_IN_SET {
            return Err(MethodError::new("requestTooLarge", "too many emails"));
        }
        let (mut created, mut not_created) = (Map::new(), Map::new());
        for (creation, object) in emails {
            let blob = object.get("blobId").and_then(Value::as_str).unwrap_or_default();
            let Some(raw) = self.jmap.blob_bytes(&access, blob).await else {
                not_created.insert(creation.clone(), json!({ "type": "blobNotFound", "notFound": [blob] }));
                continue;
            };
            let new = (|| {
                Ok::<_, String>(NewEmail {
                    mailbox_ids: self.mailbox_set_of(object.get("mailboxIds"))?,
                    keywords: match object.get("keywords") {
                        Some(value) => keyword_list(value)?,
                        None => Vec::new(),
                    },
                    received_at: received_at(object.get("receivedAt"))?,
                })
            })();
            let mut new = match new {
                Ok(new) => new,
                Err(error) => {
                    not_created.insert(creation.clone(), invalid_properties(error));
                    continue;
                }
            };
            if new.mailbox_ids.iter().any(|mailbox| !access.mailbox(*mailbox).contains(Rights::INSERT)) {
                not_created.insert(creation.clone(), forbidden("no right to add emails to these mailboxes"));
                continue;
            }
            new.keywords = allowed_keywords(new.keywords, &new.mailbox_ids, &access);
            // An app that stores mail it encrypted itself brings its summary encrypted too (RFC 0006, 5.2).
            let summary = match object.get("kernoid:encryptedSummary") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    use base64::Engine;
                    match value.as_str().and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok()) {
                        Some(summary) => Some(summary),
                        None => {
                            not_created
                                .insert(creation.clone(), invalid_properties("kernoid:encryptedSummary is base64"));
                            continue;
                        }
                    }
                }
            };
            match mail.import_email_with(account, raw, new, summary).await {
                Ok(imported) => {
                    self.created.insert(creation.clone(), imported.id.to_string());
                    created.insert(
                        creation.clone(),
                        json!({
                            "id": imported.id.to_string(),
                            "blobId": BlobId::Email(imported.id).to_string(),
                            "threadId": imported.thread_id.to_string(),
                            "size": imported.size,
                        }),
                    );
                }
                Err(error) => {
                    not_created.insert(creation.clone(), set_error(&error));
                }
            }
        }
        let new_state = mail.state(account).await?;
        Ok(vec![(
            "Email/import".into(),
            json!({
                "accountId": account.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": created,
                "notCreated": not_created,
            }),
        )])
    }
}

fn forbidden(description: &str) -> Value {
    json!({ "type": "forbidden", "description": description })
}

/// The right a keyword needs (RFC 4314, 4): `s` for `$seen`, `t` for `$deleted`, `w` for the others.
fn keyword_right(keyword: &str) -> Rights {
    match keyword {
        Keyword::SEEN => Rights::SEEN,
        "$deleted" => Rights::DELETE,
        _ => Rights::WRITE,
    }
}

/// The caller's rights on an email: those of the mailboxes it is in, together.
fn email_rights(email: &EmailInfo, access: &Access) -> Rights {
    email.mailboxes.iter().fold(Rights::NONE, |rights, (mailbox, _)| rights | access.mailbox(*mailbox))
}

/// The keywords a new email keeps: those the caller may set in its mailboxes (IMAP `APPEND` drops the others).
fn allowed_keywords(keywords: Vec<Keyword>, mailboxes: &[Uuid], access: &Access) -> Vec<Keyword> {
    let rights = mailboxes.iter().fold(Rights::NONE, |rights, mailbox| rights | access.mailbox(*mailbox));
    keywords.into_iter().filter(|keyword| rights.contains(keyword_right(keyword.as_str()))).collect()
}
