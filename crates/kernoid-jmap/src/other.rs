// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Thread/get`, `Identity/get`, `EmailSubmission/set` and `/get`, `SearchSnippet/get` (RFC 8621, 3, 6, 7 and 5).

use std::collections::BTreeSet;

use bytes::Bytes;
use kernoid_mail::{Access, Delivered, Delivery, MailError, Outgoing, Recipient};
use mail_parser::MessageParser;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    email::ids_of,
    mailbox::{ids, invalid_properties, set_error},
    request::{Context, MethodError, MethodResult},
};

/// An identity's id: derived from its address, which JMAP ids cannot hold as it is.
fn identity_id(address: &str) -> String {
    Sha256::digest(address.as_bytes())[..12].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The message without its `Bcc` header, as it is sent (RFC 8621, 7.5).
fn without_bcc(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    let mut dropping = false;
    while !rest.is_empty() {
        let end = rest.iter().position(|&b| b == b'\n').map_or(rest.len(), |i| i + 1);
        let (line, tail) = rest.split_at(end);
        if line == b"\r\n" || line == b"\n" {
            out.extend_from_slice(rest);
            return out;
        }
        if !matches!(line.first(), Some(b' ' | b'\t')) {
            dropping = line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"bcc:");
        }
        if !dropping {
            out.extend_from_slice(line);
        }
        rest = tail;
    }
    out
}

impl Context<'_> {
    pub async fn thread_get(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let mail = self.jmap.mail();
        let wanted = ids(&args)?.ok_or_else(|| MethodError::new("requestTooLarge", "name the threads"))?;
        let (mut list, mut not_found) = (Vec::new(), Vec::new());
        for id in wanted {
            match self.id(&id) {
                Some(thread) => match mail.thread(account, thread).await {
                    Ok(mut emails) => {
                        if !access.owned {
                            let readable: Vec<Uuid> = mail
                                .emails(account, &emails)
                                .await?
                                .iter()
                                .filter(|email| crate::blob::readable(email, &access))
                                .map(|email| email.id)
                                .collect();
                            emails.retain(|email| readable.contains(email));
                        }
                        if emails.is_empty() {
                            not_found.push(id);
                            continue;
                        }
                        list.push(json!({
                        "id": id,
                        "emailIds": emails.into_iter().map(|email| email.to_string()).collect::<Vec<_>>(),
                        }));
                    }
                    Err(MailError::NotFound(_)) => not_found.push(id),
                    Err(error) => return Err(error.into()),
                },
                None => not_found.push(id),
            }
        }
        let state = mail.state(account).await?;
        Ok(vec![(
            "Thread/get".into(),
            json!({ "accountId": account.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    /// One identity per address of the account, with its display name; read-only for now. Others have them only
    /// with send as (RFC 0002, 12.2). In one's own store also the addresses of groups one may send as (9.2), with
    /// the group's name.
    async fn identities(&self, access: &Access) -> Result<Vec<(String, String, String)>, MethodError> {
        if !access.send_as {
            return Ok(Vec::new());
        }
        let mail = self.jmap.mail();
        let (name, addresses) = mail.account_addresses(access.owner).await?;
        let mut identities: Vec<_> =
            addresses.into_iter().map(|address| (identity_id(&address), name.clone(), address)).collect();
        if access.owned {
            for (group, address) in mail.group_sender_addresses(access.owner).await? {
                identities.push((identity_id(&address), group, address));
            }
        }
        Ok(identities)
    }

    pub async fn identity_get(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let identities = self.identities(&access).await?;
        let wanted = ids(&args)?;
        let (mut list, mut not_found) = (Vec::new(), Vec::new());
        let object = |(id, name, email): &(String, String, String)| {
            json!({
                "id": id, "name": name, "email": email, "replyTo": null, "bcc": null,
                "textSignature": "", "htmlSignature": "", "mayDelete": false,
            })
        };
        match wanted {
            None => list.extend(identities.iter().map(object)),
            Some(ids) => {
                for id in ids {
                    match identities.iter().find(|identity| identity.0 == id) {
                        Some(identity) => list.push(object(identity)),
                        None => not_found.push(id),
                    }
                }
            }
        }
        Ok(vec![(
            "Identity/get".into(),
            json!({ "accountId": account.to_string(), "state": "0", "list": list, "notFound": not_found }),
        )])
    }

    pub async fn submission_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let mail = self.jmap.mail().clone();
        let old_state = mail.state(account).await?;
        let identities = self.identities(&access).await?;
        let (mut created, mut not_created) = (Map::new(), Map::new());
        let mut sent: Vec<(String, Uuid)> = Vec::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for (creation, object) in create {
                match self.submit(&access, object, &identities).await {
                    Ok((id, email)) => {
                        self.created.insert(creation.clone(), id.to_string());
                        created.insert(
                            creation.clone(),
                            json!({ "id": id.to_string(), "undoStatus": "final", "sendAt": chrono::Utc::now() }),
                        );
                        sent.push((creation.clone(), email));
                    }
                    Err(error) => {
                        not_created.insert(creation.clone(), error);
                    }
                }
            }
        }
        let mut not_updated = Map::new();
        if let Some(Value::Object(update)) = args.get("update") {
            for id in update.keys() {
                not_updated
                    .insert(id.clone(), json!({ "type": "cannotUnsend", "description": "mail is sent at once" }));
            }
        }
        let mut not_destroyed = Map::new();
        for id in args.get("destroy").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            not_destroyed.insert(id.to_owned(), json!({ "type": "forbidden", "description": "submissions are kept" }));
        }
        let new_state = mail.state(account).await?;
        let mut responses = vec![(
            "EmailSubmission/set".to_owned(),
            json!({
                "accountId": account.to_string(),
                "oldState": old_state.to_string(),
                "newState": new_state.to_string(),
                "created": created, "notCreated": not_created,
                "updated": {}, "notUpdated": not_updated,
                "destroyed": [], "notDestroyed": not_destroyed,
            }),
        )];

        // What follows on success (RFC 8621, 7.5): an implicit Email/set.
        let mut update = Map::new();
        if let Some(Value::Object(patches)) = args.get("onSuccessUpdateEmail") {
            for (reference, patch) in patches {
                let email = reference
                    .strip_prefix('#')
                    .and_then(|creation| sent.iter().find(|(sent, _)| sent == creation))
                    .map(|(_, email)| email.to_string())
                    .or_else(|| self.id(reference).map(|id| id.to_string()));
                if let Some(email) = email {
                    update.insert(email, patch.clone());
                }
            }
        }
        let mut destroy = Vec::new();
        for reference in
            args.get("onSuccessDestroyEmail").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
        {
            if let Some((_, email)) =
                reference.strip_prefix('#').and_then(|creation| sent.iter().find(|(sent, _)| sent == creation))
            {
                destroy.push(json!(email.to_string()));
            } else if let Some(id) = self.id(reference) {
                destroy.push(json!(id.to_string()));
            }
        }
        if !update.is_empty() || !destroy.is_empty() {
            let mut set = Map::new();
            set.insert("accountId".into(), json!(account.to_string()));
            set.insert("update".into(), Value::Object(update));
            set.insert("destroy".into(), Value::Array(destroy));
            responses.extend(self.email_set(set).await?);
        }
        Ok(responses)
    }

    /// Sends a stored email: from one of the account's identities, to the envelope's recipients or else to everyone
    /// in `To`, `Cc` and `Bcc`.
    async fn submit(
        &self,
        access: &Access,
        object: &Value,
        identities: &[(String, String, String)],
    ) -> Result<(Uuid, Uuid), Value> {
        let account = access.owner;
        let mail = self.jmap.mail();
        let identity = object
            .get("identityId")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_properties("identityId is required"))?;
        let (_, _, address) = identities
            .iter()
            .find(|candidate| candidate.0 == identity)
            .ok_or_else(|| json!({ "type": "forbiddenFrom", "description": "no such identity" }))?;
        let email = object
            .get("emailId")
            .and_then(Value::as_str)
            .and_then(|id| self.id(id))
            .ok_or_else(|| json!({ "type": "invalidEmail", "description": "no such email" }))?;
        if !self.jmap.may_read(access, email).await.unwrap_or(false) {
            return Err(json!({ "type": "invalidEmail", "description": "no such email" }));
        }
        let raw = mail.raw_email(account, email).await.map_err(|_| json!({ "type": "invalidEmail" }))?;
        let message = MessageParser::new().parse(&raw[..]).ok_or_else(|| json!({ "type": "invalidEmail" }))?;
        // Every sender address must be the account's own (RFC 0002, 10.1).
        let own: BTreeSet<&str> = identities.iter().map(|identity| identity.2.as_str()).collect();
        let senders: Vec<String> = message
            .from()
            .map(|from| from.iter().filter_map(|addr| addr.address()).map(str::to_lowercase).collect())
            .unwrap_or_default();
        if senders.is_empty() || senders.iter().any(|sender| !own.contains(sender.as_str())) {
            return Err(json!({ "type": "forbiddenFrom", "description": "send as the account's own addresses" }));
        }
        let envelope = object.get("envelope");
        let mail_from = envelope
            .and_then(|envelope| envelope.get("mailFrom"))
            .and_then(|from| from.get("email"))
            .and_then(Value::as_str)
            .map_or_else(|| address.clone(), str::to_lowercase);
        if !own.contains(mail_from.as_str()) {
            return Err(json!({ "type": "forbiddenMailFrom", "description": "send as the account's own addresses" }));
        }
        let mut recipients: Vec<String> =
            match envelope.and_then(|envelope| envelope.get("rcptTo")).and_then(Value::as_array) {
                Some(list) => list
                    .iter()
                    .filter_map(|rcpt| rcpt.get("email").and_then(Value::as_str))
                    .map(str::to_lowercase)
                    .collect(),
                None => [message.to(), message.cc(), message.bcc()]
                    .into_iter()
                    .flatten()
                    .flat_map(|list| {
                        list.iter().filter_map(|addr| addr.address()).map(str::to_lowercase).collect::<Vec<_>>()
                    })
                    .collect(),
            };
        recipients.sort();
        recipients.dedup();
        if recipients.is_empty() {
            return Err(json!({ "type": "noRecipients" }));
        }
        drop(message);
        let sending = Bytes::from(without_bcc(&raw));

        let mut local = BTreeSet::new();
        let mut remote = Vec::new();
        for recipient in &recipients {
            match mail.resolve_recipient(recipient).await.map_err(|error| set_error(&error))? {
                Recipient::Account { account: target, .. } => {
                    local.insert((target, recipient.clone()));
                }
                Recipient::Group { members, .. } => {
                    local.extend(members.into_iter().map(|member| (member, recipient.clone())))
                }
                Recipient::NotLocal => remote.push(recipient.clone()),
                // An SRS address takes bounces from other servers only.
                Recipient::Disabled | Recipient::Unknown | Recipient::Forwarded { .. } => {
                    return Err(json!({ "type": "invalidRecipients", "invalidRecipients": [recipient] }));
                }
            }
        }
        let mut delivered = BTreeSet::new();
        for (target, to) in &local {
            if !delivered.insert(*target) {
                continue;
            }
            match mail.deliver(*target, sending.clone(), Delivery { from: &mail_from, to, junk: false }).await {
                Ok(Delivered::Stored(_) | Delivered::Duplicate | Delivered::Discarded) => {}
                Err(error) => return Err(set_error(&error)),
            }
        }
        if !remote.is_empty() {
            let tenant = mail.account_tenant(account).await.map_err(|error| set_error(&error))?;
            mail.enqueue(Outgoing {
                tenant,
                account: Some(account),
                from: &mail_from,
                recipients: &remote,
                raw: sending,
                lifetime: self.jmap.queue_lifetime,
            })
            .await
            .map_err(|error| set_error(&error))?;
        }
        let id = Uuid::now_v7();
        sqlx::query!(
            "INSERT INTO email_submissions (id, account_id, email_id, identity_id, envelope_from, recipients)
             VALUES ($1, $2, $3, $4, $5, $6)",
            id,
            account,
            email,
            identity,
            mail_from,
            &recipients,
        )
        .execute(mail.pool())
        .await
        .map_err(|error| set_error(&MailError::Store(error)))?;
        Ok((id, email))
    }

    pub async fn submission_get(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        if !access.send_as {
            return Err(MethodError::new("forbidden", "only who may send as the account sees what it sent"));
        }
        let account = access.owner;
        let rows = sqlx::query!(
            "SELECT id, email_id, identity_id, envelope_from, recipients, send_at FROM email_submissions
             WHERE account_id = $1 ORDER BY send_at DESC LIMIT 500",
            account,
        )
        .fetch_all(self.jmap.mail().pool())
        .await
        .map_err(MethodError::server_fail)?;
        let wanted = ids(&args)?;
        let mut list = Vec::new();
        for row in &rows {
            if wanted.as_ref().is_some_and(|ids| !ids.contains(&row.id.to_string())) {
                continue;
            }
            list.push(json!({
                "id": row.id.to_string(),
                "identityId": row.identity_id,
                "emailId": row.email_id.to_string(),
                "threadId": null,
                "envelope": {
                    "mailFrom": { "email": row.envelope_from, "parameters": null },
                    "rcptTo": row.recipients.iter().map(|to| json!({ "email": to, "parameters": null })).collect::<Vec<_>>(),
                },
                "sendAt": row.send_at,
                "undoStatus": "final",
                "deliveryStatus": null,
                "dsnBlobIds": [],
                "mdnBlobIds": [],
            }));
        }
        let not_found: Vec<String> = wanted
            .unwrap_or_default()
            .into_iter()
            .filter(|id| !rows.iter().any(|row| row.id.to_string() == *id))
            .collect();
        let state = self.jmap.mail().state(account).await?;
        Ok(vec![(
            "EmailSubmission/get".into(),
            json!({ "accountId": account.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    /// `SearchSnippet/get` (RFC 8621, 5.1): subject and preview with the words of the filter's `text`, `body` and
    /// `subject` conditions marked; null where none is found.
    pub async fn snippet_get(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let wanted = ids_of(&args, "emailIds")?;
        let mut words = Vec::new();
        if let Some(filter) = args.get("filter") {
            filter_words(filter, &mut words);
        }
        let ids: Vec<Uuid> = wanted.iter().filter_map(|id| self.id(id)).collect();
        let found = self.jmap.mail().emails(account, &ids).await?;
        let (mut list, mut not_found) = (Vec::new(), Vec::new());
        for id in wanted {
            match self.id(&id).and_then(|id| found.iter().find(|email| email.id == id)) {
                Some(email) if crate::blob::readable(email, &access) => list.push(json!({
                    "emailId": id,
                    "subject": highlight(email.subject.as_deref().unwrap_or_default(), &words),
                    "preview": highlight(&email.preview, &words),
                })),
                _ => not_found.push(id),
            }
        }
        Ok(vec![(
            "SearchSnippet/get".into(),
            json!({ "accountId": account.to_string(), "list": list, "notFound": not_found }),
        )])
    }
}

/// The words a filter searches for, lower case.
fn filter_words(filter: &Value, out: &mut Vec<String>) {
    if let Some(conditions) = filter.get("conditions").and_then(Value::as_array) {
        for condition in conditions {
            filter_words(condition, out);
        }
    }
    for key in ["text", "body", "subject"] {
        if let Some(value) = filter.get(key).and_then(Value::as_str) {
            out.extend(value.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_lowercase));
        }
    }
}

/// `text` as HTML with the words that begin with one of `words` in `<mark>`; `None` if there is none.
fn highlight(text: &str, words: &[String]) -> Option<String> {
    let escape = |text: &str| text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let mut out = String::with_capacity(text.len() + 32);
    let mut marked = false;
    let mut rest = text;
    while !rest.is_empty() {
        let start = rest.find(char::is_alphanumeric).unwrap_or(rest.len());
        out.push_str(&escape(&rest[..start]));
        rest = &rest[start..];
        let end = rest.find(|c: char| !c.is_alphanumeric()).unwrap_or(rest.len());
        let word = &rest[..end];
        if !word.is_empty() && words.iter().any(|w| word.to_lowercase().starts_with(w.as_str())) {
            out.push_str("<mark>");
            out.push_str(&escape(word));
            out.push_str("</mark>");
            marked = true;
        } else {
            out.push_str(&escape(word));
        }
        rest = &rest[end..];
    }
    marked.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcc_is_removed_before_sending() {
        let raw = b"From: a@x.example\r\nBcc: secret@y.example,\r\n other@y.example\r\nSubject: Hi\r\n\r\nBcc: stays in the body\r\n";
        assert_eq!(
            String::from_utf8(without_bcc(raw)).unwrap(),
            "From: a@x.example\r\nSubject: Hi\r\n\r\nBcc: stays in the body\r\n"
        );
        assert_eq!(identity_id("alice@firma.example").len(), 24);
        let words = vec!["lun".to_owned()];
        assert_eq!(
            highlight("Lunch <today> & lunacy", &words).as_deref(),
            Some("<mark>Lunch</mark> &lt;today&gt; &amp; <mark>lunacy</mark>")
        );
        assert_eq!(highlight("nothing", &words), None);
    }
}
