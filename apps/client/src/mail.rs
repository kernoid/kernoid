// SPDX-License-Identifier: MIT
//! Mail over JMAP (RFC 8621): mailboxes, the emails of one, one email to read, keywords, moving, deleting,
//! sending through the Drafts mailbox (RFC 8621, 7.5), and the vacation response (RFC 8621, 8). End-to-end encrypted
//! emails are opened and sent in `e2e`.

use std::collections::BTreeMap;

use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{Client, Error, MAIL, Result, SUBMISSION, VACATION, e2e::OPENPGP, ids_of, set_error};

/// The vacation response of the user's account (RFC 8621, 8), its times here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vacation {
    pub on: bool,
    /// From when it answers; at once if not set.
    pub from: Option<NaiveDateTime>,
    /// Until when; until it is switched off if not set.
    pub until: Option<NaiveDateTime>,
    pub subject: String,
    pub text: String,
}

fn local(utc: Option<&str>) -> Option<NaiveDateTime> {
    let utc = DateTime::parse_from_rfc3339(utc?).ok()?;
    Some(utc.with_timezone(&Local).naive_local())
}

fn utc(local: Option<NaiveDateTime>) -> Option<String> {
    let at = Local.from_local_datetime(&local?).earliest()?;
    Some(at.with_timezone(&Utc).format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// The vacation response; none if the server has none for the user.
pub async fn vacation(client: &Client) -> Result<Option<Vacation>> {
    let Ok(account) = client.primary(VACATION) else { return Ok(None) };
    let result =
        client.call(&[VACATION], "VacationResponse/get", json!({ "accountId": account, "ids": ["singleton"] })).await?;
    let Some(found) = result.get("list").and_then(Value::as_array).and_then(|list| list.first()) else {
        return Ok(Some(Vacation::default()));
    };
    let text = |name: &str| found.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
    Ok(Some(Vacation {
        on: found.get("isEnabled").and_then(Value::as_bool).unwrap_or(false),
        from: local(found.get("fromDate").and_then(Value::as_str)),
        until: local(found.get("toDate").and_then(Value::as_str)),
        subject: text("subject"),
        text: text("textBody"),
    }))
}

pub async fn set_vacation(client: &Client, vacation: &Vacation) -> Result<()> {
    let account = client.primary(VACATION)?;
    let update = json!({ "update": { "singleton": {
        "isEnabled": vacation.on,
        "fromDate": utc(vacation.from),
        "toDate": utc(vacation.until),
        "subject": (!vacation.subject.is_empty()).then_some(&vacation.subject),
        "textBody": (!vacation.text.is_empty()).then_some(&vacation.text),
    } } });
    client.set(&[VACATION], "VacationResponse", &account, update, json!({})).await?;
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mailbox {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub sort_order: i64,
    #[serde(default)]
    pub total_emails: u64,
    #[serde(default)]
    pub unread_emails: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct EmailAddress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
}

impl std::fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(name) if !name.is_empty() => {
                if name.contains([',', ';', '<', '>', '"']) {
                    write!(f, "\"{}\" <{}>", name.replace('"', ""), self.email)
                } else {
                    write!(f, "{name} <{}>", self.email)
                }
            }
            _ => write!(f, "{}", self.email),
        }
    }
}

/// A list of addresses for people: `Name <a@b>, c@d`.
pub fn format_addresses(list: &[EmailAddress]) -> String {
    list.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

/// Addresses as people type them, separated by commas or semicolons (`Name <a@b>`, `"Last, First" <a@b>`, `a@b`).
pub fn parse_addresses(text: &str) -> Vec<EmailAddress> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let (mut quoted, mut angle) = (false, false);
    for c in text.chars() {
        match c {
            '"' if !angle => quoted = !quoted,
            '<' if !quoted => angle = true,
            '>' if !quoted => angle = false,
            ',' | ';' if !quoted && !angle => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    parts.push(current);
    parts
        .into_iter()
        .map(|part| part.trim().to_owned())
        .filter(|part| !part.is_empty())
        .map(|part| match (part.rfind('<'), part.ends_with('>')) {
            (Some(start), true) => {
                let name = part[..start].trim().trim_matches('"').trim();
                EmailAddress {
                    name: (!name.is_empty()).then(|| name.to_owned()),
                    email: part[start + 1..part.len() - 1].trim().to_owned(),
                }
            }
            _ => EmailAddress { name: None, email: part },
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailSummary {
    pub id: String,
    #[serde(default)]
    pub thread_id: String,
    #[serde(default)]
    pub mailbox_ids: BTreeMap<String, bool>,
    #[serde(default)]
    pub keywords: BTreeMap<String, bool>,
    #[serde(default)]
    pub from: Option<Vec<EmailAddress>>,
    #[serde(default)]
    pub to: Option<Vec<EmailAddress>>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub received_at: String,
    #[serde(default)]
    pub preview: String,
    #[serde(default)]
    pub has_attachment: bool,
    #[serde(default)]
    pub size: u64,
    /// End-to-end encrypted (RFC 0006, 5): subject and preview are the summary's, once it is decrypted here.
    #[serde(default, rename = "kernoid:encrypted")]
    pub encrypted: bool,
    /// The summary, encrypted to the account's key (base64).
    #[serde(default, rename = "kernoid:encryptedSummary")]
    pub encrypted_summary: Option<String>,
    /// Subject, preview and attachments came from the decrypted summary.
    #[serde(skip)]
    pub opened: bool,
}

impl EmailSummary {
    pub fn is_seen(&self) -> bool {
        self.keywords.get("$seen").copied().unwrap_or(false)
    }

    pub fn is_flagged(&self) -> bool {
        self.keywords.get("$flagged").copied().unwrap_or(false)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyPart {
    #[serde(default)]
    pub part_id: Option<String>,
    #[serde(default)]
    pub blob_id: Option<String>,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub size: u64,
    /// A part of an end-to-end encrypted message, decrypted here: its index in the inner message (`Email::inner`).
    #[serde(skip)]
    pub inner: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BodyValue {
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Email {
    #[serde(flatten)]
    pub summary: EmailSummary,
    #[serde(default)]
    pub cc: Option<Vec<EmailAddress>>,
    #[serde(default)]
    pub reply_to: Option<Vec<EmailAddress>>,
    #[serde(default)]
    pub message_id: Option<Vec<String>>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
    #[serde(default)]
    pub sent_at: Option<String>,
    #[serde(default)]
    pub text_body: Vec<BodyPart>,
    #[serde(default)]
    pub html_body: Vec<BodyPart>,
    #[serde(default)]
    pub attachments: Vec<BodyPart>,
    #[serde(default)]
    pub body_values: BTreeMap<String, BodyValue>,
    /// The raw message, for end-to-end encrypted emails (downloaded and decrypted here).
    #[serde(default)]
    pub blob_id: Option<String>,
    /// For an end-to-end encrypted email: locked or decrypted, and how it was signed.
    #[serde(skip)]
    pub sealed: Option<Sealed>,
    /// The decrypted message – its attachments are read from it.
    #[serde(skip)]
    pub inner: Option<Inner>,
}

/// What reading an end-to-end encrypted email gave.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sealed {
    /// Not decrypted: the key is locked, or the email is encrypted to another key.
    pub locked: bool,
    pub signed: bool,
    /// Signed by a key of its sender.
    pub verified: bool,
}

/// A decrypted message, kept in memory only; its length is all `Debug` shows.
#[derive(Clone)]
pub struct Inner(pub Vec<u8>);

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Inner({} bytes)", self.0.len())
    }
}

impl Email {
    /// The text of the email: its plain-text parts, or its HTML parts as text `width` columns wide. Nothing of the
    /// HTML is run or loaded – html2text only reads it.
    pub fn text(&self, width: usize) -> String {
        let value = |part: &BodyPart| part.part_id.as_ref().and_then(|id| self.body_values.get(id)).map(|v| &v.value);
        let plain: Vec<&String> =
            self.text_body.iter().filter(|part| part.kind != "text/html").filter_map(value).collect();
        if !plain.is_empty() {
            return plain.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n\n");
        }
        self.html_body
            .iter()
            .filter_map(|part| Some((part, value(part)?)))
            .map(|(part, text)| if part.kind == "text/html" { html_to_text(text, width) } else { text.clone() })
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// The content of an attachment decrypted here.
    pub fn part(&self, part: &BodyPart) -> Option<Result<Vec<u8>>> {
        let (inner, index) = (self.inner.as_ref()?, part.inner?);
        Some(kernoid_e2e::compose::part(&inner.0, index).map_err(Error::from))
    }
}

/// HTML as plain text, `width` columns wide.
pub fn html_to_text(html: &str, width: usize) -> String {
    html2text::config::plain().string_from_read(html.as_bytes(), width.max(20)).unwrap_or_else(|_| html.to_owned())
}

#[derive(Debug, Clone, Deserialize)]
pub struct Identity {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub email: String,
}

#[derive(Deserialize)]
struct List<T> {
    list: Vec<T>,
}

const ROLES: [&str; 6] = ["inbox", "drafts", "sent", "archive", "junk", "trash"];

/// The mailboxes of an account: by role (Inbox first), then by sort order and name.
pub async fn mailboxes(client: &Client, account: &str) -> Result<Vec<Mailbox>> {
    let result = client.call(&[MAIL], "Mailbox/get", json!({ "accountId": account })).await?;
    let mut list: Vec<Mailbox> = parse(result)?;
    let rank = |m: &Mailbox| m.role.as_deref().and_then(|r| ROLES.iter().position(|x| *x == r)).unwrap_or(99);
    list.sort_by(|a, b| rank(a).cmp(&rank(b)).then(a.sort_order.cmp(&b.sort_order)).then_with(|| a.name.cmp(&b.name)));
    Ok(list)
}

fn parse<T: serde::de::DeserializeOwned>(result: Value) -> Result<Vec<T>> {
    serde_json::from_value::<List<T>>(result).map(|list| list.list).map_err(|error| Error::Protocol(error.to_string()))
}

const SUMMARY: [&str; 10] =
    ["threadId", "mailboxIds", "keywords", "from", "to", "subject", "receivedAt", "preview", "hasAttachment", "size"];

/// The properties of a summary: with the end-to-end ones where the server has them.
fn summary(client: &Client) -> Vec<&'static str> {
    let mut properties = SUMMARY.to_vec();
    if client.session.capabilities.contains_key(OPENPGP) {
        properties.extend(["kernoid:encrypted", "kernoid:encryptedSummary"]);
    }
    properties
}

/// The capabilities a request for emails uses.
fn using(client: &Client) -> Vec<&'static str> {
    if client.session.capabilities.contains_key(OPENPGP) { vec![MAIL, OPENPGP] } else { vec![MAIL] }
}

/// A page of emails in a mailbox – or, without one, in all – newest first; `text` searches them (full text).
pub async fn emails(
    client: &Client,
    account: &str,
    mailbox: Option<&str>,
    text: &str,
    position: u64,
    limit: u64,
) -> Result<(Vec<EmailSummary>, u64)> {
    let mut filter = Map::new();
    if let Some(mailbox) = mailbox {
        filter.insert("inMailbox".into(), mailbox.into());
    }
    if !text.trim().is_empty() {
        filter.insert("text".into(), text.trim().into());
    }
    let properties = summary(client);
    let responses = client
        .request(
            &using(client),
            vec![
                (
                    "Email/query",
                    json!({
                        "accountId": account, "filter": filter, "position": position, "limit": limit,
                        "sort": [{ "property": "receivedAt", "isAscending": false }], "calculateTotal": true,
                    }),
                    "q",
                ),
                (
                    "Email/get",
                    json!({ "accountId": account, "#ids": ids_of("q", "Email/query"), "properties": properties }),
                    "g",
                ),
            ],
        )
        .await?;
    let total = responses.get("q").and_then(|q| q.get("total")).and_then(Value::as_u64).unwrap_or(0);
    let list = parse(responses.get("g").cloned().unwrap_or(Value::Null))?;
    Ok((list, total))
}

/// One email with its bodies and attachments.
pub async fn email(client: &Client, account: &str, id: &str) -> Result<Option<Email>> {
    Ok(full(client, account, &[id]).await?.into_iter().next())
}

/// Emails with their bodies and attachments, oldest first – the messages of a thread.
pub async fn full(client: &Client, account: &str, ids: &[&str]) -> Result<Vec<Email>> {
    let mut properties = summary(client);
    properties.extend([
        "blobId",
        "cc",
        "replyTo",
        "messageId",
        "references",
        "sentAt",
        "textBody",
        "htmlBody",
        "attachments",
        "bodyValues",
    ]);
    let result = client
        .call(
            &using(client),
            "Email/get",
            json!({
                "accountId": account, "ids": ids, "properties": properties,
                "fetchTextBodyValues": true, "fetchHTMLBodyValues": true, "maxBodyValueBytes": 4_000_000,
            }),
        )
        .await?;
    let mut list: Vec<Email> = parse(result)?;
    list.sort_by(|a, b| a.summary.received_at.cmp(&b.summary.received_at));
    Ok(list)
}

/// A conversation in a mailbox: its newest email there, and all its emails (in any mailbox), oldest first.
#[derive(Debug, Clone)]
pub struct Conversation {
    pub latest: EmailSummary,
    pub emails: Vec<EmailSummary>,
}

impl Conversation {
    /// The ids of its emails in `mailbox` – those that moving or deleting the conversation there acts on.
    pub fn ids_in(&self, mailbox: &str) -> Vec<String> {
        let ids: Vec<String> = self
            .emails
            .iter()
            .filter(|email| email.mailbox_ids.get(mailbox).copied().unwrap_or(false))
            .map(|email| email.id.clone())
            .collect();
        if ids.is_empty() { vec![self.latest.id.clone()] } else { ids }
    }

    pub fn unread(&self) -> bool {
        self.emails.iter().any(|email| !email.is_seen())
    }

    pub fn flagged(&self) -> bool {
        self.emails.iter().any(EmailSummary::is_flagged)
    }
}

/// A page of conversations in a mailbox, newest first (RFC 8621, 4.4.3 `collapseThreads`, then `Thread/get`); the
/// total counts conversations.
pub async fn conversations(
    client: &Client,
    account: &str,
    mailbox: Option<&str>,
    text: &str,
    position: u64,
    limit: u64,
) -> Result<(Vec<Conversation>, u64)> {
    let mut filter = Map::new();
    if let Some(mailbox) = mailbox {
        filter.insert("inMailbox".into(), mailbox.into());
    }
    if !text.trim().is_empty() {
        filter.insert("text".into(), text.trim().into());
    }
    let properties = summary(client);
    let responses = client.request(
        &using(client),
        vec![
            (
                "Email/query",
                json!({
                    "accountId": account, "filter": filter, "position": position, "limit": limit,
                    "sort": [{ "property": "receivedAt", "isAscending": false }], "calculateTotal": true,
                    "collapseThreads": true,
                }),
                "q",
            ),
            (
                "Email/get",
                json!({ "accountId": account, "#ids": ids_of("q", "Email/query"), "properties": properties }),
                "g",
            ),
            (
                "Thread/get",
                json!({ "accountId": account, "#ids": { "resultOf": "g", "name": "Email/get", "path": "/list/*/threadId" } }),
                "t",
            ),
            (
                "Email/get",
                json!({
                    "accountId": account, "properties": properties,
                    "#ids": { "resultOf": "t", "name": "Thread/get", "path": "/list/*/emailIds" },
                }),
                "m",
            ),
        ],
    ).await?;
    let total = responses.get("q").and_then(|q| q.get("total")).and_then(Value::as_u64).unwrap_or(0);
    let latest: Vec<EmailSummary> = parse(responses.get("g").cloned().unwrap_or(Value::Null))?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Thread {
        id: String,
        email_ids: Vec<String>,
    }
    let threads: Vec<Thread> = parse(responses.get("t").cloned().unwrap_or(Value::Null))?;
    let members: Vec<EmailSummary> = parse(responses.get("m").cloned().unwrap_or(Value::Null))?;
    let out = latest
        .into_iter()
        .map(|latest| {
            let ids =
                threads.iter().find(|t| t.id == latest.thread_id).map(|t| t.email_ids.clone()).unwrap_or_default();
            let mut emails: Vec<EmailSummary> =
                ids.iter().filter_map(|id| members.iter().find(|m| &m.id == id).cloned()).collect();
            if emails.is_empty() {
                emails.push(latest.clone());
            }
            emails.sort_by(|a, b| a.received_at.cmp(&b.received_at));
            Conversation { latest, emails }
        })
        .collect();
    Ok((out, total))
}

/// Sets or clears a keyword on several emails at once.
pub async fn set_keywords(client: &Client, account: &str, ids: &[String], keyword: &str, on: bool) -> Result<()> {
    let value = if on { Value::Bool(true) } else { Value::Null };
    let path = format!("keywords/{keyword}");
    let update: Map<String, Value> = ids.iter().map(|id| (id.clone(), json!({ path.as_str(): value }))).collect();
    client.set(&[MAIL], "Email", account, json!({ "update": update }), json!({})).await?;
    Ok(())
}

/// Moves several emails into one mailbox.
pub async fn move_all(client: &Client, account: &str, ids: &[String], mailbox: &str) -> Result<()> {
    let update: Map<String, Value> =
        ids.iter().map(|id| (id.clone(), json!({ "mailboxIds": { mailbox: true } }))).collect();
    client.set(&[MAIL], "Email", account, json!({ "update": update }), json!({})).await?;
    Ok(())
}

/// Removes several emails for good.
pub async fn destroy_all(client: &Client, account: &str, ids: &[String]) -> Result<()> {
    client.set(&[MAIL], "Email", account, json!({ "destroy": ids }), json!({})).await?;
    Ok(())
}

/// Sets or clears a keyword (`$seen`, `$flagged`).
pub async fn set_keyword(client: &Client, account: &str, id: &str, keyword: &str, on: bool) -> Result<()> {
    let value = if on { Value::Bool(true) } else { Value::Null };
    let path = format!("keywords/{keyword}");
    client.set(&[MAIL], "Email", account, json!({ "update": { id: { path: value } } }), json!({})).await?;
    Ok(())
}

/// Moves an email into one mailbox (out of all others).
pub async fn move_to(client: &Client, account: &str, id: &str, mailbox: &str) -> Result<()> {
    client
        .set(&[MAIL], "Email", account, json!({ "update": { id: { "mailboxIds": { mailbox: true } } } }), json!({}))
        .await?;
    Ok(())
}

/// Removes an email for good.
pub async fn destroy(client: &Client, account: &str, id: &str) -> Result<()> {
    client.set(&[MAIL], "Email", account, json!({ "destroy": [id] }), json!({})).await?;
    Ok(())
}

/// The addresses the account may send as.
pub async fn identities(client: &Client, account: &str) -> Result<Vec<Identity>> {
    parse(client.call(&[MAIL, SUBMISSION], "Identity/get", json!({ "accountId": account })).await?)
}

/// A file attached to a message being written: uploaded, or a part of another message (forwarding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub blob_id: String,
    pub kind: String,
    pub name: String,
    pub size: u64,
}

/// A message to send or keep as a draft.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Draft {
    pub from: Option<EmailAddress>,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub subject: String,
    pub body: String,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub attachments: Vec<Attachment>,
}

impl Draft {
    /// The email object of `Email/set` (RFC 8621, 4.6), in `mailbox`.
    pub fn email(&self, mailbox: &str, draft: bool) -> Value {
        let mut keywords = json!({ "$seen": true });
        if draft {
            keywords["$draft"] = true.into();
        }
        let mut email = json!({
            "mailboxIds": { mailbox: true },
            "keywords": keywords,
            "to": self.to,
            "subject": self.subject,
            "bodyValues": { "body": { "value": self.body } },
            "textBody": [{ "partId": "body", "type": "text/plain" }],
        });
        if let Some(from) = &self.from {
            email["from"] = json!([from]);
        }
        for (key, list) in [("cc", &self.cc), ("bcc", &self.bcc)] {
            if !list.is_empty() {
                email[key] = json!(list);
            }
        }
        if !self.in_reply_to.is_empty() {
            email["inReplyTo"] = json!(self.in_reply_to);
        }
        if !self.references.is_empty() {
            email["references"] = json!(self.references);
        }
        if !self.attachments.is_empty() {
            email["attachments"] = self
                .attachments
                .iter()
                .map(|file| {
                    json!({ "blobId": file.blob_id, "type": file.kind, "name": file.name, "disposition": "attachment" })
                })
                .collect();
        }
        email
    }
}

pub(crate) fn role<'a>(boxes: &'a [Mailbox], role: &str) -> Option<&'a Mailbox> {
    boxes.iter().find(|mailbox| mailbox.role.as_deref() == Some(role))
}

/// Keeps a message in Drafts; its id.
pub async fn save_draft(client: &Client, account: &str, draft: &Draft, boxes: &[Mailbox]) -> Result<String> {
    let drafts = role(boxes, "drafts").ok_or_else(|| Error::Protocol("there is no Drafts mailbox".into()))?;
    let result = client
        .set(&[MAIL], "Email", account, json!({ "create": { "draft": draft.email(&drafts.id, true) } }), json!({}))
        .await?;
    result
        .pointer("/created/draft/id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Protocol("the draft has no id".into()))
}

/// Stores the message in Drafts and submits it as `identity`; once sent it moves to Sent and is no draft any more
/// (RFC 8621, 7.5).
pub async fn send(client: &Client, account: &str, identity: &Identity, draft: &Draft, boxes: &[Mailbox]) -> Result<()> {
    let drafts = role(boxes, "drafts").ok_or_else(|| Error::Protocol("there is no Drafts mailbox".into()))?;
    let mut update = json!({ "keywords/$draft": null });
    if let Some(sent) = role(boxes, "sent") {
        update["mailboxIds"] = json!({ sent.id.as_str(): true });
    }
    let mut draft = draft.clone();
    draft.from = Some(EmailAddress {
        name: (!identity.name.is_empty()).then(|| identity.name.clone()),
        email: identity.email.clone(),
    });
    let responses = client
        .request(
            &[MAIL, SUBMISSION],
            vec![
                (
                    "Email/set",
                    json!({ "accountId": account, "create": { "draft": draft.email(&drafts.id, true) } }),
                    "e",
                ),
                (
                    "EmailSubmission/set",
                    json!({
                        "accountId": account,
                        "create": { "send": { "identityId": identity.id, "emailId": "#draft" } },
                        "onSuccessUpdateEmail": { "#send": update },
                    }),
                    "s",
                ),
            ],
        )
        .await?;
    for (_, result, _) in &responses.0 {
        set_error(result)?;
    }
    Ok(())
}

/// Uploads a file to attach.
pub async fn attach(client: &Client, account: &str, path: &std::path::Path) -> Result<Attachment> {
    let file = tokio::fs::File::open(path).await?;
    let size = file.metadata().await?.len();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("attachment").to_owned();
    let kind = crate::files::media_type(&name);
    let upload = client.upload(account, kind, file, size, |_, _| {}).await?;
    Ok(Attachment { blob_id: upload.blob_id, kind: kind.to_owned(), name, size: upload.size })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let list = parse_addresses("Alice <a@x.example>, b@x.example; \"Doe, Jane\" <j@x.example>");
        assert_eq!(
            list,
            vec![
                EmailAddress { name: Some("Alice".into()), email: "a@x.example".into() },
                EmailAddress { name: None, email: "b@x.example".into() },
                EmailAddress { name: Some("Doe, Jane".into()), email: "j@x.example".into() },
            ]
        );
        assert_eq!(format_addresses(&list), "Alice <a@x.example>, b@x.example, \"Doe, Jane\" <j@x.example>");
        assert!(parse_addresses(" , ").is_empty());
    }

    #[test]
    fn html_becomes_text() {
        let text = html_to_text("<p>Hello <b>you</b></p><script>alert(1)</script><p>Second</p>", 80);
        assert!(text.contains("Hello") && text.contains("you"), "{text}");
        assert!(text.contains("Second"));
        assert!(!text.contains("alert"));
    }

    #[test]
    fn draft_email() {
        let draft = Draft {
            to: parse_addresses("b@x.example"),
            subject: "Hi".into(),
            body: "Text".into(),
            in_reply_to: vec!["m1@x".into()],
            attachments: vec![Attachment {
                blob_id: "B".into(),
                kind: "text/plain".into(),
                name: "a.txt".into(),
                size: 1,
            }],
            ..Draft::default()
        };
        let email = draft.email("D", true);
        assert_eq!(email["mailboxIds"], json!({ "D": true }));
        assert_eq!(email["keywords"], json!({ "$seen": true, "$draft": true }));
        assert_eq!(email["inReplyTo"], json!(["m1@x"]));
        assert_eq!(email["attachments"][0]["blobId"], "B");
        assert!(email.get("cc").is_none());
    }
}
