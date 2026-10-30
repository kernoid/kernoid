// SPDX-License-Identifier: MIT
//! End-to-end encrypted mail (RFC 0006, 4–5) over kernoid's extension `https://kernoid.dev/jmap/openpgp`: the
//! account's keys with the protected copies of their secret keys (`OpenPgpKey/get`), unlocked here with the recovery
//! code and kept only in memory; the public keys of others (`OpenPgpKey/lookup`), looked up once per run; the summaries
//! of encrypted emails for the list; encrypted emails downloaded, decrypted and read here – never through the server's
//! `Email/parse` –; and messages built, encrypted and signed here, imported into Drafts with their summary and submitted
//! with an envelope, so that the server sees neither text nor attachments. The cryptography is all `kernoid-e2e`'s.

use std::{
    collections::BTreeMap,
    hash::{BuildHasher, Hasher},
    io::Cursor,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use kernoid_e2e::{
    PublicKey, SecretKey,
    compose::{self, Mailbox as Address},
    keys::normalize_recovery_code,
    mime,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    Client, Error, MAIL, Result, SUBMISSION,
    mail::{BodyPart, BodyValue, Draft, Email, EmailAddress, EmailSummary, Identity, Inner, Mailbox, Sealed, role},
    set_error,
};

pub const OPENPGP: &str = "https://kernoid.dev/jmap/openpgp";

/// A protected copy of a secret key (RFC 0006, 4.2), base64.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyCopy {
    #[serde(default)]
    pub protected: String,
    #[serde(default)]
    pub salt: Option<String>,
}

/// One of the account's keys (`OpenPgpKey/get`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    /// The fingerprint.
    pub id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub retired: Option<String>,
    #[serde(default)]
    pub copies: BTreeMap<String, KeyCopy>,
}

/// How a message goes out.
#[derive(Debug, Clone)]
pub enum Plan {
    /// End-to-end encrypted to these keys – every recipient's and the sender's own – and signed.
    Sealed(Vec<PublicKey>),
    /// As before, with the reason it is not encrypted.
    Plain(String),
}

/// A message to store: from whom, in which account, the files to attach (read here, never uploaded as they are).
#[derive(Debug, Clone, Copy)]
pub struct Outgoing<'a> {
    pub account: &'a str,
    pub identity: &'a Identity,
    pub draft: &'a Draft,
    pub files: &'a [PathBuf],
    pub boxes: &'a [Mailbox],
}

/// What this run knows of end-to-end encryption: whether the server has it, the account's keys, those unlocked here,
/// and the public keys of others looked up so far.
#[derive(Default)]
pub struct E2e {
    pub available: bool,
    pub keys: Vec<Key>,
    /// The key in use, unlocked.
    current: Option<SecretKey>,
    /// Every key unlocked: the one in use and retired ones, for mail encrypted to them before.
    unlocked: Vec<SecretKey>,
    /// Public keys by address (lower case); an address without any has none.
    known: BTreeMap<String, Vec<PublicKey>>,
}

impl std::fmt::Debug for E2e {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E2e")
            .field("available", &self.available)
            .field("keys", &self.keys.len())
            .field("unlocked", &self.current.is_some())
            .finish_non_exhaustive()
    }
}

fn decode(text: &str) -> Result<Vec<u8>> {
    STANDARD.decode(text).map_err(|_| Error::Protocol("not base64".into()))
}

fn list<T: serde::de::DeserializeOwned>(result: &Value) -> Result<Vec<T>> {
    serde_json::from_value(result.get("list").cloned().unwrap_or(Value::Null))
        .map_err(|error| Error::Protocol(error.to_string()))
}

impl E2e {
    /// Reads the account's keys – nothing if the server has no end-to-end extension.
    pub fn load(client: &Client) -> Result<E2e> {
        if !client.session.capabilities.contains_key(OPENPGP) {
            return Ok(E2e::default());
        }
        let account = client.primary(OPENPGP)?;
        let result = client.call(&[OPENPGP], "OpenPgpKey/get", json!({ "accountId": account }))?;
        Ok(E2e { available: true, keys: list(&result)?, ..E2e::default() })
    }

    /// The key in use (not retired).
    pub fn current_key(&self) -> Option<&Key> {
        self.keys.iter().find(|key| key.retired.is_none())
    }

    pub fn has_key(&self) -> bool {
        self.current_key().is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.current.is_some()
    }

    /// Unlocks the key in use with the recovery code (as typed: separators and case do not matter) – and retired keys
    /// whose copy the same code opens. They stay in this process's memory only.
    pub fn unlock(&mut self, code: &str) -> Result<()> {
        let key = self.current_key().ok_or_else(|| Error::E2e("this account has no key".into()))?;
        let copy =
            key.copies.get("recovery").ok_or_else(|| Error::E2e("the key has no copy for a recovery code".into()))?;
        let code = normalize_recovery_code(code);
        let current = SecretKey::unlock(&decode(&copy.protected)?, &code)?;
        if !current.fingerprint().eq_ignore_ascii_case(&key.id) {
            return Err(Error::E2e("the copy is not of the key in use".into()));
        }
        let mut unlocked = vec![current.clone()];
        for key in self.keys.iter().filter(|key| key.retired.is_some()) {
            let Some(copy) = key.copies.get("recovery") else { continue };
            if let Ok(secret) = decode(&copy.protected).and_then(|p| Ok(SecretKey::unlock(&p, &code)?)) {
                unlocked.push(secret);
            }
        }
        self.unlocked = unlocked;
        self.current = Some(current);
        Ok(())
    }

    /// Forgets the unlocked keys.
    pub fn lock(&mut self) {
        self.current = None;
        self.unlocked.clear();
    }

    /// The public keys of `addresses` (asked once per run).
    pub fn lookup(&mut self, client: &Client, addresses: &[String]) -> Result<BTreeMap<String, Vec<PublicKey>>> {
        let mut wanted: Vec<String> = addresses.iter().map(|a| a.to_lowercase()).collect();
        wanted.sort();
        wanted.dedup();
        wanted.retain(|address| !self.known.contains_key(address));
        if !wanted.is_empty() {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Found {
                public_key: String,
            }
            #[derive(Deserialize)]
            struct Entry {
                email: String,
                #[serde(default)]
                keys: Vec<Found>,
            }
            let account = client.primary(OPENPGP)?;
            let result =
                client.call(&[OPENPGP], "OpenPgpKey/lookup", json!({ "accountId": account, "emails": wanted }))?;
            for entry in list::<Entry>(&result)? {
                // Keys this app cannot use are left out.
                let keys =
                    entry.keys.iter().filter_map(|key| PublicKey::parse(&decode(&key.public_key).ok()?).ok()).collect();
                self.known.insert(entry.email.to_lowercase(), keys);
            }
            for address in wanted {
                self.known.entry(address).or_default();
            }
        }
        Ok(addresses
            .iter()
            .map(|a| (a.to_lowercase(), self.known.get(&a.to_lowercase()).cloned().unwrap_or_default()))
            .collect())
    }

    fn secrets(&self) -> Vec<&SecretKey> {
        self.unlocked.iter().collect()
    }

    /// Fills in subject, preview and attachments of an encrypted email from its summary, once the key is unlocked.
    pub fn open_summary(&self, email: &mut EmailSummary) {
        if !email.encrypted || email.opened || self.unlocked.is_empty() {
            return;
        }
        let Some(sealed) = email.encrypted_summary.as_deref().and_then(|s| STANDARD.decode(s).ok()) else { return };
        // Encrypted to a key not unlocked here: it stays locked.
        if let Ok(summary) = mime::decrypt_summary(&sealed, &self.secrets()) {
            email.subject = summary.subject;
            email.preview = summary.preview;
            email.has_attachment = summary.has_attachment;
            email.opened = true;
        }
    }

    /// An email to read: an encrypted one downloaded, decrypted and read into its parts here, its signature checked
    /// against its sender's keys – locked if the key is not unlocked or does not open it. Other emails as they are.
    pub fn open(&mut self, client: &Client, account: &str, mut email: Email) -> Result<Email> {
        if !email.summary.encrypted {
            return Ok(email);
        }
        self.open_summary(&mut email.summary);
        let mut locked = email.clone();
        locked.text_body.clear();
        locked.html_body.clear();
        locked.attachments.clear();
        locked.body_values.clear();
        locked.sealed = Some(Sealed { locked: true, ..Sealed::default() });
        let Some(blob) = email.blob_id.clone().filter(|_| self.is_unlocked()) else { return Ok(locked) };
        let mut raw = Vec::new();
        client.download(account, &blob, "message.eml", "message/rfc822", &mut raw, &mut |_, _| {})?;
        let senders: Vec<String> = email.summary.from.iter().flatten().map(|a| a.email.clone()).collect();
        let senders: Vec<PublicKey> = if senders.is_empty() {
            Vec::new()
        } else {
            self.lookup(client, &senders).map(|found| found.into_values().flatten().collect()).unwrap_or_default()
        };
        let senders: Vec<&PublicKey> = senders.iter().collect();
        let Ok(opened) = mime::decrypt_message(&raw, &self.secrets(), &senders) else { return Ok(locked) };
        let Ok(parsed) = compose::parse(&opened.data) else { return Ok(locked) };
        let addresses = |list: Vec<Address>| -> Vec<EmailAddress> {
            list.into_iter().map(|a| EmailAddress { name: a.name, email: a.email }).collect()
        };
        let part = |id: &str, kind: &str, size: usize| BodyPart {
            part_id: Some(id.to_owned()),
            blob_id: None,
            kind: kind.to_owned(),
            name: None,
            size: size as u64,
            inner: None,
        };
        email.summary.subject = parsed.subject;
        if !parsed.from.is_empty() {
            email.summary.from = Some(addresses(parsed.from));
        }
        if !parsed.to.is_empty() {
            email.summary.to = Some(addresses(parsed.to));
        }
        email.cc = Some(addresses(parsed.cc));
        email.reply_to = Some(addresses(parsed.reply_to));
        email.sent_at = parsed.sent_at.or(email.sent_at);
        email.message_id = parsed.message_id.map(|id| vec![id]).or(email.message_id);
        if !parsed.references.is_empty() {
            email.references = Some(parsed.references);
        }
        email.text_body.clear();
        email.html_body.clear();
        email.body_values.clear();
        if let Some(text) = parsed.text {
            email.text_body.push(part("text", "text/plain", text.len()));
            email.body_values.insert("text".into(), BodyValue { value: text });
        }
        if let Some(html) = parsed.html {
            email.html_body.push(part("html", "text/html", html.len()));
            email.body_values.insert("html".into(), BodyValue { value: html });
        } else {
            email.html_body = email.text_body.clone();
        }
        email.attachments = parsed
            .attachments
            .into_iter()
            .map(|p| BodyPart {
                part_id: None,
                blob_id: None,
                kind: p.media_type,
                name: p.name,
                size: p.size as u64,
                inner: Some(p.index),
            })
            .collect();
        email.summary.has_attachment = !email.attachments.is_empty();
        email.inner = Some(Inner(opened.data));
        email.sealed = Some(Sealed { locked: false, signed: opened.signed, verified: opened.verified_by.is_some() });
        Ok(email)
    }

    /// The key a message from `identity` in `account` is encrypted and signed with: the unlocked key in use, if the
    /// account is the user's own and the key has the address – else why not.
    fn own_key(&self, client: &Client, account: &str, identity: &Identity) -> std::result::Result<&SecretKey, String> {
        if !self.available {
            return Err("the server has no end-to-end encryption".into());
        }
        let Some(current) = &self.current else {
            return Err(if self.has_key() {
                "your key is locked (K unlocks it)".into()
            } else {
                "your account has no key (made in the web app)".into()
            });
        };
        if client.session.primary(MAIL) != Some(account) {
            return Err("it is not sent from your own account".into());
        }
        if !current.public().addresses().iter().any(|a| a.eq_ignore_ascii_case(&identity.email)) {
            return Err(format!("your key is not for {}", identity.email));
        }
        Ok(current)
    }

    /// How a message goes out: end-to-end encrypted if the key is unlocked, it is sent from the user's own account
    /// as an address of the key, and every recipient has a key (RFC 0006, 5.3) – else as before.
    pub fn plan(&mut self, client: &Client, account: &str, identity: &Identity, draft: &Draft) -> Plan {
        let own = match self.own_key(client, account, identity) {
            Ok(key) => key.public(),
            Err(reason) => return Plan::Plain(reason),
        };
        // An OpenPGP message names the key of each recipient: Bcc recipients would be seen by all.
        if !draft.bcc.is_empty() {
            return Plan::Plain("it has Bcc recipients, whom an encrypted message would show".into());
        }
        let addresses: Vec<String> = draft.to.iter().chain(&draft.cc).map(|a| a.email.clone()).collect();
        if addresses.is_empty() {
            return Plan::Plain("it has no recipients".into());
        }
        let found = match self.lookup(client, &addresses) {
            Ok(found) => found,
            Err(error) => return Plan::Plain(format!("the keys could not be looked up: {error}")),
        };
        let mut keys = Vec::new();
        for (address, list) in found {
            let usable: Vec<PublicKey> = list.into_iter().filter(PublicKey::can_encrypt).collect();
            if usable.is_empty() {
                return Plan::Plain(format!("{address} has no key"));
            }
            keys.extend(usable);
        }
        keys.push(own);
        Plan::Sealed(keys)
    }

    /// Whether a draft is kept encrypted to the user's own key – or why not.
    pub fn draft_plan(&self, client: &Client, account: &str, identity: &Identity, draft: &Draft) -> Plan {
        match self.own_key(client, account, identity) {
            Ok(_) if !draft.bcc.is_empty() => Plan::Plain("an encrypted draft cannot keep Bcc".into()),
            Ok(key) => Plan::Sealed(vec![key.public()]),
            Err(reason) => Plan::Plain(reason),
        }
    }

    /// Sends end-to-end encrypted to `recipients` (from `plan`): the message built, encrypted and signed here,
    /// uploaded as it is, imported into Drafts with its summary encrypted to the sender, submitted with an envelope
    /// (To and Cc), and moved to Sent once sent.
    pub fn send(&self, client: &Client, outgoing: Outgoing<'_>, recipients: &[PublicKey]) -> Result<()> {
        self.store(client, outgoing, recipients, true)
    }

    /// Keeps a draft encrypted to `keys` (from `draft_plan`).
    pub fn keep(&self, client: &Client, outgoing: Outgoing<'_>, keys: &[PublicKey]) -> Result<()> {
        self.store(client, outgoing, keys, false)
    }

    fn store(&self, client: &Client, outgoing: Outgoing<'_>, recipients: &[PublicKey], submit: bool) -> Result<()> {
        let Outgoing { account, identity, draft, files, boxes } = outgoing;
        let own = self.own_key(client, account, identity).map_err(Error::E2e)?;
        let drafts = role(boxes, "drafts").ok_or_else(|| Error::Protocol("there is no Drafts mailbox".into()))?;
        let mut attachments = Vec::new();
        // Forwarded files lie in the account already; they go inside the encrypted message.
        for file in &draft.attachments {
            let mut data = Vec::new();
            client.download(account, &file.blob_id, &file.name, &file.kind, &mut data, &mut |_, _| {})?;
            attachments.push(compose::Attachment {
                name: file.name.clone(),
                media_type: file.kind.clone(),
                data: STANDARD.encode(data),
            });
        }
        for path in files {
            let data = std::fs::read(path).map_err(|error| Error::Protocol(format!("{}: {error}", path.display())))?;
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("attachment").to_owned();
            let media_type = super::files::media_type(&name).to_owned();
            attachments.push(compose::Attachment { name, media_type, data: STANDARD.encode(data) });
        }
        let address = |a: &EmailAddress| Address { name: a.name.clone(), email: a.email.clone() };
        let strip = |ids: &[String]| -> Vec<String> {
            ids.iter().map(|id| id.trim().trim_start_matches('<').trim_end_matches('>').to_owned()).collect()
        };
        let domain = identity.email.rsplit_once('@').map(|(_, d)| d).unwrap_or("localhost");
        let message = compose::Draft {
            from: Some(Address {
                name: (!identity.name.is_empty()).then(|| identity.name.clone()),
                email: identity.email.clone(),
            }),
            to: draft.to.iter().map(address).collect(),
            cc: draft.cc.iter().map(address).collect(),
            reply_to: Vec::new(),
            subject: draft.subject.clone(),
            message_id: format!("{}@{domain}", random_id()),
            in_reply_to: strip(&draft.in_reply_to),
            references: strip(&draft.references),
            date: chrono::Local::now().to_rfc2822(),
            text: draft.body.clone(),
            html: None,
            attachments,
        };
        let raw = compose::build(&message)?;
        let recipients: Vec<&PublicKey> = recipients.iter().collect();
        let encrypted = mime::encrypt_message(&raw, &recipients, Some(own))?;
        let summary = mime::encrypted_summary(&raw, &[&own.public()])?;
        let size = encrypted.len() as u64;
        let upload = client.upload(account, "message/rfc822", Cursor::new(encrypted), size, &mut |_, _| {})?;
        let mut calls = vec![(
            "Email/import",
            json!({ "accountId": account, "emails": { "draft": {
                "blobId": upload.blob_id, "mailboxIds": { drafts.id.as_str(): true },
                "keywords": { "$draft": true, "$seen": true }, "kernoid:encryptedSummary": STANDARD.encode(summary),
            } } }),
            "e",
        )];
        if submit {
            let mut update = json!({ "keywords/$draft": null });
            if let Some(sent) = role(boxes, "sent") {
                update["mailboxIds"] = json!({ sent.id.as_str(): true });
            }
            let rcpt: Vec<Value> =
                draft.to.iter().chain(&draft.cc).map(|a| json!({ "email": a.email, "parameters": null })).collect();
            calls.push((
                "EmailSubmission/set",
                json!({
                    "accountId": account,
                    "create": { "send": {
                        "identityId": identity.id, "emailId": "#draft",
                        "envelope": { "mailFrom": { "email": identity.email, "parameters": null }, "rcptTo": rcpt },
                    } },
                    "onSuccessUpdateEmail": { "#send": update },
                }),
                "s",
            ));
        }
        let responses = client.request(&[MAIL, SUBMISSION, OPENPGP], calls)?;
        for (_, result, _) in &responses.0 {
            set_error(result)?;
        }
        Ok(())
    }
}

/// 128 bits for a `Message-ID` – unique, not secret: the standard library's per-process random hash keys over the
/// time.
fn random_id() -> String {
    let state = std::collections::hash_map::RandomState::new();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    let half = |n: u8| {
        let mut hasher = state.build_hasher();
        hasher.write_u128(now);
        hasher.write_u32(std::process::id());
        hasher.write_u8(n);
        hasher.finish()
    };
    format!("{:016x}{:016x}", half(0), half(1))
}
