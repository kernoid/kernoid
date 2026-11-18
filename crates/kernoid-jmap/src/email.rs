// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Email/get` and `Email/parse` (RFC 8621, 4.2 and 4.9): what PostgreSQL holds of an email, and – for the body and
//! headers – the raw message, read with mail-parser.

use std::collections::BTreeMap;

use kernoid_mail::{AddressInfo, EmailInfo};
use mail_parser::{AddressList, HeaderValue, Message, MessageParser, MessagePart, PartKind, TextList};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    MAX_OBJECTS_IN_GET,
    blob::{BlobId, part_at, part_index},
    mailbox::{ids, mailbox_ids, properties},
    request::{Context, MethodError, MethodResult},
};

pub(crate) const PROPERTIES: [&str; 24] = [
    "id",
    "blobId",
    "threadId",
    "mailboxIds",
    "keywords",
    "size",
    "receivedAt",
    "messageId",
    "inReplyTo",
    "references",
    "sender",
    "from",
    "to",
    "cc",
    "bcc",
    "replyTo",
    "subject",
    "sentAt",
    "hasAttachment",
    "preview",
    "bodyValues",
    "textBody",
    "htmlBody",
    "attachments",
];

pub(crate) const BODY_PROPERTIES: [&str; 10] =
    ["partId", "blobId", "size", "name", "type", "charset", "disposition", "cid", "language", "location"];

/// Properties only the raw message can answer.
fn needs_message(property: &str) -> bool {
    matches!(property, "bodyStructure" | "bodyValues" | "textBody" | "htmlBody" | "attachments" | "headers")
        || property.starts_with("header:")
}

/// How much of the body `Email/get` returns.
pub(crate) struct BodyOptions {
    pub properties: Vec<String>,
    pub text: bool,
    pub html: bool,
    pub all: bool,
    pub max_bytes: usize,
}

impl BodyOptions {
    pub fn from(args: &Map<String, Value>) -> Self {
        Self {
            properties: properties(args, "bodyProperties", &BODY_PROPERTIES),
            text: args.get("fetchTextBodyValues").and_then(Value::as_bool).unwrap_or(false),
            html: args.get("fetchHTMLBodyValues").and_then(Value::as_bool).unwrap_or(false),
            all: args.get("fetchAllBodyValues").and_then(Value::as_bool).unwrap_or(false),
            max_bytes: args.get("maxBodyValueBytes").and_then(Value::as_u64).unwrap_or(0) as usize,
        }
    }
}

fn address_list(list: &[AddressInfo]) -> Value {
    json!(list.iter().map(|address| json!({ "name": address.name, "email": address.email })).collect::<Vec<_>>())
}

fn mailboxes<'x>(mailboxes: impl Iterator<Item = mail_parser::Mailbox<'x>>) -> Value {
    json!(
        mailboxes.filter_map(|addr| Some(json!({ "name": addr.name(), "email": addr.address()? }))).collect::<Vec<_>>()
    )
}

fn parsed_addresses(address: Option<AddressList<'_>>) -> Value {
    address.map_or(Value::Null, |address| mailboxes(address.mailboxes()))
}

fn text_list(list: Option<TextList<'_>>) -> Value {
    list.filter(|list| !list.is_empty()).map_or(Value::Null, |list| json!(list.iter().collect::<Vec<_>>()))
}

fn id_list(value: &HeaderValue<'_>) -> Value {
    match value {
        HeaderValue::Text(id) => json!([id]),
        HeaderValue::TextList(ids) => json!(ids.iter().collect::<Vec<_>>()),
        _ => Value::Null,
    }
}

fn nonempty(list: &[String]) -> Value {
    if list.is_empty() { Value::Null } else { json!(list) }
}

fn keywords(list: &[String]) -> Value {
    Value::Object(list.iter().map(|keyword| (keyword.clone(), Value::Bool(true))).collect())
}

/// A header's value in one of the forms of RFC 8621, 4.1.2.
fn header_form(part: &MessagePart<'_>, property: &str) -> Value {
    let mut pieces = property.splitn(4, ':').skip(1);
    let name = pieces.next().unwrap_or_default();
    let mut form = "asRaw";
    let mut all = false;
    for piece in pieces {
        if piece == "all" {
            all = true;
        } else {
            form = piece;
        }
    }
    let values: Vec<Value> = part
        .headers()
        .iter()
        .filter(|header| header.raw_name().eq_ignore_ascii_case(name))
        .map(|header| {
            let value = header.value();
            match form {
                "asRaw" => json!(String::from_utf8_lossy(header.raw_value())),
                "asText" => match &value {
                    HeaderValue::Text(text) => json!(text.trim()),
                    HeaderValue::TextList(list) => json!(list.iter().collect::<Vec<_>>().join(", ")),
                    _ => Value::Null,
                },
                "asAddresses" => parsed_addresses(value.as_address()),
                "asGroupedAddresses" => match value.as_address() {
                    Some(address) => json!(
                        address
                            .groups()
                            .map(|(name, members)| json!({ "name": name, "addresses": mailboxes(members) }))
                            .collect::<Vec<_>>()
                    ),
                    None => Value::Null,
                },
                "asMessageIds" => id_list(&value),
                "asDate" => value.as_datetime().map_or(Value::Null, |date| json!(date.to_rfc3339())),
                "asURLs" => match &value {
                    HeaderValue::Text(text) => json!(
                        text.split(',')
                            .filter_map(|url| url.trim().strip_prefix('<').and_then(|url| url.strip_suffix('>')))
                            .collect::<Vec<_>>()
                    ),
                    HeaderValue::TextList(list) => json!(list.iter().collect::<Vec<_>>()),
                    HeaderValue::Address(list) => {
                        json!(list.mailboxes().filter_map(|mailbox| mailbox.address()).collect::<Vec<_>>())
                    }
                    _ => Value::Null,
                },
                _ => Value::Null,
            }
        })
        .collect();
    if all { json!(values) } else { values.into_iter().last().unwrap_or(Value::Null) }
}

/// One body part (RFC 8621, 4.1.4) with the properties asked for.
fn body_part(message: &Message<'_>, part: MessagePart<'_>, email: Option<Uuid>, options: &BodyOptions) -> Value {
    let Some(index) = part_index(message, &part) else { return Value::Null };
    let multipart = part.is_multipart();
    let mut out = Map::new();
    for property in &options.properties {
        let value = match property.as_str() {
            "partId" if !multipart => json!(index.to_string()),
            "blobId" if !multipart => email.map_or(Value::Null, |email| json!(BlobId::Part(email, index).to_string())),
            "size" => json!(part.decoded_len()),
            "headers" => headers(&part),
            "name" => json!(part.attachment_name()),
            "type" => json!(match part.content_type() {
                Some(kind) => format!("{}/{}", kind.ctype(), kind.subtype().unwrap_or("plain")).to_lowercase(),
                None if multipart => "multipart/mixed".into(),
                None => "text/plain".into(),
            }),
            "charset" => match part.content_type().and_then(|kind| kind.attribute("charset")) {
                Some(charset) => json!(charset),
                None if part.is_text() => json!("us-ascii"),
                None => Value::Null,
            },
            "disposition" => json!(part.content_disposition().map(|disposition| disposition.ctype())),
            "cid" => json!(part.content_id()),
            "language" => text_list(part.content_language()),
            "location" => json!(part.content_location()),
            "subParts" if multipart => Value::Null,
            property if property.starts_with("header:") => header_form(&part, property),
            _ => continue,
        };
        out.insert(property.clone(), value);
    }
    if multipart {
        out.insert(
            "subParts".into(),
            json!(part.children().map(|child| body_part(message, child, email, options)).collect::<Vec<_>>()),
        );
    }
    Value::Object(out)
}

/// The text of a part for `bodyValues`, cut at `max` bytes (on a character boundary) when `max` is set.
fn body_value(part: &MessagePart<'_>, max: usize) -> Value {
    let (text, problems) = match part.kind() {
        PartKind::Text | PartKind::Html => part
            .text_checked()
            .map_or_else(|| (String::new(), true), |(text, problems)| (text.into_owned(), !problems.is_empty())),
        _ => (String::new(), false),
    };
    let truncated = max > 0 && text.len() > max;
    let value = if truncated {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_owned()
    } else {
        text
    };
    json!({ "value": value, "isEncodingProblem": problems, "isTruncated": truncated })
}

/// The header fields of a part as written (RFC 8621, 4.1.3).
fn headers(part: &MessagePart<'_>) -> Value {
    json!(
        part.headers()
            .iter()
            .map(|header| json!({
                "name": header.raw_name(),
                "value": String::from_utf8_lossy(header.raw_value()),
            }))
            .collect::<Vec<_>>()
    )
}

/// The properties of an email that come from its raw message.
pub(crate) fn from_message(
    raw: &[u8],
    message: &Message<'_>,
    email: Option<Uuid>,
    property: &str,
    options: &BodyOptions,
) -> Option<Value> {
    let list = |parts: &mut dyn Iterator<Item = MessagePart<'_>>| {
        json!(parts.map(|part| body_part(message, part, email, options)).collect::<Vec<_>>())
    };
    let root = message.root();
    Some(match property {
        "bodyStructure" => body_part(message, root.root_part(), email, options),
        "textBody" => list(&mut root.text_body()),
        "htmlBody" => list(&mut root.html_body()),
        "attachments" => list(&mut root.attachments()),
        "headers" => headers(&root.root_part()),
        "bodyValues" => {
            let mut wanted: BTreeMap<usize, ()> = BTreeMap::new();
            let mut want = |parts: &mut dyn Iterator<Item = MessagePart<'_>>| {
                wanted.extend(parts.filter_map(|part| part_index(message, &part)).map(|index| (index, ())));
            };
            if options.text || options.all {
                want(&mut root.text_body());
            }
            if options.html || options.all {
                want(&mut root.html_body());
            }
            Value::Object(
                wanted
                    .keys()
                    .filter_map(|index| {
                        let part = part_at(message, *index)?;
                        part.is_text().then(|| (index.to_string(), body_value(&part, options.max_bytes)))
                    })
                    .collect(),
            )
        }
        "messageId" => message.message_id().map_or(Value::Null, |id| json!([id])),
        "inReplyTo" => text_list(message.in_reply_to()),
        "references" => text_list(message.references()),
        "sender" => parsed_addresses(message.sender()),
        "from" => parsed_addresses(message.from()),
        "to" => parsed_addresses(message.to()),
        "cc" => parsed_addresses(message.cc()),
        "bcc" => parsed_addresses(message.bcc()),
        "replyTo" => parsed_addresses(message.reply_to()),
        "subject" => json!(message.subject()),
        "sentAt" => message.date().map_or(Value::Null, |date| json!(date.to_rfc3339())),
        "hasAttachment" => json!(message.has_attachments()),
        "preview" => {
            json!(message.body_preview(256).map(|preview| preview.split_whitespace().collect::<Vec<_>>().join(" ")))
        }
        "size" => json!(raw.len()),
        property if property.starts_with("header:") => header_form(&root.root_part(), property),
        _ => return None,
    })
}

/// The properties of a stored email.
fn email_object(
    info: &EmailInfo,
    properties: &[String],
    raw: Option<(&[u8], &Message<'_>)>,
    options: &BodyOptions,
) -> Value {
    let mut out = Map::new();
    for property in properties {
        let value = match property.as_str() {
            "id" => json!(info.id.to_string()),
            "blobId" => json!(BlobId::Email(info.id).to_string()),
            "threadId" => json!(info.thread_id.to_string()),
            "mailboxIds" => mailbox_ids(&info.mailboxes),
            "keywords" => keywords(&info.keywords),
            "size" => json!(info.size),
            "receivedAt" => json!(format!("{:.0}", info.received_at)),
            "messageId" => info.message_id.as_ref().map_or(Value::Null, |id| json!([id])),
            "inReplyTo" => nonempty(&info.in_reply_to),
            "references" => nonempty(&info.references),
            "sender" => address_list(&info.sender),
            "from" => address_list(&info.from),
            "to" => address_list(&info.to),
            "cc" => address_list(&info.cc),
            "bcc" => address_list(&info.bcc),
            "replyTo" => address_list(&info.reply_to),
            "subject" => json!(info.subject),
            "sentAt" => info.sent_at.map_or(Value::Null, |at| json!(format!("{:.0}", at))),
            "hasAttachment" => json!(info.has_attachment),
            "preview" => json!(info.preview),
            // kernoid's own (RFC 0006, 5.2): whether the message is end-to-end encrypted, and its summary encrypted to
            // the same keys.
            "kernoid:encrypted" => json!(info.encrypted),
            "kernoid:encryptedSummary" => {
                use base64::Engine;
                info.encrypted_summary
                    .as_deref()
                    .map_or(Value::Null, |s| json!(base64::engine::general_purpose::STANDARD.encode(s)))
            }
            property => match raw {
                Some((raw, message)) => match from_message(raw, message, Some(info.id), property, options) {
                    Some(value) => value,
                    None => continue,
                },
                None => continue,
            },
        };
        out.insert(property.clone(), value);
    }
    out.insert("id".into(), json!(info.id.to_string()));
    Value::Object(out)
}

impl Context<'_> {
    pub async fn email_get(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let mail = self.jmap.mail();
        let wanted = match ids(&args)? {
            Some(ids) => ids,
            None => mail.email_ids(account).await?.into_iter().map(|id| id.to_string()).collect(),
        };
        if wanted.len() > MAX_OBJECTS_IN_GET {
            return Err(MethodError::new("requestTooLarge", format!("at most {MAX_OBJECTS_IN_GET} at once")));
        }
        let properties = properties(&args, "properties", &PROPERTIES);
        let options = BodyOptions::from(&args);
        let parse = properties.iter().any(|property| needs_message(property));
        let resolved: Vec<(String, Option<Uuid>)> = wanted.into_iter().map(|id| (id.clone(), self.id(&id))).collect();
        let mut found = mail.emails(account, &resolved.iter().filter_map(|(_, id)| *id).collect::<Vec<_>>()).await?;
        // Others see the emails of mailboxes they may read, in the mailboxes they may see.
        if !access.owned {
            found.retain(|email| crate::blob::readable(email, &access));
            for email in &mut found {
                email.mailboxes.retain(|(mailbox, _)| access.mailbox(*mailbox).contains(kernoid_mail::Rights::LOOKUP));
            }
        }
        let mut list = Vec::new();
        let mut not_found = Vec::new();
        for (asked, id) in resolved {
            let Some(info) = id.and_then(|id| found.iter().find(|info| info.id == id)) else {
                not_found.push(asked);
                continue;
            };
            if parse {
                let raw = mail.raw_email(account, info.id).await?;
                let message = MessageParser::new()
                    .parse(&raw[..])
                    .ok_or_else(|| MethodError::server_fail("an unparsable message"))?;
                list.push(email_object(info, &properties, Some((&raw, &message)), &options));
            } else {
                list.push(email_object(info, &properties, None, &options));
            }
        }
        let state = mail.state(account).await?;
        Ok(vec![(
            "Email/get".into(),
            json!({ "accountId": account.to_string(), "state": state.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    pub async fn email_parse(&self, args: Map<String, Value>) -> MethodResult {
        let access = self.access(&args).await?;
        let account = access.owner;
        let blobs = ids_of(&args, "blobIds")?;
        let properties = properties(
            &args,
            "properties",
            &[
                "messageId",
                "inReplyTo",
                "references",
                "sender",
                "from",
                "to",
                "cc",
                "bcc",
                "replyTo",
                "subject",
                "sentAt",
                "hasAttachment",
                "preview",
                "bodyValues",
                "textBody",
                "htmlBody",
                "attachments",
            ],
        );
        let options = BodyOptions::from(&args);
        let (mut parsed, mut not_parsable, mut not_found) = (Map::new(), Vec::new(), Vec::new());
        for blob in blobs {
            let Some(raw) = self.jmap.blob_bytes(&access, &blob).await else {
                not_found.push(blob);
                continue;
            };
            let Some(message) = MessageParser::new().parse(&raw[..]) else {
                not_parsable.push(blob);
                continue;
            };
            let mut out = Map::new();
            for property in &properties {
                if let Some(value) = from_message(&raw, &message, None, property, &options) {
                    out.insert(property.clone(), value);
                } else if matches!(
                    property.as_str(),
                    "id" | "threadId" | "mailboxIds" | "keywords" | "receivedAt" | "blobId"
                ) {
                    out.insert(property.clone(), if property == "blobId" { json!(blob) } else { Value::Null });
                }
            }
            parsed.insert(blob, Value::Object(out));
        }
        Ok(vec![(
            "Email/parse".into(),
            json!({ "accountId": account.to_string(), "parsed": parsed, "notParsable": not_parsable, "notFound": not_found }),
        )])
    }
}

/// A list of strings argument.
pub(crate) fn ids_of(args: &Map<String, Value>, key: &str) -> Result<Vec<String>, MethodError> {
    match args.get(key) {
        Some(Value::Array(list)) => Ok(list.iter().filter_map(Value::as_str).map(str::to_owned).collect()),
        _ => Err(MethodError::invalid(format!("{key} is a list"))),
    }
}
