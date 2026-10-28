// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Email/get` and `Email/parse` (RFC 8621, 4.2 and 4.9): what PostgreSQL holds of an email, and – for the body and
//! headers – the raw message, read with mail-parser.

use std::collections::BTreeMap;

use kernoid_mail::{AddressInfo, EmailInfo};
use mail_parser::{Address, HeaderValue, Message, MessageParser, MessagePart, MimeHeaders, PartType};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    MAX_OBJECTS_IN_GET,
    blob::BlobId,
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

fn parsed_addresses(address: Option<&Address<'_>>) -> Value {
    match address {
        None => Value::Null,
        Some(address) => json!(
            address
                .iter()
                .filter_map(|addr| Some(json!({ "name": addr.name(), "email": addr.address()? })))
                .collect::<Vec<_>>()
        ),
    }
}

fn id_list(value: &HeaderValue<'_>) -> Value {
    match value {
        HeaderValue::Text(id) => json!([id]),
        HeaderValue::TextList(ids) => json!(ids),
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
fn header_form(raw: &[u8], message: &Message<'_>, part: &MessagePart<'_>, property: &str) -> Value {
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
        .headers
        .iter()
        .filter(|header| header.name.as_str().eq_ignore_ascii_case(name))
        .map(|header| match form {
            "asRaw" => json!(String::from_utf8_lossy(
                raw.get(header.offset_start as usize..header.offset_end as usize).unwrap_or_default()
            )),
            "asText" => match &header.value {
                HeaderValue::Text(text) => json!(text.trim()),
                HeaderValue::TextList(list) => json!(list.join(", ")),
                _ => Value::Null,
            },
            "asAddresses" => parsed_addresses(header.value.as_address()),
            "asGroupedAddresses" => match header.value.as_address() {
                Some(address) => json!([{ "name": null, "addresses": parsed_addresses(Some(address)) }]),
                None => Value::Null,
            },
            "asMessageIds" => id_list(&header.value),
            "asDate" => header.value.as_datetime().map_or(Value::Null, |date| json!(date.to_rfc3339())),
            "asURLs" => match &header.value {
                HeaderValue::Text(text) => json!(
                    text.split(',')
                        .filter_map(|url| url.trim().strip_prefix('<').and_then(|url| url.strip_suffix('>')))
                        .collect::<Vec<_>>()
                ),
                HeaderValue::TextList(list) => json!(list),
                _ => Value::Null,
            },
            _ => Value::Null,
        })
        .collect();
    let _ = message;
    if all { json!(values) } else { values.into_iter().last().unwrap_or(Value::Null) }
}

/// One body part (RFC 8621, 4.1.4) with the properties asked for.
fn body_part(raw: &[u8], message: &Message<'_>, index: usize, email: Option<Uuid>, options: &BodyOptions) -> Value {
    let Some(part) = message.parts.get(index) else { return Value::Null };
    let multipart = matches!(part.body, PartType::Multipart(_));
    let mut out = Map::new();
    for property in &options.properties {
        let value = match property.as_str() {
            "partId" if !multipart => json!(index.to_string()),
            "blobId" if !multipart => email.map_or(Value::Null, |email| json!(BlobId::Part(email, index).to_string())),
            "size" => json!(part.len()),
            "headers" => json!(
                part.headers
                    .iter()
                    .map(|header| json!({
                        "name": header.name.as_str(),
                        "value": String::from_utf8_lossy(raw.get(header.offset_start as usize..header.offset_end as usize).unwrap_or_default()),
                    }))
                    .collect::<Vec<_>>()
            ),
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
            "language" => match part.content_language() {
                HeaderValue::Text(language) => json!([language]),
                HeaderValue::TextList(languages) => json!(languages),
                _ => Value::Null,
            },
            "location" => json!(part.content_location()),
            "subParts" if multipart => Value::Null,
            property if property.starts_with("header:") => header_form(raw, message, part, property),
            _ => continue,
        };
        out.insert(property.clone(), value);
    }
    if let PartType::Multipart(children) = &part.body {
        out.insert(
            "subParts".into(),
            json!(
                children
                    .iter()
                    .map(|child| body_part(raw, message, *child as usize, email, options))
                    .collect::<Vec<_>>()
            ),
        );
    }
    Value::Object(out)
}

/// The text of a part for `bodyValues`, cut at `max` bytes (on a character boundary) when `max` is set.
fn body_value(part: &MessagePart<'_>, max: usize) -> Value {
    let text = match &part.body {
        PartType::Text(text) => text.to_string(),
        PartType::Html(html) => html.to_string(),
        _ => String::new(),
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
    json!({ "value": value, "isEncodingProblem": part.is_encoding_problem, "isTruncated": truncated })
}

/// The properties of an email that come from its raw message.
pub(crate) fn from_message(
    raw: &[u8],
    message: &Message<'_>,
    email: Option<Uuid>,
    property: &str,
    options: &BodyOptions,
) -> Option<Value> {
    let list = |indices: &[u32]| {
        json!(indices.iter().map(|index| body_part(raw, message, *index as usize, email, options)).collect::<Vec<_>>())
    };
    Some(match property {
        "bodyStructure" => body_part(raw, message, 0, email, options),
        "textBody" => list(&message.text_body),
        "htmlBody" => list(&message.html_body),
        "attachments" => list(&message.attachments),
        "headers" => json!(
            message.parts[0]
                .headers
                .iter()
                .map(|header| json!({
                    "name": header.name.as_str(),
                    "value": String::from_utf8_lossy(raw.get(header.offset_start as usize..header.offset_end as usize).unwrap_or_default()),
                }))
                .collect::<Vec<_>>()
        ),
        "bodyValues" => {
            let mut wanted: BTreeMap<u32, ()> = BTreeMap::new();
            if options.text || options.all {
                wanted.extend(message.text_body.iter().map(|index| (*index, ())));
            }
            if options.html || options.all {
                wanted.extend(message.html_body.iter().map(|index| (*index, ())));
            }
            Value::Object(
                wanted
                    .keys()
                    .filter_map(|index| {
                        let part = message.parts.get(*index as usize)?;
                        part.is_text().then(|| (index.to_string(), body_value(part, options.max_bytes)))
                    })
                    .collect(),
            )
        }
        "messageId" => message.message_id().map_or(Value::Null, |id| json!([id])),
        "inReplyTo" => id_list(message.in_reply_to()),
        "references" => id_list(message.references()),
        "sender" => parsed_addresses(message.sender()),
        "from" => parsed_addresses(message.from()),
        "to" => parsed_addresses(message.to()),
        "cc" => parsed_addresses(message.cc()),
        "bcc" => parsed_addresses(message.bcc()),
        "replyTo" => parsed_addresses(message.reply_to()),
        "subject" => json!(message.subject()),
        "sentAt" => message.date().map_or(Value::Null, |date| json!(date.to_rfc3339())),
        "hasAttachment" => json!(message.attachment_count() > 0),
        "preview" => json!(message.body_preview(256).map(|preview| preview.split_whitespace().collect::<Vec<_>>().join(" "))),
        "size" => json!(raw.len()),
        property if property.starts_with("header:") => header_form(raw, message, &message.parts[0], property),
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
            "receivedAt" => json!(info.received_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
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
            "sentAt" => {
                info.sent_at.map_or(Value::Null, |at| json!(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)))
            }
            "hasAttachment" => json!(info.has_attachment),
            "preview" => json!(info.preview),
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
