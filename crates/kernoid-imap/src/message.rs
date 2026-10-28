// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: AGPL-3.0-only
//! What `FETCH` reads from a message: `ENVELOPE`, `BODYSTRUCTURE`, `BODY[…]` sections and `BINARY[…]`. Derived from
//! Stalwart's `crates/imap/src/op/fetch.rs` (v0.16.27), which works on Stalwart's own metadata; kernoid reads the
//! raw message with mail-parser instead.

use std::borrow::Cow;

use mail_parser::{Address as ParsedAddress, HeaderName, HeaderValue, Message, MessagePart, MimeHeaders, PartType};

use crate::proto::protocol::fetch::{
    Address, AddressGroup, BodyContents, BodyPart, BodyPartExtension, BodyPartFields, EmailAddress, Envelope, Section,
};

fn addresses<'x>(value: Option<&'x HeaderValue<'x>>) -> Vec<Address<'x>> {
    let mut out = Vec::new();
    match value.and_then(HeaderValue::as_address) {
        Some(ParsedAddress::List(list)) => {
            for addr in list {
                if let Some(email) = addr.address.as_ref() {
                    out.push(Address::Single(EmailAddress {
                        name: addr.name.as_ref().map(|name| name.as_ref().into()),
                        address: email.as_ref().into(),
                    }));
                }
            }
        }
        Some(ParsedAddress::Group(groups)) => {
            for group in groups {
                out.push(Address::Group(AddressGroup {
                    name: group.name.as_ref().map(|name| name.as_ref().into()),
                    addresses: group
                        .addresses
                        .iter()
                        .filter_map(|addr| {
                            Some(EmailAddress {
                                name: addr.name.as_ref().map(|name| name.as_ref().into()),
                                address: addr.address.as_ref()?.as_ref().into(),
                            })
                        })
                        .collect(),
                }));
            }
        }
        None => {}
    }
    out
}

/// The `ENVELOPE` of a message (RFC 9051, 7.5.2).
pub(crate) fn envelope<'x>(message: &'x Message<'x>) -> Envelope<'x> {
    let root = &message.parts[0];
    let header = |name: HeaderName<'static>| root.headers.iter().rev().find(|h| h.name == name).map(|h| &h.value);
    Envelope {
        date: message.date().cloned(),
        subject: message.subject().map(Into::into),
        from: addresses(header(HeaderName::From)),
        sender: addresses(header(HeaderName::Sender)),
        reply_to: addresses(header(HeaderName::ReplyTo)),
        to: addresses(header(HeaderName::To)),
        cc: addresses(header(HeaderName::Cc)),
        bcc: addresses(header(HeaderName::Bcc)),
        in_reply_to: match message.in_reply_to() {
            HeaderValue::Text(id) => Some(format!("<{id}>").into()),
            HeaderValue::TextList(ids) => {
                Some(ids.iter().map(|id| format!("<{id}>")).collect::<Vec<_>>().join(" ").into())
            }
            _ => None,
        },
        message_id: message.message_id().map(|id| format!("<{id}>").into()),
    }
}

fn raw<'x>(message: &'x Message<'x>, from: u32, to: u32) -> &'x [u8] {
    message.raw_message.get(from as usize..to as usize).unwrap_or_default()
}

/// One part, without its children (RFC 9051, 7.5.2 `BODYSTRUCTURE`).
fn as_body_part<'x>(message: &'x Message<'x>, part: &'x MessagePart<'x>, is_extended: bool) -> BodyPart<'x> {
    let body = raw(message, part.offset_body, part.offset_end);
    let (is_multipart, is_text) = match &part.body {
        PartType::Text(_) | PartType::Html(_) => (false, true),
        PartType::Multipart(_) => (true, false),
        _ => (false, false),
    };
    let content_type = part.content_type();
    let mut fields = BodyPartFields::default();
    let mut extension = BodyPartExtension::default();
    if !is_multipart || is_extended {
        fields.body_parameters = content_type
            .and_then(|ct| ct.attributes.as_ref())
            .map(|attributes| {
                attributes.iter().map(|a| (a.name.as_ref().into(), a.value.as_ref().into())).collect::<Vec<_>>()
            })
            .filter(|parameters| !parameters.is_empty());
    }
    if !is_multipart {
        fields.body_subtype = content_type.and_then(|ct| ct.c_subtype.as_ref().map(|subtype| subtype.as_ref().into()));
        fields.body_id = part.content_id().map(|id| format!("<{id}>").into());
        fields.body_description = part.content_description().map(Into::into);
        fields.body_encoding = part.content_transfer_encoding().map(Into::into);
        fields.body_size_octets = body.len();
        if is_text {
            if fields.body_subtype.is_none() {
                fields.body_subtype = Some("plain".into());
            }
            if fields.body_encoding.is_none() {
                fields.body_encoding = Some("7bit".into());
            }
            if fields.body_parameters.is_none() {
                fields.body_parameters = Some(vec![("charset".into(), "us-ascii".into())]);
            }
        }
    }
    if is_extended {
        extension.body_disposition = part.content_disposition().map(|cd| {
            (
                cd.c_type.as_ref().into(),
                cd.attributes
                    .as_ref()
                    .map(|attributes| {
                        attributes.iter().map(|a| (a.name.as_ref().into(), a.value.as_ref().into())).collect()
                    })
                    .unwrap_or_default(),
            )
        });
        extension.body_language = match part.content_language() {
            HeaderValue::Text(language) => Some(vec![language.as_ref().into()]),
            HeaderValue::TextList(languages) => Some(languages.iter().map(|l| l.as_ref().into()).collect()),
            _ => None,
        };
        extension.body_location = part.content_location().map(Into::into);
    }
    match &part.body {
        PartType::Multipart(_) => BodyPart::Multipart {
            body_parts: Vec::new(),
            body_subtype: content_type
                .and_then(|ct| ct.c_subtype.as_ref().map(|subtype| subtype.as_ref().into()))
                .unwrap_or_else(|| "mixed".into()),
            body_parameters: fields.body_parameters,
            extension,
        },
        PartType::Message(_) => BodyPart::Message {
            fields,
            envelope: None,
            body: None,
            body_size_lines: body.iter().filter(|&&b| b == b'\n').count(),
            body_md5: None,
            extension,
        },
        _ if is_text => BodyPart::Text {
            fields,
            body_size_lines: body.iter().filter(|&&b| b == b'\n').count(),
            body_md5: None,
            extension,
        },
        _ => BodyPart::Basic {
            body_type: content_type.map(|ct| Cow::from(ct.c_type.as_ref())),
            fields,
            body_md5: None,
            extension,
        },
    }
}

/// `BODYSTRUCTURE` (extended) or `BODY` of a message, nested messages included.
pub(crate) fn body_structure<'x>(message: &'x Message<'x>, is_extended: bool) -> BodyPart<'x> {
    part_structure(message, 0, is_extended, 0)
}

fn part_structure<'x>(message: &'x Message<'x>, index: usize, is_extended: bool, depth: usize) -> BodyPart<'x> {
    let Some(part) = message.parts.get(index) else {
        return BodyPart::Text {
            fields: BodyPartFields::default(),
            body_size_lines: 0,
            body_md5: None,
            extension: BodyPartExtension::default(),
        };
    };
    let mut out = as_body_part(message, part, is_extended);
    if depth > 50 {
        return out;
    }
    match &part.body {
        PartType::Multipart(children) => {
            for child in children {
                out.add_part(part_structure(message, *child as usize, is_extended, depth + 1));
            }
        }
        PartType::Message(nested) => {
            out.set_envelope(envelope(nested));
            out.add_part(part_structure(nested, 0, is_extended, depth + 1));
        }
        _ => {}
    }
    out
}

fn partial(bytes: &[u8], range: Option<(u32, u32)>) -> Cow<'_, [u8]> {
    match range {
        Some((start, length)) => {
            let start = (start as usize).min(bytes.len());
            let end = start.saturating_add(length as usize).min(bytes.len());
            Cow::Borrowed(&bytes[start..end])
        }
        None => Cow::Borrowed(bytes),
    }
}

/// Follows section numbers (`1.2.3`) to a part: in a multipart its n-th child, a nested message's root for what
/// follows it, and part 1 of a single part is that part itself (RFC 9051, 6.4.5).
fn walk<'x>(
    mut message: &'x Message<'x>,
    numbers: &[u32],
    follow_last: bool,
) -> Option<(&'x Message<'x>, &'x MessagePart<'x>)> {
    let mut part = &message.parts[0];
    for (position, number) in numbers.iter().enumerate() {
        let last = position == numbers.len() - 1;
        part = match part.sub_parts() {
            Some(children) => message.parts.get(*children.get(number.saturating_sub(1) as usize)? as usize)?,
            None if *number == 1 && (last || part.is_message()) => part,
            None => return None,
        };
        if let PartType::Message(nested) = &part.body
            && (!last || follow_last)
        {
            message = nested;
            part = &nested.parts[0];
        }
    }
    Some((message, part))
}

/// `BODY[…]` (RFC 9051, 6.4.5).
pub(crate) fn body_section<'x>(
    message: &'x Message<'x>,
    sections: &[Section],
    range: Option<(u32, u32)>,
) -> Option<Cow<'x, [u8]>> {
    if sections.is_empty() {
        return Some(partial(&message.raw_message, range));
    }
    let numbers: Vec<u32> = sections
        .iter()
        .take_while(|section| matches!(section, Section::Part { .. }))
        .filter_map(|section| match section {
            Section::Part { num } => Some(*num),
            _ => None,
        })
        .collect();
    let rest = &sections[numbers.len()..];
    let (message, part) = walk(message, &numbers, !rest.is_empty())?;
    let headers_where = |keep: &dyn Fn(&mail_parser::Header<'_>) -> bool| {
        let mut out = Vec::new();
        for header in &part.headers {
            if keep(header) {
                out.extend_from_slice(header.name.as_str().as_bytes());
                out.push(b':');
                out.extend_from_slice(raw(message, header.offset_start, header.offset_end));
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    };
    Some(match rest.first() {
        None => partial(raw(message, part.offset_body, part.offset_end), range),
        Some(Section::Header) => partial(raw(message, part.offset_header, part.offset_body), range),
        Some(Section::Text) => partial(raw(message, part.offset_body, part.offset_end), range),
        Some(Section::HeaderFields { not, fields }) => {
            let headers =
                headers_where(&|header| fields.iter().any(|f| header.name.as_str().eq_ignore_ascii_case(f)) != *not);
            Cow::Owned(partial(&headers, range).into_owned())
        }
        Some(Section::Mime) => {
            let headers =
                headers_where(&|header| header.name.is_mime_header() || header.name.as_str().starts_with("Content-"));
            Cow::Owned(partial(&headers, range).into_owned())
        }
        Some(Section::Part { .. }) => return None,
    })
}

/// `BINARY[…]` (RFC 3516): the decoded content; `Err` if it cannot be decoded.
pub(crate) fn binary<'x>(
    message: &'x Message<'x>,
    sections: &[u32],
    range: Option<(u32, u32)>,
) -> Result<Option<BodyContents<'x>>, ()> {
    let Some((message, part)) = walk(message, sections, false) else { return Ok(None) };
    if part.is_encoding_problem {
        return Err(());
    }
    Ok(Some(BodyContents::Bytes(match &part.body {
        PartType::Text(text) | PartType::Html(text) => Cow::Owned(partial(text.as_bytes(), range).into_owned()),
        PartType::Binary(bytes) | PartType::InlineBinary(bytes) => Cow::Owned(partial(bytes, range).into_owned()),
        PartType::Message(_) | PartType::Multipart(_) => {
            partial(raw(message, part.offset_body, part.offset_end), range)
        }
    })))
}

/// The size of `BINARY[…]`.
pub(crate) fn binary_size(message: &Message<'_>, sections: &[u32]) -> Option<usize> {
    let (message, part) = walk(message, sections, false)?;
    Some(match &part.body {
        PartType::Text(text) | PartType::Html(text) => text.len(),
        PartType::Binary(bytes) | PartType::InlineBinary(bytes) => bytes.len(),
        PartType::Message(_) | PartType::Multipart(_) => raw(message, part.offset_body, part.offset_end).len(),
    })
}
