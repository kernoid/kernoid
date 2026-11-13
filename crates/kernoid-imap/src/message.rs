// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: AGPL-3.0-only
//! What `FETCH` reads from a message: `ENVELOPE`, `BODYSTRUCTURE`, `BODY[…]` sections and `BINARY[…]`. Derived from
//! Stalwart's `crates/imap/src/op/fetch.rs` (v0.16.27), which works on Stalwart's own metadata; kernoid reads the
//! raw message with mail-parser instead.

use std::borrow::Cow;

use mail_parser::{Address as ParsedAddress, AddressList, HeaderName, Message, MessagePart, MessageRef, PartKind};

use crate::proto::protocol::fetch::{
    Address, AddressGroup, BodyContents, BodyPart, BodyPartExtension, BodyPartFields, EmailAddress, Envelope, Section,
};

fn addresses<'x>(list: Option<AddressList<'x>>) -> Vec<Address<'x>> {
    let mut out = Vec::new();
    for item in list.iter().flat_map(AddressList::iter) {
        match item {
            ParsedAddress::Mailbox(mailbox) => {
                if let Some(email) = mailbox.address() {
                    out.push(Address::Single(EmailAddress {
                        name: mailbox.name().map(Into::into),
                        address: email.into(),
                    }));
                }
            }
            ParsedAddress::Group(group) => out.push(Address::Group(AddressGroup {
                name: group.name().map(Into::into),
                addresses: group
                    .mailboxes()
                    .filter_map(|mailbox| {
                        Some(EmailAddress { name: mailbox.name().map(Into::into), address: mailbox.address()?.into() })
                    })
                    .collect(),
            })),
        }
    }
    out
}

/// The `ENVELOPE` of a message (RFC 9051, 7.5.2).
pub(crate) fn envelope<'x>(message: &'x Message<'_>) -> Envelope<'x> {
    envelope_of(message.root())
}

fn envelope_of(message: MessageRef<'_>) -> Envelope<'_> {
    let headers = message.headers();
    let addresses_of = |name: HeaderName<'static>| addresses(headers.get(name).and_then(|h| h.value().as_address()));
    Envelope {
        date: message.date(),
        subject: message.subject().map(Into::into),
        from: addresses_of(HeaderName::From),
        sender: addresses_of(HeaderName::Sender),
        reply_to: addresses_of(HeaderName::ReplyTo),
        to: addresses_of(HeaderName::To),
        cc: addresses_of(HeaderName::Cc),
        bcc: addresses_of(HeaderName::Bcc),
        in_reply_to: message
            .in_reply_to()
            .filter(|ids| !ids.is_empty())
            .map(|ids| ids.iter().map(|id| format!("<{id}>")).collect::<Vec<_>>().join(" ").into()),
        message_id: message.message_id().map(|id| format!("<{id}>").into()),
    }
}

/// One part, without its children (RFC 9051, 7.5.2 `BODYSTRUCTURE`).
fn as_body_part(part: MessagePart<'_>, is_extended: bool) -> BodyPart<'_> {
    let body = part.raw_body();
    let kind = part.kind();
    let is_multipart = matches!(kind, PartKind::Multipart);
    let is_text = matches!(kind, PartKind::Text | PartKind::Html);
    let content_type = part.content_type();
    let mut fields = BodyPartFields::default();
    let mut extension = BodyPartExtension::default();
    if !is_multipart || is_extended {
        fields.body_parameters = content_type
            .map(|ct| ct.attributes().map(|(name, value)| (name.into(), value.into())).collect::<Vec<_>>())
            .filter(|parameters| !parameters.is_empty());
    }
    if !is_multipart {
        fields.body_subtype = content_type.and_then(|ct| ct.subtype().map(Into::into));
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
        extension.body_disposition = part
            .content_disposition()
            .map(|cd| (cd.ctype().into(), cd.attributes().map(|(name, value)| (name.into(), value.into())).collect()));
        extension.body_language = part
            .content_language()
            .filter(|languages| !languages.is_empty())
            .map(|languages| languages.iter().map(Into::into).collect());
        extension.body_location = part.content_location().map(Into::into);
    }
    match kind {
        PartKind::Multipart => BodyPart::Multipart {
            body_parts: Vec::new(),
            body_subtype: content_type.and_then(|ct| ct.subtype().map(Into::into)).unwrap_or_else(|| "mixed".into()),
            body_parameters: fields.body_parameters,
            extension,
        },
        PartKind::Message(_) => BodyPart::Message {
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
            body_type: content_type.map(|ct| Cow::from(ct.ctype())),
            fields,
            body_md5: None,
            extension,
        },
    }
}

/// `BODYSTRUCTURE` (extended) or `BODY` of a message, nested messages included.
pub(crate) fn body_structure<'x>(message: &'x Message<'_>, is_extended: bool) -> BodyPart<'x> {
    part_structure(message.root().root_part(), is_extended, 0)
}

fn part_structure(part: MessagePart<'_>, is_extended: bool, depth: usize) -> BodyPart<'_> {
    let mut out = as_body_part(part, is_extended);
    if depth > 50 {
        return out;
    }
    match part.kind() {
        PartKind::Multipart => {
            for child in part.children() {
                out.add_part(part_structure(child, is_extended, depth + 1));
            }
        }
        PartKind::Message(nested) => {
            out.set_envelope(envelope_of(nested));
            out.add_part(part_structure(nested.root_part(), is_extended, depth + 1));
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
fn walk<'x>(message: &'x Message<'_>, numbers: &[u32], follow_last: bool) -> Option<MessagePart<'x>> {
    let mut part = message.root().root_part();
    for (position, number) in numbers.iter().enumerate() {
        let last = position == numbers.len() - 1;
        part = if part.is_multipart() {
            part.children().nth(number.saturating_sub(1) as usize)?
        } else if *number == 1 && (last || part.is_message()) {
            part
        } else {
            return None;
        };
        if let Some(nested) = part.nested()
            && (!last || follow_last)
        {
            part = nested.root_part();
        }
    }
    Some(part)
}

/// `BODY[…]` (RFC 9051, 6.4.5).
pub(crate) fn body_section<'x>(
    message: &'x Message<'_>,
    sections: &[Section],
    range: Option<(u32, u32)>,
) -> Option<Cow<'x, [u8]>> {
    if sections.is_empty() {
        return Some(partial(message.raw(), range));
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
    let part = walk(message, &numbers, !rest.is_empty())?;
    let headers_where = |keep: &dyn Fn(&mail_parser::Header<'_>) -> bool| {
        let mut out = Vec::new();
        for header in part.headers() {
            if keep(&header) {
                out.extend_from_slice(header.raw_name().as_bytes());
                out.push(b':');
                out.extend_from_slice(header.raw_value());
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    };
    Some(match rest.first() {
        None | Some(Section::Text) => partial(part.raw_body(), range),
        Some(Section::Header) => partial(part.raw_headers(), range),
        Some(Section::HeaderFields { not, fields }) => {
            let headers =
                headers_where(&|header| fields.iter().any(|f| header.raw_name().eq_ignore_ascii_case(f)) != *not);
            Cow::Owned(partial(&headers, range).into_owned())
        }
        Some(Section::Mime) => {
            let headers = headers_where(&|header| {
                header.name().is_mime_header()
                    || header.raw_name().get(..8).is_some_and(|p| p.eq_ignore_ascii_case("Content-"))
            });
            Cow::Owned(partial(&headers, range).into_owned())
        }
        Some(Section::Part { .. }) => return None,
    })
}

/// `BINARY[…]` (RFC 3516): the content without its transfer encoding; `Err` if it cannot be decoded.
pub(crate) fn binary<'x>(
    message: &'x Message<'_>,
    sections: &[u32],
    range: Option<(u32, u32)>,
) -> Result<Option<BodyContents<'x>>, ()> {
    let Some(part) = walk(message, sections, false) else { return Ok(None) };
    if part.is_multipart() || part.is_message() {
        return Ok(Some(BodyContents::Bytes(partial(part.raw_body(), range))));
    }
    let (bytes, problems) = part.decoded_checked();
    if !problems.is_empty() {
        return Err(());
    }
    Ok(Some(BodyContents::Bytes(Cow::Owned(partial(&bytes, range).into_owned()))))
}

/// The size of `BINARY[…]`.
pub(crate) fn binary_size(message: &Message<'_>, sections: &[u32]) -> Option<usize> {
    let part = walk(message, sections, false)?;
    Some(if part.is_multipart() || part.is_message() { part.raw_body().len() } else { part.decoded_len() })
}
