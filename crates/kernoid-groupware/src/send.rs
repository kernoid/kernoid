// SPDX-License-Identifier: AGPL-3.0-or-later
//! Invitations by mail (iMIP, RFC 6047; RFC 0004, 7): each iTIP message as an email from the account, through the
//! queue of outgoing mail, which signs it with DKIM on the way out. The layout follows Stalwart's
//! (`crates/services/src/task_manager/imip.rs`): a text part, the iTIP object as `text/calendar; method=…`, and the
//! same as an attachment.

use calcard::{
    common::IanaString,
    icalendar::{ICalendar, ICalendarProperty},
};
use kernoid_mail::Recipient;
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, content_type::ContentType},
    mime::{BodyPart, MimePart},
};
use mail_parser::MimeHeaders;
use uuid::Uuid;

use crate::{
    Groupware, GroupwareError, Result,
    scheduling::{ItipMessage, ItipSummary},
};

/// The summary of the first event in an iTIP object, for the subject.
fn title(ical: &ICalendar) -> String {
    ical.components
        .iter()
        .filter(|component| component.component_type.is_scheduling_object())
        .find_map(|component| component.property(&ICalendarProperty::Summary))
        .and_then(|entry| entry.values.first())
        .and_then(|value| value.as_text())
        .map_or_else(|| "(no title)".to_owned(), |text| text.chars().take(200).collect())
}

/// The subject and text of the email (English; OPEN: other languages).
fn wording(summary: &ItipSummary, title: &str, from: &str) -> (String, String) {
    match summary {
        ItipSummary::Invite(_) => (format!("Invitation: {title}"), format!("{from} invites you to \"{title}\".")),
        ItipSummary::Update { .. } => (format!("Updated: {title}"), format!("{from} changed \"{title}\".")),
        ItipSummary::Cancel(_) => (format!("Cancelled: {title}"), format!("{from} cancelled \"{title}\".")),
        ItipSummary::Rsvp { part_stat, .. } => {
            let answer = match part_stat.as_str() {
                "ACCEPTED" => "accepted",
                "DECLINED" => "declined",
                "TENTATIVE" => "tentatively accepted",
                "DELEGATED" => "delegated",
                _ => "answered",
            };
            (format!("{answer}: {title}"), format!("{from} {answer} \"{title}\"."))
        }
    }
}

impl Groupware {
    /// Queues each message as an email from the account; returns how many were queued.
    pub(crate) async fn send_itip(&self, account: Uuid, messages: Vec<ItipMessage<ICalendar>>) -> Result<usize> {
        let principal = self.principal(account).await?;
        let mut queued = 0;
        for message in messages {
            if message.to.is_empty() {
                continue;
            }
            let ics = message.message.to_string();
            let title = title(&message.message);
            let (subject, text) = wording(&message.summary, &title, &principal.display_name);
            let method = message.summary.method().to_owned();
            let raw = MessageBuilder::new()
                .from((principal.display_name.as_str(), message.from.as_str()))
                .to(message.to.iter().map(String::as_str).collect::<Vec<_>>())
                .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
                .subject(subject)
                .body(MimePart::new(
                    ContentType::new("multipart/mixed"),
                    BodyPart::Multipart(vec![
                        MimePart::new(
                            ContentType::new("multipart/alternative"),
                            BodyPart::Multipart(vec![
                                MimePart::new(ContentType::new("text/plain"), BodyPart::Text(text.into())),
                                MimePart::new(
                                    ContentType::new("text/calendar")
                                        .attribute("method", method.clone())
                                        .attribute("charset", "utf-8"),
                                    BodyPart::Text(ics.clone().into()),
                                ),
                            ]),
                        ),
                        MimePart::new(
                            ContentType::new("application/ics").attribute("name", "invite.ics"),
                            BodyPart::Text(ics.clone().into()),
                        )
                        .attachment("invite.ics"),
                    ]),
                ))
                .write_to_vec()
                .map_err(|error| GroupwareError::Invalid(error.to_string()))?;
            // Accounts of this installation get it at once – delivered and applied; the others through the queue.
            let mut remote = Vec::new();
            for to in message.to.iter().map(|to| to.to_lowercase()) {
                match self.mail().resolve_recipient(&to).await? {
                    Recipient::Account { account: recipient, .. } => {
                        self.deliver_itip(recipient, &message.from, &to, &raw, &ics).await;
                    }
                    Recipient::Group { members, .. } => {
                        for member in members {
                            self.deliver_itip(member, &message.from, &to, &raw, &ics).await;
                        }
                    }
                    Recipient::NotLocal => remote.push(to),
                    // An SRS address takes bounces only.
                    Recipient::Disabled | Recipient::Unknown | Recipient::Forwarded { .. } => {}
                }
            }
            if !remote.is_empty() {
                self.mail()
                    .enqueue(kernoid_mail::Outgoing {
                        tenant: principal.tenant,
                        account: Some(account),
                        from: &message.from,
                        recipients: &remote,
                        raw: raw.into(),
                        lifetime: self.mail().queue_lifetime(),
                    })
                    .await?;
            }
            queued += 1;
        }
        Ok(queued)
    }

    /// Delivers an invitation email to an account of this installation and applies it to its calendars; the sender
    /// is the account that made it. Failures are logged: the change that caused it is done.
    async fn deliver_itip(&self, recipient: Uuid, from: &str, to: &str, raw: &[u8], ics: &str) {
        let delivery = kernoid_mail::Delivery { from, to, junk: false };
        if let Err(error) = self.mail().deliver(recipient, raw.to_vec().into(), delivery).await {
            tracing::warn!(%error, %recipient, "delivering an invitation");
        }
        if let Err(error) = Box::pin(self.receive_itip(recipient, from, ics)).await {
            tracing::info!(%error, %recipient, "an invitation was not applied");
        }
    }

    /// Applies the iTIP parts of a delivered email (`text/calendar` with a method) to the account's calendars, if
    /// the caller verified that the `From` address is the sender's (DMARC passed, or the sender is logged in).
    pub async fn receive_imip(&self, account: Uuid, raw: &[u8], from_verified: bool) {
        if !from_verified {
            return;
        }
        let Some(message) = mail_parser::MessageParser::new().parse(raw) else { return };
        let Some(from) = message.from().and_then(|from| from.first()).and_then(|from| from.address()) else { return };
        let from = from.to_lowercase();
        for part in message.parts.iter() {
            let Some(content_type) = part.content_type() else { continue };
            let is_itip = content_type.c_type.eq_ignore_ascii_case("text")
                && content_type.subtype().is_some_and(|subtype| subtype.eq_ignore_ascii_case("calendar"))
                && content_type.attribute("method").is_some();
            if !is_itip {
                continue;
            }
            let Some(text) = part.text_contents() else { continue };
            if let Err(error) = self.receive_itip(account, &from, text).await {
                tracing::info!(%error, %account, "an invitation was not applied");
            }
            // One iTIP object per message (RFC 6047, 2.4).
            break;
        }
    }
}
