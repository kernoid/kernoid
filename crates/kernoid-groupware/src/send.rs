// SPDX-License-Identifier: AGPL-3.0-or-later
//! Invitations by mail (iMIP, RFC 6047; RFC 0004, 7): each iTIP message as an email from the account, through the
//! queue of outgoing mail, which signs it with DKIM on the way out. The layout follows Stalwart's
//! (`crates/services/src/task_manager/imip.rs`): a text part, the iTIP object as `text/calendar; method=…`, and the
//! same as an attachment.

use kernoid_mail::Recipient;
use kernoid_mime::{MessageBuilder, Part};
use kernoid_pim::Component;
use uuid::Uuid;

use crate::{
    Groupware, Result,
    scheduling::{ItipMessage, ItipSummary},
};

/// The summary of the first event in an iTIP object, for the subject.
fn title(ical: &Component, language: &str) -> String {
    ical.schedulable().find_map(|component| component.text("SUMMARY")).map_or_else(
        || if language == "de" { "(ohne Titel)" } else { "(no title)" }.to_owned(),
        |text| text.chars().take(200).collect(),
    )
}

/// The subject and text of the email, in the sender's language (`de`, else English).
fn wording(summary: &ItipSummary, title: &str, from: &str, language: &str) -> (String, String) {
    if language == "de" {
        return match summary {
            ItipSummary::Invite => (format!("Einladung: {title}"), format!("{from} lädt Sie zu „{title}“ ein.")),
            ItipSummary::Update => (format!("Geändert: {title}"), format!("{from} hat „{title}“ geändert.")),
            ItipSummary::Cancel => (format!("Abgesagt: {title}"), format!("{from} hat „{title}“ abgesagt.")),
            ItipSummary::Rsvp { part_stat } => {
                let (subject, answer) = match part_stat.as_str() {
                    "ACCEPTED" => ("Zugesagt", "zugesagt"),
                    "DECLINED" => ("Abgelehnt", "abgelehnt"),
                    "TENTATIVE" => ("Vorläufig zugesagt", "vorläufig zugesagt"),
                    "DELEGATED" => ("Weitergegeben", "weitergegeben"),
                    _ => ("Beantwortet", "beantwortet"),
                };
                (format!("{subject}: {title}"), format!("{from} hat „{title}“ {answer}."))
            }
        };
    }
    match summary {
        ItipSummary::Invite => (format!("Invitation: {title}"), format!("{from} invites you to \"{title}\".")),
        ItipSummary::Update => (format!("Updated: {title}"), format!("{from} changed \"{title}\".")),
        ItipSummary::Cancel => (format!("Cancelled: {title}"), format!("{from} cancelled \"{title}\".")),
        ItipSummary::Rsvp { part_stat } => {
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
    pub(crate) async fn send_itip(&self, account: Uuid, messages: Vec<ItipMessage>) -> Result<usize> {
        let principal = self.principal(account).await?;
        let mut queued = 0;
        for message in messages {
            if message.to.is_empty() {
                continue;
            }
            let ics = message.message.to_string();
            let title = title(&message.message, &principal.language);
            let (subject, text) = wording(&message.summary, &title, &principal.display_name, &principal.language);
            let method = message.summary.method().to_owned();
            let raw = MessageBuilder::new()
                .from((principal.display_name.as_str(), message.from.as_str()))
                .to(message.to.iter().map(String::as_str))
                .header("Auto-Submitted", "auto-generated")
                .subject(subject)
                .body(Part::multipart(
                    "mixed",
                    vec![
                        Part::multipart(
                            "alternative",
                            vec![
                                Part::text("text/plain", text),
                                Part::text("text/calendar", ics.clone())
                                    .parameter("method", method.clone())
                                    .parameter("charset", "utf-8"),
                            ],
                        ),
                        Part::text("application/ics", ics.clone()).attachment("invite.ics"),
                    ],
                ))
                .write();
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
        let Some(message) = kernoid_mime::Message::parse(raw) else { return };
        let Some(from) =
            message.from().and_then(|from| from.first().and_then(|from| from.address().map(str::to_lowercase)))
        else {
            return;
        };
        for part in message.root().parts() {
            let Some(content_type) = part.content_type() else { continue };
            let is_itip = content_type.ctype().eq_ignore_ascii_case("text")
                && content_type.subtype().is_some_and(|subtype| subtype.eq_ignore_ascii_case("calendar"))
                && content_type.attribute("method").is_some();
            if !is_itip {
                continue;
            }
            let Some(text) = part.text() else { continue };
            if let Err(error) = self.receive_itip(account, &from, &text).await {
                tracing::info!(%error, %account, "an invitation was not applied");
            }
            // One iTIP object per message (RFC 6047, 2.4).
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wording_follows_the_senders_language() {
        let invite = ItipSummary::Invite;
        assert_eq!(
            wording(&invite, "Planning", "Alice", "en"),
            ("Invitation: Planning".to_owned(), "Alice invites you to \"Planning\".".to_owned())
        );
        assert_eq!(
            wording(&invite, "Planung", "Alice", "de"),
            ("Einladung: Planung".to_owned(), "Alice lädt Sie zu „Planung“ ein.".to_owned())
        );
        let declined = ItipSummary::Rsvp { part_stat: "DECLINED".into() };
        assert_eq!(wording(&declined, "Planung", "Bob", "de").0, "Abgelehnt: Planung");
    }
}
