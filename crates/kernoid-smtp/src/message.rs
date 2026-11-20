// SPDX-License-Identifier: AGPL-3.0-or-later
//! What happens to a message once its data is read (RFC 0002, 9.3 and 9.4). On the MX: the loop check, DKIM, ARC
//! and DMARC with kernoid's `auth` (SPF and iprev were checked with `MAIL FROM` and `EHLO`), a refusal for DMARC
//! `p=reject`, the malware scan, the basic spam filter, and then the headers kernoid adds in front – `Received`
//! (RFC 5321, 4.4), `Authentication-Results` (RFC 8601), `Received-SPF` (RFC 7208, 9.1) and `X-Spam-Status`. The
//! message goes to every recipient's account at once – there is no queue for incoming mail, and `250` means stored.

use std::collections::BTreeSet;

use bytes::Bytes;
use kernoid_mail::{Delivered, Delivery, MailError};
use uuid::Uuid;

use crate::{
    auth::{
        DkimResult, DmarcResult, IprevResult, SpfOutput, SpfResult, arc, dkim,
        dmarc::{self, Policy},
        message::Message,
        results::{AuthenticationResults, received_spf},
        spf::SpfParameters,
    },
    session::Session,
    spam::{self, Signals},
};

/// Checks a message for malware before it is accepted (`Mail::scan_message`); the reply that refuses it.
pub(crate) async fn scan(
    mail: &kernoid_mail::Mail,
    accounts: &[uuid::Uuid],
    tenants: &[uuid::Uuid],
    raw: &[u8],
) -> Result<(), String> {
    let content = Bytes::copy_from_slice(raw);
    match mail.scan_message(accounts, tenants, &content).await {
        Ok(()) => Ok(()),
        Err(MailError::Refused(kernoid_store::scan::Refused::Infected(name))) => {
            let name: String = name.chars().filter(|c| !c.is_control()).collect();
            Err(format!("554 5.7.1 Rejected: the message contains malware ({name})"))
        }
        Err(MailError::Refused(kernoid_store::scan::Refused::Unavailable)) => {
            Err("451 4.7.1 The message could not be checked for malware, try again later".into())
        }
        Err(error) => {
            tracing::warn!(%error, "scanning a message for malware");
            Err("451 4.3.0 Temporary failure, try again later".into())
        }
    }
}

/// What the checks found about a message on the MX.
struct Checked {
    /// The headers to put in front of the message, with their line ends.
    headers: String,
    junk: bool,
    dmarc_pass: bool,
}

impl Session {
    /// The response to `DATA` (or the last `BDAT`): the message read goes in, by MX or by submission.
    pub(crate) async fn finish(&mut self) -> String {
        if self.inner.submission.is_some() {
            self.finish_submission().await
        } else {
            self.finish_message().await
        }
    }

    /// Checks, scores and delivers the message read.
    pub(crate) async fn finish_message(&mut self) -> String {
        let raw = without_own_results(&std::mem::take(&mut self.message), &self.inner.settings.hostname);
        if self.mail_from.is_none() || self.rcpts.is_empty() {
            return "503 5.5.1 RCPT is required first".into();
        }
        let checked = match self.check(&raw).await {
            Ok(checked) => checked,
            Err(reply) => return reply,
        };

        let accounts: Vec<Uuid> = self.rcpts.iter().flat_map(|rcpt| rcpt.accounts.iter().copied()).collect();
        let tenants: Vec<Uuid> =
            self.rcpts.iter().filter_map(|rcpt| rcpt.bounce_to.as_ref().map(|(_, tenant)| *tenant)).collect();
        if let Err(reply) = scan(&self.inner.mail, &accounts, &tenants, &raw).await {
            return reply;
        }

        let mut full = checked.headers.into_bytes();
        full.extend_from_slice(&raw);
        let full = Bytes::from(full);
        let from = self.mail_from.as_ref().map(|from| from.address.clone()).unwrap_or_default();
        let mail = &self.inner.mail;

        // An account in several recipients – an address and a group – gets the message once.
        let mut delivered = BTreeSet::new();
        for rcpt in &self.rcpts {
            if let Some((to, tenant)) = &rcpt.bounce_to {
                if let Err(error) = mail.forward_bounce(*tenant, to, full.clone()).await {
                    tracing::warn!(%error, "sending a bounce on to the original sender");
                    return "451 4.3.0 Temporary failure, try again later".into();
                }
                continue;
            }
            for account in &rcpt.accounts {
                if !delivered.insert(*account) {
                    continue;
                }
                let delivery = Delivery { from: &from, to: &rcpt.address, junk: checked.junk };
                match mail.deliver(*account, full.clone(), delivery).await {
                    Ok(Delivered::Stored(_)) => {
                        // Invitations count only when the `From` is shown to be the sender's (RFC 0004, 7).
                        if let Some(groupware) = &self.inner.groupware {
                            groupware.receive_imip(*account, &full, checked.dmarc_pass).await;
                        }
                    }
                    Ok(Delivered::Duplicate | Delivered::Discarded) => {}
                    // The sending server tries again; whoever has it by then skips it as a duplicate.
                    Err(MailError::OverQuota) => return "452 4.2.2 Mailbox full, try again later".into(),
                    Err(MailError::TooLarge { .. }) => return "552 5.3.4 Message too big for system".into(),
                    Err(error) => {
                        tracing::warn!(%error, "delivering a message");
                        return "451 4.3.0 Temporary failure, try again later".into();
                    }
                }
            }
        }
        "250 2.0.0 Message accepted for delivery".into()
    }

    /// The checks of RFC 0002, 9.3 on `raw`: the headers to add, or the reply that refuses the message.
    async fn check(&mut self, raw: &[u8]) -> Result<Checked, String> {
        let settings = &self.inner.settings;
        let hostname = settings.hostname.as_str();
        let message = Message::parse(raw);
        if message.headers.is_empty() {
            return Err("550 5.6.0 The message could not be parsed".into());
        }
        if message.all("Received").count() >= settings.max_received {
            return Err("554 5.4.6 Too many Received headers, the message is looping".into());
        }
        let Some(mail_from) = self.mail_from.as_ref() else {
            return Err("503 5.5.1 MAIL is required first".into());
        };
        let helo = self.helo.clone().unwrap_or_default();
        let dns = &self.inner.dns;
        let spf_params = SpfParameters::mail_from(self.remote, &helo, hostname, &mail_from.address);
        let spf = mail_from.spf.clone().unwrap_or_else(|| SpfOutput::new(mail_from.domain.clone()));

        let dkim = dkim::verify(dns, &message).await;
        let arc = arc::verify(dns, &message).await;
        let dmarc = dmarc::verify(dns, &message.from_domains(), &mail_from.domain, &spf, &dkim).await;
        let dmarc_result = dmarc.result();
        let dmarc_failed = dmarc_result == DmarcResult::Fail;
        if dmarc_failed && dmarc.policy() == Policy::Reject {
            return Err("550 5.7.1 Rejected by the sender's DMARC policy".into());
        }

        let header_from = message.first_from_address().to_lowercase();
        let from_domain = header_from.rsplit_once('@').map(|(_, domain)| domain.to_owned()).unwrap_or_default();
        let dmarc_pass = dmarc_result == DmarcResult::Pass;
        let dkim_pass_for_from = dkim.iter().any(|output| {
            output.result() == &DkimResult::Pass
                && output.signature().is_some_and(|signature| signature.domain.eq_ignore_ascii_case(&from_domain))
        });
        let spf_pass_for_from = spf.result() == SpfResult::Pass && mail_from.domain.eq_ignore_ascii_case(&from_domain);
        let local_from = !from_domain.is_empty() && self.inner.mail.serves_domain(&from_domain).await.unwrap_or(false);
        let headers_of = |name: &str| message.first(name).is_some();
        let signals = Signals {
            spf_mail_from: Some(spf.result()),
            spf_ehlo: self.spf_ehlo.as_ref().map(SpfOutput::result),
            dkim: dkim.iter().map(|output| output.result().clone()).collect(),
            dmarc: Some(dmarc_result),
            iprev: self.iprev.as_ref().map(|iprev| iprev.result.clone()),
            has_message_id: headers_of("Message-ID"),
            has_date: headers_of("Date"),
            has_from: !header_from.is_empty(),
            spoofs_local_domain: local_from && !dmarc_pass && !dkim_pass_for_from && !spf_pass_for_from,
        };
        let verdict = spam::score(&signals);
        let junk = verdict.is_spam(settings.junk_score) || (dmarc_failed && dmarc.policy() == Policy::Quarantine);

        let mut results = AuthenticationResults::new(hostname);
        if let Some(iprev) = &self.iprev {
            results = results.with_iprev_result(iprev, self.remote);
        }
        let results = results
            .with_spf_result(&spf, &spf_params)
            .with_dkim_results(&dkim)
            .with_arc_result(&arc, self.remote)
            .with_dmarc_result(&dmarc);
        let mut headers = self.received(&helo);
        headers.push_str(&results.to_header());
        headers.push_str(&received_spf(&spf, &spf_params));
        headers.push_str(&verdict.header(settings.junk_score));
        Ok(Checked { headers, junk, dmarc_pass })
    }

    /// The `Received` header of the MX (RFC 5321, 4.4): the client's name and address, and how it came.
    fn received(&self, helo: &str) -> String {
        let name = match &self.iprev {
            Some(iprev) if iprev.result == IprevResult::Pass => {
                iprev.ptr.as_ref().and_then(|names| names.first()).map(|name| name.trim_end_matches('.').to_owned())
            }
            _ => None,
        };
        let name = name.unwrap_or_else(|| "unknown".into());
        let helo: String = helo.chars().filter(|c| !c.is_control() && !matches!(c, '(' | ')')).collect();
        let mut header = format!("Received: from {helo} ({name} [{}])\r\n", self.remote);
        let protocol = match &self.tls {
            Some(tls) => {
                header.push_str(&format!("\t(using {tls})\r\n"));
                "ESMTPS"
            }
            None => "ESMTP",
        };
        header.push_str(&format!(
            "\tby {} (kernoid) with {protocol};\r\n\t{}\r\n",
            self.inner.settings.hostname,
            date_now()
        ));
        header
    }
}

/// The message without `Authentication-Results` headers that claim kernoid's host name – only kernoid may write
/// those (RFC 8601, 5).
pub(crate) fn without_own_results(raw: &[u8], hostname: &str) -> Vec<u8> {
    let body_start = header_end(raw);
    let (header, body) = raw.split_at(body_start);
    let mut kept = Vec::with_capacity(raw.len());
    let mut skipping = false;
    for line in header.split_inclusive(|byte| *byte == b'\n') {
        let continues = matches!(line.first(), Some(b' ' | b'\t'));
        if !continues {
            skipping = is_own_result(line, hostname);
        }
        if !skipping {
            kept.extend_from_slice(line);
        }
    }
    kept.extend_from_slice(body);
    kept
}

/// Where the header section ends: after its empty line, or at the end of a message without a body.
fn header_end(raw: &[u8]) -> usize {
    let mut position = 0;
    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        position += line.len();
        if line == b"\r\n" || line == b"\n" {
            return position - line.len();
        }
    }
    raw.len()
}

/// Whether a header line starts an `Authentication-Results` field whose authserv-id is `hostname`.
fn is_own_result(line: &[u8], hostname: &str) -> bool {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else { return false };
    let (name, value) = line.split_at(colon);
    if !name.trim_ascii().eq_ignore_ascii_case(b"Authentication-Results") {
        return false;
    }
    let value = String::from_utf8_lossy(&value[1..]);
    let id = value.trim_start().split([';', ' ', '\t', '\r', '\n', '(']).next().unwrap_or_default();
    id.trim_end_matches('.').eq_ignore_ascii_case(hostname)
}

/// Now as the date of a header (RFC 5322, 3.3), in UTC with the offset `+0000`.
pub(crate) fn date_now() -> String {
    jiff::Timestamp::now().strftime("%a, %d %b %Y %H:%M:%S +0000").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_claiming_this_host_are_removed_with_their_continuations() {
        let raw = b"Received: from a\r\nAuthentication-Results: MX.kernoid.example;\r\n\tdkim=pass header.d=bank.example\r\n\
                    Authentication-Results: mx.other.example; spf=pass\r\nSubject: hi\r\n\r\n\
                    Authentication-Results: mx.kernoid.example; in the body stays\r\n";
        let cleaned = String::from_utf8(without_own_results(raw, "mx.kernoid.example")).unwrap();
        assert!(!cleaned.contains("bank.example"));
        assert!(cleaned.contains("Authentication-Results: mx.other.example; spf=pass\r\n"));
        assert!(cleaned.starts_with("Received: from a\r\nAuthentication-Results: mx.other"));
        assert!(cleaned.ends_with("\r\n\r\nAuthentication-Results: mx.kernoid.example; in the body stays\r\n"));
        // A message with headers only, and one where the id has no separator.
        let raw = b"Authentication-Results: mx.kernoid.example\r\nSubject: x\r\n";
        assert_eq!(without_own_results(raw, "mx.kernoid.example"), b"Subject: x\r\n");
        let raw = b"Authentication-Results: mx.kernoid.example.evil; dkim=pass\r\n\r\nx";
        assert_eq!(without_own_results(raw, "mx.kernoid.example"), raw);
    }

    #[test]
    fn dates_are_written_as_rfc_5322_has_them() {
        let date = date_now();
        assert!(date.ends_with(" +0000"), "{date}");
        assert!(
            kernoid_mime::Message::parse_headers(format!("Date: {date}\r\n\r\n").as_bytes())
                .and_then(|message| message.date())
                .is_some()
        );
    }
}
