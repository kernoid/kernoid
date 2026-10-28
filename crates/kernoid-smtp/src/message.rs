// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: AGPL-3.0-only
//! What happens after the data of a message (RFC 0002, 9.3 and 9.4). Derived from Stalwart's `queue_message`
//! (`crates/smtp/src/inbound/data.rs`, v0.16.27): the loop check, DKIM, ARC and DMARC, the `Received`,
//! `Authentication-Results` and `Received-SPF` headers. kernoid then scores the message and delivers it to each
//! recipient's account at once – there is no queue for incoming mail.

use std::collections::BTreeSet;

use bytes::Bytes;
use kernoid_mail::{Delivered, Delivery, MailError};
use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, ReceivedSpf, SpfOutput, SpfResult,
    common::headers::HeaderWriter, dmarc::Policy, dmarc::verify::DmarcParameters,
};

use crate::{
    session::Session,
    spam::{self, Signals},
};

impl Session {
    /// The response to `DATA` (or the last `BDAT`): the message read goes in, by MX or by submission.
    pub(crate) async fn finish(&mut self) -> String {
        if self.inner.submission.is_some() { self.finish_submission().await } else { self.finish_message().await }
    }

    /// Checks, scores and delivers the message read.
    pub(crate) async fn finish_message(&mut self) -> String {
        let raw = std::mem::take(&mut self.message);
        let Some(message) = AuthenticatedMessage::parse(&raw) else {
            return "550 5.7.7 Failed to parse the message".into();
        };
        if message.received_headers_count() > self.inner.settings.max_received {
            return "450 4.4.6 Too many Received headers. Possible loop detected".into();
        }
        let dns = &self.inner.dns;
        let hostname = self.inner.settings.hostname.as_str();
        let helo = self.helo.clone().unwrap_or_default();
        let (from_address, from_domain, spf_mail_from) = match &self.mail_from {
            Some(from) => (from.address.clone(), from.domain.clone(), from.spf.clone()),
            None => (String::new(), String::new(), None),
        };

        let dkim = dns.authenticator.verify_dkim(dns.parameters(&message)).await;
        let arc = dns.authenticator.verify_arc(dns.parameters(&message)).await;
        let none = SpfOutput::new(String::new()).with_result(SpfResult::None);
        let spf_for_dmarc = spf_mail_from.as_ref().unwrap_or(&none);
        let dmarc = dns
            .authenticator
            .verify_dmarc(dns.parameters(DmarcParameters {
                message: &message,
                dkim_output: &dkim,
                dkim2_output: None,
                rfc5321_mail_from_domain: if from_domain.is_empty() { &helo } else { &from_domain },
                spf_output: spf_for_dmarc,
            }))
            .await;
        let dmarc_result = dmarc.result();
        let dmarc_failed = matches!(dmarc_result, DmarcResult::Fail(_));
        if dmarc_failed && dmarc.policy() == Policy::Reject {
            return "550 5.7.1 Rejected by the sender's DMARC policy".into();
        }
        let quarantine = dmarc_failed && dmarc.policy() == Policy::Quarantine;

        let mut results = AuthenticationResults::new(hostname);
        if !dkim.is_empty() {
            results = results.with_dkim_results(&dkim, message.from());
        }
        if let Some(spf) = &self.spf_ehlo {
            results = results.with_spf_ehlo_result(spf, self.remote, &helo);
        }
        if let Some(spf) = &spf_mail_from {
            results = results.with_spf_mailfrom_result(spf, self.remote, &from_address, &helo);
        }
        if let Some(iprev) = &self.iprev {
            results = results.with_iprev_result(iprev, self.remote);
        }
        if !matches!(arc.result(), DkimResult::None) {
            results = results.with_arc_result(&arc, self.remote);
        }
        results = results.with_dmarc_result(&dmarc);

        // A message claiming a domain kernoid serves, without anything that shows it comes from there.
        let header_from_domain = message.from().rsplit_once('@').map(|(_, domain)| domain.to_lowercase());
        let spoofs_local_domain = match &header_from_domain {
            Some(domain) if self.inner.mail.serves_domain(domain).await.unwrap_or(false) => {
                let dkim_aligned = dkim.iter().any(|output| {
                    *output.result() == DkimResult::Pass
                        && output.signature().is_some_and(|signature| signature.d.eq_ignore_ascii_case(domain))
                });
                let spf_aligned = spf_mail_from.as_ref().is_some_and(|spf| spf.result() == SpfResult::Pass)
                    && from_domain.eq_ignore_ascii_case(domain);
                dmarc_result != DmarcResult::Pass && !dkim_aligned && !spf_aligned
            }
            _ => false,
        };
        let verdict = spam::score(&Signals {
            spf_mail_from: spf_mail_from.as_ref().map(SpfOutput::result),
            spf_ehlo: self.spf_ehlo.as_ref().map(SpfOutput::result),
            dkim: dkim.iter().map(|output| output.result().clone()).collect(),
            dmarc: Some(dmarc_result.clone()),
            iprev: self.iprev.as_ref().map(|iprev| iprev.result.clone()),
            has_message_id: message.has_message_id_header(),
            has_date: message.has_date_header(),
            has_from: !message.from().is_empty(),
            spoofs_local_domain,
        });
        let threshold = self.inner.settings.junk_score;
        let junk = quarantine || verdict.is_spam(threshold);

        let mut headers = Vec::with_capacity(1024);
        self.write_received(&mut headers, &helo);
        results.write_header(&mut headers);
        if let Some(spf) = &spf_mail_from {
            ReceivedSpf::new(spf, self.remote, &helo, &from_address, hostname).write_header(&mut headers);
        }
        headers.extend_from_slice(verdict.header(threshold).as_bytes());
        headers.extend_from_slice(&without_own_results(&raw, hostname));
        drop(message);
        let full = Bytes::from(headers);

        // Each account once, under the first address that reached it.
        let mut seen = BTreeSet::new();
        let mut temporary = 0;
        let mut full_mailboxes = 0;
        for rcpt in &self.rcpts {
            for account in &rcpt.accounts {
                if !seen.insert(*account) {
                    continue;
                }
                let delivery = Delivery { from: &from_address, to: &rcpt.address, junk };
                match self.inner.mail.deliver(*account, full.clone(), delivery).await {
                    Ok(Delivered::Stored(_)) => {
                        // An invitation counts only from whom DMARC shows it is (RFC 0004, 7).
                        if let Some(groupware) = &self.inner.groupware {
                            groupware.receive_imip(*account, &full, dmarc_result == DmarcResult::Pass).await;
                        }
                    }
                    Ok(Delivered::Duplicate | Delivered::Discarded) => {}
                    Err(MailError::OverQuota) => full_mailboxes += 1,
                    Err(error) => {
                        tracing::warn!(%error, %account, "delivering a message");
                        temporary += 1;
                    }
                }
            }
        }
        // Retrying is safe: the recipients that have it skip it as a duplicate (RFC 0002, 9.4).
        if temporary > 0 {
            "451 4.3.0 Temporary failure, try again later".into()
        } else if full_mailboxes > 0 {
            "452 4.2.2 Mailbox full, try again later".into()
        } else {
            "250 2.0.0 Message accepted for delivery".into()
        }
    }

    fn write_received(&self, headers: &mut Vec<u8>, helo: &str) {
        let ptr = self
            .iprev
            .as_ref()
            .and_then(|iprev| iprev.ptr.as_ref())
            .and_then(|ptr| ptr.first().map(|name| name.strip_suffix('.').unwrap_or(name).to_owned()))
            .unwrap_or_else(|| "unknown".into());
        let tls = self.tls.as_ref().map(|tls| format!("(using {tls})\r\n\t")).unwrap_or_default();
        let with = if self.tls.is_some() { "ESMTPS" } else { "ESMTP" };
        let received = format!(
            "Received: from {helo} ({ptr} [{remote}])\r\n\t{tls}by {hostname} (kernoid) with {with};\r\n\t{date}\r\n",
            remote = self.remote,
            hostname = self.inner.settings.hostname,
            date = chrono::Utc::now().to_rfc2822(),
        );
        headers.extend_from_slice(received.as_bytes());
    }
}

/// The message without `Authentication-Results` headers that claim kernoid's host name – only kernoid may write
/// those (RFC 8601, 5).
pub(crate) fn without_own_results(raw: &[u8], hostname: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    let mut dropping = false;
    while !rest.is_empty() {
        let end = rest.iter().position(|&b| b == b'\n').map_or(rest.len(), |i| i + 1);
        let (line, tail) = rest.split_at(end);
        if line == b"\r\n" || line == b"\n" {
            // The end of the headers: the rest is the body.
            out.extend_from_slice(rest);
            return out;
        }
        let continuation = matches!(line.first(), Some(b' ' | b'\t'));
        if !continuation {
            dropping = is_own_result(line, hostname);
        }
        if !dropping {
            out.extend_from_slice(line);
        }
        rest = tail;
    }
    out
}

fn is_own_result(line: &[u8], hostname: &str) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else { return false };
    let (name, value) = line.split_at(colon);
    if !name.trim_ascii().eq_ignore_ascii_case(b"authentication-results") {
        return false;
    }
    let value = String::from_utf8_lossy(&value[1..]);
    let id = value.trim_start().split(|c: char| c == ';' || c.is_whitespace()).next().unwrap_or_default();
    id.eq_ignore_ascii_case(hostname)
}

#[cfg(test)]
mod tests {
    use super::without_own_results;

    #[test]
    fn forged_results_of_this_host_are_removed() {
        let raw = b"Authentication-Results: mx.kernoid.example;\r\n\tspf=pass\r\nAuthentication-Results: other.example; dkim=pass\r\nSubject: Hi\r\n\r\nAuthentication-Results: mx.kernoid.example; in the body\r\n";
        let cleaned = String::from_utf8(without_own_results(raw, "mx.kernoid.example")).unwrap();
        assert_eq!(
            cleaned,
            "Authentication-Results: other.example; dkim=pass\r\nSubject: Hi\r\n\r\nAuthentication-Results: mx.kernoid.example; in the body\r\n"
        );
    }
}
