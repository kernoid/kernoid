// SPDX-License-Identifier: AGPL-3.0-or-later
//! Delivery status notifications (RFC 3464): what the sender of a message gets back when kernoid gives up on some of
//! its recipients (RFC 0002, 10.2). Built with mail-builder.

use mail_builder::{
    MessageBuilder,
    headers::{content_type::ContentType, date::Date},
    mime::MimePart,
};

/// A recipient kernoid gave up on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub recipient: String,
    /// The host that refused it, if one did.
    pub remote: Option<String>,
    /// What went wrong: the remote reply, or why kernoid could not deliver.
    pub reason: String,
    /// An SMTP reply code, for `Diagnostic-Code`.
    pub code: Option<u16>,
}

/// The headers of a message: everything before the first empty line.
fn headers_of(message: &[u8]) -> &[u8] {
    let end = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 2)
        .or_else(|| message.windows(2).position(|window| window == b"\n\n").map(|position| position + 1))
        .unwrap_or(message.len());
    &message[..end]
}

/// The notification to `sender` about `failures` of `original`, from `hostname`.
pub fn bounce(hostname: &str, sender: &str, original: &[u8], failures: &[Failure]) -> Vec<u8> {
    let mut text = String::from(
        "This is the mail system at kernoid.\r\n\r\nYour message could not be delivered to these recipients:\r\n\r\n",
    );
    for failure in failures {
        text.push_str(&format!("  <{}>: {}\r\n", failure.recipient, failure.reason));
    }
    text.push_str("\r\nThe headers of your message are attached.\r\n");

    let mut status = format!("Reporting-MTA: dns; {hostname}\r\nArrival-Date: {}\r\n", Date::now().to_rfc822());
    for failure in failures {
        status.push_str(&format!("\r\nFinal-Recipient: rfc822; {}\r\nAction: failed\r\n", failure.recipient));
        status.push_str(&format!(
            "Status: {}\r\n",
            match failure.code {
                Some(code) if (500..600).contains(&code) => "5.0.0",
                _ => "4.0.0",
            }
        ));
        if let Some(remote) = &failure.remote {
            status.push_str(&format!("Remote-MTA: dns; {remote}\r\n"));
        }
        let diagnostic = failure.reason.replace(['\r', '\n'], " ");
        match failure.code {
            Some(_) => status.push_str(&format!("Diagnostic-Code: smtp; {diagnostic}\r\n")),
            None => status.push_str(&format!("Diagnostic-Code: X-kernoid; {diagnostic}\r\n")),
        }
    }

    let report = MimePart::new(
        ContentType::new("multipart/report").attribute("report-type", "delivery-status"),
        vec![
            MimePart::new("text/plain", text),
            MimePart::new("message/delivery-status", status.into_bytes()).transfer_encoding("7bit"),
            MimePart::new("text/rfc822-headers", headers_of(original).to_vec()).transfer_encoding("7bit"),
        ],
    );
    MessageBuilder::new()
        .from(mail_builder::headers::address::Address::new_address(
            Some("Mail Delivery System"),
            format!("mailer-daemon@{hostname}"),
        ))
        .to(sender)
        .subject("Undelivered Mail Returned to Sender")
        .header("Auto-Submitted", mail_builder::headers::raw::Raw::new("auto-replied"))
        .body(report)
        .write_to_vec()
        .expect("writing to memory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bounce_names_the_failures_and_carries_the_headers() {
        let original = b"From: alice@firma.example\r\nSubject: Hello\r\n\r\nThe body stays out.\r\n";
        let failure = Failure {
            recipient: "bob@remote.example".into(),
            remote: Some("mx.remote.example".into()),
            reason: "550 5.1.1 no such user".into(),
            code: Some(550),
        };
        let bounce =
            String::from_utf8(bounce("mx.kernoid.example", "alice@firma.example", original, &[failure])).unwrap();
        assert!(bounce.contains("Content-Type: multipart/report"), "{bounce}");
        assert!(bounce.contains("report-type=\"delivery-status\"") || bounce.contains("report-type=delivery-status"));
        assert!(bounce.contains("Final-Recipient: rfc822; bob@remote.example"));
        assert!(bounce.contains("Status: 5.0.0"));
        assert!(bounce.contains("Diagnostic-Code: smtp; 550 5.1.1 no such user"));
        assert!(bounce.contains("Subject: Hello"));
        assert!(!bounce.contains("The body stays out."));
        assert!(bounce.contains("Auto-Submitted: auto-replied"));
    }
}
