// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mailboxes as mbox (RFC 0002, 13.3): mboxrd quoting, the received time in the `From ` line, keywords in `Status`,
//! `X-Status` and `X-Keywords` headers as Dovecot and Thunderbird write them. Reading uses mail-parser's mbox reader.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{Keyword, Mail, MailboxEntry, NewEmail, Result};

/// The headers kernoid writes for keywords, and removes again when it reads them.
const FLAG_HEADERS: [&str; 3] = ["status", "x-status", "x-keywords"];

/// One email as an mbox entry: the `From ` line, the keyword headers, the message with its lines ending in LF and
/// `From ` lines quoted (mboxrd), and an empty line.
pub fn mbox_entry(raw: &[u8], sender: &str, received_at: DateTime<Utc>, keywords: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 128);
    let sender = if sender.is_empty() || sender.contains(char::is_whitespace) { "MAILER-DAEMON" } else { sender };
    out.extend_from_slice(format!("From {sender} {}\n", received_at.format("%a %b %e %H:%M:%S %Y")).as_bytes());
    let has = |keyword: &str| keywords.iter().any(|k| k == keyword);
    out.extend_from_slice(if has(Keyword::SEEN) { b"Status: RO\n" } else { b"Status: O\n" });
    let x_status: String = [("$answered", 'A'), ("$flagged", 'F'), ("$draft", 'T'), ("$deleted", 'D')]
        .into_iter()
        .filter(|(keyword, _)| has(keyword))
        .map(|(_, letter)| letter)
        .collect();
    if !x_status.is_empty() {
        out.extend_from_slice(format!("X-Status: {x_status}\n").as_bytes());
    }
    let others: Vec<&str> = keywords
        .iter()
        .map(String::as_str)
        .filter(|keyword| ![Keyword::SEEN, "$answered", "$flagged", "$draft", "$deleted"].contains(keyword))
        .collect();
    if !others.is_empty() {
        out.extend_from_slice(format!("X-Keywords: {}\n", others.join(" ")).as_bytes());
    }
    for line in raw.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let quoted = line.iter().position(|&b| b != b'>').is_some_and(|start| line[start..].starts_with(b"From "));
        if quoted {
            out.push(b'>');
        }
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    // `raw` ends with a line break, which left an empty last piece; one empty line separates the entries.
    if !out.ends_with(b"\n\n") {
        out.push(b'\n');
    }
    out
}

/// A message read from an mbox: as kernoid stores it (lines ending in CRLF, without the keyword headers), with its
/// keywords and the received time of its `From ` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MboxMessage {
    pub raw: Vec<u8>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<DateTime<Utc>>,
}

/// The messages of an mbox.
pub fn read_mbox(data: &[u8]) -> Vec<MboxMessage> {
    mail_parser::mailbox::mbox::MessageIterator::new(data)
        .filter_map(std::result::Result::ok)
        .map(|message| {
            let received_at = match message.internal_date() {
                0 => None,
                at => DateTime::from_timestamp(at as i64, 0),
            };
            let (raw, keywords) = split_flags(message.contents());
            MboxMessage { raw, keywords, received_at }
        })
        .collect()
}

/// Takes the keyword headers out of the header section and turns line ends into CRLF.
fn split_flags(contents: &[u8]) -> (Vec<u8>, Vec<Keyword>) {
    let mut raw = Vec::with_capacity(contents.len() + contents.len() / 32);
    let mut keywords = Vec::new();
    let mut in_headers = true;
    let mut skipping = false;
    let contents = contents.strip_suffix(b"\n").unwrap_or(contents);
    for line in contents.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if in_headers {
            if line.is_empty() {
                in_headers = false;
            } else if skipping && (line.starts_with(b" ") || line.starts_with(b"\t")) {
                continue;
            } else {
                skipping = false;
                let text = String::from_utf8_lossy(line);
                if let Some((name, value)) = text.split_once(':')
                    && FLAG_HEADERS.contains(&name.trim().to_ascii_lowercase().as_str())
                {
                    skipping = true;
                    let value = value.trim();
                    match name.trim().to_ascii_lowercase().as_str() {
                        "status" if value.contains('R') => keywords.push(Keyword::SEEN.to_owned()),
                        "x-status" => {
                            for (letter, keyword) in
                                [('A', "$answered"), ('F', "$flagged"), ('T', "$draft"), ('D', "$deleted")]
                            {
                                if value.contains(letter) {
                                    keywords.push(keyword.to_owned());
                                }
                            }
                        }
                        "x-keywords" => keywords
                            .extend(value.split([' ', ',']).filter(|keyword| !keyword.is_empty()).map(str::to_owned)),
                        _ => {}
                    }
                    continue;
                }
            }
        }
        raw.extend_from_slice(line);
        raw.extend_from_slice(b"\r\n");
    }
    // The last line break of the entry belongs to the mbox, not to the message.
    if raw.ends_with(b"\r\n\r\n") {
        raw.truncate(raw.len() - 2);
    }
    let mut keywords: Vec<Keyword> = keywords.iter().filter_map(|keyword| Keyword::parse(keyword).ok()).collect();
    keywords.sort();
    keywords.dedup();
    (raw, keywords)
}

/// What an mbox import did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MboxImport {
    pub imported: u64,
    /// Messages refused: not a message, too large, over the quota.
    pub failed: u64,
}

impl Mail {
    /// One email of a mailbox as an mbox entry.
    pub async fn mbox_entry(&self, account: Uuid, entry: &MailboxEntry) -> Result<Vec<u8>> {
        let raw = self.raw_email(account, entry.email).await?;
        let sender = self
            .emails(account, &[entry.email])
            .await?
            .first()
            .and_then(|email| email.from.first().map(|from| from.email.clone()))
            .unwrap_or_default();
        Ok(mbox_entry(&raw, &sender, entry.received_at, &entry.keywords))
    }

    /// Stores the messages of an mbox in a mailbox of the account, with their keywords and received times.
    pub async fn import_mbox(&self, account: Uuid, mailbox: Uuid, data: &[u8]) -> Result<MboxImport> {
        let mut result = MboxImport::default();
        for message in read_mbox(data) {
            let new =
                NewEmail { mailbox_ids: vec![mailbox], keywords: message.keywords, received_at: message.received_at };
            match self.import_email(account, Bytes::from(message.raw), new).await {
                Ok(_) => result.imported += 1,
                Err(
                    error @ (crate::MailError::Store(_) | crate::MailError::Blob(_) | crate::MailError::NotFound(_)),
                ) => {
                    return Err(error);
                }
                Err(error) => {
                    tracing::info!(%error, "a message of an mbox was refused");
                    result.failed += 1;
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let raw = b"From: Alice <alice@firma.example>\r\nSubject: Hi\r\n\r\nFrom here on\r\n>From there\r\nBye\r\n";
        let at = DateTime::from_timestamp(1_792_800_000, 0).unwrap();
        let keywords = vec!["$seen".to_owned(), "$flagged".to_owned(), "work".to_owned()];
        let entry = mbox_entry(raw, "alice@firma.example", at, &keywords);
        let text = String::from_utf8(entry.clone()).unwrap();
        assert!(text.starts_with("From alice@firma.example "), "{text}");
        assert!(text.contains("Status: RO\nX-Status: F\nX-Keywords: work\nFrom: Alice"), "{text}");
        assert!(text.contains("\n>From here on\n>>From there\n"), "{text}");
        let mut mbox = entry.clone();
        mbox.extend_from_slice(&mbox_entry(b"Subject: Second\r\n\r\nx\r\n", "", at, &[]));
        let messages = read_mbox(&mbox);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].raw, raw);
        let names: Vec<&str> = messages[0].keywords.iter().map(Keyword::as_str).collect();
        assert_eq!(names, ["$flagged", "$seen", "work"]);
        assert_eq!(messages[0].received_at, Some(at));
        assert_eq!(messages[1].raw, b"Subject: Second\r\n\r\nx\r\n");
        assert!(messages[1].keywords.is_empty());
    }
}
