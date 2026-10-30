// SPDX-License-Identifier: AGPL-3.0-or-later
//! Encryption on arrival (RFC 0006, 5.2): mail for an account that switched end-to-end encrypted mail on is
//! encrypted to its key in use – after Sieve, the spam filter and the malware scan, before it is stored – as PGP/MIME
//! with header protection, and its summary is encrypted to the same key for the apps' lists. Mail already encrypted
//! is stored as it came. And Autocrypt (RFC 0006, 4.4): mail an account sends through the queue carries its public
//! key, so that its correspondents' programs can encrypt to it. Through `kernoid_e2e`, the apps' own implementation.

use base64::Engine;
use bytes::Bytes;
use kernoid_e2e::{Kind, PublicKey, mime};
use mail_parser::MessageParser;
use uuid::Uuid;

use crate::{Keyword, Mail, MailError, NewEmail, Result};

/// What delivery stores: the message, and its encrypted summary if kernoid encrypted it.
pub(crate) struct Arrival {
    pub raw: Bytes,
    pub encrypted_summary: Option<Vec<u8>>,
}

impl Mail {
    /// The key mail for `account` is encrypted to on arrival – `None` if it does not encrypt its mail.
    pub(crate) async fn arrival_key(&self, account: Uuid) -> Result<Option<PublicKey>> {
        let row = sqlx::query_scalar!(
            "SELECT k.public_key FROM accounts a
             JOIN openpgp_keys k ON k.account_id = a.id AND k.retired_at IS NULL
             WHERE a.id = $1 AND a.mail_e2e",
            account,
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|key| PublicKey::parse(&key).map_err(|error| MailError::Encryption(error.to_string()))).transpose()
    }

    /// Encrypts an arriving message if the account asks for it. A failure fails the delivery (to be tried again):
    /// mail is never stored in plain text for an account that chose otherwise.
    pub(crate) async fn encrypt_on_arrival(&self, account: Uuid, raw: Bytes) -> Result<Arrival> {
        let Some(key) = self.arrival_key(account).await? else {
            return Ok(Arrival { raw, encrypted_summary: None });
        };
        tokio::task::spawn_blocking(move || {
            if mime::is_encrypted(&raw) {
                return Ok(Arrival { raw, encrypted_summary: None });
            }
            let summary = mime::encrypted_summary(&raw, &[&key]).map_err(|e| MailError::Encryption(e.to_string()))?;
            let encrypted =
                mime::encrypt_message(&raw, &[&key], None).map_err(|e| MailError::Encryption(e.to_string()))?;
            Ok(Arrival { raw: Bytes::from(encrypted), encrypted_summary: Some(summary) })
        })
        .await
        .map_err(|_| MailError::Encryption("the encryption did not finish".to_owned()))?
    }
}

impl Mail {
    /// Encrypts up to `limit` emails stored before their account switched encrypted mail on (RFC 0006, 5.2): each is
    /// replaced by its encrypted copy – a new email with the same mailboxes, keywords and time of receipt, as an
    /// email's content never changes (RFC 8621, 4). Drafts stay as their program wrote them. Returns how many.
    pub async fn encrypt_stored(&self, limit: i64) -> Result<u64> {
        let due = sqlx::query!(
            r#"SELECT e.id, e.account_id, e.received_at, e.keywords,
                      array(SELECT mailbox_id FROM email_mailboxes WHERE email_id = e.id) AS "mailboxes!"
               FROM emails e
               JOIN accounts a ON a.id = e.account_id AND a.mail_e2e
               WHERE NOT e.encrypted
                 AND EXISTS (SELECT 1 FROM openpgp_keys k WHERE k.account_id = a.id AND k.retired_at IS NULL)
                 AND NOT EXISTS (SELECT 1 FROM email_mailboxes em JOIN mailboxes m ON m.id = em.mailbox_id
                                 WHERE em.email_id = e.id AND m.role = 'drafts')
               ORDER BY e.account_id, e.received_at
               LIMIT $1"#,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut done = 0;
        for row in due {
            let raw = self.raw_email(row.account_id, row.id).await?;
            let arrival = self.encrypt_on_arrival(row.account_id, raw.clone()).await?;
            let new = NewEmail {
                mailbox_ids: row.mailboxes,
                keywords: row.keywords.iter().filter_map(|k| Keyword::parse(k).ok()).collect(),
                received_at: Some(row.received_at),
            };
            match self.import(row.account_id, arrival.raw, new, arrival.encrypted_summary, Some(row.id)).await {
                Ok(_) => done += 1,
                // Gone meanwhile, or the account is over its quota with both copies: tried again next round.
                Err(error) => tracing::info!(%error, email = %row.id, "an email was not encrypted yet"),
            }
        }
        Ok(done)
    }

    /// The `Autocrypt:` header (Autocrypt Level 1, 2.1) for a message `account` sends: when its From address is the
    /// account's and its key in use names that address. Only keys of the kind `compatible` – Level 1 knows only v4
    /// Curve25519 keys; post-quantum ones wait for Autocrypt's next version (RFC 0006, 4.4). `None` otherwise, and for
    /// a message that has the header already.
    pub(crate) async fn autocrypt_header(&self, account: Uuid, raw: &[u8]) -> Result<Option<String>> {
        let Some(headers) = MessageParser::new().parse_headers(raw) else { return Ok(None) };
        if headers.header("Autocrypt").is_some() {
            return Ok(None);
        }
        let Some(from) = headers.from().and_then(|from| from.first()).and_then(|from| from.address()) else {
            return Ok(None);
        };
        let from = from.to_lowercase();
        let key = sqlx::query_scalar!(
            "SELECT k.public_key FROM openpgp_keys k JOIN addresses a ON a.account_id = k.account_id
             WHERE k.account_id = $1 AND k.retired_at IS NULL AND k.kind = 'compatible' AND lower(a.address) = $2",
            account,
            from,
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(key) = key.and_then(|key| PublicKey::parse(&key).ok()) else { return Ok(None) };
        if key.kind() != Some(Kind::Compatible) || !key.addresses().iter().any(|a| a.eq_ignore_ascii_case(&from)) {
            return Ok(None);
        }
        let Ok(keydata) = key.to_bytes() else { return Ok(None) };
        Ok(Some(autocrypt(&from, &keydata)))
    }
}

/// The header itself, folded in lines of 76 characters of base64.
fn autocrypt(address: &str, keydata: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(keydata);
    let mut header = format!("Autocrypt: addr={address}; keydata=");
    for chunk in encoded.as_bytes().chunks(76) {
        header.push_str("\r\n ");
        header.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    header.push_str("\r\n");
    header
}

#[cfg(test)]
mod tests {
    use super::autocrypt;

    #[test]
    fn the_header_is_folded() {
        let header = autocrypt("a@example.org", &[7u8; 100]);
        assert!(header.starts_with("Autocrypt: addr=a@example.org; keydata=\r\n "));
        assert!(header.lines().all(|line| line.trim_end().len() <= 78));
        assert!(header.ends_with("\r\n"));
    }
}
