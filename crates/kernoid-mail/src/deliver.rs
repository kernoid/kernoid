// SPDX-License-Identifier: AGPL-3.0-or-later
//! Delivery of incoming mail (RFC 0002, 9.2 and 9.4): who an address belongs to, and storing a message for an
//! account – unless it is a duplicate – where its Sieve script says.

use std::collections::{BTreeSet, HashMap};

use bytes::Bytes;
use mail_parser::MessageParser;
use uuid::Uuid;

use crate::{
    Imported, Keyword, Mail, MailError, MailboxInfo, NewEmail, NewMailbox, Result, Role,
    scripts::{self, Target},
};

/// Deliveries with a Message-ID the account received this many days ago or later are skipped.
const DUPLICATE_DAYS: i32 = 7;

/// What an address of an incoming message is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    Account {
        account: Uuid,
        tenant: Uuid,
    },
    /// A distribution list: its active members.
    Group {
        group: Uuid,
        tenant: Uuid,
        members: Vec<Uuid>,
    },
    /// The account or its tenant is deactivated.
    Disabled,
    /// A domain kernoid serves, but nobody has the address.
    Unknown,
    /// An SRS address of a message kernoid forwarded (RFC 0002, 10.6): a bounce to it goes on to the original
    /// sender, through the queue of `tenant`.
    Forwarded {
        to: String,
        tenant: Uuid,
    },
    /// Not a domain of kernoid's: it does not relay.
    NotLocal,
}

/// The envelope of a delivery, and what the checks found.
#[derive(Debug, Clone, Copy)]
pub struct Delivery<'a> {
    /// `MAIL FROM`, empty for bounces.
    pub from: &'a str,
    /// The recipient's address as the sender gave it (with a subaddress, if any).
    pub to: &'a str,
    /// The spam filter or DMARC put it in Junk, unless the script files it elsewhere.
    pub junk: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    Stored(Imported),
    /// The account received it already (RFC 0002, 9.4).
    Duplicate,
    /// The account's script discarded it.
    Discarded,
}

/// `local+detail@domain` → `local@domain`; lower case.
pub fn without_subaddress(address: &str) -> String {
    let address = address.to_lowercase();
    match address.rsplit_once('@') {
        Some((local, domain)) => match local.split_once('+') {
            Some((base, _)) if !base.is_empty() => format!("{base}@{domain}"),
            _ => address,
        },
        None => address,
    }
}

/// The IMAP system flags a script may set, as JMAP keywords; other flags are keywords as they are.
fn keyword(flag: &str) -> Option<Keyword> {
    let keyword = match flag.to_ascii_lowercase().as_str() {
        "\\seen" => Keyword::SEEN.to_owned(),
        "\\flagged" => Keyword::FLAGGED.to_owned(),
        "\\answered" => Keyword::ANSWERED.to_owned(),
        "\\draft" => Keyword::DRAFT.to_owned(),
        "\\deleted" | "\\recent" => return None,
        other => other.to_owned(),
    };
    Keyword::parse(&keyword).ok()
}

/// Each mailbox's path: the names from the top, joined with `/`.
fn paths(mailboxes: &[MailboxInfo]) -> HashMap<String, Uuid> {
    let by_id: HashMap<Uuid, &MailboxInfo> = mailboxes.iter().map(|mailbox| (mailbox.id, mailbox)).collect();
    mailboxes
        .iter()
        .map(|mailbox| {
            let mut names = vec![mailbox.name.as_str()];
            let mut parent = mailbox.parent_id;
            while let Some(id) = parent {
                let Some(up) = by_id.get(&id) else { break };
                names.push(up.name.as_str());
                parent = up.parent_id;
            }
            names.reverse();
            (names.join("/"), mailbox.id)
        })
        .collect()
}

impl Mail {
    /// Who `address` (lower case, the domain in ASCII) belongs to.
    pub async fn resolve_recipient(&self, address: &str) -> Result<Recipient> {
        let address = without_subaddress(address);
        let row = sqlx::query!(
            r#"SELECT ad.account_id, ad.group_id, ad.tenant_id, t.active AS tenant_active, a.active AS "account_active?",
                      EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = ad.account_id AND s.service = 'mail' AND s.state = 'on') AS "has_mail!"
               FROM addresses ad JOIN tenants t ON t.id = ad.tenant_id LEFT JOIN accounts a ON a.id = ad.account_id
               WHERE ad.address = $1"#,
            address,
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            let domain = address.rsplit_once('@').map(|(_, domain)| domain).unwrap_or_default();
            if let Some(tenant) = self.domain_tenant(domain).await? {
                if address.starts_with("srs0=")
                    && let Some(to) = crate::srs::reverse(&self.srs_secret().await?, &address, crate::srs::today())
                {
                    return Ok(Recipient::Forwarded { to, tenant });
                }
                return Ok(Recipient::Unknown);
            }
            return Ok(Recipient::NotLocal);
        };
        if !row.tenant_active {
            return Ok(Recipient::Disabled);
        }
        match (row.account_id, row.group_id) {
            // An account without the service `mail` has no mailbox (RFC 0003, 4).
            (Some(_), _) if !row.has_mail => Ok(Recipient::Unknown),
            (Some(account), _) if row.account_active == Some(true) => {
                Ok(Recipient::Account { account, tenant: row.tenant_id })
            }
            (Some(_), _) => Ok(Recipient::Disabled),
            (None, Some(group)) => {
                let members = sqlx::query_scalar!(
                    "SELECT m.account_id FROM group_members m JOIN accounts a ON a.id = m.account_id
                     WHERE m.group_id = $1 AND a.active
                       AND EXISTS (SELECT 1 FROM account_services s WHERE s.account_id = a.id AND s.service = 'mail' AND s.state = 'on')
                     ORDER BY m.account_id",
                    group,
                )
                .fetch_all(&self.pool)
                .await?;
                Ok(if members.is_empty() {
                    Recipient::Unknown
                } else {
                    Recipient::Group { group, tenant: row.tenant_id, members }
                })
            }
            (None, None) => Ok(Recipient::Unknown),
        }
    }

    /// The tenant whose verified domain `domain` (lower case, ASCII) is, if any.
    async fn domain_tenant(&self, domain: &str) -> Result<Option<Uuid>> {
        Ok(sqlx::query_scalar!("SELECT tenant_id FROM tenant_domains WHERE domain = $1 AND verified", domain)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// The installation's SRS secret (RFC 0002, 10.6), made at its first use.
    pub(crate) async fn srs_secret(&self) -> Result<Vec<u8>> {
        if let Some(secret) = sqlx::query_scalar!("SELECT secret FROM srs_secret").fetch_optional(&self.pool).await? {
            return Ok(secret);
        }
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("the system's random source");
        sqlx::query!("INSERT INTO srs_secret (secret) VALUES ($1) ON CONFLICT (id) DO NOTHING", &secret[..])
            .execute(&self.pool)
            .await?;
        // Another process may have made it first: theirs counts.
        Ok(sqlx::query_scalar!("SELECT secret FROM srs_secret").fetch_one(&self.pool).await?)
    }

    /// The SRS address under which kernoid forwards mail of `sender` from `domain` today; `None` if `sender` is no
    /// address.
    pub async fn srs_forward(&self, sender: &str, domain: &str) -> Result<Option<String>> {
        Ok(crate::srs::forward(&self.srs_secret().await?, sender, domain, crate::srs::today()))
    }

    /// A bounce to an SRS address, sent on to the original sender (RFC 0002, 10.6) – with an empty sender, as
    /// bounces go.
    pub async fn forward_bounce(&self, tenant: Uuid, to: &str, raw: Bytes) -> Result<Uuid> {
        let recipients = [to.to_lowercase()];
        self.enqueue(crate::Outgoing {
            tenant,
            account: None,
            from: "",
            recipients: &recipients,
            raw,
            lifetime: self.limits.queue_lifetime,
        })
        .await
    }

    /// Whether `domain` (lower case, ASCII) is a verified domain of a tenant: mail for it is kernoid's.
    pub async fn serves_domain(&self, domain: &str) -> Result<bool> {
        Ok(sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM tenant_domains WHERE domain = $1 AND verified) AS "served!""#,
            domain,
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Whether the account has no room left for a message of `size` bytes.
    pub async fn over_quota(&self, account: Uuid, size: u64) -> Result<bool> {
        let (used, quota) = self.quota(account).await?;
        Ok(quota.is_some_and(|quota| used.saturating_add(size) > quota))
    }

    /// Stores an incoming message for `account`: skipped if it is a duplicate, else where the account's active Sieve
    /// script puts it – the inbox (or Junk) without one.
    pub async fn deliver(&self, account: Uuid, raw: Bytes, delivery: Delivery<'_>) -> Result<Delivered> {
        let message_id = MessageParser::new()
            .parse_headers(&raw[..])
            .and_then(|message| message.message_id().map(str::to_owned))
            .filter(|id| !id.is_empty());
        if let Some(message_id) = &message_id {
            let duplicate = sqlx::query_scalar!(
                r#"SELECT EXISTS (SELECT 1 FROM emails WHERE account_id = $1 AND message_id = $2
                                  AND received_at > now() - make_interval(days => $3)) AS "duplicate!""#,
                account,
                message_id,
                DUPLICATE_DAYS,
            )
            .fetch_one(&self.pool)
            .await?;
            if duplicate {
                return Ok(Delivered::Duplicate);
            }
        }

        let mailboxes = self.mailboxes(account).await?;
        let mut paths = paths(&mailboxes);
        let role = |role: Role| mailboxes.iter().find(|mailbox| mailbox.role == Some(role)).map(|mailbox| mailbox.id);
        let inbox = role(Role::Inbox).ok_or(MailError::NotFound("the inbox"))?;
        let keep = if delivery.junk { role(Role::Junk).unwrap_or(inbox) } else { inbox };

        let outcome = match self.active_sieve_script(account).await? {
            None => scripts::Outcome { targets: vec![(Target::Keep, Vec::new())], ..scripts::Outcome::default() },
            Some(script) => {
                let (raw, from, to) = (raw.clone(), delivery.from.to_owned(), delivery.to.to_owned());
                let names: Vec<String> = paths.keys().cloned().collect();
                tokio::task::spawn_blocking(move || scripts::run(&script, &raw, &from, &to, &names))
                    .await
                    .unwrap_or_else(|_| scripts::Outcome {
                        targets: vec![(Target::Keep, Vec::new())],
                        ..scripts::Outcome::default()
                    })
            }
        };
        if !outcome.skipped.is_empty() {
            tracing::info!(%account, skipped = ?outcome.skipped, "Sieve actions kernoid does not carry out were skipped");
        }
        // The vacation response answers after the account's script – not junk, nor what the script threw away.
        let mut outcome = outcome;
        if !delivery.junk
            && !outcome.targets.is_empty()
            && let Some(script) = self.vacation_response(account).await?.script(chrono::Utc::now())
        {
            let (raw, from, to) = (raw.clone(), delivery.from.to_owned(), delivery.to.to_owned());
            let names: Vec<String> = paths.keys().cloned().collect();
            let answer = tokio::task::spawn_blocking(move || scripts::run(&script, &raw, &from, &to, &names))
                .await
                .unwrap_or_default();
            outcome.sends.extend(answer.sends.into_iter().filter(|send| send.vacation));
        }
        // What the script sends goes out whatever happens to the message here; a failure is logged, not the delivery's.
        for send in &outcome.sends {
            if let Err(error) = self.script_send(account, &raw, delivery, send).await {
                tracing::warn!(%error, %account, "a Sieve script's message could not be queued");
            }
        }
        if outcome.targets.is_empty() {
            return Ok(Delivered::Discarded);
        }

        let mut mailbox_ids = BTreeSet::new();
        let mut keywords = BTreeSet::new();
        for (target, flags) in outcome.targets {
            let mailbox = match target {
                Target::Keep => keep,
                Target::Folder { name, create } => match paths.get(&name) {
                    Some(id) => *id,
                    None if create => {
                        let id = self.create_path(account, &name, &mut paths).await?;
                        paths.insert(name, id);
                        id
                    }
                    // A missing mailbox is an error of the script: the message is kept (RFC 5228, 4.1).
                    None => keep,
                },
            };
            mailbox_ids.insert(mailbox);
            keywords.extend(flags.iter().filter_map(|flag| keyword(flag)));
        }
        let email = NewEmail {
            mailbox_ids: mailbox_ids.into_iter().collect(),
            keywords: keywords.into_iter().collect(),
            received_at: None,
        };
        Ok(Delivered::Stored(self.import_email(account, raw, email).await?))
    }

    /// Queues what a script sends (RFC 0002, 10.6): a redirect with the original sender rewritten by SRS into an
    /// address of the account's domain (an empty sender stays empty), a vacation reply with an empty one – once per
    /// sender in its `:days`.
    async fn script_send(
        &self,
        account: Uuid,
        raw: &Bytes,
        delivery: Delivery<'_>,
        send: &scripts::Send,
    ) -> Result<()> {
        if let Some((key, seconds)) = &send.once {
            let fresh = sqlx::query_scalar!(
                r#"INSERT INTO sieve_vacation_sent (account_id, key, expires_at)
                   VALUES ($1, $2, now() + make_interval(secs => $3))
                   ON CONFLICT (account_id, key) DO UPDATE SET expires_at = EXCLUDED.expires_at
                       WHERE sieve_vacation_sent.expires_at < now()
                   RETURNING 1 AS "sent!""#,
                account,
                key,
                *seconds as f64,
            )
            .fetch_optional(&self.pool)
            .await?;
            if fresh.is_none() {
                return Ok(());
            }
        }
        let tenant = sqlx::query_scalar!("SELECT tenant_id FROM mail_accounts WHERE account_id = $1", account)
            .fetch_one(&self.pool)
            .await?;
        let own = without_subaddress(delivery.to);
        let own_domain = own.rsplit_once('@').map(|(_, domain)| domain).unwrap_or_default();
        let rewritten = if delivery.from.is_empty() {
            String::new()
        } else {
            self.srs_forward(delivery.from, own_domain).await?.unwrap_or_else(|| own.clone())
        };
        let (from, message) = match (&send.message, send.vacation) {
            (Some(reply), true) => ("", Bytes::from(reply.clone())),
            _ => (rewritten.as_str(), raw.clone()),
        };
        let recipients = [send.to.to_lowercase()];
        self.enqueue(crate::Outgoing {
            tenant,
            account: Some(account),
            from,
            recipients: &recipients,
            raw: message,
            lifetime: self.limits.queue_lifetime,
        })
        .await?;
        Ok(())
    }

    /// Creates the mailboxes of `path` that do not exist yet; returns the last one.
    async fn create_path(&self, account: Uuid, path: &str, paths: &mut HashMap<String, Uuid>) -> Result<Uuid> {
        let mut parent = None;
        let mut current = String::new();
        for name in path.split('/') {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(name);
            let id = match paths.get(&current) {
                Some(id) => *id,
                None => {
                    let new = NewMailbox {
                        parent_id: parent,
                        name: name.to_owned(),
                        is_subscribed: true,
                        ..NewMailbox::default()
                    };
                    let id = self.create_mailbox(account, new).await?;
                    paths.insert(current.clone(), id);
                    id
                }
            };
            parent = Some(id);
        }
        parent.ok_or_else(|| MailError::Invalid("an empty mailbox name".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subaddresses_and_flags() {
        assert_eq!(without_subaddress("Alice+News@Firma.example"), "alice@firma.example");
        assert_eq!(without_subaddress("+x@firma.example"), "+x@firma.example");
        assert_eq!(keyword("\\Seen").map(|k| k.as_str().to_owned()).as_deref(), Some("$seen"));
        assert_eq!(keyword("\\Deleted"), None);
        assert_eq!(keyword("Work").map(|k| k.as_str().to_owned()).as_deref(), Some("work"));
    }
}
