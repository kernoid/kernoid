// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sieve scripts of an account (RFC 0002, 9.4 and 10.6), run with sieve-rs when mail arrives: `keep`, `fileinto` (with
//! `:create`), `discard` and flags are carried out, `redirect` and `vacation` go through the queue; `reject` and
//! `notify` are skipped, and the message is then kept.

use sieve::{Compiler, Envelope, Handler, Mailbox, MessageSource, Recipient, Reply, Runtime, SieveAction, Status};
use uuid::Uuid;

use crate::{Mail, MailError, Result};

/// Largest script accepted, in bytes.
const MAX_SCRIPT_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SieveScript {
    pub id: Uuid,
    pub name: String,
    pub content: String,
    pub active: bool,
}

/// Checks that a script compiles.
pub fn check_script(content: &str) -> Result<()> {
    Compiler::new()
        .with_max_script_size(MAX_SCRIPT_SIZE)
        .compile(content.as_bytes())
        .map(drop)
        .map_err(|error| MailError::Invalid(format!("the script does not compile: {error}")))
}

/// Where a script put the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// The inbox – or Junk for mail the spam filter flagged, when the script said nothing else.
    Keep,
    Folder {
        name: String,
        create: bool,
    },
}

/// A message a script sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Send {
    /// `redirect` (the message itself) or `vacation` (a reply).
    pub vacation: bool,
    pub to: String,
    /// The reply sieve-rs built; `None` for the message itself.
    pub message: Option<Vec<u8>>,
    /// For a vacation reply: who it answers, and for how many seconds it is not sent again (RFC 5230, 4.6).
    pub once: Option<(String, u64)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// Where the message goes, with its flags; empty if it was discarded.
    pub targets: Vec<(Target, Vec<String>)>,
    /// What the script sends.
    pub sends: Vec<Send>,
    /// Actions that were not carried out.
    pub skipped: Vec<&'static str>,
}

struct Collector<'m> {
    mailboxes: &'m [String],
    outcome: Outcome,
    /// Messages sieve-rs built, by their number.
    created: std::collections::HashMap<usize, Vec<u8>>,
    /// The last `:days` check of a vacation, for the reply that follows it.
    vacation: Option<(String, u64)>,
}

impl<'x> Handler<'x> for Collector<'_> {
    fn mailbox_exists(&mut self, _: &sieve::Context<'x>, mailboxes: &[Mailbox<'_>], _: &[&str]) -> Reply<bool> {
        Reply::Ready(mailboxes.iter().all(|mailbox| match mailbox {
            Mailbox::Name(name) => {
                name.eq_ignore_ascii_case("INBOX") || self.mailboxes.iter().any(|known| known == name)
            }
            Mailbox::Id(_) => false,
        }))
    }

    fn action(&mut self, _: &sieve::Context<'x>, action: SieveAction<'x>) -> Reply<()> {
        let flags = |flags: &[&str]| flags.iter().map(|flag| (*flag).to_owned()).collect::<Vec<_>>();
        match action {
            SieveAction::Keep { flags: kept, .. } => self.outcome.targets.push((Target::Keep, flags(kept))),
            SieveAction::FileInto { folder, flags: filed, create, .. } => {
                let target = if folder.eq_ignore_ascii_case("INBOX") {
                    Target::Keep
                } else {
                    Target::Folder { name: folder.to_owned(), create }
                };
                self.outcome.targets.push((target, flags(filed)));
            }
            SieveAction::Discard => {}
            SieveAction::Reject { .. } => self.outcome.skipped.push("reject"),
            SieveAction::SendMessage { source, recipient: Recipient::Address(to), message_id, .. } => {
                let vacation = source == MessageSource::Vacation;
                self.outcome.sends.push(Send {
                    vacation,
                    to: to.to_owned(),
                    message: if message_id == 0 { None } else { self.created.remove(&message_id) },
                    once: if vacation { self.vacation.take() } else { None },
                });
            }
            SieveAction::SendMessage { .. } => self.outcome.skipped.push("sending to a list"),
            SieveAction::Notify { .. } => self.outcome.skipped.push("notify"),
            SieveAction::CreatedMessage { message_id, message } => {
                self.created.insert(message_id, message);
            }
            SieveAction::SetEnvelope { .. } => {}
        }
        Reply::Ready(())
    }

    /// Vacation asks whether it answered this sender within `:days`; kernoid answers after the script, from
    /// `sieve_vacation_sent`, and drops the reply then. Other duplicate checks (RFC 7352) see nothing seen before.
    fn duplicate_id(&mut self, _: &sieve::Context<'x>, id: &str, expiry: u64, _: bool) -> Reply<bool> {
        if id.starts_with("_v") {
            self.vacation = Some((id.to_owned(), expiry));
        }
        Reply::Ready(false)
    }
}

/// Runs `script` on `raw`; `mailboxes` are the account's mailbox paths, for `mailboxexists`. A script that fails
/// keeps the message (RFC 5228, 2.10.6).
pub(crate) fn run(script: &str, raw: &[u8], from: &str, to: &str, mailboxes: &[String]) -> Outcome {
    let Ok(compiled) = Compiler::new().with_max_script_size(MAX_SCRIPT_SIZE).compile(script.as_bytes()) else {
        return Outcome { targets: vec![(Target::Keep, Vec::new())], ..Outcome::default() };
    };
    let runtime = Runtime::new();
    let mut arena = sieve::Arena::new();
    let mut instance = runtime
        .filter(raw, &compiled, &mut arena)
        .with_envelope(Envelope::From, from.to_owned())
        .with_envelope(Envelope::To, to.to_owned())
        // The account's address without a subaddress: vacation looks for it in To and Cc.
        .with_user_address(crate::deliver::without_subaddress(to));
    let mut collector =
        Collector { mailboxes, outcome: Outcome::default(), created: Default::default(), vacation: None };
    loop {
        match instance.run(&mut collector) {
            Ok(Status::Finished) => break,
            Ok(Status::Pending) => instance.resume(true),
            Err(error) => {
                tracing::warn!(%error, "a Sieve script failed; keeping the message");
                return Outcome {
                    targets: vec![(Target::Keep, Vec::new())],
                    skipped: collector.outcome.skipped,
                    ..Outcome::default()
                };
            }
        }
    }
    let mut outcome = collector.outcome;
    // What was skipped would have taken the message somewhere; without it, the message must not get lost.
    if outcome.targets.is_empty() && !outcome.skipped.is_empty() {
        outcome.targets.push((Target::Keep, Vec::new()));
    }
    outcome
}

impl Mail {
    /// The account's scripts.
    pub async fn sieve_scripts(&self, account: Uuid) -> Result<Vec<SieveScript>> {
        Ok(sqlx::query_as!(
            SieveScript,
            "SELECT id, name, content, active FROM sieve_scripts WHERE account_id = $1 ORDER BY name",
            account,
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Saves a script under `name` (replacing one of that name), after checking that it compiles; `activate` makes
    /// it the one that runs.
    pub async fn put_sieve_script(&self, account: Uuid, name: &str, content: &str, activate: bool) -> Result<Uuid> {
        if name.trim().is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
            return Err(MailError::Invalid("a script name has 1 to 255 characters and no control characters".into()));
        }
        check_script(content)?;
        let mut tx = self.pool.begin().await?;
        self.lock(&mut tx, account).await?;
        if activate {
            sqlx::query!("UPDATE sieve_scripts SET active = false WHERE account_id = $1 AND active", account)
                .execute(&mut *tx)
                .await?;
        }
        let id = sqlx::query_scalar!(
            "INSERT INTO sieve_scripts (id, account_id, name, content, active) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (account_id, name) DO UPDATE SET content = $4, active = sieve_scripts.active OR $5, updated_at = now()
             RETURNING id",
            Uuid::now_v7(),
            account,
            name,
            content,
            activate,
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Makes the script `name` the one that runs, or none with `None`.
    pub async fn activate_sieve_script(&self, account: Uuid, name: Option<&str>) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.lock(&mut tx, account).await?;
        sqlx::query!("UPDATE sieve_scripts SET active = false WHERE account_id = $1 AND active", account)
            .execute(&mut *tx)
            .await?;
        if let Some(name) = name {
            let found = sqlx::query!(
                "UPDATE sieve_scripts SET active = true WHERE account_id = $1 AND name = $2",
                account,
                name
            )
            .execute(&mut *tx)
            .await?;
            if found.rows_affected() == 0 {
                return Err(MailError::NotFound("the script"));
            }
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_sieve_script(&self, account: Uuid, name: &str) -> Result<()> {
        let removed = sqlx::query!("DELETE FROM sieve_scripts WHERE account_id = $1 AND name = $2", account, name)
            .execute(&self.pool)
            .await?;
        if removed.rows_affected() == 0 {
            return Err(MailError::NotFound("the script"));
        }
        Ok(())
    }

    pub(crate) async fn active_sieve_script(&self, account: Uuid) -> Result<Option<String>> {
        Ok(sqlx::query_scalar!("SELECT content FROM sieve_scripts WHERE account_id = $1 AND active", account)
            .fetch_optional(&self.pool)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"From: list@lists.example\r\nList-ID: <dev.lists.example>\r\nSubject: Hello\r\n\r\nHi\r\n";

    #[test]
    fn scripts_file_flag_discard_and_keep_what_they_cannot_do() {
        let filed = run(
            r#"require ["fileinto", "imap4flags"]; if header :contains "List-ID" "dev" { fileinto :flags "\\Seen" "Lists/dev"; stop; }"#,
            MESSAGE,
            "list@lists.example",
            "alice@firma.example",
            &[],
        );
        assert_eq!(
            filed.targets,
            [(Target::Folder { name: "Lists/dev".into(), create: false }, vec!["\\Seen".into()])]
        );

        let discarded = run("discard;", MESSAGE, "a@b.example", "alice@firma.example", &[]);
        assert!(discarded.targets.is_empty());

        // Without a script action, the implicit keep.
        let kept = run(r#"if false { discard; }"#, MESSAGE, "a@b.example", "alice@firma.example", &[]);
        assert_eq!(kept.targets, [(Target::Keep, vec![])]);

        // A redirect sends the message on and cancels the implicit keep.
        let redirected =
            run(r#"redirect "bob@elsewhere.example";"#, MESSAGE, "a@b.example", "alice@firma.example", &[]);
        assert!(redirected.targets.is_empty());
        assert_eq!(
            redirected.sends,
            [Send { vacation: false, to: "bob@elsewhere.example".into(), message: None, once: None }]
        );

        // A vacation reply: built by sieve-rs, sent once per sender in :days.
        let away = run(
            r#"require "vacation"; vacation :days 3 "I am away.";"#,
            b"From: carol@other.example\r\nTo: alice@firma.example\r\nSubject: Hi\r\n\r\nHi\r\n",
            "carol@other.example",
            "alice@firma.example",
            &[],
        );
        assert_eq!(away.targets, [(Target::Keep, vec![])]);
        let reply = &away.sends[0];
        assert!(reply.vacation && reply.to == "carol@other.example");
        assert!(String::from_utf8_lossy(reply.message.as_ref().unwrap()).contains("I am away."));
        assert_eq!(reply.once.as_ref().map(|(_, seconds)| *seconds), Some(3 * 86_400));

        // A rejection cannot be sent at delivery: skipped, and the message kept.
        let rejected = run(r#"require "reject"; reject "No.";"#, MESSAGE, "a@b.example", "alice@firma.example", &[]);
        assert_eq!(rejected.targets, [(Target::Keep, vec![])]);
        assert_eq!(rejected.skipped, ["reject"]);

        assert!(check_script("require \"fileinto\"; fileinto \"x\";").is_ok());
        assert!(matches!(check_script("fileinto \"x\""), Err(MailError::Invalid(_))));
    }
}
