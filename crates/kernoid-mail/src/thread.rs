// SPDX-License-Identifier: AGPL-3.0-or-later
//! Threads (RFC 0002, 5). An email belongs to the thread of an earlier email when both have the same base subject
//! (mail-parser's `thread_name`: the subject without `Re:`, `Fwd:` and list tags, RFC 5256, 2.1) and they name a
//! common message id – each email names its own `Message-ID` and every id of its `In-Reply-To`, `References` and
//! `Resent-Message-ID`. So a reply finds the message it answers, a message finds the replies that came before it,
//! and two replies to the same message find each other.
//!
//! Each email's ids are kept in `email_thread_refs` beside a hash of its base subject. A thread id never changes
//! (RFC 8621, 4.1.1): when a new email matches emails of several threads, the threads stay apart and the email joins
//! the one of the email stored first.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{Result, parse::Summary};

/// Bytes of the subject hash kept per id: enough to tell subjects apart within one account.
const HASH_LENGTH: usize = 16;

/// What an empty base subject is hashed as, so that emails without a subject thread among themselves by their ids.
/// The value is the one kernoid stored since its first release – changing it would split existing threads.
const EMPTY_SUBJECT: &str = "!";

/// The message ids an email names: its own, and those it refers to – each once, empty ones left out.
pub(crate) fn references(summary: &Summary) -> Vec<String> {
    let named = summary
        .message_id
        .iter()
        .chain(&summary.in_reply_to)
        .chain(&summary.references)
        .chain(&summary.resent_message_ids)
        .filter(|id| !id.is_empty())
        .cloned();
    named.collect::<BTreeSet<String>>().into_iter().collect()
}

/// The first [`HASH_LENGTH`] bytes of the SHA-256 of the base subject; emails are compared by it.
pub(crate) fn subject_hash(base_subject: &str) -> Vec<u8> {
    let subject = if base_subject.is_empty() { EMPTY_SUBJECT } else { base_subject };
    Sha256::digest(subject.as_bytes())[..HASH_LENGTH].to_vec()
}

/// The thread a new email joins: that of the first stored email with the same subject hash that names one of
/// `references`; `None` starts a thread.
pub(crate) async fn find(
    tx: &mut Transaction<'static, Postgres>,
    account: Uuid,
    subject_hash: &[u8],
    references: &[String],
) -> Result<Option<Uuid>> {
    if references.is_empty() {
        return Ok(None);
    }
    let thread = sqlx::query_scalar!(
        "SELECT e.thread_id FROM email_thread_refs r JOIN emails e ON e.id = r.email_id
         WHERE r.account_id = $1 AND r.subject_hash = $2 AND r.message_ref = ANY($3)
         ORDER BY e.id
         LIMIT 1",
        account,
        subject_hash,
        references,
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(thread)
}

/// Records the ids `email` names under its subject hash, for the emails that come after it.
pub(crate) async fn remember(
    tx: &mut Transaction<'static, Postgres>,
    account: Uuid,
    email: Uuid,
    subject_hash: &[u8],
    references: &[String],
) -> Result<()> {
    if references.is_empty() {
        return Ok(());
    }
    sqlx::query!(
        "INSERT INTO email_thread_refs (account_id, subject_hash, message_ref, email_id)
         SELECT $1, $2, reference, $3 FROM unnest($4::text[]) AS reference
         ON CONFLICT DO NOTHING",
        account,
        subject_hash,
        email,
        references,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_id_counts_once_and_empty_ones_not_at_all() {
        let summary = Summary {
            message_id: Some("own@example.org".into()),
            in_reply_to: vec!["parent@example.org".into(), String::new()],
            references: vec!["root@example.org".into(), "parent@example.org".into()],
            resent_message_ids: vec!["resent@example.org".into(), "own@example.org".into()],
            ..Summary::default()
        };
        let mut ids = references(&summary);
        ids.sort();
        assert_eq!(ids, ["own@example.org", "parent@example.org", "resent@example.org", "root@example.org"]);
        assert!(references(&Summary::default()).is_empty());
    }

    #[test]
    fn subjects_hash_alike_only_when_equal() {
        assert_eq!(subject_hash("Lunch").len(), HASH_LENGTH);
        assert_eq!(subject_hash("Lunch"), subject_hash("Lunch"));
        assert_ne!(subject_hash("Lunch"), subject_hash("lunch"));
        // An empty subject is a subject like any other – not the hash of nothing.
        assert_eq!(subject_hash(""), subject_hash(""));
        assert_ne!(subject_hash(""), Sha256::digest(b"")[..HASH_LENGTH].to_vec());
    }
}
