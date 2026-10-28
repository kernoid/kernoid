// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: AGPL-3.0-only
//! Threads (RFC 0002, 5). Derived from Stalwart's threading (`crates/email/src/message/ingest.rs`, v0.16.27): two
//! emails are in one thread if their base subjects are equal and they share a message id – their own `Message-ID`,
//! an `In-Reply-To`, a `References` or a `Resent-Message-ID`. Unlike Stalwart, threads are never merged: a thread id
//! stays as it is (RFC 8621, 4.1.1), and a new email joins the earliest matching thread.

use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{Result, parse::Summary};

/// The ids threading compares, without duplicates.
pub(crate) fn references(summary: &Summary) -> Vec<String> {
    let mut ids: Vec<String> = summary
        .message_id
        .iter()
        .chain(&summary.in_reply_to)
        .chain(&summary.references)
        .chain(&summary.resent_message_ids)
        .cloned()
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// A hash of the base subject; an empty subject is a subject of its own, as in Stalwart.
pub(crate) fn subject_hash(base_subject: &str) -> Vec<u8> {
    let subject = if base_subject.is_empty() { "!" } else { base_subject };
    Sha256::digest(subject.as_bytes())[..16].to_vec()
}

/// The thread a new email joins: the thread of the earliest email that matches, if any.
pub(crate) async fn find(
    tx: &mut Transaction<'static, Postgres>,
    account: Uuid,
    subject_hash: &[u8],
    references: &[String],
) -> Result<Option<Uuid>> {
    if references.is_empty() {
        return Ok(None);
    }
    Ok(sqlx::query_scalar!(
        "SELECT e.thread_id FROM email_thread_refs r JOIN emails e ON e.id = r.email_id
         WHERE r.account_id = $1 AND r.subject_hash = $2 AND r.message_ref = ANY($3)
         ORDER BY e.received_at, e.id LIMIT 1",
        account,
        subject_hash,
        references,
    )
    .fetch_optional(&mut **tx)
    .await?)
}

/// Keeps the ids of a new email for the emails that follow it.
pub(crate) async fn remember(
    tx: &mut Transaction<'static, Postgres>,
    account: Uuid,
    email: Uuid,
    subject_hash: &[u8],
    references: &[String],
) -> Result<()> {
    sqlx::query!(
        "INSERT INTO email_thread_refs (account_id, subject_hash, message_ref, email_id)
         SELECT $1, $2, reference, $3 FROM unnest($4::text[]) AS reference",
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
    fn references_are_unique_and_include_the_own_id() {
        let summary = Summary {
            message_id: Some("b@x".into()),
            in_reply_to: vec!["a@x".into()],
            references: vec!["a@x".into(), "0@x".into()],
            ..Summary::default()
        };
        assert_eq!(references(&summary), ["0@x", "a@x", "b@x"]);
        assert_eq!(subject_hash(""), subject_hash("!"));
        assert_ne!(subject_hash("Lunch"), subject_hash("Dinner"));
    }
}
