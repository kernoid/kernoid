// SPDX-License-Identifier: AGPL-3.0-or-later
//! Checking content for malware before kernoid keeps it – the hook of a scanning module (`clamav`). A [`Scanner`]
//! set on the [`BlobStore`] sees what a tenant that switched its module on stores in parts (uploads, files) while it
//! is stored, and mail before it is accepted (`check_bytes`); content it finds malware in is refused and what was
//! stored of it becomes garbage at once. Content larger than the scanner takes is kept unscanned.

use std::{fmt, sync::Arc};

use bytes::Bytes;
use futures_util::{
    future::BoxFuture,
    stream::{self, BoxStream},
};
use tokio::{sync::mpsc, task::JoinHandle};
use uuid::Uuid;

use crate::{BlobStore, PgPool};

/// What a scanner found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    /// Malware, by the scanner's name for it.
    Infected(String),
}

/// Why content was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("the content contains malware ({0})")]
    Infected(String),
    #[error("the content could not be checked for malware; try again later")]
    Unavailable,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(transparent)]
    Refused(#[from] Refused),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// A malware scanner, given content as it arrives.
pub trait Scanner: Send + Sync + fmt::Debug {
    /// The module that scans: a tenant's content is scanned once the tenant switched it on.
    fn module(&self) -> &'static str;
    /// The most bytes it scans; larger content is kept unscanned.
    fn max_size(&self) -> u64;
    /// Whether content is refused when the scanner cannot be asked (else it is kept unscanned).
    fn refuse_unchecked(&self) -> bool;
    /// Scans `content` to its end.
    fn scan(&self, content: BoxStream<'static, Bytes>) -> BoxFuture<'static, Result<Verdict, String>>;
}

/// The scanner of the blob store, if one of `tenants` switched its module on.
pub async fn for_tenants(
    blobs: &BlobStore,
    pool: &PgPool,
    tenants: &[Uuid],
) -> Result<Option<Arc<dyn Scanner>>, sqlx::Error> {
    let Some(scanner) = blobs.scanner() else { return Ok(None) };
    let on = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM tenant_modules WHERE tenant_id = ANY($1) AND module = $2)",
        tenants,
        scanner.module(),
    )
    .fetch_one(pool)
    .await?;
    Ok(on.unwrap_or(false).then(|| scanner.clone()))
}

/// A scan running beside content that is being stored: [`Scan::feed`] it each chunk, then [`Scan::finish`].
#[derive(Debug)]
pub struct Scan {
    sender: Option<mpsc::Sender<Bytes>>,
    verdict: JoinHandle<Result<Verdict, String>>,
    max_size: u64,
    size: u64,
    refuse_unchecked: bool,
}

impl Scan {
    pub fn start(scanner: &Arc<dyn Scanner>) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Bytes>(4);
        let chunks = stream::poll_fn(move |context| receiver.poll_recv(context));
        Self {
            sender: Some(sender),
            verdict: tokio::spawn(scanner.scan(Box::pin(chunks))),
            max_size: scanner.max_size(),
            size: 0,
            refuse_unchecked: scanner.refuse_unchecked(),
        }
    }

    /// Hands the scanner the next chunk – none once the content is larger than it scans.
    pub async fn feed(&mut self, chunk: &Bytes) {
        self.size += chunk.len() as u64;
        if self.size > self.max_size {
            self.sender = None;
        }
        if let Some(sender) = &self.sender
            && sender.send(chunk.clone()).await.is_err()
        {
            // The scanner stopped early; its answer says why.
            self.sender = None;
        }
    }

    /// The scanner's answer, once all was fed.
    pub async fn finish(mut self) -> Result<(), Refused> {
        let complete = self.size <= self.max_size;
        self.sender = None;
        let verdict = self.verdict.await.unwrap_or_else(|error| Err(error.to_string()));
        match verdict {
            Ok(Verdict::Infected(name)) => {
                tracing::info!(malware = %name, "refused content with malware");
                Err(Refused::Infected(name))
            }
            Ok(Verdict::Clean) => {
                if !complete {
                    tracing::debug!(size = self.size, "content larger than the scanner takes is kept unscanned");
                }
                Ok(())
            }
            // Content the scanner did not take whole may make it fail; it is kept unscanned like it.
            Err(_) if !complete => Ok(()),
            Err(error) => {
                tracing::warn!(%error, "the malware scanner could not be asked");
                if self.refuse_unchecked { Err(Refused::Unavailable) } else { Ok(()) }
            }
        }
    }
}

/// Checks content that is in memory – mail before it is accepted – if one of `tenants` scans.
pub async fn check_bytes(blobs: &BlobStore, pool: &PgPool, tenants: &[Uuid], content: &Bytes) -> Result<(), ScanError> {
    let Some(scanner) = for_tenants(blobs, pool, tenants).await? else { return Ok(()) };
    let mut scan = Scan::start(&scanner);
    scan.feed(content).await;
    Ok(scan.finish().await?)
}
