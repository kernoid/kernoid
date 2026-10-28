// SPDX-License-Identifier: AGPL-3.0-or-later
//! Changes of mail stores as they happen (RFC 0002, 11.1): one PostgreSQL connection per process listens on
//! [`crate::CHANNEL`] and hands each account id on to whoever waits – JMAP's push stream, IMAP's `IDLE`.

use std::time::Duration;

use kernoid_store::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Notifications not taken yet before the slowest listener misses some (it then reads the state anew).
const BUFFER: usize = 4096;

/// The changes of this process, from PostgreSQL.
#[derive(Debug, Clone)]
pub struct MailEvents {
    sender: broadcast::Sender<Uuid>,
}

impl Default for MailEvents {
    fn default() -> Self {
        Self { sender: broadcast::channel(BUFFER).0 }
    }
}

impl MailEvents {
    /// Accounts whose mail changed from now on. A receiver that lags gets `Lagged` and should treat every account as
    /// changed.
    pub fn subscribe(&self) -> broadcast::Receiver<Uuid> {
        self.sender.subscribe()
    }

    /// Tells the listeners of this process that `account` changed – for changes PostgreSQL does not announce, and
    /// for tests.
    pub fn announce(&self, account: Uuid) {
        let _ = self.sender.send(account);
    }

    /// Listens on PostgreSQL until `stop`, connecting again when the connection drops.
    pub async fn listen(self, pool: PgPool, stop: CancellationToken) {
        loop {
            let listener = async {
                let mut listener = PgListener::connect_with(&pool).await?;
                listener.listen(crate::CHANNEL).await?;
                loop {
                    let notification = listener.recv().await?;
                    if let Ok(account) = Uuid::parse_str(notification.payload()) {
                        let _ = self.sender.send(account);
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), sqlx::Error>(())
            };
            tokio::select! {
                () = stop.cancelled() => return,
                result = listener => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "listening for mail changes; trying again");
                    }
                }
            }
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
    }
}
