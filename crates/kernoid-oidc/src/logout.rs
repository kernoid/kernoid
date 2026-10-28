// SPDX-License-Identifier: AGPL-3.0-or-later
//! Back-channel logout (OpenID Connect Back-Channel Logout 1.0): when a session ends, every application it logged in
//! to that registered a `backchannel_logout_uri` receives a logout token – a JWT of type `logout+jwt` naming the
//! account (`sub`) and the session (`sid`). The worker queues and delivers them; a failed delivery is tried again
//! with growing pauses, [`ATTEMPTS`] times in all.

use std::time::Duration;

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::{Oidc, Result, internal, jwt, lifetime, random_secret};

/// How often a notification is tried before kernoid gives up.
pub const ATTEMPTS: i32 = 8;
/// How many notifications one round delivers at most.
const BATCH: i64 = 20;
/// While one worker delivers a notification, others leave it alone for this long.
const LEASE: Duration = Duration::from_secs(60);
const EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// What one round of [`Oidc::deliver_logout_notifications`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Delivered {
    pub queued: u64,
    pub delivered: u64,
    pub failed: u64,
}

/// The pause before attempt `attempts + 1`: 30 seconds, doubling, at most six hours.
fn backoff(attempts: i32) -> Duration {
    Duration::from_secs(30u64.saturating_mul(1 << attempts.clamp(0, 10)).min(6 * 60 * 60))
}

impl Oidc {
    /// Queues notifications for sessions that ended, and delivers those that are due.
    pub async fn deliver_logout_notifications(&self) -> Result<Delivered> {
        let mut tx = self.pool().begin().await.map_err(internal)?;
        let queued = sqlx::query!(
            "INSERT INTO logout_notifications (session_id, application_id, account_id, instance_id)
             SELECT sa.session_id, sa.application_id, s.account_id, s.instance_id
             FROM session_applications sa
             JOIN sessions s ON s.id = sa.session_id
             JOIN applications a ON a.id = sa.application_id
             WHERE s.terminated_at IS NOT NULL AND a.backchannel_logout_uri IS NOT NULL
             ON CONFLICT DO NOTHING"
        )
        .execute(&mut *tx)
        .await
        .map_err(internal)?
        .rows_affected();
        sqlx::query!(
            "DELETE FROM session_applications sa USING sessions s
             WHERE s.id = sa.session_id AND s.terminated_at IS NOT NULL"
        )
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        // Taken for a while, so that no other worker sends them at the same time.
        let due = sqlx::query!(
            r#"UPDATE logout_notifications SET next_attempt_at = now() + make_interval(secs => $1),
                   attempts = attempts + 1
               WHERE (session_id, application_id) IN (
                   SELECT session_id, application_id FROM logout_notifications
                   WHERE delivered_at IS NULL AND next_attempt_at <= now() AND attempts < $2
                   ORDER BY next_attempt_at LIMIT $3 FOR UPDATE SKIP LOCKED)
               RETURNING session_id, application_id, account_id, instance_id, attempts"#,
            LEASE.as_secs() as f64,
            ATTEMPTS,
            BATCH,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(internal)?;
        tx.commit().await.map_err(internal)?;

        let mut result = Delivered { queued, ..Delivered::default() };
        for notification in due {
            let outcome = self
                .send_logout_token(
                    notification.instance_id,
                    notification.application_id,
                    notification.account_id,
                    notification.session_id,
                )
                .await;
            match outcome {
                Ok(()) => {
                    result.delivered += 1;
                    sqlx::query!(
                        "UPDATE logout_notifications SET delivered_at = now(), last_error = NULL
                         WHERE session_id = $1 AND application_id = $2",
                        notification.session_id,
                        notification.application_id,
                    )
                    .execute(self.pool())
                    .await
                    .map_err(internal)?;
                }
                Err(error) => {
                    result.failed += 1;
                    tracing::warn!(application = %notification.application_id, %error, "back-channel logout failed");
                    sqlx::query!(
                        "UPDATE logout_notifications SET last_error = $3, next_attempt_at = now() + make_interval(secs => $4)
                         WHERE session_id = $1 AND application_id = $2",
                        notification.session_id,
                        notification.application_id,
                        error.chars().take(500).collect::<String>(),
                        backoff(notification.attempts).as_secs() as f64,
                    )
                    .execute(self.pool())
                    .await
                    .map_err(internal)?;
                }
            }
        }
        Ok(result)
    }

    /// Posts one logout token; any answer but 2xx is a failure (Back-Channel Logout 1.0, 2.8).
    async fn send_logout_token(
        &self,
        instance: Uuid,
        application: Uuid,
        account: Uuid,
        session: Uuid,
    ) -> std::result::Result<(), String> {
        let app = self.application(application).await.map_err(|error| error.to_string())?;
        let Some(uri) = app.options.backchannel_logout_uri.filter(|_| app.active) else {
            return Ok(()); // switched off since: nothing to tell
        };
        let url = url::Url::parse(&uri).map_err(|error| error.to_string())?;
        crate::outbound::check_url(&url, self.allow_private)?;
        let primary =
            sqlx::query_scalar!("SELECT domain FROM instance_domains WHERE instance_id = $1 AND is_primary", instance,)
                .fetch_one(self.pool())
                .await
                .map_err(|error| error.to_string())?;
        let now = Utc::now().timestamp();
        let claims = json!({
            "iss": self.issuer(&primary),
            "aud": application.to_string(),
            "iat": now,
            "exp": now + lifetime::LOGOUT_TOKEN.as_secs() as i64,
            "jti": random_secret("").map_err(|error| error.to_string())?,
            "sub": account.to_string(),
            "sid": session.to_string(),
            "events": { EVENT: {} },
        });
        let (kid, key) = self.signer(instance).await.map_err(|error| error.to_string())?;
        let token = jwt::sign_typed(&key, &kid, "logout+jwt", &claims).map_err(|error| error.to_string())?;
        let response = self
            .outbound
            .post(url)
            .form(&[("logout_token", token.as_str())])
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("the application answered {}", response.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pauses_grow_and_stop_growing() {
        assert_eq!(backoff(0), Duration::from_secs(30));
        assert_eq!(backoff(1), Duration::from_secs(60));
        assert_eq!(backoff(5), Duration::from_secs(960));
        assert_eq!(backoff(20), Duration::from_secs(6 * 60 * 60));
    }
}
