// SPDX-License-Identifier: AGPL-3.0-or-later
//! The background work of identity – what the role `worker` runs, and what a program that builds kernoid in runs in its
//! own process (RFC 0009, 3). Each job runs until `shutdown`; errors are logged and tried again on the next round.

use kernoid_identity::Identity;
use kernoid_oidc::Oidc;
use tokio_util::sync::CancellationToken;

/// How often the worker removes old sessions and failure counts.
const CLEAN_UP_EVERY: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Removes ended and expired sessions and old failure counts until shutdown; with several workers, each does it –
/// the deletes do not get in each other's way.
pub async fn clean_up(identity: Identity, oidc: Oidc, shutdown: CancellationToken) {
    loop {
        if let Err(error) = identity.prune_registrations().await {
            tracing::warn!(%error, "removing expired registrations failed; trying again later");
        }
        if let Err(error) = identity.clean_up_file_link_access().await {
            tracing::warn!(%error, "removing expired link access failed; trying again later");
        }
        match identity.clean_up().await {
            Ok(cleaned) if cleaned.sessions > 0 || cleaned.failure_counts > 0 => {
                tracing::info!(sessions = cleaned.sessions, failure_counts = cleaned.failure_counts, "cleaned up");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "clean-up failed; trying again later"),
        }
        match oidc.clean_up().await {
            Ok(cleaned)
                if cleaned.auth_requests
                    + cleaned.codes
                    + cleaned.access_tokens
                    + cleaned.refresh_tokens
                    + cleaned.idp_logins
                    + cleaned.logout_notifications
                    > 0 =>
            {
                tracing::info!(
                    auth_requests = cleaned.auth_requests,
                    idp_logins = cleaned.idp_logins,
                    codes = cleaned.codes,
                    access_tokens = cleaned.access_tokens,
                    refresh_tokens = cleaned.refresh_tokens,
                    logout_notifications = cleaned.logout_notifications,
                    "cleaned up"
                )
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "clean-up failed; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(CLEAN_UP_EVERY) => {}
        }
    }
}

/// How often the worker looks for ended sessions to tell applications about.
const LOGOUT_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// Back-channel logout: queues and delivers logout tokens until shutdown; several workers share the work.
pub async fn logout_notifications(oidc: Oidc, shutdown: CancellationToken) {
    loop {
        match oidc.deliver_logout_notifications().await {
            Ok(done) if done.delivered + done.failed > 0 => {
                tracing::info!(delivered = done.delivered, failed = done.failed, "back-channel logout");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "back-channel logout failed; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(LOGOUT_EVERY) => {}
        }
    }
}

/// How often the worker checks whether signing keys are due for rotation.
const ROTATE_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

pub async fn rotate_keys(
    oidc: Oidc,
    db: kernoid_store::PgPool,
    config: kernoid_config::Oidc,
    shutdown: CancellationToken,
) {
    let day = std::time::Duration::from_secs(24 * 60 * 60);
    let rotation = day * config.key_rotation_days;
    let publish = std::time::Duration::from_secs(60 * 60) * config.key_publish_hours;
    let keep = day * config.retired_key_days;
    loop {
        // Several workers: one rotates, the others skip this round.
        match kernoid_store::lock::Lock::try_take(&db, "signing key rotation").await {
            Ok(Some(lock)) => {
                match oidc.rotate_signing_keys(rotation, publish, keep).await {
                    Ok(done) if done.added + done.activated + done.removed > 0 => {
                        tracing::info!(
                            added = done.added,
                            activated = done.activated,
                            removed = done.removed,
                            "signing keys"
                        );
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "key rotation failed; trying again later"),
                }
                if let Err(error) = lock.release().await {
                    tracing::warn!(%error, "releasing the key rotation lock");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "key rotation lock unavailable; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(ROTATE_EVERY) => {}
        }
    }
}

const ACME_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

pub async fn order_certificates(orderer: crate::acme::Orderer, shutdown: CancellationToken) {
    loop {
        match orderer.renew().await {
            Ok(done) if done.issued + done.failed > 0 => {
                tracing::info!(issued = done.issued, failed = done.failed, "certificates");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "ordering certificates failed; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(ACME_EVERY) => {}
        }
    }
}
