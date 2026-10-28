// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sessions against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

mod common;

use std::time::Duration;

use common::{WHO, identity, tenant_with};
use kernoid_events::{AggregateId, EventStore};
use kernoid_identity::{
    Address, Identity, IdentityError,
    session::{ClientMeta, FAILURES_PER_ADDRESS, FAILURES_PER_NAME},
};
use sqlx::PgPool;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery staple";

fn client(address: &str) -> ClientMeta {
    ClientMeta { address: Some(address.parse().unwrap()), user_agent: Some("test".into()) }
}

/// An instance with a tenant and the account alice@firma.de; returns (instance, tenant, account).
async fn alice(identity: &Identity) -> (Uuid, Uuid, Uuid) {
    let (instance, tenant) = tenant_with(identity, "login.firma.de", &["firma.de"]).await;
    let account = identity.add_account(tenant, &Address::parse("alice@firma.de").unwrap(), "Alice", WHO).await.unwrap();
    identity.set_password(account, PASSWORD, WHO).await.unwrap();
    (instance, tenant, account)
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_session_from_login_to_logout(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, tenant, account) = alice(&identity).await;
    let created =
        identity.create_session(instance, "Alice@firma.de", PASSWORD, None, &client("192.0.2.1")).await.unwrap();
    assert!(created.token.starts_with(&format!("ks1.{}.", created.id)));
    assert_eq!(created.account.id, account);
    let lifetime = created.expires_at - chrono::Utc::now();
    assert!(lifetime > chrono::Duration::hours(7) && lifetime <= chrono::Duration::hours(8), "{lifetime}");

    let session = identity.session(instance, &created.token).await.unwrap();
    assert_eq!(
        (session.id, session.account.id, session.checks.as_slice()),
        (created.id, account, &["password".to_owned()][..])
    );

    // The token is a credential: only its hash is stored, and nothing of it is in the events.
    let stored: Vec<u8> = sqlx::query_scalar!("SELECT token_hash FROM sessions WHERE id = $1", created.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), 32);
    let secret = created.token.rsplit('.').next().unwrap();
    let events = EventStore::new(pool.clone())
        .events(&AggregateId::new(instance, "session", created.id.to_string()))
        .await
        .unwrap();
    assert_eq!(events[0].event_type, "session.created");
    assert_eq!(events[0].owner, tenant);
    assert!(events.iter().all(|event| !event.payload.to_string().contains(secret)));

    identity.terminate_session(instance, &created.token).await.unwrap();
    assert!(matches!(identity.session(instance, &created.token).await, Err(IdentityError::InvalidSession)));
    assert!(matches!(identity.terminate_session(instance, &created.token).await, Err(IdentityError::InvalidSession)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn tokens_are_checked_strictly(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, _, _) = alice(&identity).await;
    let (other_instance, _) = tenant_with(&identity, "login.other.org", &["other.org"]).await;
    let created =
        identity.create_session(instance, "alice@firma.de", PASSWORD, None, &ClientMeta::default()).await.unwrap();

    let mut forged = created.token.clone();
    let last = forged.pop().unwrap();
    forged.push(if last == 'A' { 'B' } else { 'A' });
    let other_session = format!("ks1.{}.{}", Uuid::now_v7(), created.token.rsplit('.').next().unwrap());
    for token in [forged.as_str(), other_session.as_str(), "", "ks1.garbage", "Bearer x"] {
        assert!(matches!(identity.session(instance, token).await, Err(IdentityError::InvalidSession)), "{token}");
    }
    // A session belongs to the instance it was created at.
    assert!(matches!(identity.session(other_instance, &created.token).await, Err(IdentityError::InvalidSession)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn sessions_expire_and_follow_deactivation(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, tenant, account) = alice(&identity).await;
    assert!(matches!(
        identity
            .create_session(
                instance,
                "alice@firma.de",
                PASSWORD,
                Some(Duration::from_secs(31 * 86_400)),
                &ClientMeta::default()
            )
            .await,
        Err(IdentityError::Refused(_))
    ));

    let short = identity
        .create_session(instance, "alice@firma.de", PASSWORD, Some(Duration::from_secs(1)), &ClientMeta::default())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(matches!(identity.session(instance, &short.token).await, Err(IdentityError::InvalidSession)));

    let long =
        identity.create_session(instance, "alice@firma.de", PASSWORD, None, &ClientMeta::default()).await.unwrap();
    identity.set_account_active(account, false, WHO).await.unwrap();
    assert!(matches!(identity.session(instance, &long.token).await, Err(IdentityError::InvalidSession)));
    identity.set_account_active(account, true, WHO).await.unwrap();
    identity.session(instance, &long.token).await.unwrap();
    identity.set_tenant_active(instance, tenant, false, WHO).await.unwrap();
    assert!(matches!(identity.session(instance, &long.token).await, Err(IdentityError::InvalidSession)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn failed_attempts_are_limited_per_login_name(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, _, _) = alice(&identity).await;
    for attempt in 0..FAILURES_PER_NAME {
        // Different client addresses: only the login name counts here.
        let from = client(&format!("192.0.2.{}", attempt + 1));
        assert!(matches!(
            identity.create_session(instance, "alice@firma.de", "wrong password!!", None, &from).await,
            Err(IdentityError::InvalidCredentials)
        ));
    }
    // Now even the right password is refused – for this login name, however it is spelt.
    let refused = identity.create_session(instance, "ALICE@firma.de ", PASSWORD, None, &client("192.0.2.99")).await;
    assert!(
        matches!(refused, Err(IdentityError::TooManyAttempts { retry_after }) if retry_after <= Duration::from_secs(900))
    );
    // Unknown names are counted the same way, so the limit tells nothing about who exists.
    for _ in 0..FAILURES_PER_NAME {
        let _ = identity
            .create_session(instance, "nobody@firma.de", "wrong password!!", None, &ClientMeta::default())
            .await;
    }
    assert!(matches!(
        identity.create_session(instance, "nobody@firma.de", "wrong password!!", None, &ClientMeta::default()).await,
        Err(IdentityError::TooManyAttempts { .. })
    ));

    // When the window has passed, logins work again; a success clears the count of the name.
    sqlx::query!("UPDATE login_failures SET window_start = window_start - interval '16 minutes'")
        .execute(&pool)
        .await
        .unwrap();
    identity.create_session(instance, "alice@firma.de", PASSWORD, None, &client("192.0.2.99")).await.unwrap();
    assert_eq!(identity.clean_up().await.unwrap().failure_counts, 6, "the old counts of both names and five addresses");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn failed_attempts_are_limited_per_client_address(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, _, _) = alice(&identity).await;
    for attempt in 0..FAILURES_PER_ADDRESS {
        let _ = identity
            .create_session(
                instance,
                &format!("guess{attempt}@firma.de"),
                "wrong password!!",
                None,
                &client("198.51.100.7"),
            )
            .await;
    }
    assert!(matches!(
        identity.create_session(instance, "alice@firma.de", PASSWORD, None, &client("198.51.100.7")).await,
        Err(IdentityError::TooManyAttempts { .. })
    ));
    identity.create_session(instance, "alice@firma.de", PASSWORD, None, &client("198.51.100.8")).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn old_sessions_are_cleaned_up(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, _, _) = alice(&identity).await;
    let ended =
        identity.create_session(instance, "alice@firma.de", PASSWORD, None, &ClientMeta::default()).await.unwrap();
    let live =
        identity.create_session(instance, "alice@firma.de", PASSWORD, None, &ClientMeta::default()).await.unwrap();
    identity.terminate_session(instance, &ended.token).await.unwrap();
    assert_eq!(identity.clean_up().await.unwrap().sessions, 0, "ended just now: kept for a day");
    sqlx::query!("UPDATE sessions SET terminated_at = now() - interval '2 days' WHERE id = $1", ended.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(identity.clean_up().await.unwrap().sessions, 1);
    identity.session(instance, &live.token).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn known_devices_get_in_while_others_lock_the_name(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, _, account) = alice(&identity).await;
    let mine = client("192.0.2.10");
    let first =
        identity.create_session_on_device(instance, "alice@firma.de", PASSWORD, None, &mine, None).await.unwrap();
    let device = first.device_token.clone().expect("a password login makes the device known");
    assert!(device.starts_with("kdt1."));
    let known: i64 =
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM known_devices WHERE account_id = $1"#, account)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(known, 1);

    // Someone else fails on purpose until the name is throttled.
    for attempt in 0..FAILURES_PER_NAME {
        let from = client(&format!("198.51.100.{}", attempt + 1));
        let _ = identity.create_session(instance, "alice@firma.de", "wrong password!!", None, &from).await;
    }
    assert!(matches!(
        identity.create_session(instance, "alice@firma.de", PASSWORD, None, &mine).await,
        Err(IdentityError::TooManyAttempts { .. })
    ));
    // The known device still gets in, and keeps its token.
    let again = identity
        .create_session_on_device(instance, "alice@firma.de", PASSWORD, None, &mine, Some(&device))
        .await
        .unwrap();
    assert_eq!(again.device_token.as_deref(), Some(device.as_str()));

    // A device token is no master key: for another login name, or forged, it counts as no device.
    assert!(matches!(
        identity.create_session_on_device(instance, "alice@firma.de", PASSWORD, None, &mine, Some("kdt1.forged")).await,
        Err(IdentityError::TooManyAttempts { .. })
    ));
    // Failures with the device count against the device, which is then throttled in turn.
    for _ in 0..FAILURES_PER_NAME {
        let wrong = identity
            .create_session_on_device(instance, "alice@firma.de", "wrong password!!", None, &mine, Some(&device))
            .await;
        assert!(matches!(wrong, Err(IdentityError::InvalidCredentials)));
    }
    assert!(matches!(
        identity.create_session_on_device(instance, "alice@firma.de", PASSWORD, None, &mine, Some(&device)).await,
        Err(IdentityError::TooManyAttempts { .. })
    ));

    // Expired devices are cleaned up.
    sqlx::query!("UPDATE known_devices SET expires_at = now() - interval '1 second'").execute(&pool).await.unwrap();
    assert_eq!(identity.clean_up().await.unwrap().devices, 1);
}
