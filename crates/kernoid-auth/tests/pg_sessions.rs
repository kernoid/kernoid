// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sessions in PostgreSQL (set `DATABASE_URL` as for kernoid's other crates): kept by the hash of their id, gone when
//! expired, ended by a back-channel logout of their provider's login or of their subject.

use jiff::{SignedDuration, Timestamp};
use kernoid_auth::{
    relying::Principal,
    sessions::{PgSessions, Session, Sessions},
};
use sqlx::PgPool;

fn session(subject: &str, sid: &str, lifetime: SignedDuration) -> Session {
    Session {
        principal: Principal {
            subject: subject.into(),
            tenant: Some("t1".into()),
            roles: ["librarian".to_owned()].into(),
            name: None,
            email: None,
            session: Some(sid.into()),
        },
        id_token: "token".into(),
        expires_at: Timestamp::now() + lifetime,
    }
}

#[sqlx::test(migrator = "kernoid_auth::sessions::MIGRATOR")]
async fn sessions_live_in_postgresql(pool: PgPool) {
    let sessions = PgSessions::new(pool.clone());
    let hour = SignedDuration::from_hours(1);
    sessions.put("cookie-a", session("ada", "login-1", hour)).await;
    sessions.put("cookie-b", session("ada", "login-2", hour)).await;
    sessions.put("cookie-c", session("bob", "login-3", hour)).await;
    sessions.put("old", session("bob", "login-4", -hour)).await;
    assert_eq!(sessions.get("cookie-a").await.unwrap().principal.subject, "ada");
    assert!(sessions.get("old").await.is_none());
    // Only hashes are stored.
    let stored = sqlx::query_scalar!("SELECT count(*) FROM kernoid_auth_sessions WHERE id_hash = 'cookie-a'::bytea")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, Some(0));
    assert_eq!(sessions.clean_up().await.unwrap(), 1);
    assert_eq!(sessions.remove_logins(None, Some("login-1")).await, 1);
    assert!(sessions.get("cookie-a").await.is_none() && sessions.get("cookie-b").await.is_some());
    assert_eq!(sessions.remove_logins(Some("ada"), None).await, 1);
    sessions.remove("cookie-c").await;
    assert!(sessions.get("cookie-c").await.is_none());
}
