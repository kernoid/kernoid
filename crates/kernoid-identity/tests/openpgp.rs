// SPDX-License-Identifier: AGPL-3.0-or-later
//! The keys of accounts and the tenant's policy (RFC 0006, 4 and 8) against PostgreSQL; set `DATABASE_URL` as for the
//! other crates' tests.

mod common;

use common::{WHO, identity, tenant_with};
use kernoid_e2e::{Kind, SecretKey};
use kernoid_identity::{
    Address, IdentityError,
    openpgp::KeyCopy,
    tenant::{E2ePolicy, E2eRule},
};
use sqlx::PgPool;

fn address(value: &str) -> Address {
    Address::parse(value).unwrap()
}

fn copy(label: &str) -> KeyCopy {
    let salt = label.starts_with("passkey:").then(|| vec![7; 32]);
    KeyCopy { label: label.to_owned(), protected: b"protected by the client".to_vec(), salt }
}

fn public(kind: Kind, addresses: &[&str]) -> Vec<u8> {
    SecretKey::generate(kind, addresses).unwrap().public().to_bytes().unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn keys_are_added_retired_and_published(pool: PgPool) {
    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();

    // Only the account's own addresses, and never without a copy.
    let foreign = public(Kind::Pqc, &["alice@firma.de", "mallory@example.org"]);
    assert!(matches!(
        identity.add_openpgp_key(alice, &foreign, vec![copy("recovery")], WHO).await,
        Err(IdentityError::Refused(_))
    ));
    let first = public(Kind::Pqc, &["alice@firma.de"]);
    assert!(matches!(identity.add_openpgp_key(alice, &first, vec![], WHO).await, Err(IdentityError::Refused(_))));
    assert!(matches!(
        identity.add_openpgp_key(alice, &first, vec![KeyCopy { salt: None, ..copy("passkey:abc") }], WHO).await,
        Err(IdentityError::Refused(_))
    ));
    let first =
        identity.add_openpgp_key(alice, &first, vec![copy("recovery"), copy("passkey:cred-1")], WHO).await.unwrap();
    let keys = identity.openpgp_keys(alice).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kind, "pqc");
    assert_eq!(keys[0].copies.iter().map(|c| c.label.as_str()).collect::<Vec<_>>(), ["passkey:cred-1", "recovery"]);
    let published = identity.published_key(instance, &address("alice@firma.de")).await.unwrap().unwrap();
    assert_eq!(published.fingerprint, first);
    assert_eq!(identity.wkd_keys("firma.de", "Alice").await.unwrap(), std::slice::from_ref(&published.public_key));
    assert_eq!(identity.wkd_local_parts("firma.de").await.unwrap(), ["alice"]);

    // The last copy of the key in use stays; others go.
    identity.remove_openpgp_key_copy(alice, &first, "passkey:cred-1", WHO).await.unwrap();
    assert!(matches!(
        identity.remove_openpgp_key_copy(alice, &first, "recovery", WHO).await,
        Err(IdentityError::Refused(_))
    ));

    // Mail encryption needs a key; a new key retires the old one, which is no longer published.
    identity.set_mail_e2e(alice, true, WHO).await.unwrap();
    assert!(identity.e2e_settings(alice).await.unwrap().mail);
    let second = identity
        .add_openpgp_key(alice, &public(Kind::Compatible, &["alice@firma.de"]), vec![copy("recovery")], WHO)
        .await
        .unwrap();
    let keys = identity.openpgp_keys(alice).await.unwrap();
    assert_eq!((keys[0].fingerprint.as_str(), keys[0].retired_at.is_none()), (second.as_str(), true));
    assert!(keys[1].retired_at.is_some());
    assert_eq!(
        identity.published_key(instance, &address("alice@firma.de")).await.unwrap().unwrap().fingerprint,
        second
    );

    // Retiring the key in use switches mail encryption off.
    identity.retire_openpgp_key(alice, &second, WHO).await.unwrap();
    assert!(!identity.e2e_settings(alice).await.unwrap().mail);
    assert!(identity.published_key(instance, &address("alice@firma.de")).await.unwrap().is_none());
    assert!(identity.wkd_keys("firma.de", "alice").await.unwrap().is_empty());
    assert!(matches!(identity.set_mail_e2e(alice, true, WHO).await, Err(IdentityError::Refused(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_tenant_allows_requires_forbids_and_recovers(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let bob = identity.add_account(tenant, &address("bob@firma.de"), "Bob", WHO).await.unwrap();
    let key = public(Kind::Pqc, &["bob@firma.de"]);
    identity.add_openpgp_key(bob, &key, vec![copy("recovery")], WHO).await.unwrap();

    let forbidden = E2ePolicy { mail: E2eRule::Forbidden, ..E2ePolicy::default() };
    identity.set_e2e_policy(tenant, forbidden, WHO).await.unwrap();
    assert!(matches!(identity.set_mail_e2e(bob, true, WHO).await, Err(IdentityError::Refused(_))));

    let required = E2ePolicy { mail: E2eRule::Required, ..E2ePolicy::default() };
    identity.set_e2e_policy(tenant, required, WHO).await.unwrap();
    identity.set_mail_e2e(bob, true, WHO).await.unwrap();
    assert!(matches!(identity.set_mail_e2e(bob, false, WHO).await, Err(IdentityError::Refused(_))));

    // Recovery needs the tenant's key, then every new key brings the tenant's copy.
    let recovering = E2ePolicy { recovery: true, ..required };
    assert!(matches!(identity.set_e2e_policy(tenant, recovering, WHO).await, Err(IdentityError::Refused(_))));
    let recovery = identity.set_recovery_key(tenant, &public(Kind::Pqc, &["recovery@firma.de"]), WHO).await.unwrap();
    identity.set_e2e_policy(tenant, recovering, WHO).await.unwrap();
    let (policy, key) = identity.e2e_policy(tenant).await.unwrap();
    assert_eq!(policy, recovering);
    assert_eq!(key.unwrap().0, recovery);
    let next = public(Kind::Pqc, &["bob@firma.de"]);
    assert!(matches!(
        identity.add_openpgp_key(bob, &next, vec![copy("recovery")], WHO).await,
        Err(IdentityError::Refused(_))
    ));
    let next = identity.add_openpgp_key(bob, &next, vec![copy("recovery"), copy("tenant")], WHO).await.unwrap();
    assert!(matches!(
        identity.remove_openpgp_key_copy(bob, &next, "tenant", WHO).await,
        Err(IdentityError::Refused(_))
    ));
}
