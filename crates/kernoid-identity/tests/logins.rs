// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accounts, logins and services (RFC 0003) against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

mod common;

use common::{WHO, identity, tenant_with};
use kernoid_identity::{
    Address, IdentityError,
    services::{Assign, Service, ServicePolicy, ServiceState},
};
use sqlx::PgPool;

const PASSWORD: &str = "correct horse battery staple";

fn address(value: &str) -> Address {
    Address::parse(value).unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn services_follow_the_tenants_rules(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    // By default: mail for native accounts, nothing for external ones.
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    assert_eq!(identity.services(alice).await.unwrap(), [(Service::Mail, ServiceState::On)]);
    let guest = identity.add_external_account(tenant, "Guest", Some(("guest@gmail.com", true)), WHO).await.unwrap();
    assert!(identity.services(guest).await.unwrap().is_empty());
    assert!(!identity.account(guest).await.unwrap().native);
    assert!(matches!(identity.grant_service(guest, Service::Mail, WHO).await, Err(IdentityError::Refused(_))));
    identity.grant_service(guest, Service::Files, WHO).await.unwrap();
    assert!(identity.has_service(guest, Service::Files).await.unwrap());

    // Mail only after approval; files for everyone.
    identity
        .set_service_policy(tenant, Service::Mail, ServicePolicy { assign: Assign::Native, approval: true }, WHO)
        .await
        .unwrap();
    identity
        .set_service_policy(tenant, Service::Files, ServicePolicy { assign: Assign::All, approval: false }, WHO)
        .await
        .unwrap();
    let bob = identity.add_account(tenant, &address("bob@firma.de"), "Bob", WHO).await.unwrap();
    assert_eq!(
        identity.services(bob).await.unwrap(),
        [(Service::Files, ServiceState::On), (Service::Mail, ServiceState::Requested)]
    );
    assert!(!identity.has_service(bob, Service::Mail).await.unwrap());
    identity.grant_service(bob, Service::Mail, WHO).await.unwrap();
    assert!(identity.has_service(bob, Service::Mail).await.unwrap());
    identity.revoke_service(bob, Service::Mail, WHO).await.unwrap();
    assert!(!identity.has_service(bob, Service::Mail).await.unwrap());

    // A shared mailbox always has mail.
    let info = identity.add_shared_mailbox(tenant, &address("info@firma.de"), "Info", WHO).await.unwrap();
    assert!(identity.has_service(info, Service::Mail).await.unwrap());
    assert!(matches!(identity.revoke_service(info, Service::Mail, WHO).await, Err(IdentityError::Refused(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn logins_by_address_username_and_contact_address(pool: PgPool) {
    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let other = identity.add_tenant(instance, "Other", WHO).await.unwrap();
    let max = identity.add_account(tenant, &address("max.mustermann@firma.de"), "Max", WHO).await.unwrap();
    identity.set_password(max, PASSWORD, WHO).await.unwrap();

    // Usernames only where the tenant allows them; unique in the instance.
    assert!(matches!(identity.set_username(max, Some("maxm"), WHO).await, Err(IdentityError::Refused(_))));
    identity.set_login_policy(tenant, true, true, WHO).await.unwrap();
    identity.set_username(max, Some("MaxM"), WHO).await.unwrap();
    identity.set_login_policy(other, true, true, WHO).await.unwrap();
    let elsewhere = identity.add_external_account(other, "Other Max", None, WHO).await.unwrap();
    assert!(matches!(identity.set_username(elsewhere, Some("maxm"), WHO).await, Err(IdentityError::Exists(_))));
    assert_eq!(identity.authenticate(instance, "maxm", PASSWORD).await.unwrap().id, max);
    assert_eq!(identity.authenticate(instance, "max.mustermann@firma.de", PASSWORD).await.unwrap().id, max);

    // A separate account of the same person, external, logging in with a verified contact address.
    let external = identity
        .add_external_account(tenant, "Max (Microsoft)", Some(("maxmuster67@outlook.com", true)), WHO)
        .await
        .unwrap();
    identity.set_password(external, PASSWORD, WHO).await.unwrap();
    let found = identity.authenticate(instance, "MaxMuster67@outlook.com", PASSWORD).await.unwrap();
    assert_eq!((found.id, found.address.as_str(), found.native), (external, "maxmuster67@outlook.com", false));
    // A verified contact address belongs to one account of the instance.
    assert!(matches!(
        identity.add_external_account(other, "Copy", Some(("maxmuster67@outlook.com", true)), WHO).await,
        Err(IdentityError::Exists(_))
    ));
    assert!(matches!(
        identity.set_contact_email(external, Some("max.mustermann@firma.de"), true, WHO).await,
        Err(IdentityError::Exists(_))
    ));
    assert!(identity.login_taken(instance, "maxm").await.unwrap());
    assert!(identity.login_taken(instance, "max.mustermann@firma.de").await.unwrap());
    // Without email logins, the contact address finds nobody.
    identity.set_login_policy(tenant, true, false, WHO).await.unwrap();
    assert!(matches!(
        identity.authenticate(instance, "maxmuster67@outlook.com", PASSWORD).await,
        Err(IdentityError::InvalidCredentials)
    ));
    // An external account becomes native with an address of the tenant, and may then have mail.
    identity.add_alias(external, &address("max.privat@firma.de"), WHO).await.unwrap();
    identity.set_primary_address(external, &address("max.privat@firma.de"), WHO).await.unwrap();
    assert!(identity.account(external).await.unwrap().native);
    identity.grant_service(external, Service::Mail, WHO).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn registration_waits_for_the_code(pool: PgPool) {
    use kernoid_identity::registration::NewRegistration;
    let identity = identity(pool.clone());
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let new = |email, native| NewRegistration {
        email,
        password: PASSWORD,
        display_name: "Max",
        native_address: native,
        username: None,
    };
    // Closed until the tenant opens it.
    assert!(matches!(
        identity.start_registration(instance, new("max@gmail.com", None), None).await,
        Err(IdentityError::Refused(_))
    ));
    identity.set_registration(tenant, true, &[common::domain("firma.de")], WHO).await.unwrap();
    identity.set_registration_tenant(instance, Some(tenant), WHO).await.unwrap();
    let options = identity.registration_options(instance).await.unwrap();
    assert!(options.open && options.domains == ["firma.de"]);

    // A native account: nothing written before the code.
    let started = identity
        .start_registration(instance, new("max@gmail.com", Some("max.mustermann@firma.de")), None)
        .await
        .unwrap();
    assert_eq!(started.code.len(), 8);
    let events: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM events"#).fetch_one(&pool).await.unwrap();
    assert!(matches!(
        identity.finish_registration(instance, started.id, "00000000").await,
        Err(IdentityError::InvalidCode)
    ));
    let after: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM events"#).fetch_one(&pool).await.unwrap();
    assert_eq!(events, after, "no events from unverified registrations");
    let account = identity.finish_registration(instance, started.id, &started.code).await.unwrap();
    assert!(
        matches!(
            identity.finish_registration(instance, started.id, &started.code).await,
            Err(IdentityError::InvalidCode)
        ),
        "once only"
    );
    let info = identity.account(account).await.unwrap();
    assert!(info.native && info.address == "max.mustermann@firma.de");
    assert!(identity.has_service(account, Service::Mail).await.unwrap());
    assert_eq!(identity.authenticate(instance, "max@gmail.com", PASSWORD).await.unwrap().id, account);

    // Duplicates are refused before anything is sent.
    assert!(matches!(
        identity.start_registration(instance, new("max@gmail.com", None), None).await,
        Err(IdentityError::Exists(_))
    ));
    assert!(matches!(
        identity.start_registration(instance, new("other@gmail.com", Some("max.mustermann@firma.de")), None).await,
        Err(IdentityError::AddressTaken(_))
    ));
    // Without an own address: an external account in the registration tenant, without mail.
    let started = identity.start_registration(instance, new("erika@outlook.com", None), None).await.unwrap();
    let erika = identity.finish_registration(instance, started.id, &started.code).await.unwrap();
    assert!(!identity.account(erika).await.unwrap().native);
    assert!(identity.services(erika).await.unwrap().is_empty());
}
