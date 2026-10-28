// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accounts against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

mod common;

use common::{FakeDns, WHO, domain, identity, tenant_with};
use kernoid_events::AggregateId;
use kernoid_identity::{Address, IdentityError};
use sqlx::PgPool;

const PASSWORD: &str = "correct horse battery staple";

fn address(value: &str) -> Address {
    Address::parse(value).unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn addresses_need_a_verified_domain_of_the_tenant(pool: PgPool) {
    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    identity.add_tenant_domain(instance, tenant, &domain("unverified.de"), WHO).await.unwrap();

    let alice = identity.add_account(tenant, &address("Alice@Firma.de"), "Alice", WHO).await.unwrap();
    let found = identity.account_by_address(&address("alice@firma.de")).await.unwrap().unwrap();
    assert_eq!(
        (found.id, found.address.as_str(), found.tenant, found.instance),
        (alice, "alice@firma.de", tenant, instance)
    );

    for refused in ["bob@unverified.de", "bob@elsewhere.org"] {
        assert!(matches!(
            identity.add_account(tenant, &address(refused), "Bob", WHO).await,
            Err(IdentityError::Refused(_))
        ));
        assert!(matches!(identity.add_alias(alice, &address(refused), WHO).await, Err(IdentityError::Refused(_))));
    }
    identity.set_tenant_active(instance, tenant, false, WHO).await.unwrap();
    assert!(matches!(
        identity.add_account(tenant, &address("carol@firma.de"), "Carol", WHO).await,
        Err(IdentityError::Refused(_))
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_address_belongs_to_one_account(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    let bob = identity.add_account(tenant, &address("bob@firma.de"), "Bob", WHO).await.unwrap();

    assert!(matches!(
        identity.add_account(tenant, &address("ALICE@firma.de"), "Another Alice", WHO).await,
        Err(IdentityError::AddressTaken(a)) if a.as_str() == "alice@firma.de"
    ));
    identity.add_alias(alice, &address("info@firma.de"), WHO).await.unwrap();
    assert!(matches!(
        identity.add_alias(bob, &address("info@firma.de"), WHO).await,
        Err(IdentityError::AddressTaken(_))
    ));
    assert!(matches!(
        identity.add_alias(bob, &address("alice@firma.de"), WHO).await,
        Err(IdentityError::AddressTaken(_))
    ));
    assert!(matches!(identity.add_alias(alice, &address("info@firma.de"), WHO).await, Err(IdentityError::Exists(_))));
    // The refused alias left nothing behind on bob.
    assert_eq!(identity.account_by_address(&address("info@firma.de")).await.unwrap().unwrap().id, alice);

    // Once removed, an address is free again.
    identity.remove_alias(alice, &address("info@firma.de"), WHO).await.unwrap();
    identity.add_alias(bob, &address("info@firma.de"), WHO).await.unwrap();
    assert_eq!(identity.account_by_address(&address("info@firma.de")).await.unwrap().unwrap().id, bob);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_login_name_moves_between_addresses(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de", "firma.com"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    identity.add_alias(alice, &address("alice@firma.com"), WHO).await.unwrap();
    assert!(matches!(
        identity.remove_alias(alice, &address("alice@firma.de"), WHO).await,
        Err(IdentityError::Refused(_))
    ));

    identity.set_primary_address(alice, &address("alice@firma.com"), WHO).await.unwrap();
    assert_eq!(identity.account(alice).await.unwrap().address, "alice@firma.com");
    // The former primary address is an alias now and can be removed.
    identity.remove_alias(alice, &address("alice@firma.de"), WHO).await.unwrap();
    assert_eq!(identity.account_by_address(&address("alice@firma.de")).await.unwrap(), None);
    identity.rename_account(alice, "Alice A.", WHO).await.unwrap();
    assert_eq!(identity.accounts(tenant).await.unwrap()[0].display_name, "Alice A.");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn logins(pool: PgPool) {
    let identity = identity(pool.clone());
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let (other_instance, _) = tenant_with(&identity, "login.other.org", &["other.org"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    identity.add_alias(alice, &address("a@firma.de"), WHO).await.unwrap();

    // No password yet: no login.
    assert!(matches!(
        identity.authenticate(instance, "alice@firma.de", PASSWORD).await,
        Err(IdentityError::InvalidCredentials)
    ));
    assert!(matches!(identity.set_password(alice, "too short", WHO).await, Err(IdentityError::Refused(_))));
    identity.set_password(alice, PASSWORD, WHO).await.unwrap();

    for login in ["alice@firma.de", "Alice@Firma.DE", "a@firma.de"] {
        assert_eq!(identity.authenticate(instance, login, PASSWORD).await.unwrap().id, alice, "{login}");
    }
    for (at, login, password) in [
        (instance, "alice@firma.de", "correct horse battery stapler"),
        (instance, "nobody@firma.de", PASSWORD),
        (instance, "not an address", PASSWORD),
        (other_instance, "alice@firma.de", PASSWORD),
    ] {
        assert!(
            matches!(identity.authenticate(at, login, password).await, Err(IdentityError::InvalidCredentials)),
            "{login} {password}"
        );
    }

    // Deactivated: said only after the right password.
    identity.set_account_active(alice, false, WHO).await.unwrap();
    assert!(matches!(
        identity.authenticate(instance, "alice@firma.de", PASSWORD).await,
        Err(IdentityError::AccountDeactivated)
    ));
    assert!(matches!(
        identity.authenticate(instance, "alice@firma.de", "wrong password!!").await,
        Err(IdentityError::InvalidCredentials)
    ));
    identity.set_account_active(alice, true, WHO).await.unwrap();
    identity.set_tenant_active(instance, tenant, false, WHO).await.unwrap();
    assert!(matches!(
        identity.authenticate(instance, "alice@firma.de", PASSWORD).await,
        Err(IdentityError::AccountDeactivated)
    ));
    identity.set_tenant_active(instance, tenant, true, WHO).await.unwrap();
    identity.authenticate(instance, "alice@firma.de", PASSWORD).await.unwrap();

    // The hash is in account_passwords, never in an event.
    let events = kernoid_events::EventStore::new(pool.clone())
        .events(&AggregateId::new(instance, "account", alice.to_string()))
        .await
        .unwrap();
    let changed = events.iter().find(|event| event.event_type == "account.password_changed").unwrap();
    assert_eq!(changed.payload, serde_json::Value::Null);
    assert!(events.iter().all(|event| !event.payload.to_string().contains("argon2")));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn old_hashes_are_replaced_at_login(pool: PgPool) {
    use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
    let identity = identity(pool.clone());
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    identity.set_password(alice, PASSWORD, WHO).await.unwrap();
    let weak = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(8 * 1024, 1, 1, None).unwrap())
        .hash_password(PASSWORD.as_bytes())
        .unwrap()
        .to_string();
    sqlx::query!("UPDATE account_passwords SET hash = $2 WHERE account_id = $1", alice, weak)
        .execute(&pool)
        .await
        .unwrap();

    identity.authenticate(instance, "alice@firma.de", PASSWORD).await.unwrap();
    let hash = sqlx::query_scalar!("SELECT hash FROM account_passwords WHERE account_id = $1", alice)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{hash}");
    identity.authenticate(instance, "alice@firma.de", PASSWORD).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_domain_in_use_stays(pool: PgPool) {
    let identity = identity(pool);
    let dns = FakeDns::default();
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    assert!(matches!(
        identity.remove_tenant_domain(instance, tenant, &domain("firma.de"), WHO).await,
        Err(IdentityError::Refused(_))
    ));
    // With a second domain, the account can move over and the first domain can go.
    let token = identity.add_tenant_domain(instance, tenant, &domain("firma.com"), WHO).await.unwrap();
    dns.publish("firma.com", &token);
    identity.verify_tenant_domain(instance, tenant, &domain("firma.com"), &dns, WHO).await.unwrap();
    identity.add_alias(alice, &address("alice@firma.com"), WHO).await.unwrap();
    identity.set_primary_address(alice, &address("alice@firma.com"), WHO).await.unwrap();
    identity.remove_alias(alice, &address("alice@firma.de"), WHO).await.unwrap();
    identity.remove_tenant_domain(instance, tenant, &domain("firma.de"), WHO).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn groups_have_addresses_of_their_own(pool: PgPool) {
    let identity = identity(pool);
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    let group = identity.add_group(tenant, "Team", WHO).await.unwrap();

    identity.add_group_address(tenant, group, &address("team@firma.de"), WHO).await.unwrap();
    // One owner per address: an account's address is not a group's, and the other way round.
    assert!(matches!(
        identity.add_group_address(tenant, group, &address("alice@firma.de"), WHO).await,
        Err(IdentityError::AddressTaken(_))
    ));
    assert!(matches!(
        identity.add_alias(alice, &address("team@firma.de"), WHO).await,
        Err(IdentityError::AddressTaken(_))
    ));
    assert!(matches!(
        identity.add_group_address(tenant, group, &address("team@elsewhere.org"), WHO).await,
        Err(IdentityError::Refused(_))
    ));
    // Logging in with a group's address does not find an account.
    assert!(identity.account_by_address(&address("team@firma.de")).await.unwrap().is_none());
    assert_eq!(identity.groups(tenant).await.unwrap()[0].addresses, ["team@firma.de"]);

    // A removed group frees its addresses.
    identity.remove_group(tenant, group, WHO).await.unwrap();
    identity.add_alias(alice, &address("team@firma.de"), WHO).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mail_programs_log_in_with_app_passwords(pool: PgPool) {
    let identity = identity(pool);
    let (instance, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    identity.add_alias(alice, &address("a@firma.de"), WHO).await.unwrap();
    identity.set_password(alice, PASSWORD, WHO).await.unwrap();

    // Without a second factor, the account's password will do – under any of its addresses.
    assert_eq!(identity.mail_login("a@firma.de", PASSWORD, None).await.unwrap().id, alice);
    assert!(matches!(
        identity.mail_login("alice@firma.de", "wrong", None).await,
        Err(IdentityError::InvalidCredentials)
    ));
    assert!(matches!(
        identity.mail_login("nobody@firma.de", PASSWORD, None).await,
        Err(IdentityError::InvalidCredentials)
    ));

    let (id, secret) = identity.add_app_password(alice, "Thunderbird", WHO).await.unwrap();
    assert_eq!(identity.mail_login("alice@firma.de", &secret.to_uppercase(), None).await.unwrap().id, alice);
    let listed = identity.app_passwords(alice).await.unwrap();
    assert_eq!((listed[0].id, listed[0].name.as_str()), (id, "Thunderbird"));
    assert!(listed[0].last_used_at.is_some());

    // Once the tenant requires a second factor, only app passwords log mail programs in.
    identity.set_tenant_mfa_required(instance, tenant, true, WHO).await.unwrap();
    assert!(matches!(
        identity.mail_login("alice@firma.de", PASSWORD, None).await,
        Err(IdentityError::InvalidCredentials)
    ));
    assert_eq!(identity.mail_login("alice@firma.de", &secret, None).await.unwrap().id, alice);

    // Removed, or gone with the devices, it no longer works.
    identity.remove_app_password(alice, id, WHO).await.unwrap();
    assert!(matches!(
        identity.mail_login("alice@firma.de", &secret, None).await,
        Err(IdentityError::InvalidCredentials)
    ));
    let (_, again) = identity.add_app_password(alice, "Phone", WHO).await.unwrap();
    identity.reset_second_factors(alice, WHO).await.unwrap();
    assert!(identity.app_passwords(alice).await.unwrap().is_empty());
    assert!(matches!(
        identity.mail_login("alice@firma.de", &again, None).await,
        Err(IdentityError::InvalidCredentials)
    ));

    // Too many failures for one name: refused for a while, even with the right secret.
    let (_, current) = identity.add_app_password(alice, "Laptop", WHO).await.unwrap();
    for _ in 0..5 {
        let _ = identity.mail_login("alice@firma.de", "wrong", None).await;
    }
    assert!(matches!(
        identity.mail_login("alice@firma.de", &current, None).await,
        Err(IdentityError::TooManyAttempts { .. })
    ));

    // A deactivated account is told so, but only with the right secret.
    let bob = identity.add_account(tenant, &address("bob@firma.de"), "Bob", WHO).await.unwrap();
    let (_, bobs) = identity.add_app_password(bob, "Mail", WHO).await.unwrap();
    identity.set_account_active(bob, false, WHO).await.unwrap();
    assert!(matches!(identity.mail_login("bob@firma.de", &bobs, None).await, Err(IdentityError::AccountDeactivated)));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn shared_mailboxes_and_grants(pool: PgPool) {
    use kernoid_identity::role::Principal;
    let identity = identity(pool.clone());
    let (_, tenant) = tenant_with(&identity, "login.firma.de", &["firma.de"]).await;
    let (_, other) = tenant_with(&identity, "login.other.de", &["other.de"]).await;
    let alice = identity.add_account(tenant, &address("alice@firma.de"), "Alice", WHO).await.unwrap();
    let dave = identity.add_account(other, &address("dave@other.de"), "Dave", WHO).await.unwrap();
    let info = identity.add_shared_mailbox(tenant, &address("info@firma.de"), "Info", WHO).await.unwrap();
    assert!(identity.account(info).await.unwrap().shared);
    // Nobody logs in as it: no password, no app password, no link.
    assert!(matches!(identity.set_password(info, PASSWORD, WHO).await, Err(IdentityError::Refused(_))));
    assert!(matches!(identity.add_app_password(info, "Phone", WHO).await, Err(IdentityError::Refused(_))));

    // Grants: rights are checked and kept in canonical order; grantees are of the same tenant.
    let team = identity.add_group(tenant, "Team", WHO).await.unwrap();
    identity.set_mail_access(info, Principal::Group(team), None, "rsl", true, WHO).await.unwrap();
    identity.set_mail_access(info, Principal::Account(alice), None, "lr", false, WHO).await.unwrap();
    assert!(matches!(
        identity.set_mail_access(info, Principal::Account(alice), None, "lz", false, WHO).await,
        Err(IdentityError::Refused(_))
    ));
    assert!(matches!(
        identity.set_mail_access(info, Principal::Account(dave), None, "lr", false, WHO).await,
        Err(IdentityError::NotFound(_))
    ));
    assert!(matches!(
        identity.set_mail_access(info, Principal::Account(info), None, "lr", false, WHO).await,
        Err(IdentityError::Refused(_))
    ));
    let grants = identity.mail_access(info).await.unwrap();
    let names: Vec<_> = grants.iter().map(|g| (g.grantee_name.as_str(), g.rights.as_str(), g.send_as)).collect();
    assert_eq!(names, [("$Team", "lrs", true), ("alice@firma.de", "lr", false)]);
    assert_eq!(identity.mail_grantee(tenant, "$Team").await.unwrap(), Principal::Group(team));
    assert_eq!(identity.mail_grantee(tenant, "alice@firma.de").await.unwrap(), Principal::Account(alice));
    assert!(identity.mail_grantee(tenant, "dave@other.de").await.is_err());

    // A removed group takes its grants along; granting again brings them back.
    identity.remove_group(tenant, team, WHO).await.unwrap();
    assert_eq!(identity.mail_access(info).await.unwrap().len(), 1);
    identity.remove_mail_access(info, Principal::Account(alice), None, WHO).await.unwrap();
    identity.set_mail_access(info, Principal::Account(alice), None, "lr", false, WHO).await.unwrap();
    identity.set_mail_access(info, Principal::Account(alice), None, "lr", false, WHO).await.unwrap();
    assert_eq!(identity.mail_access(info).await.unwrap().len(), 1);
    // The tenant's default quota.
    identity.set_default_mail_quota(tenant, Some(1000), WHO).await.unwrap();
    assert_eq!(identity.default_mail_quota(tenant).await.unwrap(), Some(1000));
}
