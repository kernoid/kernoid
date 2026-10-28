// SPDX-License-Identifier: AGPL-3.0-or-later
//! Instances and tenants against PostgreSQL; set `DATABASE_URL` as for the other crates' tests.

mod common;

use common::{FakeDns, WHO, domain, identity};
use kernoid_identity::IdentityError;
use sqlx::PgPool;

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn instances_are_found_by_host(pool: PgPool) {
    let identity = identity(pool);
    let id = identity.add_instance("Example", &domain("login.example.org"), WHO).await.unwrap();
    for host in ["login.example.org", "LOGIN.Example.org", "login.example.org."] {
        let found = identity.instance_by_host(host).await.unwrap().unwrap();
        assert_eq!(
            (found.id, found.name.as_str(), found.primary_domain.as_str()),
            (id, "Example", "login.example.org")
        );
    }
    for host in ["other.example.org", "example.org", "", "login.example.org:443", "not a host"] {
        assert_eq!(identity.instance_by_host(host).await.unwrap(), None, "{host:?}");
    }

    identity.add_instance_domain(id, &domain("auth.example.org"), WHO).await.unwrap();
    assert_eq!(identity.instance_by_host("auth.example.org").await.unwrap().unwrap().id, id);
    identity.rename_instance(id, "Example e. V.", WHO).await.unwrap();
    assert_eq!(identity.instances().await.unwrap()[0].name, "Example e. V.");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_domain_names_one_instance(pool: PgPool) {
    let identity = identity(pool);
    let first = identity.add_instance("First", &domain("login.example.org"), WHO).await.unwrap();
    let taken = identity.add_instance("Second", &domain("login.example.org"), WHO).await;
    assert!(matches!(taken, Err(IdentityError::DomainTaken(d)) if d.as_str() == "login.example.org"));
    // Nothing of the refused instance remains – neither events nor read model.
    assert_eq!(identity.instances().await.unwrap().len(), 1);

    let second = identity.add_instance("Second", &domain("login.example.net"), WHO).await.unwrap();
    assert!(matches!(
        identity.add_instance_domain(second, &domain("login.example.org"), WHO).await,
        Err(IdentityError::DomainTaken(_))
    ));
    assert!(!identity.instance(second).await.unwrap().state.domains.contains(&domain("login.example.org")));
    assert_eq!(identity.instance_by_host("login.example.org").await.unwrap().unwrap().id, first);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_primary_domain_stays_until_another_takes_over(pool: PgPool) {
    let identity = identity(pool);
    let id = identity.add_instance("Example", &domain("old.example.org"), WHO).await.unwrap();
    identity.add_instance_domain(id, &domain("new.example.org"), WHO).await.unwrap();
    assert!(matches!(
        identity.remove_instance_domain(id, &domain("old.example.org"), WHO).await,
        Err(IdentityError::Refused(_))
    ));

    identity.set_primary_domain(id, &domain("new.example.org"), WHO).await.unwrap();
    // Passkeys stay bound to the first domain until the RP ID is moved – a parent domain covers both.
    let info = identity.instance_by_host("new.example.org").await.unwrap().unwrap();
    assert_eq!((info.passkey_rp_id.as_str(), info.domains.len()), ("old.example.org", 2));
    assert!(matches!(
        identity.remove_instance_domain(id, &domain("old.example.org"), WHO).await,
        Err(IdentityError::Refused(_))
    ));
    for bad in ["other.example.org", "example.com", "new.example.com"] {
        assert!(identity.set_passkey_rp_id(id, &domain(bad), WHO).await.is_err(), "{bad}");
    }
    identity.set_passkey_rp_id(id, &domain("example.org"), WHO).await.unwrap();
    identity.remove_instance_domain(id, &domain("old.example.org"), WHO).await.unwrap();
    let info = identity.instance_by_host("new.example.org").await.unwrap().unwrap();
    assert_eq!(info.passkey_rp_id, "example.org");
    assert_eq!(identity.instance_by_host("old.example.org").await.unwrap(), None);
    assert_eq!(identity.instance_by_host("new.example.org").await.unwrap().unwrap().primary_domain, "new.example.org");
    // The freed domain can be used by another instance.
    identity.add_instance("Other", &domain("old.example.org"), WHO).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn tenants_prove_their_domains(pool: PgPool) {
    let identity = identity(pool);
    let dns = FakeDns::default();
    let instance = identity.add_instance("Example", &domain("login.example.org"), WHO).await.unwrap();
    assert!(matches!(
        identity.add_tenant(uuid::Uuid::now_v7(), "Nowhere", WHO).await,
        Err(IdentityError::NotFound("the instance"))
    ));
    let firma = identity.add_tenant(instance, "Firma", WHO).await.unwrap();
    let token = identity.add_tenant_domain(instance, firma, &domain("firma.de"), WHO).await.unwrap();
    assert_eq!(token.len(), 48);

    // Claimed is not verified: no address @firma.de belongs to the tenant yet.
    assert_eq!(identity.tenant_by_domain(&domain("firma.de")).await.unwrap(), None);
    assert!(matches!(
        identity.verify_tenant_domain(instance, firma, &domain("firma.de"), &dns, WHO).await,
        Err(IdentityError::Verification(_))
    ));
    dns.publish("firma.de", "a-wrong-token");
    assert!(matches!(
        identity.verify_tenant_domain(instance, firma, &domain("firma.de"), &dns, WHO).await,
        Err(IdentityError::Verification(_))
    ));

    dns.publish("firma.de", &token);
    identity.verify_tenant_domain(instance, firma, &domain("firma.de"), &dns, WHO).await.unwrap();
    let found = identity.tenant_by_domain(&domain("firma.de")).await.unwrap().unwrap();
    assert_eq!((found.instance, found.id, found.name.as_str(), found.active), (instance, firma, "Firma", true));
    // Verifying again changes nothing.
    identity.verify_tenant_domain(instance, firma, &domain("firma.de"), &dns, WHO).await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_verified_domain_belongs_to_one_tenant(pool: PgPool) {
    let identity = identity(pool);
    let dns = FakeDns::default();
    let one = identity.add_instance("One", &domain("login.one.example"), WHO).await.unwrap();
    let two = identity.add_instance("Two", &domain("login.two.example"), WHO).await.unwrap();
    let a = identity.add_tenant(one, "A", WHO).await.unwrap();
    let b = identity.add_tenant(two, "B", WHO).await.unwrap();

    // Both may claim; whoever verifies first has it – across instances, because mail must find one recipient.
    let token_a = identity.add_tenant_domain(one, a, &domain("shared.example"), WHO).await.unwrap();
    let token_b = identity.add_tenant_domain(two, b, &domain("shared.example"), WHO).await.unwrap();
    dns.publish("shared.example", &token_a);
    identity.verify_tenant_domain(one, a, &domain("shared.example"), &dns, WHO).await.unwrap();
    dns.publish("shared.example", &token_b);
    assert!(matches!(
        identity.verify_tenant_domain(two, b, &domain("shared.example"), &dns, WHO).await,
        Err(IdentityError::DomainTaken(_))
    ));
    assert!(!identity.tenant(two, b).await.unwrap().state.domains[&domain("shared.example")].verified);
    assert_eq!(identity.tenant_by_domain(&domain("shared.example")).await.unwrap().unwrap().id, a);

    // Once A lets go, B can verify.
    identity.remove_tenant_domain(one, a, &domain("shared.example"), WHO).await.unwrap();
    identity.verify_tenant_domain(two, b, &domain("shared.example"), &dns, WHO).await.unwrap();
    assert_eq!(identity.tenant_by_domain(&domain("shared.example")).await.unwrap().unwrap().id, b);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_new_claim_needs_a_new_proof(pool: PgPool) {
    let identity = identity(pool);
    let dns = FakeDns::default();
    let instance = identity.add_instance("Example", &domain("login.example.org"), WHO).await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", WHO).await.unwrap();
    let old = identity.add_tenant_domain(instance, tenant, &domain("firma.de"), WHO).await.unwrap();
    identity.remove_tenant_domain(instance, tenant, &domain("firma.de"), WHO).await.unwrap();
    let new = identity.add_tenant_domain(instance, tenant, &domain("firma.de"), WHO).await.unwrap();
    assert_ne!(old, new);
    dns.publish("firma.de", &old);
    assert!(identity.verify_tenant_domain(instance, tenant, &domain("firma.de"), &dns, WHO).await.is_err());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn deactivated_tenants_and_modules(pool: PgPool) {
    let identity = identity(pool);
    let dns = FakeDns::default();
    let instance = identity.add_instance("Example", &domain("login.example.org"), WHO).await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", WHO).await.unwrap();
    let token = identity.add_tenant_domain(instance, tenant, &domain("firma.de"), WHO).await.unwrap();
    dns.publish("firma.de", &token);
    identity.verify_tenant_domain(instance, tenant, &domain("firma.de"), &dns, WHO).await.unwrap();

    identity.set_tenant_active(instance, tenant, false, WHO).await.unwrap();
    assert!(!identity.tenant_by_domain(&domain("firma.de")).await.unwrap().unwrap().active);
    assert!(matches!(
        identity.add_tenant_domain(instance, tenant, &domain("firma.com"), WHO).await,
        Err(IdentityError::Refused(_))
    ));
    identity.set_tenant_active(instance, tenant, true, WHO).await.unwrap();
    identity.set_tenant_active(instance, tenant, true, WHO).await.unwrap();
    assert_eq!(identity.tenant(instance, tenant).await.unwrap().sequence, 5, "the second reactivation added nothing");

    let known = ["jitsi", "wopi"];
    assert!(matches!(
        identity.set_tenant_module(instance, tenant, "jira", true, &known, WHO).await,
        Err(IdentityError::Refused(_))
    ));
    identity.set_tenant_module(instance, tenant, "jitsi", true, &known, WHO).await.unwrap();
    identity.set_tenant_module(instance, tenant, "jitsi", true, &known, WHO).await.unwrap();
    assert!(identity.tenant_uses_module(tenant, "jitsi").await.unwrap());
    assert!(!identity.tenant_uses_module(tenant, "wopi").await.unwrap());
    identity.set_tenant_module(instance, tenant, "jitsi", false, &known, WHO).await.unwrap();
    assert!(!identity.tenant_uses_module(tenant, "jitsi").await.unwrap());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn names_are_checked(pool: PgPool) {
    let identity = identity(pool);
    for name in ["", "   ", "line\nbreak", &"x".repeat(201)] {
        assert!(matches!(
            identity.add_instance(name, &domain("login.example.org"), WHO).await,
            Err(IdentityError::Refused(_))
        ));
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn operators_can_trust_a_domain_but_not_take_one(pool: PgPool) {
    let identity = identity(pool);
    let dns = FakeDns::default();
    let instance = identity.add_instance("Example", &domain("login.example.org"), WHO).await.unwrap();
    let a = identity.add_tenant(instance, "A", WHO).await.unwrap();
    let b = identity.add_tenant(instance, "B", WHO).await.unwrap();
    assert!(matches!(
        identity.trust_tenant_domain(instance, a, &domain("intern.example"), WHO).await,
        Err(IdentityError::NotFound(_))
    ));
    identity.add_tenant_domain(instance, a, &domain("intern.example"), WHO).await.unwrap();
    identity.trust_tenant_domain(instance, a, &domain("intern.example"), WHO).await.unwrap();
    assert_eq!(identity.tenant_by_domain(&domain("intern.example")).await.unwrap().unwrap().id, a);

    let token = identity.add_tenant_domain(instance, b, &domain("intern.example"), WHO).await.unwrap();
    dns.publish("intern.example", &token);
    assert!(matches!(
        identity.trust_tenant_domain(instance, b, &domain("intern.example"), WHO).await,
        Err(IdentityError::DomainTaken(_))
    ));
}
