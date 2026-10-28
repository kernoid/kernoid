// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared by the identity tests.
#![allow(dead_code)]

use std::{collections::HashMap, sync::Mutex};

use kernoid_events::EventStore;
use kernoid_identity::{CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use sqlx::PgPool;
use uuid::Uuid;

pub const WHO: &str = "operator";

pub fn domain(name: &str) -> DomainName {
    DomainName::parse(name).unwrap()
}

pub fn identity(pool: PgPool) -> Identity {
    Identity::new(EventStore::new(pool))
}

/// DNS answers set by the test.
#[derive(Default)]
pub struct FakeDns(Mutex<HashMap<String, Vec<String>>>);

impl FakeDns {
    pub fn publish(&self, domain: &str, token: &str) {
        let name = format!("{CHALLENGE_LABEL}.{domain}");
        self.0.lock().unwrap().insert(name, vec![format!("kernoid-verification={token}")]);
    }
}

impl TxtLookup for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.0.lock().unwrap().get(name).cloned().ok_or_else(|| format!("{name}: no records"))
    }
}

/// A tenant with `domains` verified, in a new instance reached under `host`; returns (instance, tenant).
pub async fn tenant_with(identity: &Identity, host: &str, domains: &[&str]) -> (Uuid, Uuid) {
    let dns = FakeDns::default();
    let instance = identity.add_instance("Instance", &domain(host), WHO).await.unwrap();
    let tenant = identity.add_tenant(instance, "Tenant", WHO).await.unwrap();
    for name in domains {
        let token = identity.add_tenant_domain(instance, tenant, &domain(name), WHO).await.unwrap();
        dns.publish(name, &token);
        identity.verify_tenant_domain(instance, tenant, &domain(name), &dns, WHO).await.unwrap();
    }
    (instance, tenant)
}
