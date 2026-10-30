// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vaults (RFC 0006, 6) in the file store, against PostgreSQL: what lies in one stays in it, names there are
//! encrypted, the tenant's policy holds, and only who may share hands out the vault's key. The keys and contents are
//! opaque bytes here – the apps encrypt them. Set `DATABASE_URL` as for the other tests.

use std::{collections::HashMap, sync::Arc, sync::Mutex};

use bytes::Bytes;
use kernoid_events::EventStore;
use kernoid_files::{FileAccess, Files, FilesError, Limits, NewNode, NewVault, NodeUpdate, Role, SetOptions};
use kernoid_identity::{
    Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup,
    role::Principal,
    services::Service,
    tenant::{E2ePolicy, E2eRule},
};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use object_store::memory::InMemory;
use sqlx::PgPool;
use uuid::Uuid;

const WHO: &str = "operator";

#[derive(Default)]
struct FakeDns(Mutex<HashMap<String, Vec<String>>>);

impl TxtLookup for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.0.lock().unwrap().get(name).cloned().ok_or_else(|| format!("{name}: no records"))
    }
}

async fn setup(pool: PgPool) -> (Identity, Files, Uuid) {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance =
        identity.add_instance("Instance", &DomainName::parse("login.firma.example").unwrap(), WHO).await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", WHO).await.unwrap();
    let domain = DomainName::parse("firma.example").unwrap();
    let token = identity.add_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
    let dns = FakeDns::default();
    dns.0
        .lock()
        .unwrap()
        .insert(format!("{CHALLENGE_LABEL}.firma.example"), vec![format!("kernoid-verification={token}")]);
    identity.verify_tenant_domain(instance, tenant, &domain, &dns, WHO).await.unwrap();
    let keys = Arc::new(TenantKeys::with_main_keys(pool.clone(), MainKeys::new(Key::random().unwrap(), Vec::new())));
    let files = Files::new(pool, BlobStore::new(Arc::new(InMemory::new()), keys), Limits::default());
    (identity, files, tenant)
}

async fn account(identity: &Identity, tenant: Uuid, local: &str) -> Uuid {
    let address = Address::parse(&format!("{local}@firma.example")).unwrap();
    let account = identity.add_account(tenant, &address, local, WHO).await.unwrap();
    identity.grant_service(account, Service::Files, WHO).await.unwrap();
    account
}

fn named(mut node: NewNode, encrypted: &[u8]) -> NewNode {
    node.encrypted_name = Some(encrypted.to_vec());
    node
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn what_lies_in_a_vault_stays_in_it(pool: PgPool) {
    let (identity, files, tenant) = setup(pool).await;
    let alice = account(&identity, tenant, "alice").await;
    let own = FileAccess::own(alice);
    let options = SetOptions::default();
    let plain = files.create(&own, NewNode::directory(None, "Plain"), &options).await.unwrap().node;

    // A vault: a directory with its public key and its secret key wrapped for the creator; an encrypted name.
    let mut new = named(NewNode::directory(None, "v-1"), b"name of the vault");
    new.vault = Some(NewVault { public_key: b"public".to_vec(), sealed: b"wrapped for alice".to_vec() });
    let vault = files.create(&own, new, &options).await.unwrap().node;
    assert_eq!((vault.vault, vault.vault_key.as_deref()), (Some(vault.id), Some(&b"public"[..])));
    assert_eq!(files.vault_key(&own, vault.id).await.unwrap().as_deref(), Some(&b"wrapped for alice"[..]));

    // Inside, names are encrypted; outside, they are not; no vault in a vault.
    let content = files.store_bytes(alice, Bytes::from_static(b"ciphertext")).await.unwrap();
    let file = NewNode::file(Some(vault.id), "f-1", content.clone(), None);
    assert!(matches!(files.create(&own, file.clone(), &options).await, Err(FilesError::Invalid(_))));
    let inside = files.create(&own, named(file, b"name of the file"), &options).await.unwrap().node;
    assert_eq!(inside.vault, Some(vault.id));
    let outside = named(NewNode::file(Some(plain.id), "x", content.clone(), None), b"name");
    assert!(matches!(files.create(&own, outside, &options).await, Err(FilesError::Invalid(_))));
    let mut nested = named(NewNode::directory(Some(vault.id), "v-2"), b"inner");
    nested.vault = Some(NewVault { public_key: b"p".to_vec(), sealed: b"s".to_vec() });
    assert!(matches!(files.create(&own, nested, &options).await, Err(FilesError::Invalid(_))));

    // Nothing moves out of the vault or into it – but to the Trash and back.
    let out = NodeUpdate { parent: Some(Some(plain.id)), ..NodeUpdate::default() };
    assert!(matches!(files.update(&own, inside.id, out, &options).await, Err(FilesError::Invalid(_))));
    let into = NodeUpdate { parent: Some(Some(vault.id)), ..NodeUpdate::default() };
    assert!(matches!(files.update(&own, plain.id, into, &options).await, Err(FilesError::Invalid(_))));
    let trash = files.nodes(alice).await.unwrap().into_iter().find(|node| node.role == Some(Role::Trash)).unwrap();
    let to_trash = NodeUpdate { parent: Some(Some(trash.id)), ..NodeUpdate::default() };
    files.update(&own, inside.id, to_trash, &options).await.unwrap();
    let back = NodeUpdate { parent: Some(Some(vault.id)), ..NodeUpdate::default() };
    files.update(&own, inside.id, back, &options).await.unwrap();
    // A rename brings its encrypted name; a plain node has none.
    let rename =
        NodeUpdate { name: Some("f-2".into()), encrypted_name: Some(b"new name".to_vec()), ..NodeUpdate::default() };
    let renamed = files.update(&own, inside.id, rename, &options).await.unwrap().node;
    assert_eq!(renamed.encrypted_name.as_deref(), Some(&b"new name"[..]));
    let plain_rename = NodeUpdate { encrypted_name: Some(b"x".to_vec()), ..NodeUpdate::default() };
    assert!(matches!(files.update(&own, plain.id, plain_rename, &options).await, Err(FilesError::Invalid(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn keys_go_to_members_from_who_may_share(pool: PgPool) {
    let (identity, files, tenant) = setup(pool).await;
    let alice = account(&identity, tenant, "alice").await;
    let bob = account(&identity, tenant, "bob").await;
    let carol = account(&identity, tenant, "carol").await;
    let options = SetOptions::default();
    let mut new = named(NewNode::directory(None, "v"), b"vault");
    new.vault = Some(NewVault { public_key: b"public".to_vec(), sealed: b"for alice".to_vec() });
    let vault = files.create(&FileAccess::own(alice), new, &options).await.unwrap().node;

    // Bob may read and write, Carol may also share.
    identity.set_file_access(alice, Some(vault.id), Principal::Account(bob), "randw", WHO).await.unwrap();
    identity.set_file_access(alice, Some(vault.id), Principal::Account(carol), "randws", WHO).await.unwrap();
    let as_bob = files.access(bob, alice).await.unwrap();
    let as_carol = files.access(carol, alice).await.unwrap();
    assert_eq!(files.vault_key(&as_bob, vault.id).await.unwrap(), None, "the grant waits for the key");
    assert!(matches!(files.set_vault_key(&as_bob, vault.id, carol, b"x").await, Err(FilesError::Forbidden(_))));
    files.set_vault_key(&as_carol, vault.id, bob, b"for bob").await.unwrap();
    assert_eq!(files.vault_key(&as_bob, vault.id).await.unwrap().as_deref(), Some(&b"for bob"[..]));
    assert_eq!(files.vault_members(&as_bob, vault.id).await.unwrap().len(), 2);
    files.remove_vault_key(&as_carol, vault.id, bob).await.unwrap();
    assert_eq!(files.vault_key(&as_bob, vault.id).await.unwrap(), None);
    // A plain directory is no vault.
    let plain = files.create(&FileAccess::own(alice), NewNode::directory(None, "p"), &options).await.unwrap().node;
    assert!(matches!(files.vault_key(&FileAccess::own(alice), plain.id).await, Err(FilesError::NotFound(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_tenant_forbids_or_requires_vaults(pool: PgPool) {
    let (identity, files, tenant) = setup(pool).await;
    let alice = account(&identity, tenant, "alice").await;
    let own = FileAccess::own(alice);
    let options = SetOptions::default();
    let vault = || {
        let mut new = named(NewNode::directory(None, format!("v-{}", Uuid::now_v7())), b"vault");
        new.vault = Some(NewVault { public_key: b"public".to_vec(), sealed: b"sealed".to_vec() });
        new
    };
    let rules = |vaults| E2ePolicy { vaults, ..E2ePolicy::default() };
    identity.set_e2e_policy(tenant, rules(E2eRule::Forbidden), WHO).await.unwrap();
    assert!(matches!(files.create(&own, vault(), &options).await, Err(FilesError::Forbidden(_))));
    files.create(&own, NewNode::directory(None, "plain"), &options).await.unwrap();
    identity.set_e2e_policy(tenant, rules(E2eRule::Required), WHO).await.unwrap();
    assert!(matches!(
        files.create(&own, NewNode::directory(None, "other"), &options).await,
        Err(FilesError::Forbidden(_))
    ));
    files.create(&own, vault(), &options).await.unwrap();
}
