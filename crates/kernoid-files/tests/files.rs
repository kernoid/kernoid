// SPDX-License-Identifier: AGPL-3.0-or-later
//! The file store against PostgreSQL, with object storage in memory; set `DATABASE_URL` as for the other crates'
//! tests.

use std::{collections::HashMap, sync::Arc, sync::Mutex};

use bytes::Bytes;
use futures_util::StreamExt;
use kernoid_events::EventStore;
use kernoid_files::{
    Content, FileAccess, Files, FilesError, Limits, LockRequest, MAX_DEPTH, NewNode, NodeUpdate, OnExists, Rights,
    Role, SetOptions,
};
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup, role::Principal, services::Service};
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

struct Setup {
    identity: Identity,
    files: Files,
    pool: PgPool,
    tenant: Uuid,
}

async fn setup(pool: PgPool, limits: Limits) -> Setup {
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
    let blobs = BlobStore::new(Arc::new(InMemory::new()), keys);
    Setup { identity, files: Files::new(pool.clone(), blobs, limits), pool, tenant }
}

impl Setup {
    async fn account(&self, local: &str) -> Uuid {
        let address = Address::parse(&format!("{local}@firma.example")).unwrap();
        let account = self.identity.add_account(self.tenant, &address, local, WHO).await.unwrap();
        self.identity.grant_service(account, Service::Files, WHO).await.unwrap();
        account
    }

    async fn content(&self, owner: Uuid, bytes: &'static [u8]) -> Content {
        self.files.store_bytes(owner, Bytes::from_static(bytes)).await.unwrap()
    }

    async fn read(&self, content: &Content) -> Vec<u8> {
        let mut out = Vec::new();
        let mut stream = std::pin::pin!(self.files.read(content, 0, content.stored.size));
        while let Some(part) = stream.next().await {
            out.extend_from_slice(&part.unwrap());
        }
        out
    }

    async fn garbage(&self) -> Vec<String> {
        sqlx::query_scalar!("SELECT key FROM blob_garbage WHERE due_at <= now() ORDER BY key")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }
}

fn options() -> SetOptions {
    SetOptions::default()
}

fn own(account: Uuid) -> FileAccess {
    FileAccess::own(account)
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_new_store_has_a_trash_that_stays(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let alice = setup.account("alice").await;
    let files = &setup.files;

    let nodes = files.nodes(alice).await.unwrap();
    assert_eq!(nodes.len(), 1);
    let trash = &nodes[0];
    assert_eq!((trash.name.as_str(), trash.role, trash.parent), ("Trash", Some(Role::Trash), None));
    assert_eq!(files.state(alice).await.unwrap(), 1);

    assert!(matches!(files.destroy(&own(alice), trash.id, true).await, Err(FilesError::Forbidden(_))));
    let rename = NodeUpdate { name: Some("Bin".into()), ..NodeUpdate::default() };
    assert!(matches!(files.update(&own(alice), trash.id, rename, &options()).await, Err(FilesError::Forbidden(_))));
    let hide = NodeUpdate { is_subscribed: Some(false), ..NodeUpdate::default() };
    assert!(!files.update(&own(alice), trash.id, hide, &options()).await.unwrap().node.is_subscribed);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn files_keep_their_content_and_versions(pool: PgPool) {
    let setup = setup(pool, Limits { versions_kept: 2, ..Limits::default() }).await;
    let alice = setup.account("alice").await;
    let files = &setup.files;
    let me = own(alice);

    let docs = files.create(&me, NewNode::directory(None, "Documents"), &options()).await.unwrap().node;
    let first = setup.content(alice, b"hello").await;
    let report = NewNode::file(Some(docs.id), "report.txt", first.clone(), Some("Text/Plain".into()));
    let report = files.create(&me, report, &options()).await.unwrap().node;
    assert_eq!((report.size, report.media_type.as_deref()), (Some(5), Some("text/plain")));
    let readable = files.readable(&me, report.content.unwrap()).await.unwrap();
    assert_eq!(setup.read(&readable.content).await, b"hello");
    assert_eq!(files.quota(alice).await.unwrap(), (5, None));
    assert!(setup.garbage().await.is_empty());

    // New content: the old one becomes a version and still counts; beyond two versions the oldest goes.
    for text in [&b"second"[..], b"third!", b"fourth!"] {
        let content = files.store_bytes(alice, Bytes::copy_from_slice(text)).await.unwrap();
        files.write(&me, report.id, content, Some("text/plain")).await.unwrap();
    }
    let versions = files.versions(&me, report.id).await.unwrap();
    let sizes: Vec<(u64, bool)> = versions.iter().map(|version| (version.size, version.current)).collect();
    assert_eq!(sizes, vec![(7, true), (6, false), (6, false)]);
    assert_eq!(files.quota(alice).await.unwrap().0, 19);
    // The first went; its part is garbage.
    assert_eq!(setup.garbage().await.len(), 1);

    // Restoring a version makes it current; the content it had becomes a version.
    let third = versions[1].id;
    let restored = files.restore(&me, report.id, third).await.unwrap();
    assert_eq!((restored.content, restored.size), (Some(third), Some(6)));
    let versions = files.versions(&me, report.id).await.unwrap();
    assert_eq!(versions[0].id, third);
    assert!(versions.iter().any(|version| version.size == 7 && !version.current));

    // A copy shares the parts: destroying the original leaves them for the copy.
    let shared = files.existing(third).await.unwrap();
    let copy = files.create(&me, NewNode::file(None, "copy.txt", shared, None), &options()).await.unwrap().node;
    files.destroy(&me, docs.id, true).await.unwrap();
    let copied = files.readable(&me, copy.content.unwrap()).await.unwrap();
    assert_eq!(setup.read(&copied.content).await, b"third!");
    assert_eq!(files.quota(alice).await.unwrap().0, 6);

    // Over the quota is refused, and nothing changes.
    setup.identity.set_files_quota(alice, Some(10), WHO).await.unwrap();
    let big = setup.content(alice, b"more than ten").await;
    let refused = files.create(&me, NewNode::file(None, "big.bin", big, None), &options()).await;
    assert!(matches!(refused, Err(FilesError::OverQuota)));
    assert_eq!(files.quota(alice).await.unwrap(), (6, Some(10)));
    // Asking about an account that never used files makes no store for it.
    let bob = setup.account("bob").await;
    assert_eq!(files.usage(bob).await.unwrap(), (0, None));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn large_content_is_stored_in_parts(pool: PgPool) {
    let setup = setup(pool, Limits { max_file_size: 20 * 1024 * 1024, ..Limits::default() }).await;
    let alice = setup.account("alice").await;
    let files = &setup.files;

    // 17 MiB arriving in small pieces: three parts, never all in memory at once.
    let piece = Bytes::from(vec![7u8; 64 * 1024]);
    let pieces = futures_util::stream::iter((0..272).map(move |_| Ok::<_, std::io::Error>(piece.clone())));
    let content = files.store(alice, pieces).await.unwrap();
    assert_eq!((content.stored.parts, content.stored.size), (3, 17 * 1024 * 1024));
    let node = files.create(&own(alice), NewNode::file(None, "big.bin", content, None), &options()).await.unwrap().node;
    let readable = files.readable(&own(alice), node.content.unwrap()).await.unwrap();
    // A range across the border of two parts.
    let start = 8 * 1024 * 1024 - 3;
    let mut range = Vec::new();
    let mut stream = std::pin::pin!(files.read(&readable.content, start, start + 6));
    while let Some(part) = stream.next().await {
        range.extend_from_slice(&part.unwrap());
    }
    assert_eq!(range, vec![7u8; 6]);

    // More than allowed is refused while it streams.
    let piece = Bytes::from(vec![0u8; 1024 * 1024]);
    let pieces = futures_util::stream::iter((0..21).map(move |_| Ok::<_, std::io::Error>(piece.clone())));
    assert!(matches!(files.store(alice, pieces).await, Err(FilesError::TooLarge { .. })));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn names_are_unique_among_siblings(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let alice = setup.account("alice").await;
    let files = &setup.files;
    let me = own(alice);
    let x = setup.content(alice, b"x").await;
    let file = |name: &str| NewNode::file(None, name, x.clone(), None);

    let first = files.create(&me, file("a.txt"), &options()).await.unwrap().node;
    match files.create(&me, file("a.txt"), &options()).await {
        Err(FilesError::AlreadyExists(existing)) => assert_eq!(existing, first.id),
        other => panic!("{other:?}"),
    }
    files.create(&me, file("A.txt"), &options()).await.unwrap();
    let insensitive = SetOptions { case_insensitive: true, ..options() };
    assert!(matches!(files.create(&me, file("a.TXT"), &insensitive).await, Err(FilesError::AlreadyExists(_))));

    let rename = SetOptions { on_exists: OnExists::Rename, ..options() };
    assert_eq!(files.create(&me, file("a.txt"), &rename).await.unwrap().node.name, "a (2).txt");
    let replace = SetOptions { on_exists: OnExists::Replace, ..options() };
    let replaced = files.create(&me, file("a.txt"), &replace).await.unwrap();
    assert_eq!(replaced.destroyed, vec![first.id]);
    assert!(files.get(alice, &[first.id]).await.unwrap().is_empty());
    let onto_trash = NewNode::directory(None, "Trash");
    assert!(matches!(files.create(&me, onto_trash, &replace).await, Err(FilesError::Forbidden(_))));
    for bad in ["", "..", "a/b", "x:y"] {
        assert!(matches!(files.create(&me, file(bad), &options()).await, Err(FilesError::Invalid(_))), "{bad}");
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_tree_has_no_cycles_and_a_limited_depth(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let alice = setup.account("alice").await;
    let files = &setup.files;
    let me = own(alice);
    let dir = |parent, name: &str| NewNode::directory(parent, name);

    let a = files.create(&me, dir(None, "a"), &options()).await.unwrap().node;
    let b = files.create(&me, dir(Some(a.id), "b"), &options()).await.unwrap().node;
    let below_itself = NodeUpdate { parent: Some(Some(b.id)), ..NodeUpdate::default() };
    assert!(matches!(files.update(&me, a.id, below_itself, &options()).await, Err(FilesError::Invalid(_))));
    let up = NodeUpdate { parent: Some(None), ..NodeUpdate::default() };
    let moved = files.update(&me, b.id, up, &options()).await.unwrap().node;
    assert_eq!((moved.parent, moved.modified), (None, b.modified));
    let empty = setup.content(alice, b"").await;
    let file = files.create(&me, NewNode::file(None, "f", empty, None), &options()).await.unwrap().node;
    assert!(matches!(files.create(&me, dir(Some(file.id), "x"), &options()).await, Err(FilesError::Invalid(_))));

    let mut parent = a.id;
    for level in 1..MAX_DEPTH {
        parent = files.create(&me, dir(Some(parent), &format!("{level}")), &options()).await.unwrap().node.id;
    }
    assert!(matches!(files.create(&me, dir(Some(parent), "deeper"), &options()).await, Err(FilesError::Invalid(_))));
    let into_deep = NodeUpdate { parent: Some(Some(parent)), ..NodeUpdate::default() };
    assert!(matches!(files.update(&me, b.id, into_deep, &options()).await, Err(FilesError::Invalid(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn shared_directories_follow_the_rights(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let (alice, bob, carol) = (setup.account("alice").await, setup.account("bob").await, setup.account("carol").await);
    let files = &setup.files;

    let project = files.create(&own(alice), NewNode::directory(None, "Project"), &options()).await.unwrap().node;
    let private = files.create(&own(alice), NewNode::directory(None, "Private"), &options()).await.unwrap().node;
    let plan = setup.content(alice, b"plan").await;
    let plan = NewNode::file(Some(project.id), "plan.txt", plan, None);
    let plan = files.create(&own(alice), plan, &options()).await.unwrap().node;

    // Bob may read in Project; Carol has nothing.
    setup.identity.set_file_access(alice, Some(project.id), Principal::Account(bob), "r", WHO).await.unwrap();
    let as_bob = files.access(bob, alice).await.unwrap();
    assert!(as_bob.any() && !as_bob.may_create_top_level());
    let view = files.view(as_bob.clone()).await.unwrap();
    assert!(view.readable(plan.id) && view.node(private.id).is_none());
    assert!(files.readable(&as_bob, plan.content.unwrap()).await.is_ok());
    let changed = setup.content(alice, b"changed").await;
    assert!(matches!(files.write(&as_bob, plan.id, changed, None).await, Err(FilesError::Forbidden(_))));
    assert!(matches!(files.destroy(&as_bob, private.id, true).await, Err(FilesError::NotFound(_))));
    assert!(!files.access(carol, alice).await.unwrap().any());
    assert_eq!(files.shared_with(bob).await.unwrap()[0].owner, alice);

    // With more rights Bob writes, adds and removes – counted against Alice's quota.
    setup.identity.set_file_access(alice, Some(project.id), Principal::Account(bob), "randw", WHO).await.unwrap();
    let as_bob = files.access(bob, alice).await.unwrap();
    let draft = setup.content(alice, b"draft").await;
    let draft = NewNode::file(Some(project.id), "draft.txt", draft, None);
    let draft = files.create(&as_bob, draft, &options()).await.unwrap().node;
    assert_eq!(files.quota(alice).await.unwrap().0, 9);
    files.destroy(&as_bob, draft.id, false).await.unwrap();
    // Not at the top, and nothing moves out into what Bob cannot reach.
    let top = NewNode::directory(None, "Mine");
    assert!(matches!(files.create(&as_bob, top, &options()).await, Err(FilesError::Forbidden(_))));
    let out = NodeUpdate { parent: Some(Some(private.id)), ..NodeUpdate::default() };
    assert!(matches!(
        files.update(&as_bob, plan.id, out, &options()).await,
        Err(FilesError::NotFound(_) | FilesError::Forbidden(_))
    ));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_drive_belongs_to_the_tenant(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let (one, two) = (setup.account("one").await, setup.account("two").await);
    let files = &setup.files;
    let drive = setup.identity.add_drive(setup.tenant, "falkOSS", WHO).await.unwrap();
    assert_eq!(setup.identity.drives(setup.tenant).await.unwrap()[0].name, "falkOSS");
    // Nobody logs in as a drive, and it always has files.
    assert!(setup.identity.set_password(drive, "a password for nobody at all", WHO).await.is_err());
    assert!(setup.identity.revoke_service(drive, Service::Files, WHO).await.is_err());

    // A drive starts empty: no trash, and nobody but those with grants.
    assert!(files.nodes(drive).await.unwrap().is_empty());
    assert!(!files.access(one, drive).await.unwrap().any());
    for member in [one, two] {
        setup.identity.set_file_access(drive, None, Principal::Account(member), "randws", WHO).await.unwrap();
    }
    let as_one = files.access(one, drive).await.unwrap();
    let as_two = files.access(two, drive).await.unwrap();
    assert!(as_one.may_create_top_level());
    let contracts = files.create(&as_one, NewNode::directory(None, "Contracts"), &options()).await.unwrap().node;
    let text = setup.content(drive, b"signed").await;
    let deal = NewNode::file(Some(contracts.id), "deal.txt", text, None);
    let deal = files.create(&as_two, deal, &options()).await.unwrap().node;
    assert_eq!(files.rights(&as_two, deal.id).await.unwrap(), Rights::ALL);
    assert_eq!(files.quota(drive).await.unwrap().0, 6);
    assert!(files.shared_with(two).await.unwrap().iter().any(|store| store.owner == drive && store.drive));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn locks_keep_others_out(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let (alice, bob) = (setup.account("alice").await, setup.account("bob").await);
    let files = &setup.files;
    let shared = files.create(&own(alice), NewNode::directory(None, "Shared"), &options()).await.unwrap().node;
    setup.identity.set_file_access(alice, Some(shared.id), Principal::Account(bob), "randw", WHO).await.unwrap();
    let as_bob = files.access(bob, alice).await.unwrap();

    let request = LockRequest { exclusive: true, deep: true, owner_info: None, timeout: chrono::Duration::minutes(5) };
    let lock = files.lock(&own(alice), shared.id, request.clone()).await.unwrap();
    assert!(matches!(files.lock(&as_bob, shared.id, request).await, Err(FilesError::Locked)));
    assert!(matches!(files.check_unlocked(&as_bob, shared.id, false, &[]).await, Err(FilesError::Locked)));
    assert!(files.check_unlocked(&own(alice), shared.id, false, std::slice::from_ref(&lock.token)).await.is_ok());
    assert!(matches!(files.unlock(&as_bob, &lock.token).await, Err(FilesError::Forbidden(_))));
    files.unlock(&own(alice), &lock.token).await.unwrap();
    assert!(files.check_unlocked(&as_bob, shared.id, true, &[]).await.is_ok());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn the_journal_tells_what_changed(pool: PgPool) {
    let setup = setup(pool, Limits::default()).await;
    let alice = setup.account("alice").await;
    let files = &setup.files;
    let me = own(alice);

    let start = files.state(alice).await.unwrap();
    let a = files.create(&me, NewNode::directory(None, "a"), &options()).await.unwrap().node;
    let b = files.create(&me, NewNode::directory(None, "b"), &options()).await.unwrap().node;
    let middle = files.state(alice).await.unwrap();
    let rename = NodeUpdate { name: Some("c".into()), ..NodeUpdate::default() };
    files.update(&me, a.id, rename, &options()).await.unwrap();
    files.destroy(&me, b.id, false).await.unwrap();

    let changes = files.changes(alice, start, None).await.unwrap();
    assert_eq!((changes.created, changes.updated, changes.destroyed), (vec![a.id], vec![], vec![]));
    let changes = files.changes(alice, middle, None).await.unwrap();
    assert_eq!((changes.created, changes.updated, changes.destroyed), (vec![], vec![a.id], vec![b.id]));
    // A change of sharing is a change of everything it covers.
    let before = files.state(alice).await.unwrap();
    files.touch(alice, Some(a.id)).await.unwrap();
    assert_eq!(files.changes(alice, before, None).await.unwrap().updated, vec![a.id]);

    kernoid_files::prune_changes(&setup.pool, chrono::Utc::now() + chrono::Duration::seconds(1), 100).await.unwrap();
    assert!(matches!(files.changes(alice, start, None).await, Err(FilesError::CannotCalculateChanges)));
}
