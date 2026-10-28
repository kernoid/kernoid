// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runs against PostgreSQL: set `DATABASE_URL` to a role that may create databases and roles (each test gets its own
//! database; roles are shared by the cluster).

use std::sync::Arc;

use bytes::Bytes;
use kernoid_config::Blob;
use kernoid_store::{BlobError, BlobStore, KeyError, MainKeys, TenantKeys, WrapStatus, crypto::Key};
use object_store::{ObjectStoreExt, PutPayload, memory::InMemory, path::Path};
use sqlx::PgPool;
use uuid::Uuid;

/// The role every test here takes on as the runtime role; created once, never given rights outside the test database.
const RUNTIME: &str = "kernoid_test_runtime";

async fn runtime_role(pool: &PgPool) {
    // CREATE ROLE has no IF NOT EXISTS; tests run in parallel, so a concurrent creation is fine too.
    let _ = sqlx::query!("CREATE ROLE kernoid_test_runtime NOLOGIN").execute(pool).await;
    sqlx::query!(r#"SELECT 1 AS "granted!" FROM kernoid_grant_runtime($1)"#, RUNTIME as &str)
        .fetch_one(pool)
        .await
        .unwrap();
}

/// Error code of `run` as the runtime role, or None if it succeeded; rolls back either way.
async fn as_runtime(
    pool: &PgPool,
    run: impl AsyncFnOnce(&mut sqlx::PgConnection) -> sqlx::Result<()>,
) -> Option<String> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query!("SET LOCAL ROLE kernoid_test_runtime").execute(&mut *tx).await.unwrap();
    let result = run(&mut tx).await;
    tx.rollback().await.unwrap();
    result.err().map(|error| error.as_database_error().and_then(|e| e.code()).unwrap_or_default().into_owned())
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn runtime_role_reads_and_adds_events_only(pool: PgPool) {
    runtime_role(&pool).await;
    let insert = async |c: &mut sqlx::PgConnection| {
        sqlx::query!(
            "INSERT INTO events (instance_id, owner, aggregate_type, aggregate_id, sequence, event_type, revision, \
             payload, creator) VALUES (gen_random_uuid(), gen_random_uuid(), 'account', 'a', 1, 'account.added', 1, '{}', 'system')"
        )
        .execute(c)
        .await
        .map(drop)
    };
    assert_eq!(as_runtime(&pool, insert).await, None);
    let select =
        async |c: &mut sqlx::PgConnection| sqlx::query!("SELECT position FROM events").fetch_all(c).await.map(drop);
    assert_eq!(as_runtime(&pool, select).await, None);

    // 42501: insufficient privilege – refused before the append-only triggers are even reached.
    let update =
        async |c: &mut sqlx::PgConnection| sqlx::query!("UPDATE events SET creator = 'x'").execute(c).await.map(drop);
    assert_eq!(as_runtime(&pool, update).await.as_deref(), Some("42501"));
    let delete = async |c: &mut sqlx::PgConnection| sqlx::query!("DELETE FROM events").execute(c).await.map(drop);
    assert_eq!(as_runtime(&pool, delete).await.as_deref(), Some("42501"));
    let disable = async |c: &mut sqlx::PgConnection| {
        sqlx::query!("ALTER TABLE events DISABLE TRIGGER events_no_update_or_delete").execute(c).await.map(drop)
    };
    assert_eq!(as_runtime(&pool, disable).await.as_deref(), Some("42501"));
    let create =
        async |c: &mut sqlx::PgConnection| sqlx::query!("CREATE TABLE intruder (x int)").execute(c).await.map(drop);
    assert_eq!(as_runtime(&pool, create).await.as_deref(), Some("42501"));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn grant_function_is_not_for_everyone(pool: PgPool) {
    runtime_role(&pool).await;
    let grant = async |c: &mut sqlx::PgConnection| {
        sqlx::query!(r#"SELECT 1 AS "granted!" FROM kernoid_grant_runtime('kernoid_test_runtime')"#)
            .fetch_one(c)
            .await
            .map(drop)
    };
    assert_eq!(as_runtime(&pool, grant).await.as_deref(), Some("42501"));
}

#[tokio::test]
async fn connections_carry_the_limits() {
    let runtime = kernoid_store::connect(&kernoid_config::Database {
        url: std::env::var("DATABASE_URL").expect("DATABASE_URL").as_str().into(),
        migrate_url: None,
        max_connections: 1,
        statement_timeout_ms: 1234,
        idle_in_transaction_timeout_ms: 5678,
    })
    .await
    .unwrap();
    let limits = sqlx::query!(
        r#"SELECT current_setting('statement_timeout') AS "statement!",
                  current_setting('idle_in_transaction_session_timeout') AS "idle!""#
    )
    .fetch_one(&runtime)
    .await
    .unwrap();
    assert_eq!((limits.statement.as_str(), limits.idle.as_str()), ("1234ms", "5678ms"));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn runtime_role_keeps_cursors_and_keys_but_cannot_remove_them(pool: PgPool) {
    runtime_role(&pool).await;
    let cursor = async |c: &mut sqlx::PgConnection| {
        sqlx::query!("INSERT INTO projection_cursors (name) VALUES ('p')").execute(&mut *c).await?;
        sqlx::query!("UPDATE projection_cursors SET position = 1 WHERE name = 'p'").execute(&mut *c).await.map(drop)
    };
    assert_eq!(as_runtime(&pool, cursor).await, None);
    let key = async |c: &mut sqlx::PgConnection| {
        sqlx::query!("INSERT INTO tenant_keys (tenant_id, number, wrapped) VALUES (gen_random_uuid(), 1, '')")
            .execute(&mut *c)
            .await?;
        sqlx::query!("SELECT number FROM tenant_keys").fetch_all(&mut *c).await.map(drop)
    };
    assert_eq!(as_runtime(&pool, key).await, None);

    let remove_cursor =
        async |c: &mut sqlx::PgConnection| sqlx::query!("DELETE FROM projection_cursors").execute(c).await.map(drop);
    assert_eq!(as_runtime(&pool, remove_cursor).await.as_deref(), Some("42501"));
    let remove_key =
        async |c: &mut sqlx::PgConnection| sqlx::query!("DELETE FROM tenant_keys").execute(c).await.map(drop);
    assert_eq!(as_runtime(&pool, remove_key).await.as_deref(), Some("42501"));
    let change_key = async |c: &mut sqlx::PgConnection| {
        sqlx::query!("UPDATE tenant_keys SET wrapped = ''").execute(c).await.map(drop)
    };
    assert_eq!(as_runtime(&pool, change_key).await.as_deref(), Some("42501"));
}

/// INSERT … ON CONFLICT … DO UPDATE needs UPDATE: every move out of a mailbox records the expunged UID that way.
#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn runtime_role_may_record_an_expunged_uid_again(pool: PgPool) {
    runtime_role(&pool).await;
    let rights = sqlx::query!(
        r#"SELECT has_column_privilege($1, 'mailbox_expunged', 'modseq', 'UPDATE') AS "modseq!",
                  has_column_privilege($1, 'mailbox_expunged', 'uid', 'UPDATE') AS "uid!""#,
        RUNTIME
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(rights.modseq);
    assert!(!rights.uid);
}

/// A blob store over memory whose raw content the test can see and change.
fn blobs(pool: &PgPool, main: Key) -> (BlobStore, Arc<InMemory>) {
    let memory = Arc::new(InMemory::new());
    let keys = Arc::new(TenantKeys::new(pool.clone(), main));
    (BlobStore::new(memory.clone(), keys), memory)
}

async fn raw(memory: &InMemory, tenant: Uuid, key: &str) -> Bytes {
    memory.get(&Path::from(format!("tenants/{tenant}/{key}"))).await.unwrap().bytes().await.unwrap()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn content_is_encrypted_per_tenant(pool: PgPool) {
    let (store, memory) = blobs(&pool, Key::random().unwrap());
    let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
    let content = Bytes::from_static(b"Subject: hello\r\n\r\nthe body of a message");
    store.put(a, "mail/1", content.clone()).await.unwrap();
    store.put(b, "mail/1", content.clone()).await.unwrap();
    assert_eq!(store.get(a, "mail/1").await.unwrap(), content);
    assert_eq!(store.get(b, "mail/1").await.unwrap(), content);

    // At rest: ciphertext only, and different for each tenant.
    let (raw_a, raw_b) = (raw(&memory, a, "mail/1").await, raw(&memory, b, "mail/1").await);
    assert!(!raw_a.windows(content.len()).any(|window| window == content.as_ref()));
    assert_ne!(raw_a, raw_b);

    // One key per tenant, created on first write, stored wrapped: nonce, key, tag.
    let keys =
        sqlx::query!(r#"SELECT tenant_id, number, length(wrapped) AS "len!" FROM tenant_keys ORDER BY tenant_id"#)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(keys.iter().map(|k| (k.tenant_id, k.number)).collect::<Vec<_>>(), [(a, 1), (b, 1)]);
    assert!(keys.iter().all(|k| k.len == 24 + 32 + 16));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn changed_or_moved_content_is_refused(pool: PgPool) {
    let (store, memory) = blobs(&pool, Key::random().unwrap());
    let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
    store.put(a, "mail/1", Bytes::from_static(b"for tenant a")).await.unwrap();
    store.put(b, "mail/1", Bytes::from_static(b"for tenant b")).await.unwrap();
    let sealed = raw(&memory, a, "mail/1").await;

    // Copied to another tenant (whose key has the same number) or to another path.
    memory.put(&Path::from(format!("tenants/{b}/mail/1")), PutPayload::from(sealed.clone())).await.unwrap();
    assert!(matches!(store.get(b, "mail/1").await, Err(BlobError::Crypto(_))));
    memory.put(&Path::from(format!("tenants/{a}/mail/2")), PutPayload::from(sealed.clone())).await.unwrap();
    assert!(matches!(store.get(a, "mail/2").await, Err(BlobError::Crypto(_))));

    // Changed in place.
    let mut changed = sealed.to_vec();
    *changed.last_mut().unwrap() ^= 1;
    memory.put(&Path::from(format!("tenants/{a}/mail/1")), PutPayload::from(changed)).await.unwrap();
    assert!(matches!(store.get(a, "mail/1").await, Err(BlobError::Crypto(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_wrong_main_key_reads_nothing(pool: PgPool) {
    let tenant = Uuid::from_u128(1);
    let (store, memory) = blobs(&pool, Key::random().unwrap());
    store.put(tenant, "mail/1", Bytes::from_static(b"secret")).await.unwrap();

    let other = BlobStore::new(memory, Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap())));
    assert!(matches!(other.get(tenant, "mail/1").await, Err(BlobError::TenantKey(KeyError::Crypto { .. }))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn concurrent_first_writes_share_one_key(pool: PgPool) {
    let tenant = Uuid::from_u128(1);
    let main = Key::random().unwrap();
    let memory = Arc::new(InMemory::new());
    let writers = (0..8).map(|i| {
        // Separate key managers, as in separate processes.
        let store = BlobStore::new(memory.clone(), Arc::new(TenantKeys::new(pool.clone(), main.clone())));
        tokio::spawn(async move { store.put(tenant, &format!("mail/{i}"), Bytes::from(format!("{i}"))).await })
    });
    for writer in writers {
        writer.await.unwrap().unwrap();
    }
    let reader = BlobStore::new(memory, Arc::new(TenantKeys::new(pool.clone(), main)));
    for i in 0..8 {
        assert_eq!(reader.get(tenant, &format!("mail/{i}")).await.unwrap(), format!("{i}"));
    }
    let count = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM tenant_keys"#).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn ping_and_paths(pool: PgPool) {
    let keys = Arc::new(TenantKeys::new(pool, Key::random().unwrap()));
    let store = BlobStore::from_config(&Blob::Memory, keys).unwrap();
    store.ping().await.unwrap();
    assert!(matches!(store.get(Uuid::from_u128(1), "missing").await, Err(BlobError::NotFound)));
    assert!(matches!(store.put(Uuid::from_u128(1), "../x", Bytes::new()).await, Err(BlobError::InvalidKey(_))));
    store.delete(Uuid::from_u128(1), "missing").await.unwrap();
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn rotated_tenant_keys_keep_old_content_readable(pool: PgPool) {
    let tenant = Uuid::from_u128(1);
    let keys = Arc::new(TenantKeys::new(pool.clone(), Key::random().unwrap()));
    let memory = Arc::new(InMemory::new());
    let store = BlobStore::new(memory.clone(), keys.clone());
    store.put(tenant, "old", Bytes::from_static(b"before")).await.unwrap();

    assert_eq!(keys.rotate(tenant).await.unwrap(), 2);
    store.put(tenant, "new", Bytes::from_static(b"after")).await.unwrap();
    assert_eq!(&raw(&memory, tenant, "old").await[5..9], 1u32.to_be_bytes());
    assert_eq!(&raw(&memory, tenant, "new").await[5..9], 2u32.to_be_bytes());
    assert_eq!(store.get(tenant, "old").await.unwrap(), "before");
    assert_eq!(store.get(tenant, "new").await.unwrap(), "after");
    // Other tenants are not affected.
    store.put(Uuid::from_u128(2), "x", Bytes::new()).await.unwrap();
    assert_eq!(&raw(&memory, Uuid::from_u128(2), "x").await[5..9], 1u32.to_be_bytes());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn main_key_rotation_rewraps_everything(pool: PgPool) {
    let (old, new) = (Key::random().unwrap(), Key::random().unwrap());
    let memory = Arc::new(InMemory::new());
    let before = BlobStore::new(memory.clone(), Arc::new(TenantKeys::new(pool.clone(), old.clone())));
    for tenant in 1..=3 {
        before.put(Uuid::from_u128(tenant), "mail/1", Bytes::from(format!("tenant {tenant}"))).await.unwrap();
    }

    // New main key configured, old one kept as previous: everything stays readable before the rewrap.
    let both = MainKeys::new(new.clone(), vec![old.clone()]);
    let status = kernoid_store::wrap_status(&pool, &both).await.unwrap();
    assert_eq!(status, WrapStatus { current: 0, previous: 3, unknown: 0 });
    let during = BlobStore::new(memory.clone(), Arc::new(TenantKeys::with_main_keys(pool.clone(), both.clone())));
    assert_eq!(during.get(Uuid::from_u128(1), "mail/1").await.unwrap(), "tenant 1");

    assert_eq!(kernoid_store::rewrap(&pool, &both).await.unwrap(), 3);
    assert_eq!(kernoid_store::rewrap(&pool, &both).await.unwrap(), 0);
    let status = kernoid_store::wrap_status(&pool, &both).await.unwrap();
    assert_eq!(status, WrapStatus { current: 3, previous: 0, unknown: 0 });

    // The old main key is no longer needed – and no longer enough.
    let after = BlobStore::new(memory.clone(), Arc::new(TenantKeys::new(pool.clone(), new)));
    for tenant in 1..=3 {
        assert_eq!(after.get(Uuid::from_u128(tenant), "mail/1").await.unwrap(), format!("tenant {tenant}"));
    }
    let stale = BlobStore::new(memory, Arc::new(TenantKeys::new(pool.clone(), old)));
    assert!(matches!(stale.get(Uuid::from_u128(1), "mail/1").await, Err(BlobError::TenantKey(_))));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn rewrap_stops_at_a_key_it_cannot_unwrap(pool: PgPool) {
    let tenant = Uuid::from_u128(1);
    TenantKeys::new(pool.clone(), Key::random().unwrap()).current(tenant).await.unwrap();
    // A main key that never wrapped anything: the existing key is "unknown" and cannot be rewrapped.
    let unrelated = MainKeys::new(Key::random().unwrap(), Vec::new());
    assert_eq!(kernoid_store::wrap_status(&pool, &unrelated).await.unwrap().unknown, 1);
    assert!(matches!(kernoid_store::rewrap(&pool, &unrelated).await, Err(KeyError::Crypto { .. })));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn one_process_holds_a_lock(pool: sqlx::PgPool) {
    use kernoid_store::lock::Lock;
    let first = Lock::try_take(&pool, "rotation").await.unwrap().expect("free");
    assert!(Lock::try_take(&pool, "rotation").await.unwrap().is_none(), "held");
    let other = Lock::try_take(&pool, "another job").await.unwrap().expect("a lock of its own");
    first.release().await.unwrap();
    let again = Lock::try_take(&pool, "rotation").await.unwrap().expect("released");
    // Dropped without release – a process that died – the lock goes with its connection.
    drop(again);
    let mut taken = None;
    for _ in 0..50 {
        taken = Lock::try_take(&pool, "rotation").await.unwrap();
        if taken.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(taken.is_some(), "the lock ended with its connection");
    other.release().await.unwrap();
}
