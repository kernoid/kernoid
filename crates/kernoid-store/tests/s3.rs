// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runs against real S3-compatible object storage, e.g. Garage from deploy/compose, and PostgreSQL (for the tenant
//! keys); ignored unless asked for:
//!
//! DATABASE_URL=… KERNOID__BLOB__ENDPOINT=http://localhost:3900 KERNOID__BLOB__REGION=garage \
//! KERNOID__BLOB__BUCKET=kernoid KERNOID__BLOB__ACCESS_KEY_ID=… KERNOID__BLOB__SECRET_ACCESS_KEY=… \
//! cargo test -p kernoid-store --test s3 -- --ignored

use std::sync::Arc;

use bytes::Bytes;
use kernoid_config::Blob;
use kernoid_store::{BlobError, BlobStore, TenantKeys, crypto::Key};
use object_store::{ObjectStoreExt, aws::AmazonS3Builder, path::Path};
use sqlx::PgPool;
use uuid::Uuid;

fn s3() -> kernoid_config::S3 {
    let config = kernoid_config::Config::from_sources(
        "",
        std::env::vars().chain([
            ("KERNOID__DATABASE__URL".into(), "unused".into()),
            ("KERNOID__ENCRYPTION__MAIN_KEY".into(), "unused".into()),
            ("KERNOID__BLOB__KIND".into(), "s3".into()),
            ("KERNOID__BLOB__ALLOW_HTTP".into(), "true".into()),
        ]),
    )
    .expect("KERNOID__BLOB__… variables");
    let Blob::S3(s3) = config.blob else { unreachable!() };
    s3
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
#[ignore = "needs S3-compatible object storage"]
async fn round_trip_stores_only_ciphertext(pool: PgPool) {
    let s3 = s3();
    let keys = Arc::new(TenantKeys::new(pool, Key::random().unwrap()));
    let store = BlobStore::from_config(&Blob::S3(s3.clone()), keys).unwrap();
    store.ping().await.unwrap();
    let tenant = Uuid::new_v4();
    let content = Bytes::from_static(b"hello, this is a message body");
    store.put(tenant, "test/round-trip", content.clone()).await.unwrap();
    assert_eq!(store.get(tenant, "test/round-trip").await.unwrap(), content);

    // What the object storage holds is not the content.
    let raw = AmazonS3Builder::new()
        .with_endpoint(s3.endpoint.unwrap())
        .with_region(s3.region)
        .with_bucket_name(s3.bucket)
        .with_access_key_id(s3.access_key_id.expose())
        .with_secret_access_key(s3.secret_access_key.expose())
        .with_allow_http(true)
        .with_virtual_hosted_style_request(false)
        .build()
        .unwrap();
    let stored =
        raw.get(&Path::from(format!("tenants/{tenant}/test/round-trip"))).await.unwrap().bytes().await.unwrap();
    assert!(stored.starts_with(b"KRNO"));
    assert!(!stored.windows(content.len()).any(|window| window == content.as_ref()));

    store.delete(tenant, "test/round-trip").await.unwrap();
    assert!(matches!(store.get(tenant, "test/round-trip").await, Err(BlobError::NotFound)));
}
