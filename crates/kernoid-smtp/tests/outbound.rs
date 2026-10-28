// SPDX-License-Identifier: AGPL-3.0-or-later
//! Delivering the queue against a second kernoid as the remote mail server, on a local port; DNS answers are put into
//! the caches. Set `DATABASE_URL` as for the other crates' tests.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use kernoid_events::EventStore;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use kernoid_mail::{EmailQuery, Limits, Mail, Outgoing, Role};
use kernoid_smtp::{
    Dns, Server, Settings, dkim,
    dns::FOREVER,
    outbound::{Outbound, OutboundSettings},
};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use mail_auth::{
    DnssecStatus, MX, RecordSet, ResolverCache, Txt, common::parse::TxtRecordParser, common::verify::DomainKey,
};
use object_store::memory::InMemory;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
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
    pool: PgPool,
    identity: Identity,
    mail: Mail,
    main: MainKeys,
    firma: Uuid,
    remote: Uuid,
}

async fn tenant(identity: &Identity, instance: Uuid, name: &str, domain: &str) -> Uuid {
    let tenant = identity.add_tenant(instance, name, WHO).await.unwrap();
    let parsed = DomainName::parse(domain).unwrap();
    let token = identity.add_tenant_domain(instance, tenant, &parsed, WHO).await.unwrap();
    let dns = FakeDns::default();
    dns.0.lock().unwrap().insert(format!("{CHALLENGE_LABEL}.{domain}"), vec![format!("kernoid-verification={token}")]);
    identity.verify_tenant_domain(instance, tenant, &parsed, &dns, WHO).await.unwrap();
    tenant
}

async fn setup(pool: PgPool) -> Setup {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance =
        identity.add_instance("Instance", &DomainName::parse("login.firma.example").unwrap(), WHO).await.unwrap();
    let firma = tenant(&identity, instance, "Firma", "firma.example").await;
    let remote = tenant(&identity, instance, "Remote", "remote.example").await;
    let main = MainKeys::new(Key::random().unwrap(), Vec::new());
    let keys = Arc::new(TenantKeys::with_main_keys(pool.clone(), main.clone()));
    let blobs = BlobStore::new(Arc::new(InMemory::new()), keys);
    Setup { pool: pool.clone(), identity, mail: Mail::new(pool, blobs, Limits::default()), main, firma, remote }
}

impl Setup {
    async fn account(&self, tenant: Uuid, address: &str) -> Uuid {
        self.identity.add_account(tenant, &Address::parse(address).unwrap(), address, WHO).await.unwrap()
    }

    async fn inbox(&self, account: Uuid) -> Vec<String> {
        let inbox = self.mail.mailbox_with_role(account, Role::Inbox).await.unwrap();
        let query = EmailQuery { in_mailbox: Some(inbox), ..EmailQuery::default() };
        let (ids, _) = self.mail.query(account, &query, 0, 100).await.unwrap();
        let mut messages = Vec::new();
        for id in ids {
            messages.push(String::from_utf8(self.mail.raw_email(account, id).await.unwrap().to_vec()).unwrap());
        }
        messages
    }

    /// The remote mail server: a second kernoid on a free local port; its DNS knows firma.example's DKIM key.
    async fn remote_server(&self) -> u16 {
        let dns = Dns::offline();
        let (selector, record) = dkim::public_record(&self.pool, "firma.example").await.unwrap().unwrap();
        let key: Txt = DomainKey::parse(record.as_bytes()).unwrap().into();
        dns.txt.insert(format!("{selector}._domainkey.firma.example.").into(), key, Instant::now() + FOREVER);
        let settings = Settings {
            hostname: "mx.remote.example".into(),
            max_message_size: 100_000,
            max_recipients: 10,
            max_received: 50,
            junk_score: 5.0,
            timeout: Duration::from_secs(5),
        };
        let server = Server::new(settings, self.mail.clone(), dns, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(server.serve(listener, 10, CancellationToken::new()));
        port
    }

    /// The sending side: MX and address of remote.example in its caches.
    fn outbound(&self, port: u16) -> Outbound {
        let dns = Dns::offline();
        let mx = RecordSet {
            rrset: Arc::from([MX { exchanges: Box::from(["mx.remote.example.".into()]), preference: 10 }]),
            dnssec_status: DnssecStatus::Insecure,
        };
        dns.mx.insert("remote.example.".into(), mx, Instant::now() + FOREVER);
        let address = RecordSet { rrset: Arc::from([Ipv4Addr::LOCALHOST]), dnssec_status: DnssecStatus::Insecure };
        dns.ipv4.insert("mx.remote.example.".into(), address, Instant::now() + FOREVER);
        let null = RecordSet {
            rrset: Arc::from([MX { exchanges: Box::from([".".into()]), preference: 0 }]),
            dnssec_status: DnssecStatus::Insecure,
        };
        dns.mx.insert("nomail.example.".into(), null, Instant::now() + FOREVER);
        let settings = OutboundSettings {
            hostname: "mx.kernoid.example".into(),
            port,
            relay: None,
            timeout: Duration::from_secs(5),
            allow_private_networks: true,
        };
        Outbound::new(settings, self.mail.clone(), dns, Some(self.main.clone()))
    }

    async fn send(&self, from: &str, to: &[&str], raw: String, lifetime: chrono::Duration) {
        // Signed by the worker on the way out.
        let signed = Bytes::from(raw);
        let recipients: Vec<String> = to.iter().map(|to| (*to).to_owned()).collect();
        self.mail
            .enqueue(Outgoing {
                tenant: self.firma,
                account: None,
                from,
                recipients: &recipients,
                raw: signed,
                lifetime,
            })
            .await
            .unwrap();
    }

    async fn queued(&self) -> Vec<(String, String, i32)> {
        sqlx::query!("SELECT address, status, attempts FROM outbound_recipients ORDER BY address")
            .fetch_all(&self.pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.address, row.status, row.attempts))
            .collect()
    }
}

/// Puts a TXT record into the sending side's DNS cache.
fn outbound_dns_txt(outbound: &Outbound, name: &str, record: Txt) {
    outbound.dns().txt.insert(name.into(), record, Instant::now() + FOREVER);
}

fn message(subject: &str) -> String {
    format!(
        "From: Alice <alice@firma.example>\r\nTo: bob@remote.example\r\nSubject: {subject}\r\n\
         Date: Sat, 24 Oct 2026 10:00:00 +0200\r\nMessage-ID: <{}@firma.example>\r\n\r\nHello Bob.\r\n",
        Uuid::now_v7()
    )
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mail_goes_out_signed_and_failures_bounce(pool: PgPool) {
    let setup = setup(pool).await;
    // The worker makes a key for each verified domain, once.
    assert_eq!(dkim::ensure_keys(&setup.pool, &setup.main).await.unwrap(), 2);
    assert_eq!(dkim::ensure_keys(&setup.pool, &setup.main).await.unwrap(), 0);
    let alice = setup.account(setup.firma, "alice@firma.example").await;
    let bob = setup.account(setup.remote, "bob@remote.example").await;
    let port = setup.remote_server().await;
    let outbound = setup.outbound(port);

    setup
        .send(
            "alice@firma.example",
            &["bob@remote.example", "nobody@remote.example"],
            message("Hello"),
            chrono::Duration::days(5),
        )
        .await;
    assert_eq!(outbound.deliver_due().await.unwrap(), 2);

    // Bob has it, signed and checked by his server.
    let received = setup.inbox(bob).await;
    assert_eq!(received.len(), 1);
    assert!(received[0].contains("dkim=pass"), "{}", received[0]);
    assert!(received[0].contains("DKIM-Signature: v=1; a=rsa-sha256;"));

    // The unknown recipient bounced to Alice; the message is done and gone from the queue.
    let bounces = setup.inbox(alice).await;
    assert_eq!(bounces.len(), 1);
    assert!(bounces[0].contains("Final-Recipient: rfc822; nobody@remote.example"), "{}", bounces[0]);
    assert!(bounces[0].contains("550 5.1.1"));
    assert!(setup.queued().await.is_empty());
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn failures_are_tried_again_until_the_message_expires(pool: PgPool) {
    let setup = setup(pool).await;
    dkim::ensure_keys(&setup.pool, &setup.main).await.unwrap();
    let alice = setup.account(setup.firma, "alice@firma.example").await;
    // Nobody listens on this port.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let outbound = setup.outbound(closed);

    setup.send("alice@firma.example", &["bob@remote.example"], message("Later"), chrono::Duration::days(5)).await;
    assert_eq!(outbound.deliver_due().await.unwrap(), 1);
    assert_eq!(setup.queued().await, [("bob@remote.example".to_owned(), "queued".to_owned(), 1)]);
    // Not due again yet.
    assert_eq!(outbound.deliver_due().await.unwrap(), 0);
    assert!(setup.inbox(alice).await.is_empty());

    // A message whose time is up fails at the next attempt, and bounces.
    setup.send("alice@firma.example", &["carol@remote.example"], message("Too late"), chrono::Duration::zero()).await;
    assert_eq!(outbound.deliver_due().await.unwrap(), 1);
    let bounces = setup.inbox(alice).await;
    assert_eq!(bounces.len(), 1);
    assert!(bounces[0].contains("gave up"), "{}", bounces[0]);

    // A null MX refuses for good at once; a bounce without a sender is not bounced again.
    setup.send("alice@firma.example", &["x@nomail.example"], message("Nowhere"), chrono::Duration::days(5)).await;
    setup.send("", &["y@nomail.example"], message("Bounce"), chrono::Duration::days(5)).await;
    assert_eq!(outbound.deliver_due().await.unwrap(), 2);
    let bounces = setup.inbox(alice).await;
    assert_eq!(bounces.len(), 2);
    assert!(bounces.iter().any(|bounce| bounce.contains("null MX")));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn an_mta_sts_policy_in_enforce_mode_requires_its_hosts_and_tls(pool: PgPool) {
    let setup = setup(pool).await;
    dkim::ensure_keys(&setup.pool, &setup.main).await.unwrap();
    setup.account(setup.firma, "alice@firma.example").await;
    let port = setup.remote_server().await;
    let outbound = setup.outbound(port);
    // remote.example publishes a policy; it is cached, so nothing is fetched.
    let record: Txt = mail_auth::mta_sts::MtaSts::parse(b"v=STSv1; id=20261024").unwrap().into();
    outbound_dns_txt(&outbound, "_mta-sts.remote.example.", record);
    sqlx::query!(
        "INSERT INTO mta_sts_policies (domain, policy_id, mode, mx, expires_at)
         VALUES ('remote.example', '20261024', 'enforce', ARRAY['mx.remote.example'], now() + interval '1 day')"
    )
    .execute(&setup.pool)
    .await
    .unwrap();

    // The named host offers no STARTTLS (the test server has no certificate): not delivered, tried again later.
    setup.send("alice@firma.example", &["bob@remote.example"], message("Secure only"), chrono::Duration::days(5)).await;
    assert_eq!(outbound.deliver_due().await.unwrap(), 1);
    let error = sqlx::query_scalar!("SELECT last_error FROM outbound_recipients").fetch_one(&setup.pool).await.unwrap();
    assert!(error.unwrap_or_default().contains("offers no STARTTLS"));

    // A policy that does not name the MX host: nothing goes there.
    sqlx::query!("UPDATE mta_sts_policies SET mx = ARRAY['mail.remote.example']").execute(&setup.pool).await.unwrap();
    sqlx::query!("UPDATE outbound_recipients SET next_attempt_at = now()").execute(&setup.pool).await.unwrap();
    assert_eq!(outbound.deliver_due().await.unwrap(), 1);
    let error = sqlx::query_scalar!("SELECT last_error FROM outbound_recipients").fetch_one(&setup.pool).await.unwrap();
    assert!(error.unwrap_or_default().contains("not named by the MTA-STS policy"));
}
