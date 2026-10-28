// SPDX-License-Identifier: AGPL-3.0-or-later
//! The MX against PostgreSQL, with object storage in memory and DNS answers put into the caches; set
//! `DATABASE_URL` as for the other crates' tests.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use kernoid_events::EventStore;
use kernoid_identity::{Address, CHALLENGE_LABEL, DomainName, Identity, TxtLookup};
use kernoid_mail::{Limits, Mail, Role};
use kernoid_smtp::{Dns, Server, Settings, Submission, dns::FOREVER};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use mail_auth::{ResolverCache, Txt, common::parse::TxtRecordParser, dmarc::Dmarc, spf::Spf};
use object_store::memory::InMemory;
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use uuid::Uuid;

const WHO: &str = "operator";
const HOSTNAME: &str = "mx.kernoid.example";
const REMOTE: &str = "192.0.2.25";

#[derive(Default)]
struct FakeDns(Mutex<HashMap<String, Vec<String>>>);

impl TxtLookup for FakeDns {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        self.0.lock().unwrap().get(name).cloned().ok_or_else(|| format!("{name}: no records"))
    }
}

struct Setup {
    identity: Identity,
    mail: Mail,
    tenant: Uuid,
}

async fn setup(pool: PgPool) -> Setup {
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
    Setup { identity, mail: Mail::new(pool, blobs, Limits::default()), tenant }
}

impl Setup {
    async fn account(&self, local: &str) -> Uuid {
        let address = Address::parse(&format!("{local}@firma.example")).unwrap();
        self.identity.add_account(self.tenant, &address, local, WHO).await.unwrap()
    }

    fn server(&self, dns: Dns, tls: Option<Arc<rustls::ServerConfig>>) -> Server {
        let settings = Settings {
            hostname: HOSTNAME.into(),
            max_message_size: 10_000,
            max_recipients: 5,
            max_received: 50,
            junk_score: 5.0,
            timeout: Duration::from_secs(5),
        };
        Server::new(settings, self.mail.clone(), dns, tls)
    }

    /// The raw messages in the account's mailbox with `role`.
    async fn messages(&self, account: Uuid, role: Role) -> Vec<String> {
        let mailbox = self.mail.mailbox_with_role(account, role).await.unwrap();
        self.messages_in(account, mailbox).await
    }

    async fn messages_in(&self, account: Uuid, mailbox: Uuid) -> Vec<String> {
        let query = kernoid_mail::EmailQuery { in_mailbox: Some(mailbox), ..Default::default() };
        let (ids, _) = self.mail.query(account, &query, 0, 100).await.unwrap();
        let mut messages = Vec::new();
        for id in ids {
            messages.push(String::from_utf8(self.mail.raw_email(account, id).await.unwrap().to_vec()).unwrap());
        }
        messages
    }
}

/// An SMTP client on the other end of an in-memory connection.
struct Client<S> {
    stream: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// The next response, all its lines joined by `\n`.
    async fn response(&mut self) -> String {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(Duration::from_secs(5), self.stream.read_line(&mut line)).await.unwrap();
            assert!(read.unwrap() > 0, "the server closed the connection");
            let line = line.trim_end().to_owned();
            let last = line.as_bytes().get(3) != Some(&b'-');
            lines.push(line);
            if last {
                return lines.join("\n");
            }
        }
    }

    async fn send(&mut self, data: &str) {
        self.stream.get_mut().write_all(data.as_bytes()).await.unwrap();
    }

    async fn command(&mut self, line: &str) -> String {
        self.send(&format!("{line}\r\n")).await;
        self.response().await
    }
}

fn connect(server: &Server) -> Client<tokio::io::DuplexStream> {
    let (client, served) = tokio::io::duplex(64 * 1024);
    let server = server.clone();
    let remote: IpAddr = REMOTE.parse().unwrap();
    tokio::spawn(async move { server.session(served, remote).await });
    Client { stream: BufReader::new(client) }
}

fn message(from: &str, subject: &str, id: &str, extra: &str) -> String {
    format!(
        "From: {from}\r\nTo: alice@firma.example\r\nSubject: {subject}\r\nDate: Sat, 24 Oct 2026 10:00:00 +0200\r\n\
         Message-ID: <{id}>\r\n{extra}\r\nHello.\r\n.\r\n"
    )
}

fn txt<T: TxtRecordParser + Into<Txt>>(dns: &Dns, name: &str, record: &str) {
    let value = T::parse(record.as_bytes()).unwrap().into();
    dns.txt.insert(name.into(), value, Instant::now() + FOREVER);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mail_is_received_checked_and_stored(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let server = setup.server(Dns::offline(), None);
    let mut client = connect(&server);
    assert_eq!(client.response().await, format!("220 {HOSTNAME} ESMTP kernoid"));
    let ehlo = client.command("EHLO sender.example").await;
    assert!(ehlo.starts_with(&format!("250-{HOSTNAME}")), "{ehlo}");
    for extension in ["PIPELINING", "8BITMIME", "SMTPUTF8", "CHUNKING", "ENHANCEDSTATUSCODES", "SIZE 10000"] {
        assert!(ehlo.contains(extension), "{extension} in {ehlo}");
    }
    assert!(!ehlo.contains("STARTTLS") && !ehlo.contains("AUTH"));

    // Pipelined: all commands at once, the responses in order.
    client
        .send(
            "MAIL FROM:<bob@sender.example>\r\nRCPT TO:<Alice+News@Firma.example>\r\nRCPT TO:<nobody@firma.example>\r\n\
             RCPT TO:<someone@elsewhere.example>\r\nDATA\r\n",
        )
        .await;
    assert_eq!(client.response().await, "250 2.1.0 OK");
    assert_eq!(client.response().await, "250 2.1.5 OK");
    assert_eq!(client.response().await, "550 5.1.1 Mailbox does not exist");
    assert_eq!(client.response().await, "550 5.7.1 Relaying not allowed");
    assert!(client.response().await.starts_with("354 "));
    let forged = "Authentication-Results: mx.kernoid.example; dkim=pass header.d=firma.example\r\n";
    client.send(&message("Bob <bob@sender.example>", "Hello", "1@sender.example", forged)).await;
    assert_eq!(client.response().await, "250 2.0.0 Message accepted for delivery");
    assert_eq!(client.command("QUIT").await, "221 2.0.0 Bye");

    let inbox = setup.messages(alice, Role::Inbox).await;
    assert_eq!(inbox.len(), 1);
    let stored = &inbox[0];
    assert!(
        stored.starts_with(
            "Received: from sender.example (unknown [192.0.2.25])\r\n\tby mx.kernoid.example (kernoid) with ESMTP;"
        ),
        "{stored}"
    );
    assert!(stored.contains(&format!("Authentication-Results: {HOSTNAME}")));
    assert!(stored.contains("X-Spam-Status: No"));
    assert!(!stored.contains("header.d=firma.example"), "the forged result is gone");
    assert!(stored.ends_with("Hello.\r\n"));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn commands_out_of_order_and_limits_are_refused(pool: PgPool) {
    let setup = setup(pool).await;
    setup.account("alice").await;
    let server = setup.server(Dns::offline(), None);
    let mut client = connect(&server);
    client.response().await;
    assert_eq!(client.command("MAIL FROM:<a@b.example>").await, "503 5.5.1 Polite people say EHLO first");
    client.command("HELO sender.example").await;
    assert_eq!(client.command("RCPT TO:<alice@firma.example>").await, "503 5.5.1 MAIL is required first");
    assert_eq!(client.command("MAIL FROM:<a@b.example> SIZE=20000").await, "552 5.3.4 Message too big for system");
    assert_eq!(client.command("MAIL FROM:<>").await, "250 2.1.0 OK");
    assert_eq!(client.command("MAIL FROM:<a@b.example>").await, "503 5.5.1 Multiple MAIL commands are not allowed");
    assert_eq!(client.command("DATA").await, "503 5.5.1 RCPT is required first");
    assert_eq!(
        client.command("AUTH PLAIN AGFsaWNlAHNlY3JldA==").await,
        "503 5.5.1 AUTH is not allowed here; use submission"
    );
    assert_eq!(client.command("STARTTLS").await, "502 5.5.1 TLS is not available");
    assert_eq!(client.command("RCPT TO:<alice@firma.example>").await, "250 2.1.5 OK");
    // Too large: read to its end, then refused.
    assert!(client.command("DATA").await.starts_with("354 "));
    client.send(&format!("Subject: big\r\n\r\n{}\r\n.\r\n", "x".repeat(12_000))).await;
    assert_eq!(client.response().await, "552 5.3.4 Message too big for system");
    assert_eq!(client.command("NOOP").await, "250 2.0.0 OK");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn groups_duplicates_and_chunks(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let bob = setup.account("bob").await;
    let group = setup.identity.add_group(setup.tenant, "Team", WHO).await.unwrap();
    setup.identity.add_group_member(setup.tenant, group, alice, WHO).await.unwrap();
    setup.identity.add_group_member(setup.tenant, group, bob, WHO).await.unwrap();
    let team = Address::parse("team@firma.example").unwrap();
    setup.identity.add_group_address(setup.tenant, group, &team, WHO).await.unwrap();
    // The address belongs to the group now, for everyone.
    assert!(setup.identity.add_alias(alice, &team, WHO).await.is_err());
    let server = setup.server(Dns::offline(), None);

    for _ in 0..2 {
        let mut client = connect(&server);
        client.response().await;
        client.command("EHLO sender.example").await;
        client.command("MAIL FROM:<carol@sender.example>").await;
        assert_eq!(client.command("RCPT TO:<team@firma.example>").await, "250 2.1.5 OK");
        assert_eq!(client.command("RCPT TO:<alice@firma.example>").await, "250 2.1.5 OK");
        let body = message("carol@sender.example", "To the team", "team-1@sender.example", "");
        let body = body.strip_suffix(".\r\n").unwrap();
        // In two chunks.
        let (first, second) = body.split_at(40);
        client.send(&format!("BDAT {}\r\n{first}", first.len())).await;
        assert_eq!(client.response().await, "250 2.6.0 Chunk accepted");
        client.send(&format!("BDAT {} LAST\r\n{second}", second.len())).await;
        assert_eq!(client.response().await, "250 2.0.0 Message accepted for delivery");
    }
    // Once each, although sent twice and to alice twice.
    assert_eq!(setup.messages(alice, Role::Inbox).await.len(), 1);
    assert_eq!(setup.messages(bob, Role::Inbox).await.len(), 1);

    // A group without members has no one to deliver to.
    setup.identity.remove_group_member(setup.tenant, group, alice, WHO).await.unwrap();
    setup.identity.remove_group_member(setup.tenant, group, bob, WHO).await.unwrap();
    let mut client = connect(&server);
    client.response().await;
    client.command("EHLO sender.example").await;
    client.command("MAIL FROM:<carol@sender.example>").await;
    assert_eq!(client.command("RCPT TO:<team@firma.example>").await, "550 5.1.1 Mailbox does not exist");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn sieve_quota_junk_and_dmarc(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;
    let dns = Dns::offline();
    // psd=n ends DMARC's walk up the tree here; the test resolver has no answers beyond the caches.
    txt::<Spf>(&dns, "evil.example.", "v=spf1 -all");
    txt::<Dmarc>(&dns, "_dmarc.evil.example.", "v=DMARC1; p=reject; psd=n");
    txt::<Spf>(&dns, "shady.example.", "v=spf1 -all");
    txt::<Dmarc>(&dns, "_dmarc.shady.example.", "v=DMARC1; p=quarantine; psd=n");
    let server = setup.server(dns, None);
    setup
        .mail
        .put_sieve_script(
            alice,
            "lists",
            r#"require ["fileinto", "mailbox"]; if header :contains "List-ID" "dev" { fileinto :create "Lists/dev"; stop; }"#,
            true,
        )
        .await
        .unwrap();

    let send = |from: &'static str, envelope: &'static str, id: &'static str, extra: &'static str| {
        let server = server.clone();
        async move {
            let mut client = connect(&server);
            client.response().await;
            client.command("EHLO sender.example").await;
            client.command(&format!("MAIL FROM:<{envelope}>")).await;
            client.command("RCPT TO:<alice@firma.example>").await;
            client.command("DATA").await;
            client.send(&message(from, "Hi", id, extra)).await;
            client.response().await
        }
    };

    // Filed by the script, the mailbox made on the way.
    assert_eq!(
        send("dev@lists.example", "dev@lists.example", "l1@lists.example", "List-ID: <dev.lists.example>\r\n").await,
        "250 2.0.0 Message accepted for delivery"
    );
    let boxes = setup.mail.mailboxes(alice).await.unwrap();
    let dev = boxes.iter().find(|mailbox| mailbox.name == "dev").unwrap();
    assert_eq!(setup.messages_in(alice, dev.id).await.len(), 1);

    // DMARC p=reject with failing SPF and no DKIM: refused; p=quarantine: Junk.
    assert_eq!(
        send("ceo@evil.example", "ceo@evil.example", "e1@evil.example", "").await,
        "550 5.7.1 Rejected by the sender's DMARC policy"
    );
    assert_eq!(
        send("x@shady.example", "x@shady.example", "s1@shady.example", "").await,
        "250 2.0.0 Message accepted for delivery"
    );
    let junk = setup.messages(alice, Role::Junk).await;
    assert_eq!(junk.len(), 1);
    assert!(junk[0].contains("dmarc=fail"), "{}", junk[0]);

    // Someone outside writing as a local address, with nothing to back it: Junk.
    assert_eq!(
        send("boss@firma.example", "boss@firma.example", "f1@outside.example", "").await,
        "250 2.0.0 Message accepted for delivery"
    );
    let junk = setup.messages(alice, Role::Junk).await;
    assert_eq!(junk.len(), 2);
    assert!(junk.iter().any(|message| message.contains("FROM_LOCAL_UNAUTHENTICATED")));

    // Over quota: told to try later, at DATA and then already at RCPT.
    let (used, _) = setup.mail.quota(alice).await.unwrap();
    setup.identity.set_mail_quota(alice, Some(used + 10), WHO).await.unwrap();
    assert_eq!(send("a@b.example", "a@b.example", "q1@b.example", "").await, "452 4.2.2 Mailbox full, try again later");
    setup.identity.set_mail_quota(alice, Some(used.saturating_sub(1)), WHO).await.unwrap();
    let mut client = connect(&server);
    client.response().await;
    client.command("EHLO sender.example").await;
    client.command("MAIL FROM:<a@b.example>").await;
    assert_eq!(client.command("RCPT TO:<alice@firma.example>").await, "452 4.2.2 Mailbox full, try again later");

    // A deactivated account takes no mail.
    setup.identity.set_account_active(alice, false, WHO).await.unwrap();
    assert_eq!(client.command("RCPT TO:<alice@firma.example>").await, "550 5.2.1 Mailbox disabled");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn starttls_upgrades_and_forgets_what_came_before(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account("alice").await;

    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap()).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_der = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();
    let leaf = rcgen::CertifiedIssuer::signed_by(
        rcgen::CertificateParams::new(vec![HOSTNAME.to_owned()]).unwrap(),
        leaf_key,
        &ca,
    )
    .unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.as_ref().der().clone()], leaf_der)
        .unwrap();
    let server = setup.server(Dns::offline(), Some(Arc::new(server_config)));

    let mut client = connect(&server);
    client.response().await;
    assert!(client.command("EHLO sender.example").await.contains("STARTTLS"));
    // A command pipelined behind STARTTLS must not be carried out.
    client.send("STARTTLS\r\nMAIL FROM:<injected@evil.example>\r\n").await;
    assert_eq!(client.response().await, "220 2.0.0 Ready to start TLS");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.as_ref().der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let plain = client.stream.into_inner();
    let tls = connector.connect(HOSTNAME.try_into().unwrap(), plain).await.unwrap();
    let mut client = Client { stream: BufReader::new(tls) };
    // Nothing from before: neither EHLO nor the injected MAIL.
    assert_eq!(client.command("RCPT TO:<alice@firma.example>").await, "503 5.5.1 MAIL is required first");
    let ehlo = client.command("EHLO sender.example").await;
    assert!(!ehlo.contains("STARTTLS"));
    client.command("MAIL FROM:<bob@sender.example>").await;
    client.command("RCPT TO:<alice@firma.example>").await;
    client.command("DATA").await;
    client.send(&message("bob@sender.example", "Secret", "t1@sender.example", "")).await;
    assert_eq!(client.response().await, "250 2.0.0 Message accepted for delivery");
    let inbox = setup.messages(alice, Role::Inbox).await;
    assert!(inbox[0].contains("with ESMTPS;") && inbox[0].contains("(using TLSv1_3 with cipher"), "{}", inbox[0]);
}

/// A CA, a certificate for the MX signed by it, and the TLS configurations of both sides.
fn tls_pair() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap()).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_der = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap();
    let leaf = rcgen::CertifiedIssuer::signed_by(
        rcgen::CertificateParams::new(vec![HOSTNAME.to_owned()]).unwrap(),
        leaf_key,
        &ca,
    )
    .unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.as_ref().der().clone()], leaf_der)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.as_ref().der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

fn b64(value: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(value)
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn accounts_submit_over_tls_as_themselves(pool: PgPool) {
    let setup = setup(pool.clone()).await;
    let alice = setup.account("alice").await;
    let bob = setup.account("bob").await;
    setup.identity.set_password(alice, "a long password of alice", WHO).await.unwrap();
    let (_, app_password) = setup.identity.add_app_password(alice, "Thunderbird", WHO).await.unwrap();
    let (server_tls, client_tls) = tls_pair();
    let settings = Settings {
        hostname: HOSTNAME.into(),
        max_message_size: 10_000,
        max_recipients: 5,
        max_received: 50,
        junk_score: 5.0,
        timeout: Duration::from_secs(5),
    };
    let submission =
        Submission { identity: setup.identity.clone(), implicit_tls: false, queue_lifetime: chrono::Duration::days(5) };
    let server =
        Server::submission(settings.clone(), setup.mail.clone(), Dns::offline(), server_tls.clone(), submission);

    let mut client = connect(&server);
    client.response().await;
    let ehlo = client.command("EHLO laptop").await;
    assert!(ehlo.contains("STARTTLS") && !ehlo.contains("AUTH"), "no login before TLS: {ehlo}");
    assert_eq!(
        client.command(&format!("AUTH PLAIN {}", b64("\0alice@firma.example\0x"))).await,
        "538 5.7.11 Encryption required for requested authentication mechanism"
    );
    assert_eq!(client.command("STARTTLS").await, "220 2.0.0 Ready to start TLS");
    let connector = tokio_rustls::TlsConnector::from(client_tls.clone());
    let tls = connector.connect(HOSTNAME.try_into().unwrap(), client.stream.into_inner()).await.unwrap();
    let mut client = Client { stream: BufReader::new(tls) };
    let ehlo = client.command("EHLO laptop").await;
    assert!(ehlo.contains("AUTH PLAIN LOGIN") || ehlo.contains("AUTH LOGIN PLAIN"), "{ehlo}");
    assert_eq!(client.command("MAIL FROM:<alice@firma.example>").await, "530 5.7.0 Authentication required");
    assert_eq!(
        client.command(&format!("AUTH PLAIN {}", b64("\0alice@firma.example\0wrong"))).await,
        "535 5.7.8 Authentication credentials invalid"
    );
    // AUTH LOGIN, step by step, with the app password.
    assert_eq!(client.command("AUTH LOGIN").await, "334 VXNlcm5hbWU6");
    assert_eq!(client.command(&b64("alice@firma.example")).await, "334 UGFzc3dvcmQ6");
    assert_eq!(client.command(&b64(&app_password)).await, "235 2.7.0 Authentication successful");

    assert_eq!(client.command("MAIL FROM:<bob@firma.example>").await, "553 5.7.1 Send as one of your own addresses");
    assert_eq!(client.command("MAIL FROM:<Alice+Sent@firma.example>").await, "250 2.1.0 OK");
    assert_eq!(client.command("RCPT TO:<bob@firma.example>").await, "250 2.1.5 OK");
    assert_eq!(client.command("RCPT TO:<carol@remote.example>").await, "250 2.1.5 OK");
    assert_eq!(client.command("RCPT TO:<nobody@firma.example>").await, "550 5.1.1 Mailbox does not exist");
    assert!(client.command("DATA").await.starts_with("354"));
    client.send("From: Bob <bob@firma.example>\r\nSubject: Forged\r\n\r\nHi\r\n.\r\n").await;
    assert_eq!(client.response().await, "550 5.7.1 You may not send as bob@firma.example");

    client.command("MAIL FROM:<alice@firma.example>").await;
    client.command("RCPT TO:<bob@firma.example>").await;
    client.command("RCPT TO:<carol@remote.example>").await;
    assert!(client.command("DATA").await.starts_with("354"));
    client
        .send("From: Alice <alice@firma.example>\r\nTo: bob@firma.example\r\nSubject: Lunch\r\n\r\nNoon?\r\n.\r\n")
        .await;
    assert_eq!(client.response().await, "250 2.0.0 Message accepted");

    // Bob has it at once, with a Message-ID and a Date added; Carol's copy waits in the queue.
    let inbox = setup.messages(bob, Role::Inbox).await;
    assert_eq!(inbox.len(), 1);
    assert!(
        inbox[0].contains("with ESMTPSA;") && inbox[0].contains("Message-ID: <") && inbox[0].contains("\r\nDate: ")
    );
    let queued = sqlx::query!(
        "SELECT r.address, m.envelope_from FROM outbound_recipients r JOIN outbound_messages m ON m.id = r.message_id"
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(
        (queued[0].address.as_str(), queued[0].envelope_from.as_str()),
        ("carol@remote.example", "alice@firma.example")
    );

    // Port 465: TLS before the greeting.
    let submission =
        Submission { identity: setup.identity.clone(), implicit_tls: true, queue_lifetime: chrono::Duration::days(5) };
    let implicit = Server::submission(settings, setup.mail.clone(), Dns::offline(), server_tls, submission);
    let (client_end, served) = tokio::io::duplex(64 * 1024);
    let remote: IpAddr = REMOTE.parse().unwrap();
    tokio::spawn(async move { implicit.session(served, remote).await });
    let connector = tokio_rustls::TlsConnector::from(client_tls);
    let tls = connector.connect(HOSTNAME.try_into().unwrap(), client_end).await.unwrap();
    let mut client = Client { stream: BufReader::new(tls) };
    assert!(client.response().await.starts_with("220 "));
    assert!(client.command("EHLO laptop").await.contains("AUTH"));
    assert_eq!(
        client.command(&format!("AUTH PLAIN {}", b64("\0alice@firma.example\0a long password of alice"))).await,
        "235 2.7.0 Authentication successful",
        "no second factor: the password does"
    );

    // A shared mailbox: only with send as.
    let info = setup
        .identity
        .add_shared_mailbox(setup.tenant, &Address::parse("info@firma.example").unwrap(), "Info", WHO)
        .await
        .unwrap();
    assert_eq!(client.command("MAIL FROM:<info@firma.example>").await, "553 5.7.1 Send as one of your own addresses");
    let alice_principal = kernoid_identity::role::Principal::Account(alice);
    setup.identity.set_mail_access(info, alice_principal, None, "lr", false, WHO).await.unwrap();
    assert_eq!(client.command("MAIL FROM:<info@firma.example>").await, "553 5.7.1 Send as one of your own addresses");
    setup.identity.set_mail_access(info, alice_principal, None, "lr", true, WHO).await.unwrap();
    assert_eq!(client.command("MAIL FROM:<info@firma.example>").await, "250 2.1.0 OK");
}
