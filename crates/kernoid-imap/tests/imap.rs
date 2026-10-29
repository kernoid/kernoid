// SPDX-License-Identifier: AGPL-3.0-or-later
//! IMAP and POP3 against PostgreSQL, with object storage in memory and TLS over in-memory connections; set
//! `DATABASE_URL` as for the other crates' tests.

use std::{net::IpAddr, sync::Arc, time::Duration};

use base64::Engine;
use bytes::Bytes;
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity};
use kernoid_imap::{Protocol, Server, Settings};
use kernoid_mail::{Limits, Mail, MailEvents, NewEmail, Role};
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use object_store::memory::InMemory;
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use uuid::Uuid;

const WHO: &str = "operator";
const HOSTNAME: &str = "mail.firma.example";
const PASSWORD: &str = "a long password of alice";

struct Setup {
    identity: Identity,
    mail: Mail,
    events: MailEvents,
    tenant: Uuid,
    alice: Uuid,
    app_password: String,
    server_tls: Arc<rustls::ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
}

async fn setup(pool: PgPool) -> Setup {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance =
        identity.add_instance("Instance", &DomainName::parse("login.firma.example").unwrap(), WHO).await.unwrap();
    let tenant = identity.add_tenant(instance, "Firma", WHO).await.unwrap();
    let domain = DomainName::parse("firma.example").unwrap();
    identity.add_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
    identity.trust_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
    let alice =
        identity.add_account(tenant, &Address::parse("alice@firma.example").unwrap(), "Alice", WHO).await.unwrap();
    identity.set_password(alice, PASSWORD, WHO).await.unwrap();
    let (_, app_password) = identity.add_app_password(alice, "Thunderbird", WHO).await.unwrap();
    let keys = Arc::new(TenantKeys::with_main_keys(pool.clone(), MainKeys::new(Key::random().unwrap(), Vec::new())));
    let blobs = BlobStore::new(Arc::new(InMemory::new()), keys);
    let mail = Mail::new(pool, blobs, Limits::default());
    let (server_tls, client_tls) = tls_pair();
    Setup { identity, mail, events: MailEvents::default(), tenant, alice, app_password, server_tls, client_tls }
}

impl Setup {
    fn server(&self, implicit_tls: bool) -> Server {
        let settings = Settings { max_message_size: 100_000, timeout: Duration::from_secs(5) };
        Server::new(
            settings,
            self.mail.clone(),
            self.identity.clone(),
            self.events.clone(),
            self.server_tls.clone(),
            implicit_tls,
        )
    }

    async fn deliver(&self, subject: &str, body: &str) -> Uuid {
        self.deliver_to(self.alice, subject, body).await
    }

    async fn deliver_to(&self, account: Uuid, subject: &str, body: &str) -> Uuid {
        self.mail.ensure_account(account).await.unwrap();
        let inbox = self.mail.mailbox_with_role(account, Role::Inbox).await.unwrap();
        let raw = format!(
            "From: Bob <bob@remote.example>\r\nTo: alice@firma.example\r\nSubject: {subject}\r\n\
             Date: Fri, 23 Oct 2026 10:00:00 +0000\r\nMessage-ID: <{subject}@remote.example>\r\n\r\n{body}\r\n"
        );
        let new = NewEmail { mailbox_ids: vec![inbox], ..NewEmail::default() };
        self.mail.import_email(account, Bytes::from(raw), new).await.unwrap().id
    }

    /// A client over TLS from the start, logged in as Alice.
    async fn logged_in(&self, protocol: Protocol) -> Client<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>> {
        self.logged_in_as(protocol, "alice@firma.example", &self.app_password).await
    }

    async fn logged_in_as(
        &self,
        protocol: Protocol,
        user: &str,
        password: &str,
    ) -> Client<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>> {
        let (client_end, served) = tokio::io::duplex(1024 * 1024);
        let server = self.server(true);
        let remote: IpAddr = "192.0.2.10".parse().unwrap();
        tokio::spawn(async move { server.session(protocol, served, remote).await });
        let connector = tokio_rustls::TlsConnector::from(self.client_tls.clone());
        let tls = connector.connect(HOSTNAME.try_into().unwrap(), client_end).await.unwrap();
        let mut client = Client { stream: BufReader::new(tls) };
        client.line().await;
        let login = match protocol {
            Protocol::Imap => client.run(&format!("l LOGIN {user} \"{password}\"")).await,
            Protocol::Pop3 => {
                client.send(&format!("USER {user}\r\n")).await;
                client.line().await;
                client.command(&format!("PASS {password}")).await
            }
        };
        assert!(login.contains("OK"), "{login}");
        client
    }
}

/// A CA, a certificate for the server signed by it, and the TLS configurations of both sides.
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
    base64::engine::general_purpose::STANDARD.encode(value)
}

/// A mail client on the other end of an in-memory connection.
struct Client<S> {
    stream: BufReader<S>,
}

/// The size of the literal a line ends with (`{n}\r\n`).
fn literal(line: &[u8]) -> Option<usize> {
    let line = line.strip_suffix(b"}\r\n")?;
    let start = line.iter().rposition(|&b| b == b'{')?;
    std::str::from_utf8(&line[start + 1..]).ok()?.parse().ok()
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// One line, with the literals it carries.
    async fn line(&mut self) -> String {
        let mut line = Vec::new();
        loop {
            let mut chunk = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(5), self.stream.read_until(b'\n', &mut chunk)).await;
            assert!(read.expect("the server answers in time").unwrap() > 0, "the server closed the connection");
            line.extend_from_slice(&chunk);
            match literal(&chunk) {
                Some(size) => {
                    let mut data = vec![0; size];
                    self.stream.read_exact(&mut data).await.unwrap();
                    line.extend_from_slice(&data);
                }
                None => return String::from_utf8_lossy(&line).into_owned(),
            }
        }
    }

    async fn send(&mut self, data: &str) {
        self.stream.get_mut().write_all(data.as_bytes()).await.unwrap();
    }

    /// Sends a tagged IMAP command; everything up to and with its tagged response.
    async fn run(&mut self, command: &str) -> String {
        let tag = command.split(' ').next().unwrap().to_owned();
        self.send(&format!("{command}\r\n")).await;
        self.until(&tag).await
    }

    async fn until(&mut self, tag: &str) -> String {
        let mut out = String::new();
        loop {
            let line = self.line().await;
            out.push_str(&line);
            if line.starts_with(&format!("{tag} ")) {
                return out;
            }
        }
    }

    /// A POP3 command and its one-line response.
    async fn command(&mut self, line: &str) -> String {
        self.send(&format!("{line}\r\n")).await;
        self.line().await
    }

    /// A POP3 multi-line response, up to its `.`.
    async fn lines(&mut self) -> String {
        let mut out = String::new();
        loop {
            let line = self.line().await;
            if line == ".\r\n" {
                return out;
            }
            out.push_str(&line);
        }
    }
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mail_clients_log_in_over_tls_only(pool: PgPool) {
    let setup = setup(pool).await;
    let (client_end, served) = tokio::io::duplex(64 * 1024);
    let server = setup.server(false);
    tokio::spawn(async move { server.session(Protocol::Imap, served, "192.0.2.10".parse().unwrap()).await });
    let mut client = Client { stream: BufReader::new(client_end) };
    let greeting = client.line().await;
    assert!(greeting.starts_with("* OK [CAPABILITY IMAP4rev2") && greeting.contains("STARTTLS LOGINDISABLED"));
    let refused = client.run("a LOGIN alice@firma.example x").await;
    assert!(refused.starts_with("a NO [PRIVACYREQUIRED]"), "{refused}");
    assert!(client.run("b SELECT INBOX").await.starts_with("b BAD"));
    assert!(client.run("c STARTTLS").await.starts_with("c OK"));
    let connector = tokio_rustls::TlsConnector::from(setup.client_tls.clone());
    let tls = connector.connect(HOSTNAME.try_into().unwrap(), client.stream.into_inner()).await.unwrap();
    let mut client = Client { stream: BufReader::new(tls) };
    let capabilities = client.run("d CAPABILITY").await;
    assert!(capabilities.contains("AUTH=PLAIN") && !capabilities.contains("LOGINDISABLED"), "{capabilities}");
    let wrong = client.run(&format!("e AUTHENTICATE PLAIN {}", b64("\0alice@firma.example\0wrong"))).await;
    assert!(wrong.starts_with("e NO [AUTHENTICATIONFAILED]"), "{wrong}");
    // Without a second factor, the password does; AUTHENTICATE with a continuation.
    client.send("f AUTHENTICATE PLAIN\r\n").await;
    assert_eq!(client.line().await, "+ \r\n");
    client.send(&format!("{}\r\n", b64(&format!("\0alice@firma.example\0{PASSWORD}")))).await;
    let ok = client.until("f").await;
    assert!(ok.starts_with("f OK [CAPABILITY IMAP4rev2") && ok.contains("IDLE"), "{ok}");
    assert!(client.run("g LOGOUT").await.contains("* BYE"));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn mailboxes_messages_and_flags(pool: PgPool) {
    let setup = setup(pool).await;
    setup.deliver("first", "Hello Alice").await;
    setup.deliver("second", "Lunch?").await;
    let mut client = setup.logged_in(Protocol::Imap).await;

    let list = client.run("a LIST \"\" \"*\"").await;
    assert!(list.contains("* LIST (\\HasNoChildren) \"/\" \"INBOX\""), "{list}");
    assert!(list.contains("* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent\""), "{list}");
    assert!(client.run("b LIST \"\" \"\"").await.contains("* LIST (\\Noselect) \"/\" \"\""));
    assert!(client.run("c CREATE Work/2026").await.starts_with("c OK"));
    let list = client.run("d LIST (SPECIAL-USE) \"\" \"*\"").await;
    assert!(list.contains("\"Trash\"") && !list.contains("Work"), "{list}");
    let list = client.run("e LIST \"\" \"Work/%\" RETURN (STATUS (MESSAGES UIDNEXT))").await;
    assert!(list.contains("\"Work/2026\"") && list.contains("* STATUS \"Work/2026\" (MESSAGES 0 UIDNEXT 1)"), "{list}");

    let select = client.run("f SELECT INBOX").await;
    assert!(select.contains("* 2 EXISTS") && select.contains("[UIDVALIDITY ") && select.contains("f OK [READ-WRITE]"));
    let fetch = client.run("g FETCH 1:* (UID FLAGS RFC822.SIZE ENVELOPE)").await;
    assert!(fetch.contains("* 1 FETCH (UID 1 FLAGS () RFC822.SIZE "), "{fetch}");
    assert!(
        fetch.contains("\"first\"") && fetch.contains("\"second\"") && fetch.contains("\"bob\" \"remote.example\"")
    );
    let body = client.run("h FETCH 1 BODY[TEXT]").await;
    assert!(body.contains("Hello Alice") && body.contains("FLAGS (\\Seen)"), "reading marks it seen: {body}");
    let structure = client.run("i FETCH 2 BODYSTRUCTURE").await;
    assert!(structure.contains("(\"text\" \"plain\""), "{structure}");
    let search = client.run("j SEARCH UNSEEN").await;
    assert!(search.contains("* SEARCH 2\r\n"), "{search}");
    let search = client.run("k UID SEARCH RETURN (COUNT ALL) OR SUBJECT second BODY hello SEEN").await;
    assert!(search.contains("* ESEARCH (TAG \"k\") UID COUNT 1 ALL 1"), "{search}");
    // SORT and THREAD (RFC 5256), and the quota (RFC 9208): none set, so no root.
    let capability = client.run("k1 CAPABILITY").await;
    assert!(capability.contains(" SORT") && capability.contains("THREAD=REFERENCES") && capability.contains(" QUOTA"));
    assert!(client.run("k2 SORT (REVERSE SUBJECT) UTF-8 ALL").await.contains("* SORT 2 1\r\n"));
    assert!(client.run("k3 UID SORT (ARRIVAL) UTF-8 SUBJECT second").await.contains("* SORT 2\r\n"));
    let threads = client.run("k4 THREAD REFERENCES UTF-8 ALL").await;
    assert!(threads.contains("* THREAD (1)(2)\r\n"), "{threads}");
    let root = client.run("k5 GETQUOTAROOT INBOX").await;
    assert!(root.contains("* QUOTAROOT \"INBOX\"\r\n") && root.contains("k5 OK"), "{root}");

    // COPY and MOVE answer with UIDs.
    let copy = client.run("l COPY 1 Work/2026").await;
    assert!(copy.contains("l OK [COPYUID ") && copy.contains(" 1 1]"), "{copy}");
    let moved = client.run("m UID MOVE 2 Work/2026").await;
    assert!(moved.contains("* OK [COPYUID ") && moved.contains("* 2 EXPUNGE") && moved.starts_with("* OK"), "{moved}");
    assert!(client.run("n STATUS Work/2026 (MESSAGES UNSEEN)").await.contains("(MESSAGES 2 UNSEEN 1)"));

    // A synchronizing literal waits for the continuation.
    let message = "From: alice@firma.example\r\nSubject: draft\r\n\r\nNot yet\r\n";
    client.send(&format!("o APPEND INBOX (\\Draft $Work) {{{}}}\r\n", message.len())).await;
    assert_eq!(client.line().await, "+ Ready for literal data\r\n");
    client.send(&format!("{message}\r\n")).await;
    let appended = client.until("o").await;
    assert!(appended.contains("[APPENDUID ") && appended.contains("* 2 EXISTS"), "{appended}");
    assert!(client.run("p FETCH 2 FLAGS").await.contains("FLAGS (\\Draft $work)"));

    // \Deleted, then EXPUNGE; STORE answers with the new flags.
    let store = client.run("q STORE 1 +FLAGS (\\Deleted)").await;
    assert!(store.contains("* 1 FETCH (FLAGS (\\Deleted \\Seen))"), "{store}");
    let expunge = client.run("r EXPUNGE").await;
    assert!(expunge.contains("* 1 EXPUNGE") && expunge.starts_with("* 1 EXPUNGE"), "{expunge}");
    // The copy in Work/2026 stays.
    assert!(client.run("s STATUS Work/2026 (MESSAGES)").await.contains("(MESSAGES 2)"));
    assert!(client.run("t DELETE Work").await.starts_with("t NO [HASCHILDREN]"));
    assert!(client.run("u RENAME Work/2026 Archive/Old").await.starts_with("u OK"));
    assert!(client.run("v LIST \"\" \"Archive/*\"").await.contains("\"Archive/Old\""));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn idle_condstore_and_qresync(pool: PgPool) {
    let setup = setup(pool).await;
    let first = setup.deliver("first", "One").await;
    let mut client = setup.logged_in(Protocol::Imap).await;
    assert!(client.run("a ENABLE QRESYNC").await.contains("* ENABLED QRESYNC"));
    let select = client.run("b SELECT INBOX").await;
    let validity: u32 = select.split("[UIDVALIDITY ").nth(1).unwrap().split(']').next().unwrap().parse().unwrap();
    let modseq: u64 = select.split("[HIGHESTMODSEQ ").nth(1).unwrap().split(']').next().unwrap().parse().unwrap();

    // IDLE hears of new mail as it comes.
    client.send("c IDLE\r\n").await;
    assert_eq!(client.line().await, "+ idling\r\n");
    setup.deliver("second", "Two").await;
    setup.events.announce(setup.alice);
    assert_eq!(client.line().await, "* 2 EXISTS\r\n");
    client.send("DONE\r\n").await;
    assert!(client.until("c").await.starts_with("c OK"));

    // A flag changed elsewhere arrives with its MODSEQ; the email destroyed vanishes.
    let seen = kernoid_mail::Keyword::parse("$seen").unwrap();
    let second = setup
        .mail
        .mailbox_entries(setup.alice, setup.mail.mailbox_with_role(setup.alice, Role::Inbox).await.unwrap())
        .await
        .unwrap()[1]
        .email;
    setup.mail.update_keywords(setup.alice, second, &[seen], &[]).await.unwrap();
    setup.mail.destroy_email(setup.alice, first).await.unwrap();
    let noop = client.run("d NOOP").await;
    assert!(noop.contains("* VANISHED 1\r\n"), "{noop}");
    assert!(noop.contains("FETCH (UID 2 FLAGS (\\Seen) MODSEQ ("), "{noop}");

    // A client coming back learns the same since its last state.
    let mut again = setup.logged_in(Protocol::Imap).await;
    again.run("a ENABLE QRESYNC").await;
    let select = again.run(&format!("b SELECT INBOX (QRESYNC ({validity} {modseq}))")).await;
    assert!(select.contains("* VANISHED (EARLIER) 1\r\n"), "{select}");
    assert!(select.contains("* 1 FETCH (UID 2 FLAGS (\\Seen) MODSEQ ("), "{select}");
    // UNCHANGEDSINCE refuses a STORE on what changed after it.
    let store = again.run(&format!("c UID STORE 2 (UNCHANGEDSINCE {modseq}) +FLAGS (\\Flagged)")).await;
    assert!(store.contains("c OK [MODIFIED 2]"), "{store}");
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn pop3_reads_and_deletes_the_inbox(pool: PgPool) {
    let setup = setup(pool).await;
    let first = setup.deliver("first", "Hello\r\n.dotted line").await;
    setup.deliver("second", "Lunch?").await;

    // Plain text first: no login before STLS.
    let (client_end, served) = tokio::io::duplex(64 * 1024);
    let server = setup.server(false);
    tokio::spawn(async move { server.session(Protocol::Pop3, served, "192.0.2.10".parse().unwrap()).await });
    let mut client = Client { stream: BufReader::new(client_end) };
    assert!(client.line().await.starts_with("+OK"));
    assert!(client.command("USER alice@firma.example").await.starts_with("-ERR [AUTH]"));
    assert!(client.command("CAPA").await.starts_with("+OK"));
    assert!(client.lines().await.contains("STLS"));
    assert!(client.command("STLS").await.starts_with("+OK"));
    let connector = tokio_rustls::TlsConnector::from(setup.client_tls.clone());
    let tls = connector.connect(HOSTNAME.try_into().unwrap(), client.stream.into_inner()).await.unwrap();
    let mut client = Client { stream: BufReader::new(tls) };
    let auth =
        client.command(&format!("AUTH PLAIN {}", b64(&format!("\0alice@firma.example\0{}", setup.app_password)))).await;
    assert_eq!(auth, "+OK 2 messages\r\n");
    assert!(client.command("STAT").await.starts_with("+OK 2 "));
    assert!(client.command("UIDL").await.starts_with("+OK"));
    assert!(client.lines().await.starts_with(&format!("1 {first}\r\n")));
    assert!(client.command("RETR 1").await.starts_with("+OK"));
    let message = client.lines().await;
    assert!(message.contains("Subject: first\r\n") && message.contains("\r\n..dotted line\r\n"), "{message}");
    assert!(client.command("TOP 2 0").await.starts_with("+OK"));
    let top = client.lines().await;
    assert!(top.contains("Subject: second") && !top.contains("Lunch?"), "{top}");
    assert!(client.command("DELE 1").await.starts_with("+OK"));
    assert!(client.command("RETR 1").await.starts_with("-ERR"));
    assert!(client.command("STAT").await.starts_with("+OK 1 "));
    assert_eq!(client.command("QUIT").await, "+OK Bye; 1 messages deleted\r\n");

    let mut client = setup.logged_in(Protocol::Pop3).await;
    assert!(client.command("STAT").await.starts_with("+OK 1 "));
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn shared_mailboxes_and_acl(pool: PgPool) {
    use kernoid_identity::role::Principal;
    let setup = setup(pool).await;
    let identity = &setup.identity;
    let info = identity
        .add_shared_mailbox(setup.tenant, &Address::parse("info@firma.example").unwrap(), "Info", WHO)
        .await
        .unwrap();
    assert!(identity.set_password(info, PASSWORD, WHO).await.is_err(), "nobody logs in as a shared mailbox");
    setup.deliver_to(info, "question", "Do you ship to Austria?").await;
    let support = identity.add_group(setup.tenant, "Support", WHO).await.unwrap();
    identity.add_group_member(setup.tenant, support, setup.alice, WHO).await.unwrap();
    identity.set_mail_access(info, Principal::Group(support), None, "lrsw", false, WHO).await.unwrap();

    let mut alice = setup.logged_in(Protocol::Imap).await;
    assert!(alice.run("a NAMESPACE").await.contains("((\"Shared/\" \"/\"))"));
    let list = alice.run("b LIST \"\" \"*\"").await;
    assert!(list.contains("* LIST (\\NoSelect \\HasChildren) \"/\" \"Shared\""), "{list}");
    assert!(
        list.contains("* LIST (\\HasNoChildren) \"/\" \"Shared/info@firma.example/Sent\""),
        "no special use: {list}"
    );
    assert!(list.contains("\"Shared/info@firma.example/INBOX\""), "{list}");
    let select = alice.run("c SELECT Shared/info@firma.example/INBOX").await;
    assert!(select.contains("* 1 EXISTS") && select.contains("c OK [READ-WRITE]"), "{select}");
    // Searching the shared mailbox searches the owner's emails.
    assert!(alice.run("ca SEARCH BODY austr").await.contains("* SEARCH 1\r\n"));
    assert!(alice.run("cb SEARCH FROM bob SUBJECT question").await.contains("* SEARCH 1\r\n"));
    assert!(
        alice
            .run("d MYRIGHTS Shared/info@firma.example/INBOX")
            .await
            .contains("* MYRIGHTS \"Shared/info@firma.example/INBOX\" lrsw")
    );
    assert!(alice.run("e FETCH 1 BODY[TEXT]").await.contains("FLAGS (\\Seen)"));
    // Without `t`, \Deleted stays off; without `e`, nothing is expunged.
    let store = alice.run("f STORE 1 +FLAGS (\\Deleted \\Flagged)").await;
    assert!(store.contains("FLAGS (\\Flagged \\Seen)") && !store.contains("Deleted"), "{store}");
    assert!(alice.run("g EXPUNGE").await.starts_with("g NO [NOPERM]"));
    assert!(alice.run("h GETACL Shared/info@firma.example/INBOX").await.starts_with("h NO [NOPERM]"));
    assert!(alice.run("i CREATE Shared/info@firma.example/Sub").await.starts_with("i NO [NOPERM]"));
    // A copy into the own store is a new email there.
    let copy = alice.run("j COPY 1 INBOX").await;
    assert!(copy.contains("j OK [COPYUID "), "{copy}");
    assert!(alice.run("k STATUS INBOX (MESSAGES)").await.contains("(MESSAGES 1)"));

    // The owner shares their own inbox, read-only, with Bob.
    let bob =
        identity.add_account(setup.tenant, &Address::parse("bob@firma.example").unwrap(), "Bob", WHO).await.unwrap();
    let (_, bob_password) = identity.add_app_password(bob, "Phone", WHO).await.unwrap();
    assert!(alice.run("l SETACL INBOX bob@firma.example lr").await.starts_with("l OK"));
    assert!(alice.run("m SETACL INBOX $Support +s").await.starts_with("m OK"));
    let acl = alice.run("n GETACL INBOX").await;
    assert!(acl.contains("\"alice@firma.example\" lrswipkxtea") && acl.contains("\"bob@firma.example\" lr"), "{acl}");
    assert!(acl.contains("\"$Support\" s"), "{acl}");
    let mut bob_client = setup.logged_in_as(Protocol::Imap, "bob@firma.example", &bob_password).await;
    assert!(bob_client.run("a LIST \"\" \"Shared/*\"").await.contains("\"Shared/alice@firma.example/INBOX\""));
    let select = bob_client.run("b SELECT Shared/alice@firma.example/INBOX").await;
    assert!(select.contains("* 1 EXISTS") && select.contains("b OK [READ-ONLY]"), "{select}");
    assert!(bob_client.run("c STORE 1 +FLAGS (\\Seen)").await.starts_with("c NO [READ-ONLY]"));
    assert!(bob_client.run("d SELECT Shared/info@firma.example/INBOX").await.starts_with("d NO [NONEXISTENT]"));
    assert!(alice.run("o DELETEACL INBOX bob@firma.example").await.starts_with("o OK"));
    assert!(!bob_client.run("e LIST \"\" \"*\"").await.contains("alice@firma.example"));
}
