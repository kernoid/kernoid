// SPDX-License-Identifier: AGPL-3.0-or-later
//! The directory over LDAP against PostgreSQL, with TLS over in-memory connections and ldap3_proto as the client;
//! set `DATABASE_URL` as for the other crates' tests.

use std::{net::IpAddr, sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use kernoid_events::EventStore;
use kernoid_identity::{Address, DomainName, Identity};
use kernoid_ldap::{Io, Server, Settings};
use ldap3_proto::{
    LdapCodec,
    control::LdapControl,
    proto::{
        LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapExtendedRequest, LdapFilter, LdapMsg, LdapOp,
        LdapResultCode, LdapSearchRequest, LdapSearchScope,
    },
};
use sqlx::PgPool;
use tokio_util::codec::Framed;
use uuid::Uuid;

const WHO: &str = "operator";
const HOSTNAME: &str = "ldap.firma.example";
const PASSWORD: &str = "a long password of alice";

struct Setup {
    identity: Identity,
    tenant: Uuid,
    other: Uuid,
    server_tls: Arc<rustls::ServerConfig>,
    client_tls: Arc<rustls::ClientConfig>,
}

async fn setup(pool: PgPool) -> Setup {
    let identity = Identity::new(EventStore::new(pool.clone()));
    let instance =
        identity.add_instance("Instance", &DomainName::parse("login.firma.example").unwrap(), WHO).await.unwrap();
    let mut tenants = Vec::new();
    for (name, domain) in [("Firma", "firma.example"), ("Other", "other.example")] {
        let tenant = identity.add_tenant(instance, name, WHO).await.unwrap();
        let domain = DomainName::parse(domain).unwrap();
        identity.add_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
        identity.trust_tenant_domain(instance, tenant, &domain, WHO).await.unwrap();
        tenants.push(tenant);
    }
    let (server_tls, client_tls) = tls_pair();
    Setup { identity, tenant: tenants[0], other: tenants[1], server_tls, client_tls }
}

type Client = Framed<Box<dyn Io>, LdapCodec>;

impl Setup {
    fn server(&self, implicit_tls: bool, max_entries: usize) -> Server {
        let settings = Settings { timeout: Duration::from_secs(5), max_entries };
        Server::new(settings, self.identity.clone(), self.server_tls.clone(), implicit_tls)
    }

    async fn account(&self, tenant: Uuid, address: &str, name: &str) -> Uuid {
        let account = self.identity.add_account(tenant, &Address::parse(address).unwrap(), name, WHO).await.unwrap();
        self.identity.set_password(account, PASSWORD, WHO).await.unwrap();
        account
    }

    async fn tls(&self, plain: Box<dyn Io>) -> Box<dyn Io> {
        let connector = tokio_rustls::TlsConnector::from(self.client_tls.clone());
        Box::new(connector.connect(HOSTNAME.try_into().unwrap(), plain).await.unwrap())
    }

    /// A connection to a server; over TLS from the start if `implicit_tls`.
    async fn connect(&self, implicit_tls: bool, max_entries: usize) -> Client {
        let (client_end, served) = tokio::io::duplex(1024 * 1024);
        let server = self.server(implicit_tls, max_entries);
        let remote: IpAddr = "192.0.2.10".parse().unwrap();
        tokio::spawn(async move { server.session(served, remote).await });
        let stream: Box<dyn Io> = Box::new(client_end);
        let stream = if implicit_tls { self.tls(stream).await } else { stream };
        Framed::new(stream, LdapCodec::default())
    }
}

/// Sends `op` as message `id`; the responses up to the last one for it.
async fn call(client: &mut Client, id: i32, op: LdapOp, controls: Vec<LdapControl>) -> Vec<LdapMsg> {
    let mut message = LdapMsg::new(id, op);
    message.ctrl = controls;
    client.send(message).await.unwrap();
    let mut out = Vec::new();
    loop {
        let response = tokio::time::timeout(Duration::from_secs(5), client.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(response.msgid, id);
        let last = !matches!(response.op, LdapOp::SearchResultEntry(_));
        out.push(response);
        if last {
            return out;
        }
    }
}

fn bind(dn: &str, password: &str) -> LdapOp {
    LdapOp::BindRequest(LdapBindRequest { dn: dn.into(), cred: LdapBindCred::Simple(password.into()) })
}

fn code(response: &LdapMsg) -> LdapResultCode {
    match &response.op {
        LdapOp::BindResponse(response) => response.res.code.clone(),
        LdapOp::SearchResultDone(result)
        | LdapOp::ModifyResponse(result)
        | LdapOp::AddResponse(result)
        | LdapOp::DelResponse(result) => result.code.clone(),
        LdapOp::ExtendedResponse(response) => response.res.code.clone(),
        other => panic!("not a result: {other:?}"),
    }
}

fn search(base: &str, scope: LdapSearchScope, filter: LdapFilter, attrs: &[&str]) -> LdapOp {
    LdapOp::SearchRequest(LdapSearchRequest {
        base: base.into(),
        scope,
        aliases: LdapDerefAliases::Never,
        sizelimit: 0,
        timelimit: 0,
        typesonly: false,
        filter,
        attrs: attrs.iter().map(|name| (*name).to_owned()).collect(),
    })
}

/// The DNs of a search's entries, and the attribute `name` of each.
fn found(responses: &[LdapMsg], name: &str) -> Vec<(String, Vec<String>)> {
    responses
        .iter()
        .filter_map(|response| match &response.op {
            LdapOp::SearchResultEntry(entry) => Some((
                entry.dn.clone(),
                entry
                    .attributes
                    .iter()
                    .filter(|attribute| attribute.atype.eq_ignore_ascii_case(name))
                    .flat_map(|attribute| attribute.vals.iter().map(|value| String::from_utf8(value.clone()).unwrap()))
                    .collect(),
            )),
            _ => None,
        })
        .collect()
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn a_bound_account_reads_its_tenants_directory(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account(setup.tenant, "alice@firma.example", "Alice Liddell").await;
    let bob = setup.account(setup.tenant, "bob@firma.example", "Bob").await;
    setup.account(setup.other, "carol@other.example", "Carol").await;
    let staff = setup.identity.add_group(setup.tenant, "Staff", WHO).await.unwrap();
    setup.identity.add_group_member(setup.tenant, staff, alice, WHO).await.unwrap();
    let _ = bob;
    let base = format!("o={}", setup.tenant);
    let alice_dn = format!("uid=alice@firma.example,ou=people,{base}");

    let mut client = setup.connect(false, 100).await;
    // The root DSE without a bind; nothing else.
    let root = call(
        &mut client,
        1,
        search("", LdapSearchScope::Base, LdapFilter::Present("objectClass".into()), &["+", "*"]),
        vec![],
    )
    .await;
    assert_eq!(found(&root, "supportedExtension")[0].1, ["1.3.6.1.4.1.1466.20037", "1.3.6.1.4.1.4203.1.11.3"]);
    assert!(found(&root, "namingContexts")[0].1.is_empty());
    let denied = call(
        &mut client,
        2,
        search(&base, LdapSearchScope::Subtree, LdapFilter::Present("objectClass".into()), &[]),
        vec![],
    )
    .await;
    assert_eq!(code(&denied[0]), LdapResultCode::InsufficentAccessRights);

    // No password in plain text; StartTLS first.
    let plain = call(&mut client, 3, bind(&alice_dn, PASSWORD), vec![]).await;
    assert_eq!(code(&plain[0]), LdapResultCode::ConfidentialityRequired);
    let start = LdapOp::ExtendedRequest(LdapExtendedRequest { name: "1.3.6.1.4.1.1466.20037".into(), value: None });
    assert_eq!(code(&call(&mut client, 4, start, vec![]).await[0]), LdapResultCode::Success);
    let stream = client.into_inner();
    let mut client = Framed::new(setup.tls(stream).await, LdapCodec::default());

    assert_eq!(
        code(&call(&mut client, 5, bind(&alice_dn, "wrong"), vec![]).await[0]),
        LdapResultCode::InvalidCredentials
    );
    assert_eq!(code(&call(&mut client, 6, bind(&alice_dn, ""), vec![]).await[0]), LdapResultCode::UnwillingToPerform);
    assert_eq!(code(&call(&mut client, 7, bind(&alice_dn, PASSWORD), vec![]).await[0]), LdapResultCode::Success);
    let whoami = LdapOp::ExtendedRequest(LdapExtendedRequest { name: "1.3.6.1.4.1.4203.1.11.3".into(), value: None });
    match &call(&mut client, 8, whoami, vec![]).await[0].op {
        LdapOp::ExtendedResponse(response) => {
            assert_eq!(response.value.as_deref(), Some(format!("dn:{alice_dn}").as_bytes()))
        }
        other => panic!("{other:?}"),
    }

    // People and groups of the tenant, with what software asks for.
    let people = call(
        &mut client,
        9,
        search(
            &format!("ou=people,{base}"),
            LdapSearchScope::OneLevel,
            LdapFilter::Equality("objectClass".into(), "inetOrgPerson".into()),
            &["mail", "memberOf"],
        ),
        vec![LdapControl::SimplePagedResults { size: 50, cookie: Vec::new() }],
    )
    .await;
    assert_eq!(
        found(&people, "mail"),
        [
            (alice_dn.clone(), vec!["alice@firma.example".into()]),
            (format!("uid=bob@firma.example,ou=people,{base}"), vec!["bob@firma.example".into()])
        ]
    );
    assert_eq!(found(&people, "memberOf")[0].1, [format!("cn=Staff,ou=groups,{base}")]);
    assert!(found(&people, "cn").iter().all(|(_, values)| values.is_empty()), "only what was asked for");
    let done = people.last().unwrap();
    assert_eq!(code(done), LdapResultCode::Success);
    assert!(matches!(done.ctrl.as_slice(), [LdapControl::SimplePagedResults { cookie, .. }] if cookie.is_empty()));
    let groups = call(
        &mut client,
        10,
        search(
            &base,
            LdapSearchScope::Subtree,
            LdapFilter::And(vec![
                LdapFilter::Equality("objectClass".into(), "groupOfNames".into()),
                LdapFilter::Equality("member".into(), alice_dn.to_uppercase()),
            ]),
            &["cn"],
        ),
        vec![],
    )
    .await;
    assert_eq!(found(&groups, "cn"), [(format!("cn=Staff,ou=groups,{base}"), vec!["Staff".into()])]);

    // Another tenant's tree does not exist for Alice; nothing is written.
    let elsewhere = call(
        &mut client,
        11,
        search(&format!("o={}", setup.other), LdapSearchScope::Subtree, LdapFilter::Present("objectClass".into()), &[]),
        vec![],
    )
    .await;
    assert_eq!(code(&elsewhere[0]), LdapResultCode::NoSuchObject);
    let delete = call(&mut client, 12, LdapOp::DelRequest(alice_dn.clone()), vec![]).await;
    assert_eq!(code(&delete[0]), LdapResultCode::UnwillingToPerform);
}

#[sqlx::test(migrator = "kernoid_store::MIGRATOR")]
async fn ldaps_binds_with_an_address_and_limits_searches(pool: PgPool) {
    let setup = setup(pool).await;
    let alice = setup.account(setup.tenant, "alice@firma.example", "Alice").await;
    let (_, app_password) = setup.identity.add_app_password(alice, "Wiki", WHO).await.unwrap();
    setup.account(setup.tenant, "bob@firma.example", "Bob").await;
    let base = format!("o={}", setup.tenant);
    let mut client = setup.connect(true, 2).await;
    assert_eq!(
        code(&call(&mut client, 1, bind("alice@firma.example", &app_password), vec![]).await[0]),
        LdapResultCode::Success
    );
    let root = call(
        &mut client,
        2,
        search("", LdapSearchScope::Base, LdapFilter::Present("objectClass".into()), &["namingContexts"]),
        vec![],
    )
    .await;
    assert_eq!(found(&root, "namingContexts")[0].1, std::slice::from_ref(&base));
    let all = call(
        &mut client,
        3,
        search(&base, LdapSearchScope::Subtree, LdapFilter::Present("objectClass".into()), &["1.1"]),
        vec![],
    )
    .await;
    assert_eq!(found(&all, "x").len(), 2);
    assert_eq!(code(all.last().unwrap()), LdapResultCode::SizeLimitExceeded);
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
