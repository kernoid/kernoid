// SPDX-License-Identifier: AGPL-3.0-or-later
//! Configuration of a kernoid process.
//!
//! The configuration is read from a TOML file and can be overridden by environment variables: `KERNOID__A__B=value`
//! sets the key `a.b` (two underscores separate the levels). Values from the environment are parsed as TOML values
//! where possible (`true`, `10`, `["api"]`) and taken as strings otherwise.

use std::{fmt, net::SocketAddr, path::Path};

use serde::Deserialize;

/// Prefix of environment variables that override configuration keys.
pub const ENV_PREFIX: &str = "KERNOID__";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Roles this process takes on; `all` takes on every role.
    #[serde(default = "default_roles")]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub http: Http,
    pub database: Database,
    pub blob: Blob,
    pub encryption: Encryption,
    /// One table per module, `[modules.<name>]`; a module is on only with `enabled = true` (see kernoid-module).
    #[serde(default)]
    pub modules: std::collections::BTreeMap<String, toml::Table>,
    #[serde(default)]
    pub log: Log,
    #[serde(default)]
    pub outbound: Outbound,
    #[serde(default)]
    pub oidc: Oidc,
    #[serde(default)]
    pub mail: Mail,
    #[serde(default)]
    pub files: Files,
    /// Receiving mail from other servers (RFC 0002, 9); without this table, no process listens for it.
    pub smtp: Option<Smtp>,
    /// Mail clients over IMAP and POP3 (RFC 0002, 11.2, 11.3); without this table, no process listens for them.
    pub imap: Option<Imap>,
}

/// IMAP for mail clients, and POP3 if asked for; both only with certificates, since logging in needs TLS.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Imap {
    /// IMAP with `STARTTLS`.
    #[serde(default = "default_imap_listen")]
    pub listen: SocketAddr,
    /// IMAP with TLS from the start (RFC 8314).
    #[serde(default = "default_imaps_listen")]
    pub tls_listen: SocketAddr,
    /// POP3 with `STLS` – off unless set, e.g. to `0.0.0.0:110`.
    pub pop3_listen: Option<SocketAddr>,
    /// POP3 with TLS from the start – off unless set, e.g. to `0.0.0.0:995`.
    pub pop3_tls_listen: Option<SocketAddr>,
    /// Sessions at once per listener; more connections wait.
    #[serde(default = "default_max_connections_imap")]
    pub max_connections: usize,
    /// How long a session may say nothing, `IDLE` included, in seconds (RFC 9051: at least 30 minutes).
    #[serde(default = "default_imap_timeout")]
    pub timeout_seconds: u64,
}

fn default_imap_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 143))
}

fn default_imaps_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 993))
}

fn default_max_connections_imap() -> usize {
    5000
}

fn default_imap_timeout() -> u64 {
    1800
}

/// The SMTP server that receives mail for the tenants' domains (the MX).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Smtp {
    /// The name the server greets with and puts into `Received` and `Authentication-Results`; the name the tenants'
    /// MX records point to.
    pub hostname: String,
    #[serde(default = "default_smtp_listen")]
    pub listen: SocketAddr,
    /// Submission with `STARTTLS` (RFC 6409); only with certificates.
    #[serde(default = "default_submission_listen")]
    pub submission_listen: SocketAddr,
    /// Submission with TLS from the start (RFC 8314); only with certificates.
    #[serde(default = "default_submissions_listen")]
    pub submissions_listen: SocketAddr,
    #[serde(default = "default_max_recipients")]
    pub max_recipients: usize,
    /// Sessions at once; more connections wait.
    #[serde(default = "default_max_connections_smtp")]
    pub max_connections: usize,
    /// More `Received` headers than this means a loop.
    #[serde(default = "default_max_received")]
    pub max_received: usize,
    /// Mail with at least this spam score goes to Junk.
    #[serde(default = "default_junk_score")]
    pub junk_score: f32,
    /// How long the server waits for a command or data, in seconds.
    #[serde(default = "default_smtp_timeout")]
    pub timeout_seconds: u64,
    /// How long outgoing mail is tried before it bounces, in days.
    #[serde(default = "default_queue_days")]
    pub queue_days: u32,
    /// The SPF record the DNS check suggests; by default `v=spf1 mx -all`. Set it when mail leaves through a relay.
    pub spf: Option<String>,
    /// Hand all mail for other servers to this relay instead of delivering it directly.
    pub relay: Option<SmtpRelay>,
}

/// A relay (smarthost) for outgoing mail, reached over TLS.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpRelay {
    pub host: String,
    #[serde(default = "default_relay_port")]
    pub port: u16,
    /// TLS from the start (usually port 465) instead of `STARTTLS`.
    #[serde(default)]
    pub implicit_tls: bool,
    pub username: Option<String>,
    pub password: Option<Secret>,
}

fn default_queue_days() -> u32 {
    5
}

fn default_relay_port() -> u16 {
    587
}

fn default_smtp_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 25))
}

fn default_submission_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 587))
}

fn default_submissions_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 465))
}

fn default_max_recipients() -> usize {
    100
}

fn default_max_connections_smtp() -> usize {
    1000
}

fn default_max_received() -> usize {
    50
}

fn default_junk_score() -> f32 {
    5.0
}

fn default_smtp_timeout() -> u64 {
    300
}

/// The mail store (RFC 0002).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mail {
    /// Largest message accepted, in bytes.
    #[serde(default = "default_max_message_size")]
    pub max_message_size: u64,
    /// The journal of changes behind JMAP's `*/changes` keeps this many days; clients away longer start over.
    #[serde(default = "default_changes_kept_days")]
    pub changes_kept_days: u32,
    /// Certificates for SMTP, IMAP and POP3 from files – when a reverse proxy holds them (e.g. Caddy's); read again
    /// when they change. Without it, the mail protocols use ACME's or `http.tls`.
    pub tls: Option<Tls>,
    /// The sender of kernoid's own messages – registration codes (RFC 0003, 5) – on a domain kernoid sends for;
    /// without it, people register only with identity providers.
    pub notification_from: Option<String>,
}

impl Default for Mail {
    fn default() -> Self {
        Self {
            max_message_size: default_max_message_size(),
            changes_kept_days: default_changes_kept_days(),
            tls: None,
            notification_from: None,
        }
    }
}

fn default_max_message_size() -> u64 {
    50 * 1024 * 1024
}

fn default_changes_kept_days() -> u32 {
    30
}

/// The file store (RFC 0005).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    /// Largest file accepted, in bytes; content streams to object storage in parts.
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
    /// Earlier contents kept per file.
    #[serde(default = "default_versions_kept")]
    pub versions_kept: u32,
}

impl Default for Files {
    fn default() -> Self {
        Self { max_file_size: default_max_file_size(), versions_kept: default_versions_kept() }
    }
}

fn default_max_file_size() -> u64 {
    10 * 1024 * 1024 * 1024
}

fn default_versions_kept() -> u32 {
    10
}

/// kernoid as an OpenID provider: how the worker rotates the instances' signing keys.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    /// A signing key signs this many days, then a successor takes over; `0` turns rotation off.
    #[serde(default = "default_key_rotation_days")]
    pub key_rotation_days: u32,
    /// The successor is published this many hours before it signs, for clients that cache the JWKS.
    #[serde(default = "default_key_publish_hours")]
    pub key_publish_hours: u32,
    /// A key that no longer signs stays published this many days (ID tokens may come back as `id_token_hint`), then
    /// it is removed.
    #[serde(default = "default_retired_key_days")]
    pub retired_key_days: u32,
}

impl Default for Oidc {
    fn default() -> Self {
        Self {
            key_rotation_days: default_key_rotation_days(),
            key_publish_hours: default_key_publish_hours(),
            retired_key_days: default_retired_key_days(),
        }
    }
}

fn default_key_rotation_days() -> u32 {
    90
}

fn default_key_publish_hours() -> u32 {
    24
}

fn default_retired_key_days() -> u32 {
    30
}

/// Requests kernoid makes itself – to identity providers that tenants connect. Their addresses come from tenant
/// administrators, so by default only HTTPS to public addresses is allowed: nobody may point kernoid at a service
/// inside the installation's network.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outbound {
    /// Allow private, loopback and link-local addresses and plain HTTP – for identity providers inside the network
    /// (e.g. an own Keycloak). Only for installations whose tenants are trusted with that.
    #[serde(default)]
    pub allow_private_networks: bool,
}

/// A part of kernoid that a process can run. Roles are added here as the components are built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Every role.
    All,
    /// Web interface and administration API.
    Api,
    /// Background work: projections and the jobs of modules.
    Worker,
    /// The MX: receives mail from other servers, when `[smtp]` is configured.
    Smtp,
    /// Mail clients: IMAP and POP3, when `[imap]` is configured.
    Imap,
}

impl Role {
    /// Every role except `All`.
    pub const EACH: &[Role] = &[Role::Api, Role::Worker, Role::Smtp, Role::Imap];
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Serve HTTPS directly with this certificate; leave out behind a reverse proxy that terminates TLS.
    pub tls: Option<Tls>,
    /// Serve HTTPS directly with certificates from an ACME CA (Let's Encrypt …) for every instance domain.
    pub acme: Option<Acme>,
    /// Reverse proxies (addresses or networks, e.g. `10.0.0.0/8`) whose `Forwarded` / `X-Forwarded-*` headers are
    /// believed. From anyone else they are ignored – a client must not choose the host or address kernoid sees.
    #[serde(default)]
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Serve Prometheus metrics at `/metrics` on this address – an internal one, it is not protected.
    pub metrics_listen: Option<SocketAddr>,
    /// How instances are reached from outside: `https`, or `http` only for trying kernoid out without TLS. Issuer
    /// and links are built from it and the instance's primary domain – never from a request.
    #[serde(default = "default_public_scheme")]
    pub public_scheme: PublicScheme,
    /// The built login UI (`web/login`), served at `/login`; the container image has it at the default path.
    #[serde(default = "default_login_ui")]
    pub login_ui: std::path::PathBuf,
    /// The web app – mail, calendar, contacts – served at `/app`.
    #[serde(default = "default_web_app")]
    pub web_app: std::path::PathBuf,
}

/// Where the web app's files are (`web/app/dist`); kernoid serves them at `/app`.
fn default_web_app() -> std::path::PathBuf {
    "/usr/share/kernoid/app".into()
}

fn default_login_ui() -> std::path::PathBuf {
    "/usr/share/kernoid/login".into()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PublicScheme {
    #[default]
    Https,
    Http,
}

impl PublicScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            PublicScheme::Https => "https",
            PublicScheme::Http => "http",
        }
    }
}

fn default_public_scheme() -> PublicScheme {
    PublicScheme::Https
}

impl Default for Http {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            tls: None,
            acme: None,
            trusted_proxies: Vec::new(),
            metrics_listen: None,
            public_scheme: PublicScheme::Https,
            login_ui: default_login_ui(),
            web_app: default_web_app(),
        }
    }
}

/// Certificates from an ACME CA (RFC 8555): the worker orders them for every domain of every instance and renews them;
/// every `api` process serves them and answers the CA's HTTP-01 challenges on `http_listen`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
    /// The CA's ACME directory.
    #[serde(default = "default_acme_directory")]
    pub directory: String,
    /// Contact URIs for the CA, e.g. `mailto:ops@example.org`.
    #[serde(default)]
    pub contact: Vec<String>,
    /// That the operator agrees to the CA's terms of service – required, kernoid does not agree on their behalf.
    #[serde(default)]
    pub terms_agreed: bool,
    /// Where the CA's HTTP-01 requests arrive (port 80 from outside); other requests there are redirected to HTTPS.
    #[serde(default = "default_acme_listen")]
    pub http_listen: SocketAddr,
    /// Renew this many days before a certificate ends.
    #[serde(default = "default_renew_days")]
    pub renew_days: u32,
    /// A further root certificate (PEM) to trust for the CA – for a test CA such as Pebble.
    pub ca_root: Option<std::path::PathBuf>,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".into()
}

fn default_acme_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 80))
}

fn default_renew_days() -> u32 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// PEM file with the certificate chain, leaf first.
    pub certificate: std::path::PathBuf,
    /// PEM file with the private key.
    pub key: std::path::PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    /// Connection URL of the runtime role, e.g. `postgres://kernoid_app:secret@db/kernoid?sslmode=verify-full`. The
    /// role needs no rights of its own: `kernoid migrate` grants it what it needs.
    pub url: Secret,
    /// Connection URL of the role that owns the schema and runs `kernoid migrate`. Leave out only if the runtime role
    /// owns the schema – then it can change and remove events, which the separation is there to prevent.
    pub migrate_url: Option<Secret>,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Longest time one statement may run, in milliseconds; 0 for no limit.
    #[serde(default = "default_statement_timeout_ms")]
    pub statement_timeout_ms: u32,
    /// Longest time a transaction may stay open without a statement, in milliseconds; 0 for no limit. Open
    /// transactions hold back readers of all events.
    #[serde(default = "default_idle_in_transaction_timeout_ms")]
    pub idle_in_transaction_timeout_ms: u32,
}

/// Where kernoid keeps content: message bodies, attachments, files.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Blob {
    /// S3-compatible object storage.
    S3(S3),
    /// Kept in memory and lost on exit – for tests and trying kernoid out only.
    Memory,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Encryption {
    /// Main key, 64 hex characters (256 bit), e.g. from `openssl rand -hex 32`. It wraps the tenant keys that content
    /// in object storage is encrypted with: without it, that content cannot be read again – keep a copy apart from
    /// the database and the object storage. To change it, set the new key here, move the old one to
    /// `previous_main_keys` and run `kernoid keys rewrap`.
    pub main_key: Secret,
    /// Earlier main keys, only for reading tenant keys not yet rewrapped; remove them once `kernoid keys status`
    /// shows none left.
    #[serde(default)]
    pub previous_main_keys: Vec<Secret>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3 {
    /// Endpoint URL; leave out for AWS.
    pub endpoint: Option<String>,
    #[serde(default = "default_region")]
    pub region: String,
    pub bucket: String,
    pub access_key_id: Secret,
    pub secret_access_key: Secret,
    /// Allow an endpoint over plain HTTP, e.g. object storage on the same host.
    #[serde(default)]
    pub allow_http: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    /// Filter in the syntax of `tracing_subscriber::EnvFilter`, e.g. `info,kernoid=debug`.
    pub filter: Option<String>,
    #[serde(default)]
    pub format: LogFormat,
    /// Send traces to an OpenTelemetry collector over OTLP/HTTP, e.g. `http://otel-collector:4318/v1/traces`.
    pub otlp_endpoint: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// A value that must not appear in logs; `Debug` prints `***`.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("invalid configuration: {0}")]
    Invalid(#[from] toml::de::Error),
    #[error("environment variable {0} does not name a key")]
    EnvKey(String),
    #[error("environment variable {0} overrides a key that is not a table")]
    EnvConflict(String),
}

impl Config {
    /// Reads `path` (if given) and applies overrides from the process environment.
    pub fn load(path: Option<&Path>) -> Result<Self, Error> {
        let text = match path {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|source| Error::Read { path: path.display().to_string(), source })?,
            None => String::new(),
        };
        Self::from_sources(&text, std::env::vars())
    }

    /// Parses `toml` and applies overrides from `env` (pairs of name and value).
    pub fn from_sources(toml: &str, env: impl IntoIterator<Item = (String, String)>) -> Result<Self, Error> {
        let mut table: toml::Table = toml.parse()?;
        for (name, value) in env {
            let Some(key) = name.strip_prefix(ENV_PREFIX) else { continue };
            let path: Vec<String> = key.split("__").map(str::to_lowercase).collect();
            if path.iter().any(String::is_empty) {
                return Err(Error::EnvKey(name));
            }
            set(&mut table, &path, parse_env_value(&value)).map_err(|()| Error::EnvConflict(name))?;
        }
        let mut config: Config = table.try_into()?;
        if config.roles.contains(&Role::All) {
            config.roles = Role::EACH.to_vec();
        }
        config.roles.dedup();
        Ok(config)
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }
}

fn parse_env_value(value: &str) -> toml::Value {
    toml::from_str::<toml::Table>(&format!("v = {value}"))
        .ok()
        .and_then(|mut table| table.remove("v"))
        .unwrap_or_else(|| toml::Value::String(value.to_owned()))
}

fn set(table: &mut toml::Table, path: &[String], value: toml::Value) -> Result<(), ()> {
    let (last, parents) = path.split_last().ok_or(())?;
    let mut current = table;
    for key in parents {
        let entry = current.entry(key.clone()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
        current = entry.as_table_mut().ok_or(())?;
    }
    current.insert(last.clone(), value);
    Ok(())
}

fn default_roles() -> Vec<Role> {
    vec![Role::All]
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

fn default_max_connections() -> u32 {
    10
}

fn default_statement_timeout_ms() -> u32 {
    30_000
}

fn default_idle_in_transaction_timeout_ms() -> u32 {
    10_000
}

fn default_region() -> String {
    "us-east-1".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [database]
        url = "postgres://kernoid:secret@localhost/kernoid"

        [blob]
        kind = "memory"

        [encryption]
        main_key = "0000000000000000000000000000000000000000000000000000000000000000"
    "#;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn defaults() {
        let config = Config::from_sources(MINIMAL, []).unwrap();
        assert_eq!(config.roles, Role::EACH);
        assert_eq!(config.http.listen, default_listen());
        assert_eq!(config.database.max_connections, 10);
        assert!(config.database.migrate_url.is_none());
        assert_eq!(config.database.statement_timeout_ms, 30_000);
        assert_eq!(config.database.idle_in_transaction_timeout_ms, 10_000);
        assert!(matches!(config.blob, Blob::Memory));
        assert_eq!(config.log.format, LogFormat::Text);
    }

    #[test]
    fn environment_overrides_file() {
        let config = Config::from_sources(
            MINIMAL,
            env(&[
                ("KERNOID__DATABASE__MAX_CONNECTIONS", "3"),
                ("KERNOID__HTTP__LISTEN", "127.0.0.1:9000"),
                ("KERNOID__ROLES", r#"["api"]"#),
                ("OTHER__DATABASE__URL", "ignored"),
            ]),
        )
        .unwrap();
        assert_eq!(config.database.max_connections, 3);
        assert_eq!(config.http.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.roles, [Role::Api]);
        assert!(config.modules.is_empty());
        assert_eq!(config.database.url.expose(), "postgres://kernoid:secret@localhost/kernoid");
    }

    #[test]
    fn environment_alone_is_enough() {
        let config = Config::from_sources(
            "",
            env(&[
                ("KERNOID__DATABASE__URL", "postgres://db/kernoid"),
                ("KERNOID__BLOB__KIND", "s3"),
                ("KERNOID__BLOB__BUCKET", "kernoid"),
                ("KERNOID__BLOB__ACCESS_KEY_ID", "id"),
                ("KERNOID__BLOB__SECRET_ACCESS_KEY", "key"),
                ("KERNOID__ENCRYPTION__MAIN_KEY", "00"),
            ]),
        )
        .unwrap();
        let Blob::S3(s3) = config.blob else { panic!("expected S3") };
        assert_eq!(s3.bucket, "kernoid");
        assert_eq!(s3.region, "us-east-1");
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let config = Config::from_sources(MINIMAL, []).unwrap();
        assert!(!format!("{config:?}").contains("secret"));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let toml = format!("{MINIMAL}\n[http]\nlisten = \"0.0.0.0:80\"\nport = 80\n");
        assert!(Config::from_sources(&toml, []).is_err());
    }

    #[test]
    fn bad_environment_keys_are_rejected() {
        assert!(matches!(
            Config::from_sources(MINIMAL, env(&[("KERNOID__DATABASE____URL", "x")])),
            Err(Error::EnvKey(_))
        ));
        assert!(matches!(
            Config::from_sources(MINIMAL, env(&[("KERNOID__DATABASE__URL__X", "x")])),
            Err(Error::EnvConflict(_))
        ));
    }
}
