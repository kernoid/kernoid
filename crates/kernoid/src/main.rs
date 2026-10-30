// SPDX-License-Identifier: AGPL-3.0-or-later
//! The kernoid program: one binary, one container image; the configuration decides which roles a process takes on.

use std::{io::IsTerminal, path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::{Parser, Subcommand};
use kernoid_config::{Config, Http, LogFormat, Role};
use kernoid_events::EventStore;
use kernoid_identity::{
    Address, CHALLENGE_LABEL, DnsResolver, DomainName, Identity,
    role::{Principal, Role as AccessRole},
};
use kernoid_module::{Context as ModuleContext, Module, Registry};
use kernoid_oidc::{Oidc, application::Kind as AppKind};
use kernoid_server::AppState;
use kernoid_store::{BlobStore, MainKeys, TenantKeys, crypto::Key};
use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(version, about = "One core for email, identity and storage.")]
struct Cli {
    /// Configuration file (TOML); `KERNOID__…` environment variables override it.
    #[arg(short, long, env = "KERNOID_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the roles of this process until SIGINT or SIGTERM.
    Serve,
    /// Bring the database schema up to date, then exit.
    Migrate,
    /// Read the configuration, print it with secrets hidden, then exit.
    CheckConfig,
    /// Print the OpenAPI description of the REST API (JSON); needs no configuration.
    Openapi,
    /// Print the GraphQL schema (SDL); needs no configuration.
    GraphqlSchema,
    /// Tenant keys and the main key.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// Instances: identity providers with their own domains.
    #[command(subcommand)]
    Instance(InstanceCommand),
    /// Tenants: organisations within an instance, with their mail domains.
    #[command(subcommand)]
    Tenant(TenantCommand),
    /// Accounts: login, mailbox and owner of files at once.
    #[command(subcommand)]
    Account(AccountCommand),
    /// Applications: the OpenID Connect clients of a tenant.
    #[command(subcommand)]
    App(AppCommand),
    /// The keys an instance signs ID tokens with.
    #[command(subcommand)]
    SigningKey(SigningKeyCommand),
    /// kernoid's SAML keys of an instance (for SAML identity providers).
    #[command(subcommand)]
    SamlKey(SamlKeyCommand),
    /// Projects: a tenant's applications and the roles they know.
    #[command(subcommand)]
    Project(ProjectCommand),
    /// Certificates from the ACME CA (`http.acme`).
    #[command(subcommand)]
    Acme(AcmeCommand),
    /// The mail store of accounts: mailboxes and emails.
    #[command(subcommand)]
    Mail(MailCommand),
    /// Calendars and address books of accounts (RFC 0004).
    #[command(subcommand)]
    Collections(CollectionCommand),
    /// Files: drives of a tenant and who may use whose files (RFC 0005).
    #[command(subcommand)]
    Files(FilesCommand),
}

#[derive(Debug, Subcommand)]
enum FilesCommand {
    /// The drives of a tenant: file stores that belong to the tenant, not to a person.
    Drives { tenant: Uuid },
    /// Create a drive of a tenant; prints its id. People reach it through grants (`kernoid files grant`).
    AddDrive {
        tenant: Uuid,
        #[arg(long)]
        name: String,
    },
    /// Who may use an account's files or a drive.
    Access { account: Uuid },
    /// Grant rights on an account's files or a drive – a directory, or the whole store – replacing an earlier grant.
    Grant {
        account: Uuid,
        /// An address of an account of the tenant, or `$` and a group's name.
        grantee: String,
        /// Letters of `randws`: read, add, rename, delete, write content, share.
        rights: String,
        /// A directory; leave out for the whole store.
        #[arg(long)]
        node: Option<Uuid>,
    },
    /// Remove a grant.
    Revoke {
        account: Uuid,
        grantee: String,
        #[arg(long)]
        node: Option<Uuid>,
    },
}

#[derive(Debug, Subcommand)]
enum CollectionCommand {
    /// An account's calendars and address books.
    List { account: Uuid },
    /// Who may use an account's calendars and address books (RFC 0004, 9).
    Access { account: Uuid },
    /// Grant a level on a calendar or address book, replacing an earlier grant to the same grantee.
    Share {
        account: Uuid,
        collection: Uuid,
        /// An address of an account of the tenant, or `$` and a group's name.
        grantee: String,
        /// `freebusy`, `read`, `rsvp`, `write` or `admin`; address books: `read`, `write` or `admin`.
        level: String,
    },
    /// Remove a grant.
    Unshare { account: Uuid, collection: Uuid, grantee: String },
    /// Write a calendar as iCalendar or an address book as vCard to standard output.
    Export { account: Uuid, collection: Uuid },
    /// Store the events of an iCalendar file, or the contacts of a vCard file (`-` for standard input); one with a UID
    /// that is there already is replaced.
    Import { account: Uuid, collection: Uuid, file: std::path::PathBuf },
}

#[derive(Debug, Subcommand)]
enum MailCommand {
    /// An account's mailboxes with their counts.
    Mailboxes { account: Uuid },
    /// Store a message (RFC 5322, as a file, or `-` for standard input) in an account's mailbox – its inbox unless
    /// `--mailbox` names another.
    Import {
        account: Uuid,
        file: std::path::PathBuf,
        /// A mailbox id or a role (`inbox`, `archive`, …).
        #[arg(long)]
        mailbox: Option<String>,
    },
    /// Write every mailbox of an account into DIRECTORY as mbox, one file per mailbox, with the keywords.
    Export { account: Uuid, directory: std::path::PathBuf },
    /// Store the messages of an mbox file (`-` for standard input) in an account's mailbox – its inbox unless
    /// `--mailbox` names another – with their keywords.
    ImportMbox {
        account: Uuid,
        file: std::path::PathBuf,
        /// A mailbox id or a role (`inbox`, `archive`, …).
        #[arg(long)]
        mailbox: Option<String>,
    },
    /// Sieve scripts that file incoming mail.
    #[command(subcommand)]
    Sieve(SieveCommand),
    /// Who may use an account's mail (RFC 0002, 12.2).
    Access { account: Uuid },
    /// Grant access to an account's mail – the whole store, or one mailbox – replacing an earlier grant there.
    Grant {
        account: Uuid,
        /// An address of an account of the tenant, or `$` and a group's name.
        grantee: String,
        /// IMAP ACL rights (RFC 4314), letters of `lrswipkxtea`, e.g. `lrs` to read, `lrswite` to work in it.
        #[arg(long)]
        rights: String,
        /// One mailbox (its id or role) instead of the whole store.
        #[arg(long)]
        mailbox: Option<String>,
        /// The grantee may send from the account's addresses (whole store only).
        #[arg(long)]
        send_as: bool,
    },
    /// Remove a grant.
    Revoke {
        account: Uuid,
        grantee: String,
        #[arg(long)]
        mailbox: Option<String>,
    },
    /// The queue of outgoing mail: each recipient's state, newest first.
    Queue {
        #[arg(long, default_value_t = 100)]
        limit: i64,
    },
}

#[derive(Debug, Subcommand)]
enum SieveCommand {
    /// An account's scripts; `*` marks the active one.
    List {
        account: Uuid,
    },
    /// Save a script from FILE (`-` for standard input), checked first; `--activate` makes it the one that runs.
    Put {
        account: Uuid,
        name: String,
        file: std::path::PathBuf,
        #[arg(long)]
        activate: bool,
    },
    /// Make NAME the script that runs.
    Activate {
        account: Uuid,
        name: String,
    },
    /// Run no script: mail goes to the inbox.
    Deactivate {
        account: Uuid,
    },
    Remove {
        account: Uuid,
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum AcmeCommand {
    /// Every instance domain with its certificate's end, or why ordering one failed.
    Status,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Create a project in TENANT; prints its id.
    Add {
        tenant: Uuid,
        #[arg(long)]
        name: String,
    },
    List {
        tenant: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum AppCommand {
    /// Register an application in PROJECT; prints its client id and, for a confidential one, its secret – shown once.
    Add {
        project: Uuid,
        #[arg(long)]
        name: String,
        /// A browser or mobile app without a secret (PKCE only).
        #[arg(long)]
        public: bool,
        /// Exact redirect URI; repeat for several. A confidential application may have none (an API).
        #[arg(long = "redirect-uri")]
        redirect_uris: Vec<String>,
        /// Where a logout may send the browser back to; repeat for several.
        #[arg(long = "post-logout-redirect-uri")]
        post_logout_redirect_uris: Vec<String>,
    },
    List {
        tenant: Uuid,
    },
    SetPostLogoutRedirectUris {
        application: Uuid,
        #[arg(long = "post-logout-redirect-uri")]
        post_logout_redirect_uris: Vec<String>,
    },
    SetRedirectUris {
        application: Uuid,
        #[arg(long = "redirect-uri", required = true)]
        redirect_uris: Vec<String>,
    },
    /// Replace the secret of a confidential application; prints the new one.
    NewSecret {
        application: Uuid,
    },
    Deactivate {
        application: Uuid,
    },
    Reactivate {
        application: Uuid,
    },
    /// Require (or stop requiring) a second factor for logins to the application.
    RequireMfa {
        application: Uuid,
        #[arg(long, action = clap::ArgAction::Set)]
        required: bool,
    },
    /// Set the application's options; what is not given is off.
    SetOptions {
        application: Uuid,
        /// Access tokens as JWTs (RFC 9068) instead of opaque ones.
        #[arg(long)]
        jwt: bool,
        /// May ask for `offline_access` (with the person's consent).
        #[arg(long)]
        offline_access: bool,
        /// Ask the person to agree before the first login.
        #[arg(long)]
        consent_required: bool,
        #[arg(long)]
        backchannel_logout_uri: Option<String>,
        #[arg(long)]
        frontchannel_logout_uri: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum SamlKeyCommand {
    List {
        instance: Uuid,
    },
    /// Start a change: a new key, in the metadata at once, signing only once activated.
    Add {
        instance: Uuid,
    },
    /// Sign with the waiting key from now on; the key active so far leaves the metadata.
    Activate {
        instance: Uuid,
        id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum SigningKeyCommand {
    List {
        instance: Uuid,
    },
    /// Create a key: published at once, signing only once activated.
    Add {
        instance: Uuid,
    },
    /// Sign with this key from now on; the key active so far stays published, inactive.
    Activate {
        instance: Uuid,
        kid: String,
    },
    /// Remove an inactive key whose tokens have expired.
    Remove {
        instance: Uuid,
        kid: String,
    },
}

#[derive(Debug, Subcommand)]
enum AccountCommand {
    /// Create an account; ADDRESS is its login name and must be on a verified domain of the tenant.
    Add {
        tenant: Uuid,
        address: String,
        #[arg(long)]
        name: String,
    },
    /// Create an account without an address of the tenant (RFC 0003): for logins only – and files, if granted.
    AddExternal {
        tenant: Uuid,
        #[arg(long)]
        name: String,
        /// A contact address of any domain.
        #[arg(long)]
        email: Option<String>,
        /// Mark the contact address verified – it then logs in, and is unique in the instance.
        #[arg(long)]
        verified: bool,
        #[arg(long)]
        username: Option<String>,
    },
    /// Give the account a username to log in with (`none` removes it); the tenant must use usernames.
    Username {
        account: Uuid,
        username: String,
    },
    /// Set the contact address (`none` removes it).
    Contact {
        account: Uuid,
        email: String,
        #[arg(long)]
        verified: bool,
    },
    /// The account's services (`mail`, `files`) and their states.
    Services {
        account: Uuid,
    },
    /// Grant a service – also one the account requested.
    GrantService {
        account: Uuid,
        service: String,
    },
    RevokeService {
        account: Uuid,
        service: String,
    },
    /// Create a shared mailbox (`info@`, `support@`): an account nobody logs in as, used through granted access.
    AddShared {
        tenant: Uuid,
        address: String,
        #[arg(long)]
        name: String,
    },
    List {
        tenant: Uuid,
    },
    Rename {
        account: Uuid,
        name: String,
    },
    /// The language of the emails kernoid writes to the account: en, de; `none` for its tenant's.
    Language {
        account: Uuid,
        language: String,
    },
    /// Set the password, read from standard input (without echo on a terminal) – never from the command line.
    Password {
        account: Uuid,
    },
    AddAlias {
        account: Uuid,
        address: String,
    },
    RemoveAlias {
        account: Uuid,
        address: String,
    },
    /// Make an alias the login name; the former one stays as an alias.
    SetPrimary {
        account: Uuid,
        address: String,
    },
    Deactivate {
        account: Uuid,
    },
    Reactivate {
        account: Uuid,
    },
    /// Check an address and a password (read from standard input) at INSTANCE.
    CheckLogin {
        instance: Uuid,
        address: String,
    },
    /// Remove all TOTP, passkeys, recovery codes and app passwords of an account – when someone has lost their devices.
    ResetSecondFactors {
        account: Uuid,
    },
    /// App passwords for mail programs.
    #[command(subcommand)]
    AppPassword(AppPasswordCommand),
    /// How many bytes the account's emails may take; `none` for the tenant's default.
    MailQuota {
        account: Uuid,
        #[arg(value_parser = parse_quota)]
        bytes: Quota,
    },
    /// How many bytes the account's files may take; `none` for the tenant's default.
    FilesQuota {
        account: Uuid,
        #[arg(value_parser = parse_quota)]
        bytes: Quota,
    },
}

#[derive(Debug, Subcommand)]
enum AppPasswordCommand {
    /// Make an app password named NAME; it is printed this once.
    Add {
        account: Uuid,
        name: String,
    },
    List {
        account: Uuid,
    },
    Remove {
        account: Uuid,
        id: Uuid,
    },
}

#[derive(Debug, Clone, Copy)]
struct Quota(Option<u64>);

/// Days, or `none`.
#[derive(Debug, Clone, Copy)]
struct Days(Option<u32>);

fn parse_days(value: &str) -> Result<Days, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(Days(None));
    }
    value.parse().map(|days| Days(Some(days))).map_err(|_| "a number of days or `none`".to_owned())
}

fn parse_quota(value: &str) -> Result<Quota, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(Quota(None));
    }
    value.parse().map(|bytes| Quota(Some(bytes))).map_err(|_| "a number of bytes or `none`".to_owned())
}

#[derive(Debug, Subcommand)]
enum InstanceCommand {
    /// Create an instance reached under DOMAIN.
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        domain: String,
    },
    List,
    Rename {
        instance: Uuid,
        name: String,
    },
    /// The tenant where people without an address of a tenant register (RFC 0003); `none`: nowhere.
    RegistrationTenant {
        instance: Uuid,
        tenant: String,
    },
    /// Reach the instance under another domain as well.
    AddDomain {
        instance: Uuid,
        domain: String,
    },
    RemoveDomain {
        instance: Uuid,
        domain: String,
    },
    /// The domain links and the issuer use.
    SetPrimary {
        instance: Uuid,
        domain: String,
    },
    /// Send logins to a login UI of the instance's own (an HTTPS URL); without URL, back to kernoid's.
    SetLoginUi {
        instance: Uuid,
        url: Option<String>,
    },
    /// Bind passkeys to another RP ID (a domain of the instance or a parent of one); passkeys under the former stop
    /// working.
    SetPasskeyRpId {
        instance: Uuid,
        rp_id: String,
    },
    /// Define an instance role of the instance's own: instance permissions apply at the instance, tenant permissions
    /// in every tenant.
    DefineRole {
        instance: Uuid,
        role: String,
        #[arg(long = "permission", required = true)]
        permissions: Vec<String>,
    },
    DeleteRole {
        instance: Uuid,
        role: String,
    },
    /// Assign an instance role to an account or group of a tenant of INSTANCE – e.g. the first `instance_admin`.
    Grant {
        instance: Uuid,
        #[command(flatten)]
        principal: PrincipalArgs,
        /// instance_admin, instance_auditor or one of the instance's own.
        #[arg(long)]
        role: String,
    },
    /// Take an instance role back; the last `instance_admin` assignment stays.
    Revoke {
        instance: Uuid,
        #[command(flatten)]
        principal: PrincipalArgs,
        #[arg(long)]
        role: String,
    },
    /// List who holds which instance role.
    Roles {
        instance: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum TenantCommand {
    /// Create a tenant in INSTANCE.
    Add {
        instance: Uuid,
        #[arg(long)]
        name: String,
    },
    List {
        instance: Uuid,
    },
    Rename {
        tenant: Uuid,
        name: String,
    },
    Deactivate {
        tenant: Uuid,
    },
    Reactivate {
        tenant: Uuid,
    },
    /// Claim a mail domain; prints the DNS record that proves it.
    AddDomain {
        tenant: Uuid,
        domain: String,
    },
    /// Look up the DNS record and mark the domain verified.
    VerifyDomain {
        tenant: Uuid,
        domain: String,
        /// Mark it verified without asking DNS – for internal domains or domains checked otherwise.
        #[arg(long)]
        trust: bool,
    },
    RemoveDomain {
        tenant: Uuid,
        domain: String,
    },
    /// The mail quota of every account without its own, in bytes; `none` for no limit.
    MailQuota {
        tenant: Uuid,
        #[arg(value_parser = parse_quota)]
        bytes: Quota,
    },
    /// The files quota of every account without its own, in bytes; `none` for no limit.
    FilesQuota {
        tenant: Uuid,
        #[arg(value_parser = parse_quota)]
        bytes: Quota,
    },
    /// How the tenant's accounts log in: with usernames, with their verified contact address.
    LoginPolicy {
        tenant: Uuid,
        #[arg(long, action = clap::ArgAction::Set)]
        usernames: bool,
        #[arg(long, action = clap::ArgAction::Set)]
        email_login: bool,
    },
    /// Whether people may register with the tenant, and on which of its domains they may take an address.
    Registration {
        tenant: Uuid,
        #[arg(long, action = clap::ArgAction::Set)]
        allowed: bool,
        #[arg(long = "domain")]
        domains: Vec<String>,
    },
    /// Who gets a service (`mail`, `files`) when an account is created – `none`, `native` or `all` – and whether it
    /// waits for approval.
    ServicePolicy {
        tenant: Uuid,
        service: String,
        #[arg(long)]
        assign: String,
        #[arg(long)]
        approval: bool,
    },
    /// How many days emails stay in the accounts' Trash and Junk; `none` keeps them.
    MailRetention {
        tenant: Uuid,
        #[arg(long, value_parser = parse_days)]
        trash_days: Days,
        #[arg(long, value_parser = parse_days)]
        junk_days: Days,
    },
    /// How many days what is in the accounts' file trash stays; `none` keeps it.
    FilesRetention {
        tenant: Uuid,
        #[arg(long, value_parser = parse_days)]
        trash_days: Days,
    },
    /// The language of the emails kernoid writes to accounts that chose none: en, de; `none` for English.
    Language {
        tenant: Uuid,
        language: String,
    },
    /// What the tenant's accounts may encrypt end to end (RFC 0006, 8): each allowed, required or forbidden.
    E2ePolicy {
        tenant: Uuid,
        #[arg(long, default_value = "allowed")]
        mail: String,
        #[arg(long, default_value = "allowed")]
        vaults: String,
        #[arg(long, default_value = "allowed")]
        collections: String,
        /// Every account's secret key recoverable with the tenant's recovery key (set it first).
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        recovery: bool,
    },
    /// Set the tenant's recovery key: an OpenPGP public key (armored or binary) on standard input; its secret key
    /// stays with the administrators.
    RecoveryKey {
        tenant: Uuid,
    },
    /// Switch a module on or off for the tenant.
    Module {
        tenant: Uuid,
        module: String,
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Require (or stop requiring) a second factor for logins to applications by the tenant's accounts.
    RequireMfa {
        tenant: Uuid,
        #[arg(long, action = clap::ArgAction::Set)]
        required: bool,
    },
    /// Let accounts without a second factor log in without one for DAYS after the requirement (or the account)
    /// began.
    MfaGrace {
        tenant: Uuid,
        days: u32,
    },
    /// Assign a role to an account or group of the tenant – e.g. the first `tenant_admin`.
    Grant {
        tenant: Uuid,
        #[command(flatten)]
        principal: PrincipalArgs,
        /// tenant_admin, user_manager, application_manager or auditor.
        #[arg(long)]
        role: String,
    },
    /// Take a role back; the last `tenant_admin` assignment stays.
    Revoke {
        tenant: Uuid,
        #[command(flatten)]
        principal: PrincipalArgs,
        #[arg(long)]
        role: String,
    },
    /// List who holds which role.
    Roles {
        tenant: Uuid,
    },
    /// The DNS records the tenant's mail domains need (MX, SPF, DKIM, DMARC) and whether they are published.
    MailDns {
        tenant: Uuid,
    },
    /// Starts a change of a mail domain's DKIM key: a new key, signing once DNS shows its record.
    DkimRotate {
        tenant: Uuid,
        #[arg(long)]
        domain: String,
        /// `rsa` or `ed25519`.
        #[arg(long, default_value = "rsa")]
        algorithm: String,
    },
}

/// Who holds a role: exactly one of `--account` and `--group`.
#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
struct PrincipalArgs {
    #[arg(long)]
    account: Option<Uuid>,
    #[arg(long)]
    group: Option<Uuid>,
}

impl PrincipalArgs {
    fn principal(&self) -> Principal {
        match (self.account, self.group) {
            (Some(account), _) => Principal::Account(account),
            (None, Some(group)) => Principal::Group(group),
            (None, None) => unreachable!("clap requires one"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Count the tenant keys by the main key that wraps them.
    Status,
    /// Add a tenant's next key; new content is encrypted with it, older content stays readable.
    Rotate {
        /// The tenant's id.
        tenant: uuid::Uuid,
    },
    /// Wrap every tenant key with the current main key (after changing it); runs as the owner (database.migrate_url).
    Rewrap,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Openapi => {
            println!("{}", kernoid_server::openapi().to_pretty_json()?);
            return Ok(());
        }
        Command::GraphqlSchema => {
            print!("{}", kernoid_server::graphql_schema());
            return Ok(());
        }
        _ => {}
    }
    let config = Config::load(cli.config.as_deref()).context("loading the configuration")?;
    let traces = init_logging(&config)?;
    let result = match cli.command {
        Command::Serve => serve(config).await,
        Command::Migrate => {
            let separated = kernoid_store::migrate(&config.database).await.context("migrating the database")?;
            if !separated {
                tracing::warn!("database.url and database.migrate_url use the same role: kernoid can change events");
            }
            tracing::info!("database schema is up to date");
            Ok(())
        }
        Command::CheckConfig => {
            println!("{config:#?}");
            Ok(())
        }
        Command::Keys(command) => keys(&config, command).await,
        Command::Instance(command) => instance(&config, command).await,
        Command::Tenant(command) => tenant(&config, command).await,
        Command::Account(command) => account(&config, command).await,
        Command::App(command) => app(&config, command).await,
        Command::SigningKey(command) => signing_key(&config, command).await,
        Command::SamlKey(command) => saml_key(&config, command).await,
        Command::Project(command) => project(&config, command).await,
        Command::Acme(AcmeCommand::Status) => acme_status(&config).await,
        Command::Mail(command) => mail(&config, command).await,
        Command::Collections(command) => collections(&config, command).await,
        Command::Files(command) => files(&config, command).await,
        Command::Openapi | Command::GraphqlSchema => unreachable!("handled before the configuration"),
    };
    if let Some(traces) = traces {
        let _ = traces.shutdown();
    }
    result
}

/// The modules compiled into kernoid; each is off unless `[modules.<name>] enabled = true`.
const MODULES: &[&dyn Module] = &[&kernoid_clamav::ClamAvModule, &kernoid_jitsi::JitsiModule];

async fn serve(config: Config) -> anyhow::Result<()> {
    let modules = Registry::new(MODULES, &config.modules).context("modules")?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        roles = ?config.roles,
        modules = ?modules.names().collect::<Vec<_>>(),
        "starting"
    );
    let main_keys = main_keys(&config)?;
    let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
    // Checked at the start, so that a wrong ACME configuration stops the process instead of failing later.
    let orderer = match &config.http.acme {
        Some(acme) => Some(kernoid_server::acme::Orderer::new(db.clone(), main_keys.clone(), acme.clone())?),
        None => None,
    };
    let keys = Arc::new(TenantKeys::with_main_keys(db.clone(), main_keys.clone()));
    let mut blobs = BlobStore::from_config(&config.blob, keys.clone()).context("setting up object storage")?;
    // Content of tenants that switched the module on is scanned as it is stored, mail before it is accepted.
    if let Some(table) = modules.config(kernoid_clamav::NAME) {
        blobs = blobs.with_scanner(kernoid_clamav::ClamAvModule::scanner(table).map_err(anyhow::Error::msg)?);
    }
    let events = EventStore::new(db.clone());
    let oidc = Oidc::new(events.clone(), main_keys.clone(), config.http.public_scheme.as_str())
        .public_port(config.http.public_port)
        .allow_private_networks(config.outbound.allow_private_networks);
    // Tenants switch on for themselves what the installation switched on.
    let known: Vec<&'static str> = modules.names().collect();
    let mut state = AppState::new(
        db.clone(),
        blobs.clone(),
        Identity::with_secrets(events.clone(), main_keys.clone()),
        oidc.clone(),
    )
    .with_modules(&known);
    match DnsResolver::from_system() {
        Ok(dns) => state = state.with_dns(dns),
        Err(error) => tracing::warn!(%error, "no DNS resolver; tenants cannot verify domains themselves"),
    }
    if let Some(checker) = mail_dns_checker(&config).await? {
        state = state.with_mail_dns(checker);
    }
    // Changes of mail stores, from PostgreSQL – for JMAP's push and IMAP's IDLE.
    let mail_events = kernoid_mail::MailEvents::default();
    let queue_days = config.smtp.as_ref().map_or(5, |smtp| smtp.queue_days);
    state = state.with_jmap(
        kernoid_jmap::Jmap::new(
            mail_store(db.clone(), blobs.clone(), &config),
            config.mail.max_message_size.max(config.files.max_file_size),
            chrono::Duration::days(i64::from(queue_days)),
        )
        .with_groupware(kernoid_groupware::Groupware::new(mail_store(db.clone(), blobs.clone(), &config), keys.clone()))
        .with_files(file_store(db.clone(), blobs.clone(), &config))
        .with_identity(Identity::new(events.clone()))
        .with_key_directory(std::sync::Arc::new(kernoid_server::wkd::Lookup::new())),
        mail_events.clone(),
    );
    // Calendars and contacts (RFC 0004) over CalDAV and CardDAV.
    state = state.with_dav(kernoid_dav::Dav::new(kernoid_groupware::Groupware::new(
        mail_store(db.clone(), blobs.clone(), &config),
        keys.clone(),
    )));
    if let Some(from) = &config.mail.notification_from {
        state = state.with_notifications(from.clone());
    }
    if let Some(smtp) = &config.smtp {
        state = state.with_mail_host(smtp.hostname.clone(), config.imap.is_some());
    }
    let sessions: Arc<dyn kernoid_module::Sessions> = Arc::new(kernoid_server::ModuleSessions::new(state.clone()));
    let context = |config| ModuleContext {
        db: db.clone(),
        events: events.clone(),
        blobs: blobs.clone(),
        sessions: Some(sessions.clone()),
        config,
    };

    // One shutdown for every task: on SIGINT/SIGTERM, or as soon as one task fails.
    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            shutdown_signal().await;
            shutdown.cancel();
        }
    });
    let mut tasks = tokio::task::JoinSet::new();
    let receives_mail = config.has_role(Role::Smtp) && config.smtp.is_some();
    let serves_clients = config.has_role(Role::Imap) && config.imap.is_some();
    let serves_directory = config.has_role(Role::Ldap) && config.ldap.is_some();
    // Certificates from ACME serve HTTPS and STARTTLS alike.
    let certificates = match &config.http.acme {
        Some(_) if config.has_role(Role::Api) || receives_mail || serves_clients || serves_directory => {
            let fallback = match &config.http.tls {
                Some(tls) => Some(Arc::new(kernoid_server::acme::static_certificate(&tls.certificate, &tls.key)?)),
                None => None,
            };
            let certificates =
                Arc::new(kernoid_server::acme::Certificates::new(db.clone(), main_keys.clone(), fallback));
            certificates.refresh().await.context("loading certificates")?;
            tasks.spawn({
                let certificates = certificates.clone();
                let stop = shutdown.clone().cancelled_owned();
                async move {
                    certificates.keep_fresh(stop).await;
                    Ok(())
                }
            });
            Some(certificates)
        }
        _ => None,
    };
    // JMAP's push stream and IMAP's IDLE hear of changes through one connection per process.
    // Certificates of the mail protocols from files (`mail.tls`, e.g. Caddy's), read again when they change.
    let mail_certificates = match &config.mail.tls {
        Some(tls) if receives_mail || serves_clients || serves_directory => {
            let files = Arc::new(
                kernoid_server::certificate_files::FileCertificates::load(&tls.certificate, &tls.key)
                    .context("reading mail.tls")?,
            );
            tasks.spawn({
                let (files, stop) = (files.clone(), shutdown.clone().cancelled_owned());
                async move {
                    files.keep_fresh(stop).await;
                    Ok(())
                }
            });
            Some(files)
        }
        _ => None,
    };
    if config.has_role(Role::Api) || serves_clients {
        tasks.spawn({
            let (events, db, stop) = (mail_events.clone(), db.clone(), shutdown.clone());
            async move {
                events.listen(db, stop).await;
                Ok(())
            }
        });
    }
    if config.has_role(Role::Api) {
        let router = kernoid_server::router(state, modules.routes(context), &config.http);
        let stop = shutdown.clone().cancelled_owned();
        let http = config.http.clone();
        if let Some(acme) = &config.http.acme {
            // The CA's HTTP-01 requests, and HTTP to HTTPS for everyone else.
            let challenges = kernoid_server::acme::http_router(db.clone(), Identity::new(events.clone()));
            let plain = Http { listen: acme.http_listen, tls: None, acme: None, ..Http::default() };
            let stop = shutdown.clone().cancelled_owned();
            tasks.spawn(async move { kernoid_server::serve(&plain, challenges, stop).await.context("acme http") });
        }
        let certificates = certificates.clone();
        tasks.spawn(async move {
            kernoid_server::serve_with(&http, router, stop, certificates).await.context("http server")
        });
    }
    if config.has_role(Role::Smtp) {
        match &config.smtp {
            Some(smtp) => {
                let tls = kernoid_server::mail_tls(&config.http, certificates.clone(), mail_certificates.clone())
                    .context("TLS for SMTP")?;
                if tls.is_none() {
                    tracing::warn!("no certificates (http.tls or http.acme): SMTP without STARTTLS");
                }
                let dns = kernoid_smtp::Dns::from_system().map_err(|error| anyhow::anyhow!("DNS for SMTP: {error}"))?;
                let server = kernoid_smtp::Server::new(
                    kernoid_smtp::Settings::from_config(smtp, &config.mail),
                    mail_store(db.clone(), blobs.clone(), &config),
                    dns,
                    tls.clone(),
                )
                .with_groupware(kernoid_groupware::Groupware::new(
                    mail_store(db.clone(), blobs.clone(), &config),
                    keys.clone(),
                ));
                let listener = tokio::net::TcpListener::bind(smtp.listen)
                    .await
                    .with_context(|| format!("listening for SMTP on {}", smtp.listen))?;
                tracing::info!(address = %smtp.listen, hostname = %smtp.hostname, "smtp listening");
                let max_connections = smtp.max_connections;
                let stop = shutdown.clone();
                tasks.spawn(async move {
                    server.serve(listener, max_connections, stop).await;
                    Ok(())
                });
                // Submission: only over TLS, so only with certificates (RFC 0002, 10.1).
                if let Some(tls) = &tls {
                    for (listen, implicit_tls) in [(smtp.submission_listen, false), (smtp.submissions_listen, true)] {
                        let dns = kernoid_smtp::Dns::from_system()
                            .map_err(|error| anyhow::anyhow!("DNS for SMTP: {error}"))?;
                        let submission = kernoid_smtp::Submission {
                            identity: Identity::with_secrets(events.clone(), main_keys.clone()),
                            implicit_tls,
                            queue_lifetime: chrono::Duration::days(i64::from(smtp.queue_days)),
                        };
                        let server = kernoid_smtp::Server::submission(
                            kernoid_smtp::Settings::from_config(smtp, &config.mail),
                            mail_store(db.clone(), blobs.clone(), &config),
                            dns,
                            tls.clone(),
                            submission,
                        )
                        .with_groupware(kernoid_groupware::Groupware::new(
                            mail_store(db.clone(), blobs.clone(), &config),
                            keys.clone(),
                        ));
                        let listener = tokio::net::TcpListener::bind(listen)
                            .await
                            .with_context(|| format!("listening for submission on {listen}"))?;
                        tracing::info!(address = %listen, implicit_tls, "submission listening");
                        let stop = shutdown.clone();
                        tasks.spawn(async move {
                            server.serve(listener, max_connections, stop).await;
                            Ok(())
                        });
                    }
                }
            }
            None => tracing::info!("no [smtp] in the configuration: not receiving mail"),
        }
    }
    if config.has_role(Role::Imap) {
        match &config.imap {
            Some(imap) => match kernoid_server::mail_tls(&config.http, certificates.clone(), mail_certificates.clone())
                .context("TLS for IMAP")?
            {
                Some(tls) => {
                    let listeners = [
                        (Some(imap.listen), kernoid_imap::Protocol::Imap, false),
                        (Some(imap.tls_listen), kernoid_imap::Protocol::Imap, true),
                        (imap.pop3_listen, kernoid_imap::Protocol::Pop3, false),
                        (imap.pop3_tls_listen, kernoid_imap::Protocol::Pop3, true),
                    ];
                    for (listen, protocol, implicit_tls) in listeners {
                        let Some(listen) = listen else { continue };
                        let server = kernoid_imap::Server::new(
                            kernoid_imap::Settings::from_config(imap, &config.mail),
                            mail_store(db.clone(), blobs.clone(), &config),
                            Identity::with_secrets(events.clone(), main_keys.clone()),
                            mail_events.clone(),
                            tls.clone(),
                            implicit_tls,
                        );
                        let listener = tokio::net::TcpListener::bind(listen)
                            .await
                            .with_context(|| format!("listening for {protocol:?} on {listen}"))?;
                        tracing::info!(address = %listen, ?protocol, implicit_tls, "mail clients listening");
                        let (max_connections, stop) = (imap.max_connections, shutdown.clone());
                        tasks.spawn(async move {
                            server.serve(protocol, listener, max_connections, stop).await;
                            Ok(())
                        });
                    }
                }
                None => tracing::warn!("no certificates (http.tls or http.acme): no IMAP, since logging in needs TLS"),
            },
            None => tracing::info!("no [imap] in the configuration: not serving mail clients"),
        }
    }
    if config.has_role(Role::Ldap) {
        match &config.ldap {
            Some(ldap) => match kernoid_server::mail_tls(&config.http, certificates.clone(), mail_certificates.clone())
                .context("TLS for LDAP")?
            {
                Some(tls) => {
                    for (listen, implicit_tls) in [(ldap.listen, false), (ldap.tls_listen, true)] {
                        let server = kernoid_ldap::Server::new(
                            kernoid_ldap::Settings::from_config(ldap),
                            Identity::with_secrets(events.clone(), main_keys.clone()),
                            tls.clone(),
                            implicit_tls,
                        );
                        let listener = tokio::net::TcpListener::bind(listen)
                            .await
                            .with_context(|| format!("listening for LDAP on {listen}"))?;
                        tracing::info!(address = %listen, implicit_tls, "directory listening");
                        let (max_connections, stop) = (ldap.max_connections, shutdown.clone());
                        tasks.spawn(async move {
                            server.serve(listener, max_connections, stop).await;
                            Ok(())
                        });
                    }
                }
                None => tracing::warn!("no certificates (http.tls or http.acme): no LDAP, since binding needs TLS"),
            },
            None => tracing::info!("no [ldap] in the configuration: not serving the directory"),
        }
    }
    if let Some(listen) = config.http.metrics_listen {
        let handle = PrometheusBuilder::new().install_recorder().context("metrics")?;
        let metrics = Http { listen, ..Http::default() };
        let stop = shutdown.clone().cancelled_owned();
        tasks.spawn(async move {
            kernoid_server::serve(&metrics, kernoid_server::metrics::router(handle), stop).await.context("metrics")
        });
    }
    if config.has_role(Role::Worker) {
        tasks.spawn(clean_up(Identity::new(events.clone()), oidc.clone(), shutdown.clone()));
        tasks.spawn(logout_notifications(oidc.clone(), shutdown.clone()));
        if config.oidc.key_rotation_days > 0 {
            tasks.spawn(rotate_keys(oidc.clone(), db.clone(), config.oidc.clone(), shutdown.clone()));
        }
        if let Some(orderer) = orderer {
            tasks.spawn(order_certificates(orderer, shutdown.clone()));
        }
        match &config.smtp {
            Some(smtp) => {
                let lookups =
                    kernoid_smtp::Dns::from_system().map_err(|error| anyhow::anyhow!("DNS for DKIM: {error}"))?;
                tasks.spawn(dkim_keys(db.clone(), main_keys.clone(), lookups, shutdown.clone()));
                let dns =
                    kernoid_smtp::Dns::from_system().map_err(|error| anyhow::anyhow!("DNS for sending: {error}"))?;
                let outbound = kernoid_smtp::outbound::Outbound::new(
                    kernoid_smtp::outbound::OutboundSettings::from_config(smtp, &config.outbound),
                    mail_store(db.clone(), blobs.clone(), &config),
                    dns,
                    Some(main_keys.clone()),
                );
                let stop = shutdown.clone();
                tasks.spawn(async move {
                    outbound.run(stop).await;
                    Ok(())
                });
            }
            None => tracing::info!("no [smtp] in the configuration: not sending mail"),
        }
        tasks.spawn(held_submissions(mail_store(db.clone(), blobs.clone(), &config), shutdown.clone()));
        tasks.spawn(link_notices(
            Identity::new(events.clone()),
            mail_store(db.clone(), blobs.clone(), &config),
            config.smtp.as_ref().map(|smtp| smtp.hostname.clone()),
            shutdown.clone(),
        ));
        tasks.spawn(mail_housekeeping(
            mail_store(db.clone(), blobs.clone(), &config),
            file_store(db.clone(), blobs.clone(), &config),
            blobs.clone(),
            config.mail.changes_kept_days,
            shutdown.clone(),
        ));
        for (module, job) in modules.jobs(context) {
            let stop = shutdown.child_token();
            tasks.spawn(async move { job(stop).await.map_err(|error| anyhow::anyhow!("module {module}: {error}")) });
        }
    }
    let mut failure = None;
    while let Some(result) = tasks.join_next().await {
        let result = result.context("task panicked").and_then(|result| result);
        if let Err(error) = result {
            tracing::error!(error = format!("{error:#}"), "stopping");
            shutdown.cancel();
            failure.get_or_insert(error);
        }
    }
    db.close().await;
    tracing::info!("stopped");
    failure.map_or(Ok(()), Err)
}

fn main_keys(config: &Config) -> anyhow::Result<MainKeys> {
    let current = Key::from_hex(config.encryption.main_key.expose()).context("encryption.main_key")?;
    let previous = config
        .encryption
        .previous_main_keys
        .iter()
        .enumerate()
        .map(|(i, key)| Key::from_hex(key.expose()).with_context(|| format!("encryption.previous_main_keys[{i}]")));
    Ok(MainKeys::new(current, previous.collect::<anyhow::Result<_>>()?))
}

async fn keys(config: &Config, command: KeysCommand) -> anyhow::Result<()> {
    let main_keys = main_keys(config)?;
    match command {
        KeysCommand::Status => {
            let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
            let status = kernoid_store::wrap_status(&db, &main_keys).await?;
            println!("tenant keys wrapped with the current main key: {}", status.current);
            println!("                      with a previous main key: {}", status.previous);
            println!("                          with an unknown key: {}", status.unknown);
        }
        KeysCommand::Rotate { tenant } => {
            let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
            let number = TenantKeys::with_main_keys(db, main_keys).rotate(tenant).await?;
            println!("tenant {tenant}: key {number} is current");
        }
        KeysCommand::Rewrap => {
            let owner = kernoid_store::connect_owner(&config.database).await.context("connecting as the owner")?;
            let count = kernoid_store::rewrap(&owner, &main_keys).await?;
            println!("rewrapped {count} tenant keys with the current main key");
            let oidc = Oidc::new(EventStore::new(owner), main_keys, config.http.public_scheme.as_str())
                .public_port(config.http.public_port);
            println!("sealed {} signing keys again with the current main key", oidc.rewrap_signing_keys().await?);
        }
    }
    Ok(())
}

/// Logs to stdout as text or JSON; with `log.otlp_endpoint`, traces also go to an OpenTelemetry collector. The
/// returned provider must be shut down at exit, so that the last traces are sent.
/// How often the worker removes old sessions and failure counts.
const CLEAN_UP_EVERY: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Removes ended and expired sessions and old failure counts until shutdown; with several workers, each does it –
/// the deletes do not get in each other's way.
async fn clean_up(identity: Identity, oidc: Oidc, shutdown: CancellationToken) -> anyhow::Result<()> {
    loop {
        if let Err(error) = identity.prune_registrations().await {
            tracing::warn!(%error, "removing expired registrations failed; trying again later");
        }
        if let Err(error) = identity.clean_up_file_link_access().await {
            tracing::warn!(%error, "removing expired link access failed; trying again later");
        }
        match identity.clean_up().await {
            Ok(cleaned) if cleaned.sessions > 0 || cleaned.failure_counts > 0 => {
                tracing::info!(sessions = cleaned.sessions, failure_counts = cleaned.failure_counts, "cleaned up");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "clean-up failed; trying again later"),
        }
        match oidc.clean_up().await {
            Ok(cleaned)
                if cleaned.auth_requests
                    + cleaned.codes
                    + cleaned.access_tokens
                    + cleaned.refresh_tokens
                    + cleaned.idp_logins
                    + cleaned.logout_notifications
                    > 0 =>
            {
                tracing::info!(
                    auth_requests = cleaned.auth_requests,
                    idp_logins = cleaned.idp_logins,
                    codes = cleaned.codes,
                    access_tokens = cleaned.access_tokens,
                    refresh_tokens = cleaned.refresh_tokens,
                    logout_notifications = cleaned.logout_notifications,
                    "cleaned up"
                )
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "clean-up failed; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(CLEAN_UP_EVERY) => {}
        }
    }
}

/// How often the worker looks for ended sessions to tell applications about.
const LOGOUT_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// Back-channel logout: queues and delivers logout tokens until shutdown; several workers share the work.
async fn logout_notifications(oidc: Oidc, shutdown: CancellationToken) -> anyhow::Result<()> {
    loop {
        match oidc.deliver_logout_notifications().await {
            Ok(done) if done.delivered + done.failed > 0 => {
                tracing::info!(delivered = done.delivered, failed = done.failed, "back-channel logout");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "back-channel logout failed; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(LOGOUT_EVERY) => {}
        }
    }
}

/// How often the worker checks whether signing keys are due for rotation.
const ROTATE_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

async fn rotate_keys(
    oidc: Oidc,
    db: kernoid_store::PgPool,
    config: kernoid_config::Oidc,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let day = std::time::Duration::from_secs(24 * 60 * 60);
    let rotation = day * config.key_rotation_days;
    let publish = std::time::Duration::from_secs(60 * 60) * config.key_publish_hours;
    let keep = day * config.retired_key_days;
    loop {
        // Several workers: one rotates, the others skip this round.
        match kernoid_store::lock::Lock::try_take(&db, "signing key rotation").await {
            Ok(Some(lock)) => {
                match oidc.rotate_signing_keys(rotation, publish, keep).await {
                    Ok(done) if done.added + done.activated + done.removed > 0 => {
                        tracing::info!(
                            added = done.added,
                            activated = done.activated,
                            removed = done.removed,
                            "signing keys"
                        );
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "key rotation failed; trying again later"),
                }
                if let Err(error) = lock.release().await {
                    tracing::warn!(%error, "releasing the key rotation lock");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "key rotation lock unavailable; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(ROTATE_EVERY) => {}
        }
    }
}

/// How often the worker looks for verified domains without DKIM keys and for published records of waiting keys.
const DKIM_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

async fn dkim_keys(
    db: kernoid_store::PgPool,
    main_keys: MainKeys,
    dns: kernoid_smtp::Dns,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        // Several workers may make a key for the same domain at once; the first one stays (ON CONFLICT).
        match kernoid_smtp::dkim::ensure_keys(&db, &main_keys).await {
            Ok(0) => {}
            Ok(made) => tracing::info!(made, "DKIM keys"),
            Err(error) => tracing::warn!(%error, "making DKIM keys failed; trying again later"),
        }
        match kernoid_smtp::dkim::activate_published(&db, &dns).await {
            Ok(0) => {}
            Ok(activated) => tracing::info!(activated, "DKIM keys signing now"),
            Err(error) => tracing::warn!(%error, "activating DKIM keys failed; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(DKIM_EVERY) => {}
        }
    }
}

/// How often the worker removes due objects and old journal rows of the mail store.
const MAIL_HOUSEKEEPING_EVERY: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// Rows handled per round trip; a round repeats while there is more.
const HOUSEKEEPING_BATCH: i64 = 1000;

fn mail_store(db: kernoid_store::PgPool, blobs: BlobStore, config: &Config) -> kernoid_mail::Mail {
    let queue_days = config.smtp.as_ref().map_or(5, |smtp| smtp.queue_days);
    let limits = kernoid_mail::Limits {
        max_message_size: config.mail.max_message_size,
        queue_lifetime: chrono::Duration::days(i64::from(queue_days)),
    };
    kernoid_mail::Mail::new(db, blobs, limits)
}

fn file_store(db: kernoid_store::PgPool, blobs: BlobStore, config: &Config) -> kernoid_files::Files {
    let limits =
        kernoid_files::Limits { max_file_size: config.files.max_file_size, versions_kept: config.files.versions_kept };
    kernoid_files::Files::new(db, blobs, limits)
}

/// Sends what was held to be taken back (RFC 8621, 7; `kernoid_mail::Mail::release_held`) once its time has come –
/// checked every two seconds, so an email goes out at most that late. With several workers, each takes what the others
/// have not.
async fn held_submissions(mail: kernoid_mail::Mail, shutdown: CancellationToken) -> anyhow::Result<()> {
    loop {
        match mail.release_held(50).await {
            Ok(0) => {}
            Ok(sent) => tracing::info!(sent, "held emails sent"),
            Err(error) => tracing::warn!(%error, "sending held emails failed; trying again shortly"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
        }
    }
}

/// Tells the makers of links what came in through them (`kernoid_server::file_links`), every minute. With several
/// workers, each does it – what one takes, the others do not see.
async fn link_notices(
    identity: Identity,
    mail: kernoid_mail::Mail,
    hostname: Option<String>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        match kernoid_server::file_links::notify_arrivals(
            &identity,
            &mail,
            hostname.as_deref(),
            kernoid_server::file_links::NOTICE_AFTER_QUIET,
        )
        .await
        {
            Ok(0) => {}
            Ok(sent) => tracing::info!(sent, "notices of files added through links"),
            Err(error) => tracing::warn!(%error, "notices of files added through links failed; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
        }
    }
}

async fn mail_housekeeping(
    mail: kernoid_mail::Mail,
    files: kernoid_files::Files,
    blobs: BlobStore,
    changes_kept_days: u32,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        // Several workers: one does it, the others skip this round.
        match kernoid_store::lock::Lock::try_take(mail.pool(), "mail housekeeping").await {
            Ok(Some(lock)) => {
                let mut collected = 0;
                loop {
                    match kernoid_store::garbage::collect(mail.pool(), &blobs, HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            collected += done;
                            if (done as i64) < HOUSEKEEPING_BATCH || shutdown.is_cancelled() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "removing objects failed; trying again later");
                            break;
                        }
                    }
                }
                let before = chrono::Utc::now() - chrono::Duration::days(i64::from(changes_kept_days));
                let mut pruned = 0;
                loop {
                    match mail.prune_changes(before, HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            pruned += done;
                            if (done as i64) < HOUSEKEEPING_BATCH || shutdown.is_cancelled() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "pruning the mail journal failed; trying again later");
                            break;
                        }
                    }
                }
                // The journal of calendars and contacts (RFC 0004, 2) ages out with the mail journal.
                loop {
                    match kernoid_groupware::prune_changes(mail.pool(), before, HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            pruned += done;
                            if (done as i64) < HOUSEKEEPING_BATCH || shutdown.is_cancelled() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "pruning the calendar and contacts journal failed; trying again later");
                            break;
                        }
                    }
                }
                // The journal of files (RFC 0005, 6) as well.
                loop {
                    match kernoid_files::prune_changes(mail.pool(), before, HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            pruned += done;
                            if (done as i64) < HOUSEKEEPING_BATCH || shutdown.is_cancelled() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "pruning the files journal failed; trying again later");
                            break;
                        }
                    }
                }
                // Notifications of scheduling go after 30 days (RFC 0004, 6).
                if let Err(error) = kernoid_groupware::prune_notifications(mail.pool(), HOUSEKEEPING_BATCH).await {
                    tracing::warn!(%error, "removing old calendar notifications failed; trying again later");
                }
                if let Err(error) = mail.prune_uploads().await {
                    tracing::warn!(%error, "removing expired uploads failed; trying again later");
                }
                // Retention (RFC 0002, 13.2): Trash and Junk emptied after the tenants' days.
                let mut expired = 0;
                loop {
                    match mail.apply_retention(HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            expired += done;
                            if (done as i64) < HOUSEKEEPING_BATCH || shutdown.is_cancelled() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "applying mail retention failed; trying again later");
                            break;
                        }
                    }
                }
                // Mail stored before its account switched encryption on (RFC 0006, 5.2), a few minutes per round.
                let encrypting_until = std::time::Instant::now() + std::time::Duration::from_secs(300);
                let mut encrypted = 0;
                loop {
                    match mail.encrypt_stored(HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            encrypted += done;
                            let more = done as i64 == HOUSEKEEPING_BATCH;
                            if !more || shutdown.is_cancelled() || std::time::Instant::now() > encrypting_until {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "encrypting stored mail failed; trying again later");
                            break;
                        }
                    }
                }
                if encrypted > 0 {
                    tracing::info!(encrypted, "stored mail encrypted to its accounts' keys");
                }
                // The search index of emails stored before it (RFC 0002, 13.1), a few minutes per round at most.
                let indexing_until = std::time::Instant::now() + std::time::Duration::from_secs(300);
                let mut indexed = 0;
                loop {
                    match mail.index_pending(HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            indexed += done;
                            let more = done as i64 == HOUSEKEEPING_BATCH;
                            if !more || shutdown.is_cancelled() || std::time::Instant::now() > indexing_until {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "indexing mail for search failed; trying again later");
                            break;
                        }
                    }
                }
                if expired + indexed > 0 {
                    tracing::info!(expired, indexed, "mail retention and search index");
                }
                // Files (RFC 0005, 4 and 8): trashes emptied after the tenants' days, and the text of contents indexed.
                let (mut emptied, mut files_indexed) = (0, 0);
                loop {
                    match files.apply_trash_retention(HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            emptied += done;
                            if (done as i64) < HOUSEKEEPING_BATCH || shutdown.is_cancelled() {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "emptying file trashes failed; trying again later");
                            break;
                        }
                    }
                }
                let indexing_until = std::time::Instant::now() + std::time::Duration::from_secs(300);
                loop {
                    match files.index_pending(HOUSEKEEPING_BATCH).await {
                        Ok(done) => {
                            files_indexed += done;
                            let more = done as i64 == HOUSEKEEPING_BATCH;
                            if !more || shutdown.is_cancelled() || std::time::Instant::now() > indexing_until {
                                break;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "indexing files for search failed; trying again later");
                            break;
                        }
                    }
                }
                if emptied + files_indexed > 0 {
                    tracing::info!(emptied, indexed = files_indexed, "file trashes and search index");
                }
                if collected + pruned as usize > 0 {
                    tracing::info!(objects = collected, journal_rows = pruned, "mail housekeeping");
                }
                if let Err(error) = lock.release().await {
                    tracing::warn!(%error, "releasing the mail housekeeping lock");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "mail housekeeping lock unavailable; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(MAIL_HOUSEKEEPING_EVERY) => {}
        }
    }
}

async fn files(config: &Config, command: FilesCommand) -> anyhow::Result<()> {
    let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
    let keys = Arc::new(TenantKeys::with_main_keys(db.clone(), main_keys(config)?));
    let blobs = BlobStore::from_config(&config.blob, keys).context("setting up object storage")?;
    let identity = Identity::new(EventStore::new(db.clone()));
    let files = file_store(db, blobs, config);
    match command {
        FilesCommand::Drives { tenant } => {
            for drive in identity.drives(tenant).await? {
                let state = if drive.active { "" } else { "  (deactivated)" };
                println!("{}  {}{state}", drive.id, drive.name);
            }
        }
        FilesCommand::AddDrive { tenant, name } => println!("{}", identity.add_drive(tenant, &name, OPERATOR).await?),
        FilesCommand::Access { account } => {
            for grant in identity.file_access(account, None).await? {
                let node = grant.node.map_or_else(|| "(all)".to_owned(), |node| node.to_string());
                println!("{node}  {}  {:<6}  {}", grant.grantee_name, grant.rights, grant.grantee.kind());
            }
        }
        FilesCommand::Grant { account, grantee, rights, node } => {
            let tenant = identity.account(account).await?.tenant;
            let grantee = identity.mail_grantee(tenant, &grantee).await?;
            identity.set_file_access(account, node, grantee, &rights, OPERATOR).await?;
            files.touch(account, node).await?;
        }
        FilesCommand::Revoke { account, grantee, node } => {
            let tenant = identity.account(account).await?.tenant;
            let grantee = identity.mail_grantee(tenant, &grantee).await?;
            identity.remove_file_access(account, node, grantee, OPERATOR).await?;
            files.touch(account, node).await?;
        }
    }
    Ok(())
}

async fn collections(config: &Config, command: CollectionCommand) -> anyhow::Result<()> {
    let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
    let keys = Arc::new(TenantKeys::with_main_keys(db.clone(), main_keys(config)?));
    let blobs = BlobStore::from_config(&config.blob, keys.clone()).context("setting up object storage")?;
    let identity = Identity::new(EventStore::new(db.clone()));
    let groupware = kernoid_groupware::Groupware::new(mail_store(db, blobs, config), keys);
    match command {
        CollectionCommand::List { account } => {
            for calendar in groupware.calendars(account).await? {
                let default = if calendar.is_default { "  default" } else { "" };
                println!("{}  calendar     {}{default}", calendar.id, calendar.name);
            }
            for book in groupware.addressbooks(account).await? {
                let default = if book.is_default { "  default" } else { "" };
                println!("{}  addressbook  {}{default}", book.id, book.name);
            }
        }
        CollectionCommand::Access { account } => {
            for grant in identity.collection_access(account, None).await? {
                println!("{}  {}  {:<8}  {}", grant.collection, grant.grantee_name, grant.level, grant.grantee.kind());
            }
        }
        CollectionCommand::Share { account, collection, grantee, level } => {
            let tenant = identity.account(account).await?.tenant;
            let grantee = identity.mail_grantee(tenant, &grantee).await?;
            identity.set_collection_access(account, collection, grantee, &level, OPERATOR).await?;
        }
        CollectionCommand::Unshare { account, collection, grantee } => {
            let tenant = identity.account(account).await?.tenant;
            let grantee = identity.mail_grantee(tenant, &grantee).await?;
            identity.remove_collection_access(account, collection, grantee, OPERATOR).await?;
        }
        CollectionCommand::Export { account, collection } => {
            let text = if groupware.calendar(account, collection).await.is_ok() {
                groupware.export_calendar(account, collection).await?
            } else {
                groupware.export_addressbook(account, collection).await?
            };
            print!("{text}");
        }
        CollectionCommand::Import { account, collection, file } => {
            let text = if file.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin()).context("reading standard input")?
            } else {
                std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?
            };
            let imported = if groupware.calendar(account, collection).await.is_ok() {
                groupware.import_calendar(account, collection, &text).await?
            } else {
                groupware.import_addressbook(account, collection, &text).await?
            };
            println!("{} stored", imported.stored);
            for (uid, reason) in imported.refused {
                eprintln!("{uid}: {reason}");
            }
        }
    }
    Ok(())
}

async fn mail(config: &Config, command: MailCommand) -> anyhow::Result<()> {
    let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
    let keys = Arc::new(TenantKeys::with_main_keys(db.clone(), main_keys(config)?));
    let blobs = BlobStore::from_config(&config.blob, keys).context("setting up object storage")?;
    let identity = Identity::new(EventStore::new(db.clone()));
    let mail = mail_store(db, blobs, config);
    // A mailbox by id or role.
    let mailbox_of = async |account: Uuid, value: Option<String>| -> anyhow::Result<Option<Uuid>> {
        Ok(match value {
            None => None,
            Some(value) => Some(match kernoid_mail::Role::parse(&value) {
                Some(role) => mail.mailbox_with_role(account, role).await?,
                None => value.parse().context("a mailbox id or a role")?,
            }),
        })
    };
    match command {
        MailCommand::Access { account } => {
            for grant in identity.mail_access(account).await? {
                let scope = grant.mailbox.map_or_else(|| "whole store".to_owned(), |mailbox| mailbox.to_string());
                let send_as = if grant.send_as { "  send as" } else { "" };
                println!("{}  {:<11}  {}  {scope}{send_as}", grant.grantee_name, grant.rights, grant.grantee.kind());
            }
        }
        MailCommand::Grant { account, grantee, rights, mailbox, send_as } => {
            let tenant = identity.account(account).await?.tenant;
            let grantee = identity.mail_grantee(tenant, &grantee).await?;
            let mailbox = mailbox_of(account, mailbox).await?;
            identity.set_mail_access(account, grantee, mailbox, &rights, send_as, OPERATOR).await?;
        }
        MailCommand::Revoke { account, grantee, mailbox } => {
            let tenant = identity.account(account).await?.tenant;
            let grantee = identity.mail_grantee(tenant, &grantee).await?;
            let mailbox = mailbox_of(account, mailbox).await?;
            identity.remove_mail_access(account, grantee, mailbox, OPERATOR).await?;
        }
        MailCommand::Export { account, directory } => {
            std::fs::create_dir_all(&directory).with_context(|| format!("creating {}", directory.display()))?;
            let mailboxes = mail.mailboxes(account).await?;
            for mailbox in &mailboxes {
                // The path in the tree, `.`-separated, as the file name.
                let mut path = vec![mailbox.name.clone()];
                let mut parent = mailbox.parent_id;
                while let Some(id) = parent {
                    let Some(up) = mailboxes.iter().find(|m| m.id == id) else { break };
                    path.push(up.name.clone());
                    parent = up.parent_id;
                }
                path.reverse();
                let name: String =
                    path.join(".").chars().map(|c| if c == '/' || c.is_control() { '_' } else { c }).collect();
                let file = directory.join(format!("{name}.mbox"));
                let mut out = std::io::BufWriter::new(
                    std::fs::File::create(&file).with_context(|| format!("creating {}", file.display()))?,
                );
                let entries = mail.mailbox_entries(account, mailbox.id).await?;
                for entry in &entries {
                    std::io::Write::write_all(&mut out, &mail.mbox_entry(account, entry).await?)?;
                }
                std::io::Write::flush(&mut out)?;
                println!("{}  {} emails", file.display(), entries.len());
            }
        }
        MailCommand::ImportMbox { account, file, mailbox } => {
            let target = match mailbox_of(account, mailbox).await? {
                Some(mailbox) => mailbox,
                None => mail.mailbox_with_role(account, kernoid_mail::Role::Inbox).await?,
            };
            let data = read_input(&file)?;
            let done = mail.import_mbox(account, target, &data).await?;
            println!("{} imported, {} refused", done.imported, done.failed);
        }
        MailCommand::Mailboxes { account } => {
            for mailbox in mail.mailboxes(account).await? {
                let role = mailbox.role.map_or("", kernoid_mail::Role::as_str);
                println!(
                    "{}  {role:<8}  {:>6} emails  {:>6} unread  {}",
                    mailbox.id, mailbox.total_emails, mailbox.unread_emails, mailbox.name
                );
            }
        }
        MailCommand::Import { account, file, mailbox } => {
            let target = match mailbox {
                None => mail.mailbox_with_role(account, kernoid_mail::Role::Inbox).await?,
                Some(value) => match kernoid_mail::Role::parse(&value) {
                    Some(role) => mail.mailbox_with_role(account, role).await?,
                    None => value.parse().context("a mailbox id or a role")?,
                },
            };
            let raw = read_input(&file)?;
            let email = kernoid_mail::NewEmail { mailbox_ids: vec![target], ..kernoid_mail::NewEmail::default() };
            let imported = mail.import_email(account, bytes::Bytes::from(raw), email).await?;
            println!("{} (thread {})", imported.id, imported.thread_id);
        }
        MailCommand::Queue { limit } => {
            for recipient in mail.queue(limit).await? {
                println!(
                    "{}  {:<9} {:>2} tries  next {}  {}{}",
                    recipient.message,
                    recipient.status,
                    recipient.attempts,
                    recipient.next_attempt_at.format("%Y-%m-%d %H:%M"),
                    recipient.address,
                    recipient.last_error.map(|error| format!("  – {error}")).unwrap_or_default(),
                );
            }
        }
        MailCommand::Sieve(command) => match command {
            SieveCommand::List { account } => {
                for script in mail.sieve_scripts(account).await? {
                    println!("{} {}", if script.active { "*" } else { " " }, script.name);
                }
            }
            SieveCommand::Put { account, name, file, activate } => {
                let content = String::from_utf8(read_input(&file)?).context("a script is UTF-8")?;
                mail.put_sieve_script(account, &name, &content, activate).await?;
            }
            SieveCommand::Activate { account, name } => mail.activate_sieve_script(account, Some(&name)).await?,
            SieveCommand::Deactivate { account } => mail.activate_sieve_script(account, None).await?,
            SieveCommand::Remove { account, name } => mail.remove_sieve_script(account, &name).await?,
        },
    }
    Ok(())
}

/// The content of FILE, or of standard input for `-`.
fn read_input(file: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    if file.as_os_str() == "-" {
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut raw)?;
        return Ok(raw);
    }
    std::fs::read(file).with_context(|| format!("reading {}", file.display()))
}

/// How often the worker looks for certificates to order or renew.
const ACME_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

async fn order_certificates(orderer: kernoid_server::acme::Orderer, shutdown: CancellationToken) -> anyhow::Result<()> {
    loop {
        match orderer.renew().await {
            Ok(done) if done.issued + done.failed > 0 => {
                tracing::info!(issued = done.issued, failed = done.failed, "certificates");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "ordering certificates failed; trying again later"),
        }
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(ACME_EVERY) => {}
        }
    }
}

async fn acme_status(config: &Config) -> anyhow::Result<()> {
    let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
    for state in kernoid_server::acme::status(&db).await? {
        let certificate = state.not_after.map_or_else(|| "no certificate".to_owned(), |end| format!("until {end}"));
        print!("{:<40} {certificate}", state.domain);
        if let Some(error) = state.last_error {
            print!(
                "  – {} failed attempt(s), next {}: {error}",
                state.attempts,
                state.next_attempt_at.map(|t| t.to_string()).unwrap_or_default()
            );
        }
        println!();
    }
    Ok(())
}

/// Who changes identity data from the command line.
const OPERATOR: &str = "operator";

async fn identity(config: &Config) -> anyhow::Result<Identity> {
    let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
    Ok(Identity::with_secrets(EventStore::new(db), main_keys(config)?))
}

fn domain(name: &str) -> anyhow::Result<DomainName> {
    Ok(DomainName::parse(name)?)
}

async fn instance(config: &Config, command: InstanceCommand) -> anyhow::Result<()> {
    let identity = identity(config).await?;
    match command {
        InstanceCommand::Add { name, domain: name_of_domain } => {
            let id = identity.add_instance(&name, &domain(&name_of_domain)?, OPERATOR).await?;
            println!("{id}");
        }
        InstanceCommand::List => {
            for instance in identity.instances().await? {
                println!("{}  {}  {}", instance.id, instance.primary_domain, instance.name);
            }
        }
        InstanceCommand::Rename { instance, name } => identity.rename_instance(instance, &name, OPERATOR).await?,
        InstanceCommand::RegistrationTenant { instance, tenant } => {
            let tenant = if tenant == "none" { None } else { Some(tenant.parse().context("a tenant id or `none`")?) };
            identity.set_registration_tenant(instance, tenant, OPERATOR).await?;
        }
        InstanceCommand::AddDomain { instance, domain: name } => {
            identity.add_instance_domain(instance, &domain(&name)?, OPERATOR).await?;
        }
        InstanceCommand::RemoveDomain { instance, domain: name } => {
            identity.remove_instance_domain(instance, &domain(&name)?, OPERATOR).await?;
        }
        InstanceCommand::SetPrimary { instance, domain: name } => {
            identity.set_primary_domain(instance, &domain(&name)?, OPERATOR).await?;
        }
        InstanceCommand::SetLoginUi { instance, url } => {
            identity.set_login_ui(instance, url.as_deref(), OPERATOR).await?;
        }
        InstanceCommand::SetPasskeyRpId { instance, rp_id } => {
            identity.set_passkey_rp_id(instance, &domain(&rp_id)?, OPERATOR).await?;
        }
        InstanceCommand::DefineRole { instance, role, permissions } => {
            let permissions = permissions.iter().map(|name| name.parse()).collect::<Result<_, _>>()?;
            identity.define_instance_role(instance, &AccessRole::parse(&role)?, &permissions, OPERATOR).await?;
        }
        InstanceCommand::DeleteRole { instance, role } => {
            identity.delete_instance_role(instance, &AccessRole::parse(&role)?, OPERATOR).await?;
        }
        InstanceCommand::Grant { instance, principal, role } => {
            identity.grant_instance_role(instance, principal.principal(), &AccessRole::parse(&role)?, OPERATOR).await?;
        }
        InstanceCommand::Revoke { instance, principal, role } => {
            identity
                .revoke_instance_role(instance, principal.principal(), &AccessRole::parse(&role)?, OPERATOR)
                .await?;
        }
        InstanceCommand::Roles { instance } => {
            for assignment in identity.instance_role_assignments(instance).await? {
                let principal = assignment.principal;
                println!("{:<20} {:<8} {}", assignment.role, principal.kind(), principal.id());
            }
        }
    }
    Ok(())
}

async fn tenant(config: &Config, command: TenantCommand) -> anyhow::Result<()> {
    let identity = identity(config).await?;
    let instance_of = async |tenant| identity.tenant_instance(tenant).await;
    match command {
        TenantCommand::Add { instance, name } => println!("{}", identity.add_tenant(instance, &name, OPERATOR).await?),
        TenantCommand::List { instance } => {
            for tenant in identity.tenants(instance).await? {
                println!("{}  {}  {}", tenant.id, if tenant.active { "active  " } else { "inactive" }, tenant.name);
            }
        }
        TenantCommand::Rename { tenant, name } => {
            identity.rename_tenant(instance_of(tenant).await?, tenant, &name, OPERATOR).await?;
        }
        TenantCommand::RequireMfa { tenant, required } => {
            identity.set_tenant_mfa_required(instance_of(tenant).await?, tenant, required, OPERATOR).await?;
        }
        TenantCommand::MfaGrace { tenant, days } => {
            identity.set_tenant_mfa_grace(instance_of(tenant).await?, tenant, days, OPERATOR).await?;
        }
        TenantCommand::Deactivate { tenant } => {
            identity.set_tenant_active(instance_of(tenant).await?, tenant, false, OPERATOR).await?;
        }
        TenantCommand::Reactivate { tenant } => {
            identity.set_tenant_active(instance_of(tenant).await?, tenant, true, OPERATOR).await?;
        }
        TenantCommand::AddDomain { tenant, domain: name } => {
            let domain = domain(&name)?;
            let token = identity.add_tenant_domain(instance_of(tenant).await?, tenant, &domain, OPERATOR).await?;
            println!("Publish this DNS record, then run `kernoid tenant verify-domain {tenant} {domain}`:");
            println!("{CHALLENGE_LABEL}.{domain}. TXT \"kernoid-verification={token}\"");
        }
        TenantCommand::VerifyDomain { tenant, domain: name, trust } => {
            let domain = domain(&name)?;
            let instance = instance_of(tenant).await?;
            if trust {
                identity.trust_tenant_domain(instance, tenant, &domain, OPERATOR).await?;
            } else {
                let dns = DnsResolver::from_system().map_err(anyhow::Error::msg)?;
                identity.verify_tenant_domain(instance, tenant, &domain, &dns, OPERATOR).await?;
            }
            println!("{domain} is verified");
        }
        TenantCommand::RemoveDomain { tenant, domain: name } => {
            identity.remove_tenant_domain(instance_of(tenant).await?, tenant, &domain(&name)?, OPERATOR).await?;
        }
        TenantCommand::MailQuota { tenant, bytes } => {
            identity.set_default_mail_quota(tenant, bytes.0, OPERATOR).await?
        }
        TenantCommand::FilesQuota { tenant, bytes } => {
            identity.set_default_files_quota(tenant, bytes.0, OPERATOR).await?
        }
        TenantCommand::LoginPolicy { tenant, usernames, email_login } => {
            identity.set_login_policy(tenant, usernames, email_login, OPERATOR).await?;
        }
        TenantCommand::Registration { tenant, allowed, domains } => {
            let domains = domains.iter().map(|name| domain(name)).collect::<anyhow::Result<Vec<_>>>()?;
            identity.set_registration(tenant, allowed, &domains, OPERATOR).await?;
        }
        TenantCommand::ServicePolicy { tenant, service, assign, approval } => {
            use kernoid_identity::services::{Assign, Service, ServicePolicy};
            let rule = ServicePolicy { assign: Assign::parse(&assign)?, approval };
            identity.set_service_policy(tenant, Service::parse(&service)?, rule, OPERATOR).await?;
        }
        TenantCommand::MailRetention { tenant, trash_days, junk_days } => {
            identity.set_mail_retention(tenant, trash_days.0, junk_days.0, OPERATOR).await?;
        }
        TenantCommand::FilesRetention { tenant, trash_days } => {
            identity.set_files_retention(tenant, trash_days.0, OPERATOR).await?;
        }
        TenantCommand::Language { tenant, language } => {
            identity
                .set_tenant_language(tenant, Some(language.as_str()).filter(|code| *code != "none"), OPERATOR)
                .await?;
        }
        TenantCommand::E2ePolicy { tenant, mail, vaults, collections, recovery } => {
            let rule = |value: &str| {
                kernoid_identity::tenant::E2eRule::parse(value)
                    .ok_or_else(|| anyhow::anyhow!("{value}: a rule is allowed, required or forbidden"))
            };
            let policy = kernoid_identity::tenant::E2ePolicy {
                mail: rule(&mail)?,
                vaults: rule(&vaults)?,
                collections: rule(&collections)?,
                recovery,
            };
            identity.set_e2e_policy(tenant, policy, OPERATOR).await?;
        }
        TenantCommand::RecoveryKey { tenant } => {
            let mut key = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut key).context("reading standard input")?;
            println!("{}", identity.set_recovery_key(tenant, &key, OPERATOR).await?);
        }
        TenantCommand::Module { tenant, module, enabled } => {
            let known: Vec<&str> = MODULES.iter().map(|module| module.name()).collect();
            identity.set_tenant_module(instance_of(tenant).await?, tenant, &module, enabled, &known, OPERATOR).await?;
        }
        TenantCommand::Grant { tenant, principal, role } => {
            identity.grant_role(tenant, principal.principal(), &AccessRole::parse(&role)?, OPERATOR).await?;
        }
        TenantCommand::Revoke { tenant, principal, role } => {
            identity.revoke_role(tenant, principal.principal(), &AccessRole::parse(&role)?, OPERATOR).await?;
        }
        TenantCommand::Roles { tenant } => {
            for assignment in identity.role_assignments(tenant).await? {
                let principal = assignment.principal;
                println!("{:<20} {:<8} {}", assignment.role, principal.kind(), principal.id());
            }
        }
        TenantCommand::DkimRotate { tenant, domain, algorithm } => {
            let checker =
                mail_dns_checker(config).await?.context("no [smtp] in the configuration: kernoid handles no mail")?;
            let algorithm =
                kernoid_smtp::dkim::Algorithm::parse(&algorithm).context("the algorithm is rsa or ed25519")?;
            let domain = self::domain(&domain)?;
            let instance = identity.tenant_instance(tenant).await?;
            let state = identity.tenant(instance, tenant).await?.state;
            if !state.domains.get(&domain).is_some_and(|claim| claim.verified) {
                anyhow::bail!("{domain} is not a verified domain of the tenant");
            }
            let selector = checker.rotate_dkim(domain.as_str(), algorithm).await?;
            println!("publish {selector}._domainkey.{domain}; `kernoid tenant mail-dns` shows the record");
        }
        TenantCommand::MailDns { tenant } => {
            let checker =
                mail_dns_checker(config).await?.context("no [smtp] in the configuration: kernoid handles no mail")?;
            let instance = identity.tenant_instance(tenant).await?;
            for (domain, claim) in identity.tenant(instance, tenant).await?.state.domains {
                if !claim.verified {
                    continue;
                }
                println!("{domain}");
                for check in checker.check(domain.as_str()).await {
                    println!("  {:<6} {:<9} {:<40} {}", check.kind, check.status.as_str(), check.name, check.expected);
                    for found in &check.found {
                        println!("  {:<6} {:<9} {:<40} found: {found}", "", "", "");
                    }
                }
            }
        }
    }
    Ok(())
}

/// The DNS check of mail domains, when `[smtp]` is configured.
async fn mail_dns_checker(config: &Config) -> anyhow::Result<Option<kernoid_smtp::dns_check::Checker>> {
    let Some(smtp) = &config.smtp else { return Ok(None) };
    let pool = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
    let dns = kernoid_smtp::Dns::from_system().map_err(|error| anyhow::anyhow!("DNS: {error}"))?;
    Ok(Some(kernoid_smtp::dns_check::Checker {
        dns,
        pool,
        hostname: smtp.hostname.trim_end_matches('.').to_lowercase(),
        spf: smtp.spf.clone(),
        main: main_keys(config)?,
    }))
}

fn address(value: &str) -> anyhow::Result<Address> {
    Ok(Address::parse(value)?)
}

/// One line from standard input; on a terminal, asked for without echo.
fn read_password(prompt: &str) -> anyhow::Result<String> {
    if std::io::stdin().is_terminal() {
        return Ok(rpassword::prompt_password(prompt)?);
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

async fn account(config: &Config, command: AccountCommand) -> anyhow::Result<()> {
    let identity = identity(config).await?;
    match command {
        AccountCommand::Add { tenant, address: value, name } => {
            println!("{}", identity.add_account(tenant, &address(&value)?, &name, OPERATOR).await?);
        }
        AccountCommand::AddExternal { tenant, name, email, verified, username } => {
            let account =
                identity.add_external_account(tenant, &name, email.as_deref().map(|e| (e, verified)), OPERATOR).await?;
            if let Some(username) = username {
                identity.set_username(account, Some(&username), OPERATOR).await?;
            }
            println!("{account}");
        }
        AccountCommand::Username { account, username } => {
            let username = (username != "none").then_some(username);
            identity.set_username(account, username.as_deref(), OPERATOR).await?;
        }
        AccountCommand::Contact { account, email, verified } => {
            let email = (email != "none").then_some(email);
            identity.set_contact_email(account, email.as_deref(), verified, OPERATOR).await?;
        }
        AccountCommand::Services { account } => {
            for (service, state) in identity.services(account).await? {
                println!("{}  {}", service.as_str(), state.as_str());
            }
        }
        AccountCommand::GrantService { account, service } => {
            identity.grant_service(account, kernoid_identity::services::Service::parse(&service)?, OPERATOR).await?;
        }
        AccountCommand::RevokeService { account, service } => {
            identity.revoke_service(account, kernoid_identity::services::Service::parse(&service)?, OPERATOR).await?;
        }
        AccountCommand::AddShared { tenant, address: value, name } => {
            println!("{}", identity.add_shared_mailbox(tenant, &address(&value)?, &name, OPERATOR).await?);
        }
        AccountCommand::List { tenant } => {
            for account in identity.accounts(tenant).await? {
                let state = if account.active { "active  " } else { "inactive" };
                let kind = if account.drive {
                    "drive "
                } else if account.shared {
                    "shared"
                } else {
                    "person"
                };
                println!("{}  {state}  {kind}  {}  {}", account.id, account.address, account.display_name);
            }
        }
        AccountCommand::Rename { account, name } => identity.rename_account(account, &name, OPERATOR).await?,
        AccountCommand::Language { account, language } => {
            let language = Some(language.as_str()).filter(|code| *code != "none");
            identity.set_account_language(account, language, OPERATOR).await?;
        }
        AccountCommand::Password { account } => {
            let password = read_password("New password: ")?;
            identity.set_password(account, &password, OPERATOR).await?;
        }
        AccountCommand::AddAlias { account, address: value } => {
            identity.add_alias(account, &address(&value)?, OPERATOR).await?;
        }
        AccountCommand::RemoveAlias { account, address: value } => {
            identity.remove_alias(account, &address(&value)?, OPERATOR).await?;
        }
        AccountCommand::SetPrimary { account, address: value } => {
            identity.set_primary_address(account, &address(&value)?, OPERATOR).await?;
        }
        AccountCommand::ResetSecondFactors { account } => identity.reset_second_factors(account, OPERATOR).await?,
        AccountCommand::Deactivate { account } => identity.set_account_active(account, false, OPERATOR).await?,
        AccountCommand::Reactivate { account } => identity.set_account_active(account, true, OPERATOR).await?,
        AccountCommand::MailQuota { account, bytes } => identity.set_mail_quota(account, bytes.0, OPERATOR).await?,
        AccountCommand::FilesQuota { account, bytes } => identity.set_files_quota(account, bytes.0, OPERATOR).await?,
        AccountCommand::AppPassword(AppPasswordCommand::Add { account, name }) => {
            let (id, password) = identity.add_app_password(account, &name, OPERATOR).await?;
            println!("{id}  {password}");
        }
        AccountCommand::AppPassword(AppPasswordCommand::List { account }) => {
            for info in identity.app_passwords(account).await? {
                let used = info.last_used_at.map_or_else(|| "never used".to_owned(), |at| format!("used {at}"));
                println!("{}  {}  {used}", info.id, info.name);
            }
        }
        AccountCommand::AppPassword(AppPasswordCommand::Remove { account, id }) => {
            identity.remove_app_password(account, id, OPERATOR).await?;
        }
        AccountCommand::CheckLogin { instance, address } => {
            let password = read_password("Password: ")?;
            let account = identity.authenticate(instance, &address, &password).await?;
            println!("ok: {} ({})", account.address, account.id);
        }
    }
    Ok(())
}

async fn oidc(config: &Config) -> anyhow::Result<Oidc> {
    let db = kernoid_store::connect(&config.database).await.context("connecting to PostgreSQL")?;
    Ok(Oidc::new(EventStore::new(db), main_keys(config)?, config.http.public_scheme.as_str())
        .public_port(config.http.public_port)
        .allow_private_networks(config.outbound.allow_private_networks))
}

async fn app(config: &Config, command: AppCommand) -> anyhow::Result<()> {
    let oidc = oidc(config).await?;
    match command {
        AppCommand::Add { project, name, public, redirect_uris, post_logout_redirect_uris } => {
            let kind = if public { AppKind::Public } else { AppKind::Confidential };
            let tenant = identity(config).await?.project(project).await?.tenant;
            let uris = (&redirect_uris[..], &post_logout_redirect_uris[..]);
            let (id, secret) = oidc.add_application(tenant, project, &name, kind, uris.0, uris.1, OPERATOR).await?;
            println!("client_id:     {id}");
            if let Some(secret) = secret {
                println!("client_secret: {secret}   (shown once)");
            }
        }
        AppCommand::List { tenant } => {
            for app in oidc.applications(tenant).await? {
                let state = if app.active { "active  " } else { "inactive" };
                println!(
                    "{}  {state}  {:<12}  {}  {}",
                    app.id,
                    app.kind.as_str(),
                    app.name,
                    app.redirect_uris.join(" ")
                );
            }
        }
        AppCommand::SetRedirectUris { application, redirect_uris } => {
            oidc.set_redirect_uris(application, &redirect_uris, OPERATOR).await?;
        }
        AppCommand::SetPostLogoutRedirectUris { application, post_logout_redirect_uris } => {
            oidc.set_post_logout_redirect_uris(application, &post_logout_redirect_uris, OPERATOR).await?;
        }
        AppCommand::NewSecret { application } => {
            println!("client_secret: {}   (shown once)", oidc.new_client_secret(application, OPERATOR).await?);
        }
        AppCommand::RequireMfa { application, required } => {
            oidc.set_application_mfa_required(application, required, OPERATOR).await?;
        }
        AppCommand::SetOptions {
            application,
            jwt,
            offline_access,
            consent_required,
            backchannel_logout_uri,
            frontchannel_logout_uri,
        } => {
            let options = kernoid_oidc::application::AppOptions {
                access_token_format: if jwt {
                    kernoid_oidc::application::TokenFormat::Jwt
                } else {
                    kernoid_oidc::application::TokenFormat::Opaque
                },
                offline_access,
                consent_required,
                backchannel_logout_uri,
                frontchannel_logout_uri,
            };
            oidc.set_application_options(application, &options, OPERATOR).await?;
        }
        AppCommand::Deactivate { application } => oidc.set_application_active(application, false, OPERATOR).await?,
        AppCommand::Reactivate { application } => oidc.set_application_active(application, true, OPERATOR).await?,
    }
    Ok(())
}

async fn project(config: &Config, command: ProjectCommand) -> anyhow::Result<()> {
    let identity = identity(config).await?;
    match command {
        ProjectCommand::Add { tenant, name } => println!("{}", identity.add_project(tenant, &name, OPERATOR).await?),
        ProjectCommand::List { tenant } => {
            for project in identity.projects(tenant).await? {
                let roles: Vec<_> = project.roles.iter().map(|role| role.key.as_str()).collect();
                println!("{}  {}  roles: {}", project.id, project.name, roles.join(" "));
            }
        }
    }
    Ok(())
}

async fn signing_key(config: &Config, command: SigningKeyCommand) -> anyhow::Result<()> {
    let oidc = oidc(config).await?;
    match command {
        SigningKeyCommand::List { instance } => {
            for key in oidc.signing_keys(instance).await? {
                println!("{}  {:<8}  {}  since {}", key.kid, key.state.as_str(), key.algorithm, key.state_since);
            }
        }
        SigningKeyCommand::Add { instance } => println!("{}", oidc.add_signing_key(instance, OPERATOR).await?),
        SigningKeyCommand::Activate { instance, kid } => oidc.activate_signing_key(instance, &kid, OPERATOR).await?,
        SigningKeyCommand::Remove { instance, kid } => oidc.remove_signing_key(instance, &kid, OPERATOR).await?,
    }
    Ok(())
}

async fn saml_key(config: &Config, command: SamlKeyCommand) -> anyhow::Result<()> {
    let oidc = oidc(config).await?;
    match command {
        SamlKeyCommand::List { instance } => {
            for key in oidc.saml_keys(instance).await? {
                println!("{}  {:<7}  since {}  {}", key.id, key.state, key.state_since, key.fingerprint);
            }
        }
        SamlKeyCommand::Add { instance } => {
            let info = Identity::new(EventStore::new(kernoid_store::connect(&config.database).await?))
                .instances()
                .await?
                .into_iter()
                .find(|info| info.id == instance)
                .context("no such instance")?;
            println!("{}", oidc.add_saml_key(&info).await?);
        }
        SamlKeyCommand::Activate { instance, id } => oidc.activate_saml_key(instance, id).await?,
    }
    Ok(())
}

fn init_logging(config: &Config) -> anyhow::Result<Option<SdkTracerProvider>> {
    let filter = match &config.log.filter {
        Some(filter) => EnvFilter::try_new(filter).context("log.filter")?,
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };
    let provider = match &config.log.otlp_endpoint {
        Some(endpoint) => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .build()
                .context("log.otlp_endpoint")?;
            let resource = Resource::builder().with_service_name("kernoid").build();
            Some(SdkTracerProvider::builder().with_batch_exporter(exporter).with_resource(resource).build())
        }
        None => None,
    };
    let otel = provider.as_ref().map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("kernoid")));
    let (text, json) = match config.log.format {
        LogFormat::Text => (Some(tracing_subscriber::fmt::layer()), None),
        LogFormat::Json => (None, Some(tracing_subscriber::fmt::layer().json())),
    };
    tracing_subscriber::registry().with(filter).with(text).with(json).with(otel).init();
    Ok(provider)
}

async fn shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c().await.expect("listening for SIGINT");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("listening for SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
