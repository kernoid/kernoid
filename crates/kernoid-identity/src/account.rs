// SPDX-License-Identifier: AGPL-3.0-or-later
//! The account: a login, a mailbox and an owner of calendars and files at once (RFC 0001). Its login name is its
//! primary address; aliases are further addresses. Every address is on a domain the tenant has verified and belongs
//! to one account in the whole installation. Accounts are owned by their tenant.

use std::collections::{BTreeMap, BTreeSet};

use kernoid_events::{
    Error, Event, InlineFuture,
    aggregate::{Aggregate, DomainEvent},
    inline,
};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    Address, Identity, IdentityError, Result, password,
    role::Principal,
    services::{Service, ServiceState},
    tenant::Tenant,
    valid_name,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AccountEvent {
    #[serde(rename = "account.added")]
    Added { address: Address, display_name: String, services: Vec<Service> },
    #[serde(rename = "account.renamed")]
    Renamed { display_name: String },
    #[serde(rename = "account.alias_added")]
    AliasAdded { address: Address },
    #[serde(rename = "account.alias_removed")]
    AliasRemoved { address: Address },
    /// An alias becomes the primary address (the login name); the former primary address becomes an alias.
    #[serde(rename = "account.primary_address_changed")]
    PrimaryAddressChanged { address: Address },
    /// The hash itself is a credential, kept in `account_passwords`, never in an event.
    #[serde(rename = "account.password_changed")]
    PasswordChanged,
    /// The account can no longer log in.
    #[serde(rename = "account.deactivated")]
    Deactivated,
    #[serde(rename = "account.reactivated")]
    Reactivated,
    /// TOTP set up and confirmed; the secret is in `account_totp`, sealed.
    #[serde(rename = "account.totp_enabled")]
    TotpEnabled,
    #[serde(rename = "account.totp_removed")]
    TotpRemoved,
    /// A passkey registered; its public key is in `account_passkeys`.
    #[serde(rename = "account.passkey_added")]
    PasskeyAdded { id: Uuid, name: String },
    #[serde(rename = "account.passkey_removed")]
    PasskeyRemoved { id: Uuid },
    /// New recovery codes replace all earlier ones; the codes are in `account_recovery_codes`, hashed.
    #[serde(rename = "account.recovery_codes_generated")]
    RecoveryCodesGenerated { count: u32 },
    #[serde(rename = "account.recovery_codes_removed")]
    RecoveryCodesRemoved,
    /// An identity at an external identity provider (its `sub`) logs in as this account.
    #[serde(rename = "account.link_added")]
    LinkAdded { idp: Uuid, subject: String },
    #[serde(rename = "account.link_removed")]
    LinkRemoved { idp: Uuid, subject: String },
    /// The identifier a directory knows the account by (SCIM `externalId`).
    #[serde(rename = "account.external_id_set")]
    ExternalIdSet { external_id: Option<String> },
    /// The account agreed that an application may have these scopes (replacing an earlier consent to it).
    #[serde(rename = "account.consent_granted")]
    ConsentGranted { application: Uuid, scopes: Vec<String> },
    #[serde(rename = "account.consent_revoked")]
    ConsentRevoked { application: Uuid },
    /// How many bytes the account's emails may take; none for no limit (RFC 0002, 8).
    #[serde(rename = "account.mail_quota_set")]
    MailQuotaSet { bytes: Option<u64> },
    /// How many bytes the account's files may take; none for the tenant's default (RFC 0005, 10).
    #[serde(rename = "account.files_quota_set")]
    FilesQuotaSet { bytes: Option<u64> },
    /// An app password for a mail program; its hash is in `account_app_passwords`.
    #[serde(rename = "account.app_password_added")]
    AppPasswordAdded { id: Uuid, name: String },
    #[serde(rename = "account.app_password_removed")]
    AppPasswordRemoved { id: Uuid },
    /// A shared mailbox (RFC 0002, 12.1): an account nobody logs in as.
    #[serde(rename = "account.shared_added")]
    SharedAdded { address: Address, display_name: String },
    /// Access to the account's mail (RFC 0002, 12.2): to the whole store or one mailbox, replacing an earlier grant
    /// to the same grantee there.
    #[serde(rename = "account.mail_access_set")]
    MailAccessSet { grantee: Principal, mailbox: Option<Uuid>, rights: String, send_as: bool },
    #[serde(rename = "account.mail_access_removed")]
    MailAccessRemoved { grantee: Principal, mailbox: Option<Uuid> },
    /// Access to one of the account's calendars or address books (RFC 0004, 9), replacing an earlier grant to the
    /// same grantee there.
    #[serde(rename = "account.collection_access_set")]
    CollectionAccessSet { grantee: Principal, collection_type: String, collection: Uuid, level: String },
    #[serde(rename = "account.collection_access_removed")]
    CollectionAccessRemoved { grantee: Principal, collection: Uuid },
    /// A drive of the tenant (RFC 0005, 12): an account that holds files, without a login and without an address.
    #[serde(rename = "account.drive_added")]
    DriveAdded { display_name: String },
    /// Access to the account's files (RFC 0005, 11): to one directory and what lies below it, or to the whole store,
    /// replacing an earlier grant to the same grantee there. Rights are letters of `randws`.
    #[serde(rename = "account.file_access_set")]
    FileAccessSet { grantee: Principal, node: Option<Uuid>, rights: String },
    #[serde(rename = "account.file_access_removed")]
    FileAccessRemoved { grantee: Principal, node: Option<Uuid> },
    /// An account without a native address (RFC 0003, 1): for logins – and files, if granted – only.
    #[serde(rename = "account.external_added")]
    ExternalAdded { display_name: String, services: Vec<Service> },
    /// A login name of its own, unique in the instance (RFC 0003, 2); `None` removes it.
    #[serde(rename = "account.username_set")]
    UsernameSet { username: Option<String> },
    /// The contact address, of any domain; a verified one is a login and unique in the instance.
    #[serde(rename = "account.email_set")]
    EmailSet { email: Option<String>, verified: bool },
    /// A service waits for an administrator (RFC 0003, 4).
    #[serde(rename = "account.service_requested")]
    ServiceRequested { service: Service },
    #[serde(rename = "account.service_granted")]
    ServiceGranted { service: Service },
    #[serde(rename = "account.service_revoked")]
    ServiceRevoked { service: Service },
}

impl DomainEvent for AccountEvent {
    fn revision(event_type: &str) -> i16 {
        match event_type {
            // 2: the services the account starts with (RFC 0003).
            "account.added" => 2,
            _ => 1,
        }
    }

    fn upcast(
        event_type: &str,
        revision: i16,
        mut payload: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, String> {
        match (event_type, revision) {
            // Every account before RFC 0003 had mail.
            ("account.added", 1) => {
                payload["services"] = serde_json::json!(["mail"]);
                Ok(payload)
            }
            _ => Err(format!("no upcast of {event_type} from revision {revision}")),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Account {
    pub exists: bool,
    pub display_name: String,
    pub primary: Option<Address>,
    pub aliases: BTreeSet<Address>,
    pub active: bool,
    pub has_password: bool,
    pub totp: bool,
    pub passkeys: BTreeSet<Uuid>,
    pub recovery_codes: bool,
    /// External identities: (identity provider, subject).
    pub links: BTreeSet<(Uuid, String)>,
    pub external_id: Option<String>,
    /// Applications the account consented to, with the scopes.
    pub consents: BTreeMap<Uuid, Vec<String>>,
    pub mail_quota: Option<u64>,
    pub files_quota: Option<u64>,
    pub app_passwords: BTreeSet<Uuid>,
    /// A shared mailbox: no login of any kind.
    pub shared: bool,
    /// A drive (RFC 0005, 12): files only, no login of any kind, no address.
    pub drive: bool,
    /// Grants on the account's files: (grantee, directory or the whole store) → rights.
    pub file_access: BTreeMap<(Principal, Option<Uuid>), String>,
    /// Grants on the account's mail: (grantee, mailbox) → (rights, send as).
    pub mail_access: BTreeMap<(Principal, Option<Uuid>), (String, bool)>,
    /// Grants on the account's calendars and address books: (grantee, collection) → level.
    pub collection_access: BTreeMap<(Principal, Uuid), String>,
    pub services: BTreeMap<Service, ServiceState>,
    pub username: Option<String>,
    /// The contact address and whether it is verified.
    pub email: Option<(String, bool)>,
}

impl Account {
    fn has_address(&self, address: &Address) -> bool {
        self.primary.as_ref() == Some(address) || self.aliases.contains(address)
    }
}

impl Aggregate for Account {
    const TYPE: &'static str = "account";
    type Event = AccountEvent;

    fn apply(&mut self, event: AccountEvent) {
        match event {
            AccountEvent::Added { address, display_name, services } => {
                *self = Self {
                    exists: true,
                    display_name,
                    primary: Some(address),
                    active: true,
                    services: services.into_iter().map(|service| (service, ServiceState::On)).collect(),
                    ..Self::default()
                };
            }
            AccountEvent::ExternalAdded { display_name, services } => {
                *self = Self {
                    exists: true,
                    display_name,
                    active: true,
                    services: services.into_iter().map(|service| (service, ServiceState::On)).collect(),
                    ..Self::default()
                };
            }
            AccountEvent::UsernameSet { username } => self.username = username,
            AccountEvent::EmailSet { email, verified } => self.email = email.map(|email| (email, verified)),
            AccountEvent::ServiceRequested { service } => {
                self.services.insert(service, ServiceState::Requested);
            }
            AccountEvent::ServiceGranted { service } => {
                self.services.insert(service, ServiceState::On);
            }
            AccountEvent::ServiceRevoked { service } => {
                self.services.remove(&service);
            }
            AccountEvent::Renamed { display_name } => self.display_name = display_name,
            AccountEvent::AliasAdded { address } => {
                self.aliases.insert(address);
            }
            AccountEvent::AliasRemoved { address } => {
                self.aliases.remove(&address);
            }
            AccountEvent::PrimaryAddressChanged { address } => {
                self.aliases.remove(&address);
                if let Some(former) = self.primary.replace(address) {
                    self.aliases.insert(former);
                }
            }
            AccountEvent::PasswordChanged => self.has_password = true,
            AccountEvent::Deactivated => self.active = false,
            AccountEvent::Reactivated => self.active = true,
            AccountEvent::TotpEnabled => self.totp = true,
            AccountEvent::TotpRemoved => self.totp = false,
            AccountEvent::PasskeyAdded { id, .. } => {
                self.passkeys.insert(id);
            }
            AccountEvent::PasskeyRemoved { id } => {
                self.passkeys.remove(&id);
            }
            AccountEvent::RecoveryCodesGenerated { .. } => self.recovery_codes = true,
            AccountEvent::RecoveryCodesRemoved => self.recovery_codes = false,
            AccountEvent::LinkAdded { idp, subject } => {
                self.links.insert((idp, subject));
            }
            AccountEvent::LinkRemoved { idp, subject } => {
                self.links.remove(&(idp, subject));
            }
            AccountEvent::ExternalIdSet { external_id } => self.external_id = external_id,
            AccountEvent::ConsentGranted { application, scopes } => {
                self.consents.insert(application, scopes);
            }
            AccountEvent::ConsentRevoked { application } => {
                self.consents.remove(&application);
            }
            AccountEvent::MailQuotaSet { bytes } => self.mail_quota = bytes,
            AccountEvent::FilesQuotaSet { bytes } => self.files_quota = bytes,
            AccountEvent::AppPasswordAdded { id, .. } => {
                self.app_passwords.insert(id);
            }
            AccountEvent::AppPasswordRemoved { id } => {
                self.app_passwords.remove(&id);
            }
            AccountEvent::SharedAdded { address, display_name } => {
                *self = Self {
                    exists: true,
                    display_name,
                    primary: Some(address),
                    active: true,
                    shared: true,
                    services: BTreeMap::from([(Service::Mail, ServiceState::On)]),
                    ..Self::default()
                };
            }
            AccountEvent::MailAccessSet { grantee, mailbox, rights, send_as } => {
                self.mail_access.insert((grantee, mailbox), (rights, send_as));
            }
            AccountEvent::MailAccessRemoved { grantee, mailbox } => {
                self.mail_access.remove(&(grantee, mailbox));
            }
            AccountEvent::CollectionAccessSet { grantee, collection, level, .. } => {
                self.collection_access.insert((grantee, collection), level);
            }
            AccountEvent::CollectionAccessRemoved { grantee, collection } => {
                self.collection_access.remove(&(grantee, collection));
            }
            AccountEvent::DriveAdded { display_name } => {
                *self = Self {
                    exists: true,
                    display_name,
                    active: true,
                    drive: true,
                    services: BTreeMap::from([(Service::Files, ServiceState::On)]),
                    ..Self::default()
                };
            }
            AccountEvent::FileAccessSet { grantee, node, rights } => {
                self.file_access.insert((grantee, node), rights);
            }
            AccountEvent::FileAccessRemoved { grantee, node } => {
                self.file_access.remove(&(grantee, node));
            }
        }
    }
}

/// Keeps `accounts` and `addresses` current, in the transaction of the events.
pub(crate) async fn project(connection: &mut PgConnection, events: &[Event]) -> std::result::Result<(), Error> {
    for event in events {
        let tenant = event.owner;
        let id = Uuid::parse_str(&event.aggregate.aggregate_id).map_err(|error| Error::Decode {
            event_type: event.event_type.clone(),
            revision: event.revision,
            message: format!("account id: {error}"),
        })?;
        match AccountEvent::decode(&event.event_type, event.revision, event.payload.clone())? {
            AccountEvent::Added { address, display_name, services } => {
                sqlx::query!(
                    "INSERT INTO accounts (id, tenant_id, display_name, primary_address) VALUES ($1, $2, $3, $4)",
                    id,
                    tenant,
                    display_name,
                    address.as_str(),
                )
                .execute(&mut *connection)
                .await?;
                insert_address(connection, tenant, id, &address, true).await?;
                for service in services {
                    set_service(connection, id, service, Some(ServiceState::On)).await?;
                }
            }
            AccountEvent::ExternalAdded { display_name, services } => {
                sqlx::query!(
                    "INSERT INTO accounts (id, tenant_id, display_name) VALUES ($1, $2, $3)",
                    id,
                    tenant,
                    display_name,
                )
                .execute(&mut *connection)
                .await?;
                for service in services {
                    set_service(connection, id, service, Some(ServiceState::On)).await?;
                }
            }
            AccountEvent::UsernameSet { username } => {
                sqlx::query!("UPDATE accounts SET username = $2 WHERE id = $1", id, username)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query!("DELETE FROM account_usernames WHERE account_id = $1", id)
                    .execute(&mut *connection)
                    .await?;
                if let Some(username) = username {
                    sqlx::query!(
                        "INSERT INTO account_usernames (instance_id, username, account_id)
                         SELECT instance_id, $2, $1 FROM tenants WHERE id = $3",
                        id,
                        username,
                        tenant,
                    )
                    .execute(&mut *connection)
                    .await?;
                }
            }
            AccountEvent::EmailSet { email, verified } => {
                sqlx::query!("UPDATE accounts SET email = $2, email_verified = $3 WHERE id = $1", id, email, verified)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query!("DELETE FROM account_emails WHERE account_id = $1", id).execute(&mut *connection).await?;
                if let Some(email) = email.filter(|_| verified) {
                    sqlx::query!(
                        "INSERT INTO account_emails (instance_id, email, account_id)
                         SELECT instance_id, $2, $1 FROM tenants WHERE id = $3",
                        id,
                        email,
                        tenant,
                    )
                    .execute(&mut *connection)
                    .await?;
                }
            }
            AccountEvent::ServiceRequested { service } => {
                set_service(connection, id, service, Some(ServiceState::Requested)).await?;
            }
            AccountEvent::ServiceGranted { service } => {
                set_service(connection, id, service, Some(ServiceState::On)).await?;
            }
            AccountEvent::ServiceRevoked { service } => set_service(connection, id, service, None).await?,
            AccountEvent::Renamed { display_name } => {
                sqlx::query!("UPDATE accounts SET display_name = $2 WHERE id = $1", id, display_name)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::AliasAdded { address } => insert_address(connection, tenant, id, &address, false).await?,
            AccountEvent::AliasRemoved { address } => {
                sqlx::query!("DELETE FROM addresses WHERE address = $1 AND account_id = $2", address.as_str(), id)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::PrimaryAddressChanged { address } => {
                // Unset first: one primary address per account (addresses_one_primary).
                sqlx::query!("UPDATE addresses SET is_primary = false WHERE account_id = $1", id)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query!(
                    "UPDATE addresses SET is_primary = true WHERE account_id = $1 AND address = $2",
                    id,
                    address.as_str(),
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query!("UPDATE accounts SET primary_address = $2 WHERE id = $1", id, address.as_str())
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::PasswordChanged => {}
            AccountEvent::Deactivated => {
                sqlx::query!("UPDATE accounts SET active = false WHERE id = $1", id).execute(&mut *connection).await?;
            }
            AccountEvent::Reactivated => {
                sqlx::query!("UPDATE accounts SET active = true WHERE id = $1", id).execute(&mut *connection).await?;
            }
            // Enabling, adding and generating are written by the command, which holds the secret, key or codes.
            AccountEvent::TotpEnabled
            | AccountEvent::PasskeyAdded { .. }
            | AccountEvent::AppPasswordAdded { .. }
            | AccountEvent::RecoveryCodesGenerated { .. } => {}
            AccountEvent::AppPasswordRemoved { id: app_password } => {
                sqlx::query!("DELETE FROM account_app_passwords WHERE id = $1 AND account_id = $2", app_password, id)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::RecoveryCodesRemoved => {
                sqlx::query!("DELETE FROM account_recovery_codes WHERE account_id = $1", id)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::TotpRemoved => {
                sqlx::query!("DELETE FROM account_totp WHERE account_id = $1", id).execute(&mut *connection).await?;
            }
            AccountEvent::PasskeyRemoved { id: passkey } => {
                sqlx::query!("DELETE FROM account_passkeys WHERE id = $1 AND account_id = $2", passkey, id)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::LinkAdded { idp, subject } => {
                sqlx::query!(
                    "INSERT INTO account_links (idp_id, subject, account_id) VALUES ($1, $2, $3)",
                    idp,
                    subject,
                    id,
                )
                .execute(&mut *connection)
                .await?;
            }
            AccountEvent::ExternalIdSet { external_id } => {
                sqlx::query!("UPDATE accounts SET external_id = $2 WHERE id = $1", id, external_id)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::ConsentGranted { application, scopes } => {
                sqlx::query!(
                    "INSERT INTO consents (account_id, application_id, scopes, granted_at) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (account_id, application_id) DO UPDATE SET scopes = $3, granted_at = $4",
                    id,
                    application,
                    &scopes,
                    event.created_at,
                )
                .execute(&mut *connection)
                .await?;
            }
            AccountEvent::ConsentRevoked { application } => {
                sqlx::query!("DELETE FROM consents WHERE account_id = $1 AND application_id = $2", id, application)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::LinkRemoved { idp, subject } => {
                sqlx::query!(
                    "DELETE FROM account_links WHERE idp_id = $1 AND subject = $2 AND account_id = $3",
                    idp,
                    subject,
                    id,
                )
                .execute(&mut *connection)
                .await?;
            }
            AccountEvent::MailQuotaSet { bytes } => {
                let bytes = bytes.map(|bytes| i64::try_from(bytes).unwrap_or(i64::MAX));
                sqlx::query!("UPDATE accounts SET mail_quota = $2 WHERE id = $1", id, bytes)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::FilesQuotaSet { bytes } => {
                let bytes = bytes.map(|bytes| i64::try_from(bytes).unwrap_or(i64::MAX));
                sqlx::query!("UPDATE accounts SET files_quota = $2 WHERE id = $1", id, bytes)
                    .execute(&mut *connection)
                    .await?;
            }
            AccountEvent::SharedAdded { address, display_name } => {
                sqlx::query!(
                    "INSERT INTO accounts (id, tenant_id, display_name, primary_address, kind)
                     VALUES ($1, $2, $3, $4, 'shared')",
                    id,
                    tenant,
                    display_name,
                    address.as_str(),
                )
                .execute(&mut *connection)
                .await?;
                insert_address(connection, tenant, id, &address, true).await?;
                set_service(connection, id, Service::Mail, Some(ServiceState::On)).await?;
            }
            AccountEvent::MailAccessSet { grantee, mailbox, rights, send_as } => {
                let (account, group) = match grantee {
                    Principal::Account(account) => (Some(account), None),
                    Principal::Group(group) => (None, Some(group)),
                };
                sqlx::query!(
                    "DELETE FROM mail_access WHERE owner_id = $1 AND mailbox_id IS NOT DISTINCT FROM $2
                     AND grantee_account IS NOT DISTINCT FROM $3 AND grantee_group IS NOT DISTINCT FROM $4",
                    id,
                    mailbox,
                    account,
                    group,
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query!(
                    "INSERT INTO mail_access (owner_id, mailbox_id, grantee_account, grantee_group, rights, send_as, granted_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    id,
                    mailbox,
                    account,
                    group,
                    rights,
                    send_as,
                    event.created_at,
                )
                .execute(&mut *connection)
                .await?;
            }
            AccountEvent::MailAccessRemoved { grantee, mailbox } => {
                let (account, group) = match grantee {
                    Principal::Account(account) => (Some(account), None),
                    Principal::Group(group) => (None, Some(group)),
                };
                sqlx::query!(
                    "DELETE FROM mail_access WHERE owner_id = $1 AND mailbox_id IS NOT DISTINCT FROM $2
                     AND grantee_account IS NOT DISTINCT FROM $3 AND grantee_group IS NOT DISTINCT FROM $4",
                    id,
                    mailbox,
                    account,
                    group,
                )
                .execute(&mut *connection)
                .await?;
            }
            AccountEvent::CollectionAccessSet { grantee, collection_type, collection, level } => {
                let (account, group) = match grantee {
                    Principal::Account(account) => (Some(account), None),
                    Principal::Group(group) => (None, Some(group)),
                };
                sqlx::query!(
                    "DELETE FROM collection_access WHERE collection_id = $1
                     AND grantee_account IS NOT DISTINCT FROM $2 AND grantee_group IS NOT DISTINCT FROM $3",
                    collection,
                    account,
                    group,
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query!(
                    "INSERT INTO collection_access
                         (owner_id, collection_type, collection_id, grantee_account, grantee_group, level, granted_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    id,
                    collection_type,
                    collection,
                    account,
                    group,
                    level,
                    event.created_at,
                )
                .execute(&mut *connection)
                .await?;
            }
            AccountEvent::CollectionAccessRemoved { grantee, collection } => {
                let (account, group) = match grantee {
                    Principal::Account(account) => (Some(account), None),
                    Principal::Group(group) => (None, Some(group)),
                };
                sqlx::query!(
                    "DELETE FROM collection_access WHERE collection_id = $1
                     AND grantee_account IS NOT DISTINCT FROM $2 AND grantee_group IS NOT DISTINCT FROM $3",
                    collection,
                    account,
                    group,
                )
                .execute(&mut *connection)
                .await?;
            }
            AccountEvent::DriveAdded { display_name } => {
                sqlx::query!(
                    "INSERT INTO accounts (id, tenant_id, display_name, kind) VALUES ($1, $2, $3, 'drive')",
                    id,
                    tenant,
                    display_name,
                )
                .execute(&mut *connection)
                .await?;
                set_service(connection, id, Service::Files, Some(ServiceState::On)).await?;
            }
            AccountEvent::FileAccessSet { grantee, node, rights } => {
                let (account, group) = match grantee {
                    Principal::Account(account) => (Some(account), None),
                    Principal::Group(group) => (None, Some(group)),
                };
                sqlx::query!(
                    "DELETE FROM file_access WHERE owner_id = $1 AND node_id IS NOT DISTINCT FROM $2
                     AND grantee_account IS NOT DISTINCT FROM $3 AND grantee_group IS NOT DISTINCT FROM $4",
                    id,
                    node,
                    account,
                    group,
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query!(
                    "INSERT INTO file_access (owner_id, node_id, grantee_account, grantee_group, rights, granted_at)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    id,
                    node,
                    account,
                    group,
                    rights,
                    event.created_at,
                )
                .execute(&mut *connection)
                .await?;
            }
            AccountEvent::FileAccessRemoved { grantee, node } => {
                let (account, group) = match grantee {
                    Principal::Account(account) => (Some(account), None),
                    Principal::Group(group) => (None, Some(group)),
                };
                sqlx::query!(
                    "DELETE FROM file_access WHERE owner_id = $1 AND node_id IS NOT DISTINCT FROM $2
                     AND grantee_account IS NOT DISTINCT FROM $3 AND grantee_group IS NOT DISTINCT FROM $4",
                    id,
                    node,
                    account,
                    group,
                )
                .execute(&mut *connection)
                .await?;
            }
        }
    }
    Ok(())
}

async fn set_service(
    connection: &mut PgConnection,
    account: Uuid,
    service: Service,
    state: Option<ServiceState>,
) -> std::result::Result<(), Error> {
    match state {
        Some(state) => {
            sqlx::query!(
                "INSERT INTO account_services (account_id, service, state) VALUES ($1, $2, $3)
                 ON CONFLICT (account_id, service) DO UPDATE SET state = $3",
                account,
                service.as_str(),
                state.as_str(),
            )
            .execute(&mut *connection)
            .await?;
        }
        None => {
            sqlx::query!(
                "DELETE FROM account_services WHERE account_id = $1 AND service = $2",
                account,
                service.as_str()
            )
            .execute(&mut *connection)
            .await?;
        }
    }
    Ok(())
}

async fn insert_address(
    connection: &mut PgConnection,
    tenant: Uuid,
    account: Uuid,
    address: &Address,
    primary: bool,
) -> std::result::Result<(), Error> {
    let domain = address.domain();
    sqlx::query!(
        "INSERT INTO addresses (address, tenant_id, account_id, is_primary, domain) VALUES ($1, $2, $3, $4, $5)",
        address.as_str(),
        tenant,
        account,
        primary,
        domain.as_str(),
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// An account as lookups return it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub instance: Uuid,
    pub tenant: Uuid,
    pub id: Uuid,
    pub display_name: String,
    /// The login name to show: the primary address, else the username, else the contact address (RFC 0003, 2).
    pub address: String,
    /// It has a primary address on a domain of its tenant (RFC 0003, 1).
    pub native: bool,
    pub active: bool,
    /// A shared mailbox (RFC 0002, 12.1).
    pub shared: bool,
    /// A drive (RFC 0005, 12): a file store of the tenant.
    pub drive: bool,
}

fn existing(account: &Account) -> Result<()> {
    if account.exists { Ok(()) } else { Err(IdentityError::NotFound("the account")) }
}

/// Credentials only for accounts people log in as – not for shared mailboxes (RFC 0002, 12.1) or drives (RFC 0005,
/// 12).
pub(crate) fn with_login(account: &Account) -> Result<()> {
    if account.shared {
        Err(IdentityError::Refused("nobody logs in as a shared mailbox".into()))
    } else if account.drive {
        Err(IdentityError::Refused("nobody logs in as a drive".into()))
    } else {
        Ok(())
    }
}

/// The address must be on a domain the tenant has verified.
pub(crate) fn on_verified_domain(tenant: &Tenant, address: &Address) -> Result<()> {
    match tenant.domains.get(&address.domain()) {
        Some(domain) if domain.verified => Ok(()),
        _ => Err(IdentityError::Refused(format!("{} is not a verified domain of the tenant", address.domain()))),
    }
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

/// Runs password hashing off the async threads.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.expect("hashing does not panic")
}

impl Identity {
    pub(crate) async fn account_command(
        &self,
        instance: Uuid,
        tenant: Uuid,
        account: Uuid,
        creator: &str,
        address: Option<&Address>,
        decide: impl Fn(&Account) -> Result<Vec<AccountEvent>>,
    ) -> Result<()> {
        self.events
            .execute_with(instance, tenant, &account.to_string(), creator, decide, |c, e| Box::pin(project(c, e)))
            .await
            .map(drop)
            .map_err(|error| address_error(error, address))
    }

    /// The tenant an account belongs to and that tenant's instance.
    pub(crate) async fn account_owner(&self, account: Uuid) -> Result<(Uuid, Uuid)> {
        let row = sqlx::query!(
            "SELECT t.instance_id, a.tenant_id FROM accounts a JOIN tenants t ON t.id = a.tenant_id WHERE a.id = $1",
            account,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::NotFound("the account"))?;
        Ok((row.instance_id, row.tenant_id))
    }

    /// Creates an account of `tenant` with `address` as its login name; returns its id.
    pub async fn add_account(
        &self,
        tenant: Uuid,
        address: &Address,
        display_name: &str,
        creator: &str,
    ) -> Result<Uuid> {
        let display_name = valid_name(display_name)?;
        let instance = self.tenant_instance(tenant).await?;
        let tenant_state = self.tenant(instance, tenant).await?.state;
        if !tenant_state.active {
            return Err(IdentityError::Refused("the tenant is deactivated".into()));
        }
        on_verified_domain(&tenant_state, address)?;
        // The services the tenant's rules give a native account (RFC 0003, 4).
        let (on, requested) = crate::services::initial(&tenant_state.service_policies, true);
        let id = Uuid::now_v7();
        self.account_command(instance, tenant, id, creator, Some(address), |account| {
            if account.exists {
                return Err(IdentityError::Exists("the account"));
            }
            let mut events = vec![AccountEvent::Added {
                address: address.clone(),
                display_name: display_name.clone(),
                services: on.clone(),
            }];
            events.extend(requested.iter().map(|service| AccountEvent::ServiceRequested { service: *service }));
            Ok(events)
        })
        .await?;
        Ok(id)
    }

    pub async fn rename_account(&self, account: Uuid, display_name: &str, creator: &str) -> Result<()> {
        let display_name = valid_name(display_name)?;
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            existing(state)?;
            Ok(vec![AccountEvent::Renamed { display_name: display_name.clone() }])
        })
        .await
    }

    /// Sets how many bytes the account's emails may take; `None` for no limit. Emails already stored stay, even
    /// over a new, lower quota; only new ones are refused.
    pub async fn set_mail_quota(&self, account: Uuid, bytes: Option<u64>, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            existing(state)?;
            if state.mail_quota == bytes {
                return Ok(vec![]);
            }
            Ok(vec![AccountEvent::MailQuotaSet { bytes }])
        })
        .await
    }

    /// Sets how many bytes the account's files may take; `None` for the tenant's default (RFC 0005, 10). Files
    /// already stored stay, even over a new, lower quota; only more is refused.
    pub async fn set_files_quota(&self, account: Uuid, bytes: Option<u64>, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            existing(state)?;
            if state.files_quota == bytes {
                return Ok(vec![]);
            }
            Ok(vec![AccountEvent::FilesQuotaSet { bytes }])
        })
        .await
    }

    pub async fn add_alias(&self, account: Uuid, address: &Address, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        on_verified_domain(&self.tenant(instance, tenant).await?.state, address)?;
        self.account_command(instance, tenant, account, creator, Some(address), |state| {
            existing(state)?;
            if state.has_address(address) {
                return Err(IdentityError::Exists("the address"));
            }
            Ok(vec![AccountEvent::AliasAdded { address: address.clone() }])
        })
        .await
    }

    /// Removes an alias; the primary address cannot be removed – make another address primary first.
    pub async fn remove_alias(&self, account: Uuid, address: &Address, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            existing(state)?;
            if state.primary.as_ref() == Some(address) {
                return Err(IdentityError::Refused("the primary address cannot be removed".into()));
            }
            if !state.aliases.contains(address) {
                return Err(IdentityError::NotFound("the alias"));
            }
            Ok(vec![AccountEvent::AliasRemoved { address: address.clone() }])
        })
        .await
    }

    /// Makes an alias the primary address – the login name; the former primary address stays as an alias.
    pub async fn set_primary_address(&self, account: Uuid, address: &Address, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        self.account_command(instance, tenant, account, creator, None, |state| {
            existing(state)?;
            if state.primary.as_ref() == Some(address) {
                return Ok(Vec::new());
            }
            if !state.aliases.contains(address) {
                return Err(IdentityError::NotFound("the alias"));
            }
            Ok(vec![AccountEvent::PrimaryAddressChanged { address: address.clone() }])
        })
        .await
    }

    /// Deactivates or reactivates an account; nothing happens if it is already in that state.
    pub async fn set_account_active(&self, account: Uuid, active: bool, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        if !active {
            self.keep_an_admin(Some(tenant), instance, |held| held.account == account).await?;
        }
        self.account_command(instance, tenant, account, creator, None, |state| {
            existing(state)?;
            Ok(match (state.active, active) {
                (true, false) => vec![AccountEvent::Deactivated],
                (false, true) => vec![AccountEvent::Reactivated],
                _ => Vec::new(),
            })
        })
        .await
    }

    /// Sets the account's password. The event records that it changed; the hash goes to `account_passwords` in the
    /// same transaction.
    pub async fn set_password(&self, account: Uuid, password: &str, creator: &str) -> Result<()> {
        let password = password.to_owned();
        let hash = blocking(move || password::hash(&password)).await?;
        self.set_password_hash(account, hash, creator).await
    }

    /// Stores a hash made by [`password::hash`] – for a registration, which hashed the password when it began.
    pub(crate) async fn set_password_hash(&self, account: Uuid, hash: String, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        let store_hash = inline(move |connection, events| {
            let hash = hash.clone();
            Box::pin(async move {
                project(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO account_passwords (account_id, hash) VALUES ($1, $2)
                     ON CONFLICT (account_id) DO UPDATE SET hash = excluded.hash, changed_at = now()",
                    account,
                    hash,
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        self.events
            .execute_with(
                instance,
                tenant,
                &account.to_string(),
                creator,
                |state: &Account| {
                    existing(state)?;
                    with_login(state)?;
                    Ok(vec![AccountEvent::PasswordChanged])
                },
                store_hash,
            )
            .await
            .map(drop)
            .map_err(|error| address_error(error, None))
    }

    pub async fn account(&self, account: Uuid) -> Result<AccountInfo> {
        self.account_where(None, Some(account)).await?.ok_or(IdentityError::NotFound("the account"))
    }

    /// The account an address – primary or alias – belongs to.
    pub async fn account_by_address(&self, address: &Address) -> Result<Option<AccountInfo>> {
        self.account_where(Some(address), None).await
    }

    async fn account_where(&self, address: Option<&Address>, id: Option<Uuid>) -> Result<Option<AccountInfo>> {
        let row = sqlx::query!(
            r#"SELECT t.instance_id, a.tenant_id, a.id, a.display_name, coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!", a.primary_address IS NOT NULL AS "native!", a.active, a.kind
             FROM accounts a JOIN tenants t ON t.id = a.tenant_id
             WHERE ($1::text IS NOT NULL AND a.id = (SELECT account_id FROM addresses WHERE address = $1))
                OR ($2::uuid IS NOT NULL AND a.id = $2)"#,
            address.map(Address::as_str),
            id,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        Ok(row.map(|row| AccountInfo {
            instance: row.instance_id,
            tenant: row.tenant_id,
            id: row.id,
            display_name: row.display_name,
            address: row.primary_address,
            native: row.native,
            active: row.active,
            shared: row.kind == "shared",
            drive: row.kind == "drive",
        }))
    }

    /// The addresses of an account, each with whether it is the primary one: the primary first, then the aliases.
    pub async fn account_addresses(&self, account: Uuid) -> Result<Vec<(String, bool)>> {
        let rows = sqlx::query!(
            "SELECT address, is_primary FROM addresses WHERE account_id = $1 ORDER BY is_primary DESC, address",
            account
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows.into_iter().map(|row| (row.address, row.is_primary)).collect())
    }

    pub async fn accounts(&self, tenant: Uuid) -> Result<Vec<AccountInfo>> {
        let rows = sqlx::query!(
            r#"SELECT t.instance_id, a.tenant_id, a.id, a.display_name, coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!", a.primary_address IS NOT NULL AS "native!", a.active, a.kind
             FROM accounts a JOIN tenants t ON t.id = a.tenant_id
             WHERE a.tenant_id = $1 ORDER BY 5"#,
            tenant,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(rows
            .into_iter()
            .map(|row| AccountInfo {
                instance: row.instance_id,
                tenant: row.tenant_id,
                id: row.id,
                display_name: row.display_name,
                address: row.primary_address,
                native: row.native,
                active: row.active,
                shared: row.kind == "shared",
                drive: row.kind == "drive",
            })
            .collect())
    }

    /// Checks a login at `instance` with a login name (RFC 0003, 2: an address, a username, a verified contact
    /// address) and a password. Every failure that could tell whether an account exists is the same
    /// `InvalidCredentials`, and takes as long; only after a correct password does the answer say that the account or
    /// its tenant is deactivated. A hash made with older parameters is replaced.
    pub async fn authenticate(&self, instance: Uuid, login: &str, password: &str) -> Result<AccountInfo> {
        let row = match self.find_login(instance, login).await? {
            Some(account) => sqlx::query!(
                r#"SELECT t.instance_id, a.tenant_id, a.id, a.display_name,
                          coalesce(a.primary_address, a.username, a.email, '') AS "primary_address!",
                          a.primary_address IS NOT NULL AS "native!", a.active, a.kind,
                          t.active AS tenant_active, p.hash AS "hash?"
                   FROM accounts a
                   JOIN tenants t ON t.id = a.tenant_id
                   LEFT JOIN account_passwords p ON p.account_id = a.id
                   WHERE a.id = $1"#,
                account,
            )
            .fetch_optional(self.pool())
            .await
            .map_err(store_error)?,
            None => None,
        };
        let hash = row.as_ref().and_then(|row| row.hash.clone());
        let attempt = password.to_owned();
        let checked = hash.clone();
        let matches = blocking(move || password::verify(checked.as_deref(), &attempt)).await;
        let Some(row) = row.filter(|_| matches) else { return Err(IdentityError::InvalidCredentials) };
        if !row.active || !row.tenant_active {
            return Err(IdentityError::AccountDeactivated);
        }
        if let Some(hash) = hash.filter(|hash| password::needs_rehash(hash)) {
            let password = password.to_owned();
            match blocking(move || password::hash(&password)).await {
                Ok(new) => {
                    let updated = sqlx::query!(
                        "UPDATE account_passwords SET hash = $2 WHERE account_id = $1 AND hash = $3",
                        row.id,
                        new,
                        hash,
                    )
                    .execute(self.pool())
                    .await;
                    if let Err(error) = updated {
                        tracing::warn!(%error, "could not store the rehashed password");
                    }
                }
                Err(error) => tracing::warn!(%error, "could not rehash the password"),
            }
        }
        Ok(AccountInfo {
            instance: row.instance_id,
            tenant: row.tenant_id,
            id: row.id,
            display_name: row.display_name,
            address: row.primary_address,
            native: row.native,
            active: row.active,
            shared: row.kind == "shared",
            drive: row.kind == "drive",
        })
    }
}

/// Like the tenant and instance commands: a broken uniqueness rule on an address means it is taken.
pub(crate) fn address_error(
    error: kernoid_events::aggregate::CommandError<IdentityError>,
    address: Option<&Address>,
) -> IdentityError {
    use kernoid_events::aggregate::CommandError;
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(Error::Database(sqlx::Error::Database(database)))
            if database.is_unique_violation() && address.is_some() =>
        {
            IdentityError::AddressTaken(address.expect("checked").clone())
        }
        CommandError::Store(error) => IdentityError::Store(error),
    }
}

#[cfg(test)]
mod tests {
    use kernoid_events::aggregate::DomainEvent;

    use super::*;

    #[test]
    fn accounts_from_before_services_have_mail() {
        let stored = serde_json::json!({ "address": "alice@firma.de", "display_name": "Alice" });
        let event = AccountEvent::decode("account.added", 1, stored).unwrap();
        let AccountEvent::Added { services, .. } = event else { panic!("{event:?}") };
        assert_eq!(services, [Service::Mail]);
    }
}
