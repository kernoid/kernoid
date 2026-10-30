// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end encryption (RFC 0006): an account's OpenPGP keys, made by its client – kernoid takes only the public key
//! and protected copies of the secret key (4.2) –, whether its mail is encrypted on arrival (5.1), and its tenant's
//! policy and recovery key (8). Public keys are read through `kernoid_e2e`, which checks their self-signatures.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use kernoid_e2e::{Kind, PublicKey};
use kernoid_events::{InlineFuture, aggregate::CommandError, inline};
use uuid::Uuid;

use crate::{
    Address, Identity, IdentityError, Result,
    account::{Account, AccountEvent, project},
    role::{Admin, Permission},
    tenant::{E2ePolicy, E2eRule, Tenant, TenantEvent},
};

/// Protected copies one key may have.
const MAX_COPIES: usize = 20;
/// The largest public key or protected copy taken (the tables' limit).
const MAX_BYTES: usize = 65_536;

/// A protected copy of a secret key, as the client made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCopy {
    pub label: String,
    pub protected: Vec<u8>,
    /// For a passkey: what its PRF extension is evaluated with.
    pub salt: Option<Vec<u8>>,
}

/// One of an account's keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpKeyInfo {
    pub fingerprint: String,
    pub kind: String,
    pub public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
    pub copies: Vec<KeyCopy>,
}

/// Someone's public key in use, as others look it up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    pub fingerprint: String,
    pub kind: String,
    pub public_key: Vec<u8>,
}

/// What an account may and does encrypt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eSettings {
    pub mail: bool,
    pub policy: E2ePolicy,
    /// The tenant's recovery key: fingerprint and public key.
    pub recovery_key: Option<(String, Vec<u8>)>,
}

fn store_error(error: sqlx::Error) -> IdentityError {
    IdentityError::Store(error.into())
}

fn command_error(error: CommandError<IdentityError>) -> IdentityError {
    match error {
        CommandError::Refused(error) => error,
        CommandError::Store(error) => IdentityError::Store(error),
    }
}

fn refused(message: &str) -> IdentityError {
    IdentityError::Refused(message.to_owned())
}

/// A label of RFC 0006, 4.2: `recovery`, `tenant`, `passkey:<credential id>`, `device:<id>`.
fn checked_label(label: &str) -> Result<()> {
    let id_ok = |id: &str, max: usize| {
        !id.is_empty() && id.len() <= max && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let ok = match label.split_once(':') {
        None => matches!(label, "recovery" | "tenant"),
        Some(("passkey", id)) => id_ok(id, 200),
        Some(("device", id)) => id_ok(id, 64),
        Some(_) => false,
    };
    if ok { Ok(()) } else { Err(refused("a copy's label is recovery, tenant, passkey:<id> or device:<id>")) }
}

fn checked_copy(copy: &KeyCopy) -> Result<()> {
    checked_label(&copy.label)?;
    if copy.protected.is_empty() || copy.protected.len() > MAX_BYTES {
        return Err(refused("a protected copy has 1 to 65536 bytes"));
    }
    match &copy.salt {
        Some(salt) if !(16..=64).contains(&salt.len()) => Err(refused("a salt has 16 to 64 bytes")),
        None if copy.label.starts_with("passkey:") => Err(refused("a passkey's copy needs the salt of its PRF")),
        _ => Ok(()),
    }
}

/// Reads a public key and checks what kernoid needs of it: a kind of RFC 0006, 4.1, and a subkey to encrypt to.
fn checked_key(public_key: &[u8]) -> Result<(PublicKey, Kind)> {
    if public_key.len() > MAX_BYTES {
        return Err(refused("a public key has at most 65536 bytes"));
    }
    let key = PublicKey::parse(public_key).map_err(|error| IdentityError::Refused(error.to_string()))?;
    let kind = key.kind().ok_or_else(|| refused("the key is neither v6 (pqc) nor v4 (compatible)"))?;
    if !key.can_encrypt() {
        return Err(refused("the key has no subkey to encrypt to"));
    }
    Ok((key, kind))
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Pqc => "pqc",
        Kind::Compatible => "compatible",
    }
}

fn policy_of(row_mail: &str, row_vaults: &str, row_collections: &str, recovery: bool) -> E2ePolicy {
    E2ePolicy {
        mail: E2eRule::parse(row_mail).unwrap_or_default(),
        vaults: E2eRule::parse(row_vaults).unwrap_or_default(),
        collections: E2eRule::parse(row_collections).unwrap_or_default(),
        recovery,
    }
}

impl Identity {
    /// Adds a key the account's client made, with protected copies of its secret key; the key in use until now is
    /// retired. Every address of the key must be the account's; at least one copy is needed, and the `tenant` copy
    /// if the tenant recovers keys. Returns the fingerprint.
    pub async fn add_openpgp_key(
        &self,
        account: Uuid,
        public_key: &[u8],
        copies: Vec<KeyCopy>,
        creator: &str,
    ) -> Result<String> {
        let (key, kind) = checked_key(public_key)?;
        if copies.is_empty() || copies.len() > MAX_COPIES {
            return Err(IdentityError::Refused(format!("a key has 1 to {MAX_COPIES} protected copies")));
        }
        copies.iter().try_for_each(checked_copy)?;
        let labels: BTreeSet<String> = copies.iter().map(|c| c.label.clone()).collect();
        if labels.len() != copies.len() {
            return Err(refused("each label once"));
        }
        let addresses = key
            .addresses()
            .iter()
            .map(|a| Address::parse(a).map_err(|_| refused("each user id of the key is an address")))
            .collect::<Result<Vec<_>>>()?;
        if addresses.is_empty() {
            return Err(refused("the key names none of the account's addresses"));
        }
        let (instance, tenant) = self.account_owner(account).await?;
        let policy = self.e2e_settings(account).await?;
        if policy.policy.recovery && !labels.contains("tenant") {
            return Err(refused("the tenant recovers keys: add the copy for its recovery key"));
        }
        let fingerprint = key.fingerprint();
        let stored = key.to_bytes().map_err(|error| IdentityError::Refused(error.to_string()))?;
        let (fp, kind_text) = (fingerprint.clone(), kind_name(kind).to_owned());
        let store = inline(move |connection, events| {
            let (fp, kind_text, stored, copies) = (fp.clone(), kind_text.clone(), stored.clone(), copies.clone());
            Box::pin(async move {
                project(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO openpgp_keys (fingerprint, account_id, tenant_id, kind, public_key)
                     VALUES ($1, $2, $3, $4, $5)",
                    fp,
                    account,
                    tenant,
                    kind_text,
                    stored,
                )
                .execute(&mut *connection)
                .await?;
                for copy in copies {
                    sqlx::query!(
                        "INSERT INTO openpgp_key_copies (fingerprint, label, protected, salt) VALUES ($1, $2, $3, $4)",
                        fp,
                        copy.label,
                        copy.protected,
                        copy.salt,
                    )
                    .execute(&mut *connection)
                    .await?;
                }
                Ok(())
            }) as InlineFuture<'_>
        });
        let labels: Vec<String> = labels.into_iter().collect();
        let (fp, kind_text) = (fingerprint.clone(), kind_name(kind).to_owned());
        self.events
            .execute_with(
                instance,
                tenant,
                &account.to_string(),
                creator,
                |state: &Account| {
                    if !state.exists {
                        return Err(IdentityError::NotFound("the account"));
                    }
                    crate::account::with_login(state)?;
                    if !addresses.iter().all(|a| state.has_address(a)) {
                        return Err(refused("every address of the key must be the account's"));
                    }
                    if state.openpgp_keys.contains_key(&fp) {
                        return Err(IdentityError::Exists("the key"));
                    }
                    let mut events: Vec<AccountEvent> = state
                        .openpgp_keys
                        .iter()
                        .filter(|(_, retired)| !**retired)
                        .map(|(fingerprint, _)| AccountEvent::OpenPgpKeyRetired { fingerprint: fingerprint.clone() })
                        .collect();
                    events.push(AccountEvent::OpenPgpKeyAdded { fingerprint: fp.clone(), kind: kind_text.clone() });
                    events.extend(labels.iter().map(|label| AccountEvent::OpenPgpKeyCopySet {
                        fingerprint: fp.clone(),
                        label: label.clone(),
                    }));
                    Ok(events)
                },
                store,
            )
            .await
            .map_err(command_error)?;
        Ok(fingerprint)
    }

    /// Retires a key: it stays to decrypt, nothing is encrypted to it again. Mail encryption needs a key in use, so
    /// retiring the last one switches it off – unless the tenant requires it.
    pub async fn retire_openpgp_key(&self, account: Uuid, fingerprint: &str, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        let required = self.e2e_settings(account).await?.policy.mail == E2eRule::Required;
        self.account_command(instance, tenant, account, creator, None, |state| {
            match state.openpgp_keys.get(fingerprint) {
                None => Err(IdentityError::NotFound("the key")),
                Some(true) => Ok(Vec::new()),
                Some(false) => {
                    if state.mail_e2e && required {
                        return Err(refused("the tenant requires encrypted mail: add a new key instead"));
                    }
                    let mut events = vec![AccountEvent::OpenPgpKeyRetired { fingerprint: fingerprint.to_owned() }];
                    if state.mail_e2e {
                        events.push(AccountEvent::MailE2eSet { on: false });
                    }
                    Ok(events)
                }
            }
        })
        .await
    }

    /// Adds or replaces a protected copy of one of the account's keys.
    pub async fn set_openpgp_key_copy(
        &self,
        account: Uuid,
        fingerprint: &str,
        copy: KeyCopy,
        creator: &str,
    ) -> Result<()> {
        checked_copy(&copy)?;
        let (instance, tenant) = self.account_owner(account).await?;
        let (fp, label) = (fingerprint.to_owned(), copy.label.clone());
        let store = inline(move |connection, events| {
            let (fp, copy) = (fp.clone(), copy.clone());
            Box::pin(async move {
                project(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO openpgp_key_copies (fingerprint, label, protected, salt) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (fingerprint, label) DO UPDATE SET protected = $3, salt = $4, created_at = now()",
                    fp,
                    copy.label,
                    copy.protected,
                    copy.salt,
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        let fp = fingerprint.to_owned();
        self.events
            .execute_with(
                instance,
                tenant,
                &account.to_string(),
                creator,
                |state: &Account| {
                    if !state.openpgp_keys.contains_key(&fp) {
                        return Err(IdentityError::NotFound("the key"));
                    }
                    let known = state.openpgp_copies.contains(&(fp.clone(), label.clone()));
                    let count = state.openpgp_copies.iter().filter(|(f, _)| *f == fp).count();
                    if !known && count >= MAX_COPIES {
                        return Err(IdentityError::Refused(format!("a key has at most {MAX_COPIES} protected copies")));
                    }
                    Ok(vec![AccountEvent::OpenPgpKeyCopySet { fingerprint: fp.clone(), label: label.clone() }])
                },
                store,
            )
            .await
            .map_err(command_error)?;
        Ok(())
    }

    /// Removes a protected copy; the last one of a key in use stays (the key would be lost), and so does the `tenant`
    /// copy while the tenant recovers keys.
    pub async fn remove_openpgp_key_copy(
        &self,
        account: Uuid,
        fingerprint: &str,
        label: &str,
        creator: &str,
    ) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        let recovery = self.e2e_settings(account).await?.policy.recovery;
        self.account_command(instance, tenant, account, creator, None, |state| {
            let entry = (fingerprint.to_owned(), label.to_owned());
            if !state.openpgp_copies.contains(&entry) {
                return Err(IdentityError::NotFound("the copy"));
            }
            let in_use = state.openpgp_keys.get(fingerprint) == Some(&false);
            let count = state.openpgp_copies.iter().filter(|(f, _)| f == fingerprint).count();
            if in_use && count == 1 {
                return Err(refused("the last copy of the key in use stays: without it the key is lost"));
            }
            if in_use && recovery && label == "tenant" {
                return Err(refused("the tenant recovers keys: its copy stays"));
            }
            Ok(vec![AccountEvent::OpenPgpKeyCopyRemoved { fingerprint: entry.0, label: entry.1 }])
        })
        .await
    }

    /// The account's keys, the one in use first, with their protected copies.
    pub async fn openpgp_keys(&self, account: Uuid) -> Result<Vec<OpenPgpKeyInfo>> {
        let keys = sqlx::query!(
            "SELECT fingerprint, kind, public_key, created_at, retired_at FROM openpgp_keys WHERE account_id = $1
             ORDER BY retired_at IS NOT NULL, created_at DESC",
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        let copies = sqlx::query!(
            "SELECT c.fingerprint, c.label, c.protected, c.salt FROM openpgp_key_copies c
             JOIN openpgp_keys k ON k.fingerprint = c.fingerprint WHERE k.account_id = $1 ORDER BY c.label",
            account,
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)?;
        Ok(keys
            .into_iter()
            .map(|key| OpenPgpKeyInfo {
                copies: copies
                    .iter()
                    .filter(|c| c.fingerprint == key.fingerprint)
                    .map(|c| KeyCopy { label: c.label.clone(), protected: c.protected.clone(), salt: c.salt.clone() })
                    .collect(),
                fingerprint: key.fingerprint,
                kind: key.kind,
                public_key: key.public_key,
                created_at: key.created_at,
                retired_at: key.retired_at,
            })
            .collect())
    }

    /// Switches encryption of the account's mail on arrival on or off (RFC 0006, 5.1), as its tenant allows.
    pub async fn set_mail_e2e(&self, account: Uuid, on: bool, creator: &str) -> Result<()> {
        let (instance, tenant) = self.account_owner(account).await?;
        let rule = self.e2e_settings(account).await?.policy.mail;
        self.account_command(instance, tenant, account, creator, None, |state| {
            if !state.exists {
                return Err(IdentityError::NotFound("the account"));
            }
            if state.mail_e2e == on {
                return Ok(Vec::new());
            }
            if on && rule == E2eRule::Forbidden {
                return Err(refused("the tenant does not allow encrypted mail"));
            }
            if !on && rule == E2eRule::Required {
                return Err(refused("the tenant requires encrypted mail"));
            }
            if on && !state.openpgp_keys.values().any(|retired| !retired) {
                return Err(refused("encrypted mail needs a key"));
            }
            Ok(vec![AccountEvent::MailE2eSet { on }])
        })
        .await
    }

    /// What the account encrypts, what its tenant allows, and the tenant's recovery key.
    pub async fn e2e_settings(&self, account: Uuid) -> Result<E2eSettings> {
        let row = sqlx::query!(
            "SELECT a.mail_e2e, t.e2e_mail, t.e2e_vaults, t.e2e_collections, t.e2e_recovery,
                    r.fingerprint AS \"recovery_fingerprint?\", r.public_key AS \"recovery_key?\"
             FROM accounts a JOIN tenants t ON t.id = a.tenant_id
             LEFT JOIN tenant_recovery_keys r ON r.tenant_id = t.id WHERE a.id = $1",
            account,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::NotFound("the account"))?;
        Ok(E2eSettings {
            mail: row.mail_e2e,
            policy: policy_of(&row.e2e_mail, &row.e2e_vaults, &row.e2e_collections, row.e2e_recovery),
            recovery_key: row.recovery_fingerprint.zip(row.recovery_key),
        })
    }

    /// The key in use of the account with `address` in `instance`, if it has one – for the apps' lookup.
    pub async fn published_key(&self, instance: Uuid, address: &Address) -> Result<Option<PublishedKey>> {
        let row = sqlx::query!(
            "SELECT k.fingerprint, k.kind, k.public_key FROM addresses ad
             JOIN accounts a ON a.id = ad.account_id JOIN tenants t ON t.id = a.tenant_id
             JOIN openpgp_keys k ON k.account_id = a.id AND k.retired_at IS NULL
             WHERE ad.address = $1 AND t.instance_id = $2 AND a.active",
            address.as_str(),
            instance,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?;
        Ok(row.map(|r| PublishedKey { fingerprint: r.fingerprint, kind: r.kind, public_key: r.public_key }))
    }

    /// The keys in use for a local part on a verified domain of any tenant – what the Web Key Directory serves
    /// (RFC 0006, 4.4). `local` is compared as WKD does: in lower case.
    pub async fn wkd_keys(&self, domain: &str, local: &str) -> Result<Vec<Vec<u8>>> {
        let address = format!("{}@{}", local.to_lowercase(), domain.to_lowercase());
        sqlx::query_scalar!(
            "SELECT k.public_key FROM addresses ad
             JOIN accounts a ON a.id = ad.account_id
             JOIN tenant_domains d ON d.tenant_id = a.tenant_id AND d.domain = $2 AND d.verified
             JOIN openpgp_keys k ON k.account_id = a.id AND k.retired_at IS NULL
             WHERE lower(ad.address) = $1 AND a.active",
            address,
            domain.to_lowercase(),
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)
    }

    /// The local parts on a verified domain whose accounts have a key in use – for WKD requests without `l=`.
    pub async fn wkd_local_parts(&self, domain: &str) -> Result<Vec<String>> {
        sqlx::query_scalar!(
            "SELECT DISTINCT lower(split_part(ad.address, '@', 1)) AS \"local!\" FROM addresses ad
             JOIN accounts a ON a.id = ad.account_id
             JOIN tenant_domains d ON d.tenant_id = a.tenant_id AND d.domain = $1 AND d.verified
             JOIN openpgp_keys k ON k.account_id = a.id AND k.retired_at IS NULL
             WHERE lower(split_part(ad.address, '@', 2)) = $1 AND a.active",
            domain.to_lowercase(),
        )
        .fetch_all(self.pool())
        .await
        .map_err(store_error)
    }

    /// Whether `domain` is a verified domain of a tenant – WKD answers only for those.
    pub async fn wkd_domain(&self, domain: &str) -> Result<bool> {
        sqlx::query_scalar!(
            "SELECT EXISTS (SELECT 1 FROM tenant_domains WHERE domain = $1 AND verified) AS \"exists!\"",
            domain.to_lowercase(),
        )
        .fetch_one(self.pool())
        .await
        .map_err(store_error)
    }

    /// The tenant's end-to-end policy and recovery key.
    pub async fn e2e_policy(&self, tenant: Uuid) -> Result<(E2ePolicy, Option<(String, Vec<u8>)>)> {
        let row = sqlx::query!(
            "SELECT t.e2e_mail, t.e2e_vaults, t.e2e_collections, t.e2e_recovery,
                    r.fingerprint AS \"recovery_fingerprint?\", r.public_key AS \"recovery_key?\"
             FROM tenants t LEFT JOIN tenant_recovery_keys r ON r.tenant_id = t.id WHERE t.id = $1",
            tenant,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .ok_or(IdentityError::NotFound("the tenant"))?;
        Ok((
            policy_of(&row.e2e_mail, &row.e2e_vaults, &row.e2e_collections, row.e2e_recovery),
            row.recovery_fingerprint.zip(row.recovery_key),
        ))
    }

    /// Sets the tenant's policy. Recovery through the tenant needs its recovery key first.
    pub async fn set_e2e_policy(&self, tenant: Uuid, policy: E2ePolicy, creator: &str) -> Result<()> {
        let instance = self.tenant_instance(tenant).await?;
        self.tenant_command(instance, tenant, creator, None, |state: &Tenant| {
            if !state.exists {
                return Err(IdentityError::NotFound("the tenant"));
            }
            if policy.recovery && state.recovery_key.is_none() {
                return Err(refused("recovery through the tenant needs its recovery key"));
            }
            if state.e2e_policy == policy {
                return Ok(Vec::new());
            }
            Ok(vec![TenantEvent::E2ePolicySet {
                mail: policy.mail,
                vaults: policy.vaults,
                collections: policy.collections,
                recovery: policy.recovery,
            }])
        })
        .await
    }

    /// Sets the tenant's recovery key – a public key an administrator's app made. Returns its fingerprint.
    pub async fn set_recovery_key(&self, tenant: Uuid, public_key: &[u8], creator: &str) -> Result<String> {
        let (key, _) = checked_key(public_key)?;
        let instance = self.tenant_instance(tenant).await?;
        let fingerprint = key.fingerprint();
        let stored = key.to_bytes().map_err(|error| IdentityError::Refused(error.to_string()))?;
        let fp = fingerprint.clone();
        let store = inline(move |connection, events| {
            let (fp, stored) = (fp.clone(), stored.clone());
            Box::pin(async move {
                crate::tenant::project(connection, events).await?;
                sqlx::query!(
                    "INSERT INTO tenant_recovery_keys (tenant_id, fingerprint, public_key) VALUES ($1, $2, $3)
                     ON CONFLICT (tenant_id) DO UPDATE SET fingerprint = $2, public_key = $3, created_at = now()",
                    tenant,
                    fp,
                    stored,
                )
                .execute(&mut *connection)
                .await?;
                Ok(())
            }) as InlineFuture<'_>
        });
        let fp = fingerprint.clone();
        self.events
            .execute_with(
                instance,
                tenant,
                &tenant.to_string(),
                creator,
                |state: &Tenant| {
                    if !state.exists {
                        return Err(IdentityError::NotFound("the tenant"));
                    }
                    if state.recovery_key.as_ref() == Some(&fp) {
                        return Ok(Vec::new());
                    }
                    Ok(vec![TenantEvent::RecoveryKeySet { fingerprint: fp.clone() }])
                },
                store,
            )
            .await
            .map_err(command_error)?;
        Ok(fingerprint)
    }

    /// The `tenant` copy of an account's key in use – the secret key encrypted to the tenant's recovery key (RFC 0006,
    /// 8.2): useless without that key's secret, which only the administrators hold. Needs `accounts.manage`.
    pub async fn admin_recovery_copy(&self, admin: &Admin, account: Uuid) -> Result<(String, Vec<u8>)> {
        admin.require(Permission::AccountsManage)?;
        self.admin_account(admin, account).await?;
        sqlx::query!(
            "SELECT k.fingerprint, c.protected FROM openpgp_keys k
             JOIN openpgp_key_copies c ON c.fingerprint = k.fingerprint AND c.label = 'tenant'
             WHERE k.account_id = $1 AND k.retired_at IS NULL",
            account,
        )
        .fetch_optional(self.pool())
        .await
        .map_err(store_error)?
        .map(|row| (row.fingerprint, row.protected))
        .ok_or(IdentityError::NotFound("a copy for the recovery key"))
    }

    pub async fn admin_e2e_policy(&self, admin: &Admin) -> Result<(E2ePolicy, Option<(String, Vec<u8>)>)> {
        admin.require(Permission::DirectoryRead)?;
        self.e2e_policy(admin.tenant()).await
    }

    pub async fn admin_set_e2e_policy(&self, admin: &Admin, policy: E2ePolicy) -> Result<()> {
        admin.require(Permission::TenantManage)?;
        self.set_e2e_policy(admin.tenant(), policy, &admin.creator()).await
    }

    pub async fn admin_set_recovery_key(&self, admin: &Admin, public_key: &[u8]) -> Result<String> {
        admin.require(Permission::TenantManage)?;
        self.set_recovery_key(admin.tenant(), public_key, &admin.creator()).await
    }
}

/// The hash WKD names a local part by (draft-koch-openpgp-webkey-service, 3.1): SHA-1 of its lower case, z-base-32.
pub fn wkd_hash(local: &str) -> String {
    use sha1::{Digest, Sha1};
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let digest = Sha1::digest(local.to_lowercase().as_bytes());
    let mut out = String::with_capacity(32);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in digest {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_those_of_the_rfc() {
        for label in ["recovery", "tenant", "passkey:AbC-_1", "device:laptop"] {
            assert!(checked_label(label).is_ok(), "{label}");
        }
        for label in ["", "other", "passkey:", "passkey:a b", "device:x/y", "recovery:1"] {
            assert!(checked_label(label).is_err(), "{label}");
        }
    }

    #[test]
    fn the_wkd_hash_is_the_drafts() {
        // The example of draft-koch-openpgp-webkey-service, 3.1: Joe.Doe@Example.ORG.
        assert_eq!(wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    }
}
