// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's JMAP extension for end-to-end encryption (`https://kernoid.dev/jmap/openpgp`, RFC 0006, 4.3): the
//! caller's own keys with the protected copies of their secret keys (`OpenPgpKey/get`, `/set`), the public keys of
//! others (`OpenPgpKey/lookup`: local accounts from the directory, others through their domain's Web Key Directory),
//! and the account's settings with its tenant's policy (`E2eSettings/get`, `/set`). Secret keys are never here
//! unprotected: the client makes them and protects them before they come.

use std::{
    future::Future,
    hash::{DefaultHasher, Hash, Hasher},
    pin::Pin,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::SecondsFormat;
use kernoid_identity::{
    Address, Identity, IdentityError,
    openpgp::{E2eSettings, KeyCopy, OpenPgpKeyInfo},
    tenant::E2eRule,
};
use serde_json::{Map, Value, json};

use crate::{
    mailbox::{ids, invalid_properties},
    request::{Context, MethodError, MethodResult},
};

pub const OPENPGP: &str = "https://kernoid.dev/jmap/openpgp";
const SINGLETON: &str = "singleton";
/// Addresses one lookup may ask for.
const MAX_LOOKUP: usize = 50;

/// Where keys of addresses outside the instance come from: their domain's Web Key Directory, asked by the server
/// (through its outbound client – public addresses over HTTPS only). The public keys found, binary.
pub trait KeyDirectory: Send + Sync {
    fn lookup<'a>(&'a self, address: &'a str) -> Pin<Box<dyn Future<Output = Vec<Vec<u8>>> + Send + 'a>>;
}

fn b64(bytes: &[u8]) -> Value {
    json!(STANDARD.encode(bytes))
}

pub(crate) fn b64_or_null(bytes: Option<&[u8]>) -> Value {
    bytes.map_or(Value::Null, b64)
}

/// A calendar or address book just made, made encrypted if `kernoid:newEncrypted` (`publicKey`, `sealed`: the secret
/// key wrapped for the creator) asks for it (RFC 0006, 7). If that fails, the collection goes again.
pub(crate) async fn seal_new(
    groupware: &kernoid_groupware::Groupware,
    owner: uuid::Uuid,
    creator: uuid::Uuid,
    id: uuid::Uuid,
    object: &Map<String, Value>,
) -> Result<uuid::Uuid, kernoid_groupware::GroupwareError> {
    let Some(encrypted) = object.get("kernoid:newEncrypted").and_then(Value::as_object) else { return Ok(id) };
    let field = |key: &str| encrypted.get(key).and_then(Value::as_str).and_then(|text| STANDARD.decode(text).ok());
    let outcome = match (field("publicKey"), field("sealed")) {
        (Some(public), Some(sealed)) => groupware.seal_collection(owner, id, &public, creator, &sealed).await,
        _ => Err(kernoid_groupware::GroupwareError::Invalid("kernoid:newEncrypted has publicKey and sealed".into())),
    };
    if let Err(error) = outcome {
        let _ = groupware.destroy_calendar(owner, id, true).await;
        let _ = groupware.destroy_addressbook(owner, id, true).await;
        return Err(error);
    }
    Ok(id)
}

fn bytes(value: &Value, what: &str) -> Result<Vec<u8>, Value> {
    value
        .as_str()
        .and_then(|text| STANDARD.decode(text).ok())
        .ok_or_else(|| invalid_properties(format!("{what} is base64")))
}

fn copy_object(copy: &KeyCopy) -> Value {
    json!({ "protected": b64(&copy.protected), "salt": copy.salt.as_deref().map(b64) })
}

fn key_object(key: &OpenPgpKeyInfo) -> Value {
    let copies: Map<String, Value> = key.copies.iter().map(|c| (c.label.clone(), copy_object(c))).collect();
    json!({
        "id": key.fingerprint,
        "kind": key.kind,
        "publicKey": b64(&key.public_key),
        "created": key.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        "retired": key.retired_at.map(|at| at.to_rfc3339_opts(SecondsFormat::Secs, true)),
        "copies": copies,
    })
}

fn copy_from(label: &str, value: &Value) -> Result<KeyCopy, Value> {
    let object = value.as_object().ok_or_else(|| invalid_properties("a copy is an object"))?;
    let protected = bytes(object.get("protected").unwrap_or(&Value::Null), "protected")?;
    let salt = match object.get("salt") {
        None | Some(Value::Null) => None,
        Some(salt) => Some(bytes(salt, "salt")?),
    };
    Ok(KeyCopy { label: label.to_owned(), protected, salt })
}

fn rule(rule: E2eRule) -> &'static str {
    rule.as_str()
}

fn settings_object(settings: &E2eSettings) -> Value {
    json!({
        "id": SINGLETON,
        "mail": settings.mail,
        "policy": {
            "mail": rule(settings.policy.mail),
            "vaults": rule(settings.policy.vaults),
            "collections": rule(settings.policy.collections),
            "recovery": settings.policy.recovery,
        },
        "recoveryKey": settings.recovery_key.as_ref().map(|(id, key)| json!({ "id": id, "publicKey": b64(key) })),
    })
}

fn state_of(value: &Value) -> String {
    let mut hasher = DefaultHasher::new();
    value.to_string().hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// What an identity error becomes in a `SetError`.
fn set_error(error: IdentityError) -> Value {
    match error {
        IdentityError::Refused(text) => invalid_properties(text),
        IdentityError::NotFound(_) => json!({ "type": "notFound" }),
        IdentityError::Exists(_) => json!({ "type": "alreadyExists" }),
        other => json!({ "type": "serverFail", "description": other.to_string() }),
    }
}

fn or_null(map: Map<String, Value>) -> Value {
    if map.is_empty() { Value::Null } else { Value::Object(map) }
}

impl Context<'_> {
    /// The identity, for the caller's own account only: keys belong to the account that holds them.
    fn keys_of_own(&self, args: &Map<String, Value>) -> Result<&Identity, MethodError> {
        let identity = self.jmap.identity.as_ref().ok_or_else(|| MethodError::new("unknownMethod", "no keys here"))?;
        if args.get("accountId").and_then(Value::as_str) != Some(self.caller.account.to_string().as_str()) {
            return Err(MethodError::new("accountNotSupportedByMethod", "keys are in the caller's own account"));
        }
        Ok(identity)
    }

    fn creator(&self) -> String {
        format!("account:{}", self.caller.account)
    }

    async fn keys_state(&self, identity: &Identity) -> Result<(Vec<OpenPgpKeyInfo>, String), MethodError> {
        let keys = identity.openpgp_keys(self.caller.account).await.map_err(MethodError::server_fail)?;
        let state = state_of(&Value::Array(keys.iter().map(key_object).collect()));
        Ok((keys, state))
    }

    pub async fn openpgp_key_get(&self, args: Map<String, Value>) -> MethodResult {
        let identity = self.keys_of_own(&args)?;
        let (keys, state) = self.keys_state(identity).await?;
        let (mut list, mut not_found) = (Vec::new(), Vec::new());
        match ids(&args)? {
            None => list.extend(keys.iter().map(key_object)),
            Some(wanted) => {
                for id in wanted {
                    match keys.iter().find(|key| key.fingerprint == id) {
                        Some(key) => list.push(key_object(key)),
                        None => not_found.push(Value::String(id)),
                    }
                }
            }
        }
        Ok(vec![(
            "OpenPgpKey/get".into(),
            json!({ "accountId": self.caller.account.to_string(), "state": state, "list": list, "notFound": not_found }),
        )])
    }

    /// `create`: `publicKey` and `copies` (`{ label: { protected, salt } }`); the key in use until then is retired.
    /// `update`: `retired: true`, or `copies/<label>` set to a copy or `null`. Keys are never destroyed – what was
    /// encrypted to them would be lost.
    pub async fn openpgp_key_set(&self, args: Map<String, Value>) -> MethodResult {
        let identity = self.keys_of_own(&args)?;
        let (_, old_state) = self.keys_state(identity).await?;
        if let Some(Value::String(expected)) = args.get("ifInState")
            && *expected != old_state
        {
            return Err(MethodError::new("stateMismatch", "the keys have changed"));
        }
        let account = self.caller.account;
        let creator = self.creator();
        let (mut created, mut not_created) = (Map::new(), Map::new());
        if let Some(Value::Object(create)) = args.get("create") {
            for (creation, object) in create {
                let result = async {
                    let object = object.as_object().ok_or_else(|| invalid_properties("a key is an object"))?;
                    let public = bytes(object.get("publicKey").unwrap_or(&Value::Null), "publicKey")?;
                    let copies = object
                        .get("copies")
                        .and_then(Value::as_object)
                        .ok_or_else(|| invalid_properties("copies is an object"))?
                        .iter()
                        .map(|(label, copy)| copy_from(label, copy))
                        .collect::<Result<Vec<_>, _>>()?;
                    identity.add_openpgp_key(account, &public, copies, &creator).await.map_err(set_error)
                }
                .await;
                match result {
                    Ok(fingerprint) => {
                        created.insert(creation.clone(), json!({ "id": fingerprint }));
                    }
                    Err(error) => {
                        not_created.insert(creation.clone(), error);
                    }
                }
            }
        }
        let (mut updated, mut not_updated) = (Map::new(), Map::new());
        if let Some(Value::Object(update)) = args.get("update") {
            for (fingerprint, patch) in update {
                let result = async {
                    let patch = patch.as_object().ok_or_else(|| invalid_properties("a patch object"))?;
                    for (property, value) in patch {
                        if property == "retired" {
                            if value != &Value::Bool(true) {
                                return Err(invalid_properties("a retired key stays retired"));
                            }
                            identity.retire_openpgp_key(account, fingerprint, &creator).await.map_err(set_error)?;
                        } else if let Some(label) = property.strip_prefix("copies/") {
                            if value.is_null() {
                                identity
                                    .remove_openpgp_key_copy(account, fingerprint, label, &creator)
                                    .await
                                    .map_err(set_error)?;
                            } else {
                                let copy = copy_from(label, value)?;
                                identity
                                    .set_openpgp_key_copy(account, fingerprint, copy, &creator)
                                    .await
                                    .map_err(set_error)?;
                            }
                        } else {
                            return Err(invalid_properties(format!("{property} cannot be set")));
                        }
                    }
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => {
                        updated.insert(fingerprint.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(fingerprint.clone(), error);
                    }
                }
            }
        }
        let mut not_destroyed = Map::new();
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy.iter().filter_map(Value::as_str) {
                not_destroyed.insert(
                    id.to_owned(),
                    json!({ "type": "forbidden", "description": "keys are retired, not destroyed" }),
                );
            }
        }
        let (_, new_state) = self.keys_state(identity).await?;
        Ok(vec![(
            "OpenPgpKey/set".into(),
            json!({
                "accountId": account.to_string(),
                "oldState": old_state,
                "newState": new_state,
                "created": or_null(created),
                "updated": or_null(updated),
                "destroyed": null,
                "notCreated": or_null(not_created),
                "notUpdated": or_null(not_updated),
                "notDestroyed": or_null(not_destroyed),
            }),
        )])
    }

    /// The public keys in use for `emails`: local accounts of the instance first, else the address's Web Key
    /// Directory. Each entry says where its keys came from (`local`, `wkd`); an address without keys has none.
    pub async fn openpgp_key_lookup(&self, args: Map<String, Value>) -> MethodResult {
        let identity = self.keys_of_own(&args)?;
        let emails: Vec<String> = args
            .get("emails")
            .and_then(Value::as_array)
            .ok_or_else(|| MethodError::invalid("emails is a list of addresses"))?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if emails.len() > MAX_LOOKUP {
            return Err(MethodError::new("requestTooLarge", format!("at most {MAX_LOOKUP} addresses")));
        }
        let instance = identity.tenant_instance(self.caller.tenant).await.map_err(MethodError::server_fail)?;
        let mut list = Vec::new();
        for email in emails {
            let Ok(address) = Address::parse(&email) else {
                list.push(json!({ "email": email, "keys": [] }));
                continue;
            };
            if let Some(key) = identity.published_key(instance, &address).await.map_err(MethodError::server_fail)? {
                list.push(json!({
                    "email": email,
                    "keys": [{ "id": key.fingerprint, "kind": key.kind, "publicKey": b64(&key.public_key), "source": "local" }],
                }));
                continue;
            }
            let mut keys = Vec::new();
            if let Some(directory) = &self.jmap.key_directory {
                for found in directory.lookup(address.as_str()).await {
                    // Only keys that name the address and can be encrypted to.
                    let Ok(key) = kernoid_e2e::PublicKey::parse(&found) else { continue };
                    let names = key.addresses().iter().any(|a| a.eq_ignore_ascii_case(address.as_str()));
                    let Some(kind) = key.kind() else { continue };
                    if names && key.can_encrypt() {
                        let kind = match kind {
                            kernoid_e2e::Kind::Pqc => "pqc",
                            kernoid_e2e::Kind::Compatible => "compatible",
                        };
                        keys.push(
                            json!({ "id": key.fingerprint(), "kind": kind, "publicKey": b64(&found), "source": "wkd" }),
                        );
                    }
                }
            }
            list.push(json!({ "email": email, "keys": keys }));
        }
        Ok(vec![("OpenPgpKey/lookup".into(), json!({ "accountId": self.caller.account.to_string(), "list": list }))])
    }

    pub async fn e2e_settings_get(&self, args: Map<String, Value>) -> MethodResult {
        let identity = self.keys_of_own(&args)?;
        let settings = identity.e2e_settings(self.caller.account).await.map_err(MethodError::server_fail)?;
        let object = settings_object(&settings);
        let state = state_of(&object);
        let (mut list, mut not_found) = (Vec::new(), Vec::new());
        match ids(&args)? {
            None => list.push(object),
            Some(wanted) => {
                for id in wanted {
                    if id == SINGLETON { list.push(object.clone()) } else { not_found.push(Value::String(id)) }
                }
            }
        }
        Ok(vec![(
            "E2eSettings/get".into(),
            json!({ "accountId": self.caller.account.to_string(), "state": state, "list": list, "notFound": not_found }),
        )])
    }

    /// Only `mail` can be set, as the tenant's policy allows.
    pub async fn e2e_settings_set(&self, args: Map<String, Value>) -> MethodResult {
        let identity = self.keys_of_own(&args)?;
        let account = self.caller.account;
        let old_state =
            state_of(&settings_object(&identity.e2e_settings(account).await.map_err(MethodError::server_fail)?));
        if let Some(Value::String(expected)) = args.get("ifInState")
            && *expected != old_state
        {
            return Err(MethodError::new("stateMismatch", "the settings have changed"));
        }
        let (mut updated, mut not_updated) = (Map::new(), Map::new());
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, patch) in update {
                if id != SINGLETON {
                    not_updated.insert(id.clone(), json!({ "type": "notFound" }));
                    continue;
                }
                let result = async {
                    for (property, value) in patch.as_object().ok_or_else(|| invalid_properties("a patch object"))? {
                        match (property.as_str(), value) {
                            ("mail", Value::Bool(on)) => {
                                identity.set_mail_e2e(account, *on, &self.creator()).await.map_err(set_error)?
                            }
                            ("id", Value::String(id)) if id == SINGLETON => {}
                            (other, _) => return Err(invalid_properties(format!("{other} cannot be set"))),
                        }
                    }
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), error);
                    }
                }
            }
        }
        let singleton = || json!({ "type": "singleton", "description": "there is one object of settings" });
        let not_created: Map<String, Value> = match args.get("create") {
            Some(Value::Object(create)) => create.keys().map(|k| (k.clone(), singleton())).collect(),
            _ => Map::new(),
        };
        let new_state =
            state_of(&settings_object(&identity.e2e_settings(account).await.map_err(MethodError::server_fail)?));
        Ok(vec![(
            "E2eSettings/set".into(),
            json!({
                "accountId": account.to_string(),
                "oldState": old_state,
                "newState": new_state,
                "created": null,
                "updated": or_null(updated),
                "destroyed": null,
                "notCreated": or_null(not_created),
                "notUpdated": or_null(not_updated),
                "notDestroyed": null,
            }),
        )])
    }
}

impl Context<'_> {
    /// The encrypted collection `collectionId` names and the caller's level on it.
    async fn sealed_collection(
        &self,
        args: &Map<String, Value>,
        wanted: kernoid_groupware::Level,
    ) -> Result<(uuid::Uuid, uuid::Uuid), MethodError> {
        let (owner, access) = self.groupware_access(args).await?;
        let collection = args
            .get("collectionId")
            .and_then(Value::as_str)
            .and_then(|id| self.id(id))
            .ok_or_else(|| MethodError::invalid("collectionId is required"))?;
        if !access.allows(collection, wanted) {
            return Err(MethodError::new("forbidden", "not allowed in this collection"));
        }
        Ok((owner, collection))
    }

    /// `SealedItem/get` (RFC 0006, 7): every entry of an encrypted calendar or address book (`collectionId`), with
    /// `data` (an OpenPGP message, base64) and `updated`.
    pub async fn sealed_item_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, collection) = self.sealed_collection(&args, kernoid_groupware::Level::Read).await?;
        let groupware = self.groupware()?;
        let items = groupware.sealed_items(owner, collection).await.map_err(MethodError::server_fail)?;
        let state = groupware.state(owner).await?;
        let list: Vec<Value> = items
            .iter()
            .map(|item| {
                json!({
                    "id": item.id.to_string(),
                    "data": b64(&item.data),
                    "updated": item.updated.to_rfc3339_opts(SecondsFormat::Secs, true),
                })
            })
            .collect();
        Ok(vec![(
            "SealedItem/get".into(),
            json!({ "accountId": owner.to_string(), "collectionId": collection.to_string(), "state": state.to_string(), "list": list }),
        )])
    }

    /// `SealedItem/set`: `create` and `update` with `data` (base64), `destroy` – in one encrypted collection.
    pub async fn sealed_item_set(&mut self, args: Map<String, Value>) -> MethodResult {
        let (owner, collection) = self.sealed_collection(&args, kernoid_groupware::Level::Write).await?;
        let groupware = self.groupware()?.clone();
        let data = |object: &Value| {
            object
                .get("data")
                .and_then(Value::as_str)
                .and_then(|text| STANDARD.decode(text).ok())
                .ok_or_else(|| invalid_properties("data is base64"))
        };
        let error = |error: kernoid_groupware::GroupwareError| crate::contacts::set_error(&error);
        let (mut created, mut not_created) = (Map::new(), Map::new());
        if let Some(Value::Object(create)) = args.get("create") {
            for (creation, object) in create {
                let result = match data(object) {
                    Ok(bytes) => groupware.put_sealed_item(owner, collection, None, &bytes).await.map_err(error),
                    Err(failure) => Err(failure),
                };
                match result {
                    Ok(id) => {
                        self.created.insert(creation.clone(), id.to_string());
                        created.insert(creation.clone(), json!({ "id": id.to_string() }));
                    }
                    Err(failure) => {
                        not_created.insert(creation.clone(), failure);
                    }
                }
            }
        }
        let (mut updated, mut not_updated) = (Map::new(), Map::new());
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, object) in update {
                let result = match (self.id(id), data(object)) {
                    (Some(item), Ok(bytes)) => {
                        groupware.put_sealed_item(owner, collection, Some(item), &bytes).await.map(drop).map_err(error)
                    }
                    (None, _) => Err(json!({ "type": "notFound" })),
                    (_, Err(failure)) => Err(failure),
                };
                match result {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(failure) => {
                        not_updated.insert(id.clone(), failure);
                    }
                }
            }
        }
        let (mut destroyed, mut not_destroyed) = (Vec::new(), Map::new());
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy.iter().filter_map(Value::as_str) {
                let result = match self.id(id) {
                    Some(item) => groupware.destroy_sealed_item(owner, collection, item).await.map_err(error),
                    None => Err(json!({ "type": "notFound" })),
                };
                match result {
                    Ok(()) => destroyed.push(Value::String(id.to_owned())),
                    Err(failure) => {
                        not_destroyed.insert(id.to_owned(), failure);
                    }
                }
            }
        }
        let state = groupware.state(owner).await?;
        Ok(vec![(
            "SealedItem/set".into(),
            json!({
                "accountId": owner.to_string(),
                "collectionId": collection.to_string(),
                "newState": state.to_string(),
                "created": or_null(created),
                "updated": or_null(updated),
                "destroyed": destroyed,
                "notCreated": or_null(not_created),
                "notUpdated": or_null(not_updated),
                "notDestroyed": or_null(not_destroyed),
            }),
        )])
    }

    /// `CollectionKey/get`: for the collections asked for (`ids`), the caller's wrapped key (or null) and the accounts
    /// that have one.
    pub async fn collection_key_get(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let wanted = ids(&args)?.ok_or_else(|| MethodError::invalid("ids is required"))?;
        let (mut list, mut not_found) = (Vec::new(), Vec::new());
        for id in wanted {
            let Some(collection) = self.id(&id).filter(|c| access.allows(*c, kernoid_groupware::Level::Read)) else {
                not_found.push(Value::String(id));
                continue;
            };
            let sealed =
                groupware.collection_key(collection, self.caller.account).await.map_err(MethodError::server_fail)?;
            let members = groupware.collection_members(collection).await.map_err(MethodError::server_fail)?;
            list.push(json!({
                "id": id,
                "sealed": b64_or_null(sealed.as_deref()),
                "members": members.iter().map(uuid::Uuid::to_string).collect::<Vec<_>>(),
            }));
        }
        Ok(vec![(
            "CollectionKey/get".into(),
            json!({ "accountId": owner.to_string(), "list": list, "notFound": not_found }),
        )])
    }

    /// `CollectionKey/set`: `update` of a collection with `members/<account id>` – a wrapped key or null; for whoever may
    /// administer the collection (its owner, or a grant at `admin`).
    pub async fn collection_key_set(&self, args: Map<String, Value>) -> MethodResult {
        let (owner, access) = self.groupware_access(&args).await?;
        let groupware = self.groupware()?;
        let (mut updated, mut not_updated) = (Map::new(), Map::new());
        if let Some(Value::Object(update)) = args.get("update") {
            for (id, patch) in update {
                let result = async {
                    let collection = self.id(id).ok_or_else(|| json!({ "type": "notFound" }))?;
                    if !access.allows(collection, kernoid_groupware::Level::Admin) {
                        return Err(
                            json!({ "type": "forbidden", "description": "only who administers the collection" }),
                        );
                    }
                    for (key, value) in patch.as_object().ok_or_else(|| invalid_properties("a patch object"))? {
                        let member = key
                            .strip_prefix("members/")
                            .and_then(|m| uuid::Uuid::parse_str(m).ok())
                            .ok_or_else(|| invalid_properties(format!("{key} cannot be set")))?;
                        let sealed = match value {
                            Value::Null => None,
                            Value::String(text) => {
                                Some(STANDARD.decode(text).map_err(|_| invalid_properties("a wrapped key is base64"))?)
                            }
                            _ => return Err(invalid_properties("a wrapped key or null")),
                        };
                        groupware
                            .set_collection_key(collection, member, sealed.as_deref())
                            .await
                            .map_err(|error| crate::contacts::set_error(&error))?;
                    }
                    Ok(())
                }
                .await;
                match result {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(failure) => {
                        not_updated.insert(id.clone(), failure);
                    }
                }
            }
        }
        Ok(vec![(
            "CollectionKey/set".into(),
            json!({ "accountId": owner.to_string(), "updated": or_null(updated), "notUpdated": or_null(not_updated) }),
        )])
    }
}
