// SPDX-License-Identifier: MIT
//! Vaults on spaces (RFC 0010, 5): a vault is a space of the relay's protocol 2 at the account's kernoid, kept here
//! through [`kernoid_replica::streams`]. Its root directory is the space stream, every directory and file a stream of
//! its own linked below its directory; names and moves are events of the directory, versions events of the file,
//! contents originals in parts. The file store keeps only the vault's directory, which names the space
//! (`kernoid:space`) and holds nothing – the server sees no names.
//!
//! Who is a member: every person of the space is an account – its name in the roster is the account's id, which the
//! relay, being the account's kernoid, knows anyway. Making a
//! vault and sharing it hand each account a **recovery code** of its person, encrypted to the account's OpenPGP key and
//! kept by the server (`VaultKey/set`); any device of the account opens it with the account's key and comes in with it
//! ([`Vaults::enter`]). Whoever added a person knew its code – as whoever wrapped an OpenPGP vault's key knew it.
//!
//! A [`Vaults`] keeps its spaces in a store of its own on the device (SQLite, `kernoid-space-store`): keys of streams
//! and persons are there, **not** yet in the system's key store (**OPEN**, RFC 0012, 11).

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use kernoid_crypt::RecoveryCode;
use kernoid_e2e::{PublicKey, message};
use kernoid_replica::{SyncError, streams::Streams};
use kernoid_space_store::Store;
use kernoid_vault::{FileInfo, stream_id};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{E2e, OPENPGP, decode, list};
use crate::{
    Client, Error, FILENODE, Result,
    files::{FileNode, Principal},
};

pub use kernoid_vault::Entry;

const USING: [&str; 2] = [FILENODE, OPENPGP];
/// The capability that names the relay of vaults on spaces.
pub const SPACE_VAULTS: &str = "https://kernoid.dev/jmap/space-vaults";

fn vault_error(error: SyncError) -> Error {
    Error::E2e(format!("vault: {error}"))
}

fn stream(id: Option<&str>) -> Result<Option<kernoid_crypt::stream::StreamId>> {
    id.map(stream_id).transpose().map_err(vault_error)
}

fn space_id(node: &FileNode) -> Result<kernoid_base::SpaceId> {
    node.space
        .as_deref()
        .ok_or_else(|| Error::E2e("not a vault on a space".into()))?
        .parse()
        .map_err(|_| Error::Protocol("a space's id that is not one".into()))
}

/// The vaults on spaces of one account on this device.
#[derive(Clone)]
pub struct Vaults {
    streams: Arc<Mutex<Streams>>,
}

impl std::fmt::Debug for Vaults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vaults").finish_non_exhaustive()
    }
}

/// Whether the server keeps vaults on spaces: the relay it names for them. Like every URL of the session, on the
/// origin the session came from – the founder's token goes nowhere else.
pub fn relay_url(client: &Client) -> Option<String> {
    client.session.capabilities.get(SPACE_VAULTS)?.get("relayUrl")?.as_str().map(|url| client.here(url))
}

impl Vaults {
    /// The vaults kept in `path` (a SQLite file of this account on this device), made there the first time; this
    /// device's name in the spaces is made once and kept with them – `name` (e.g. the host name) and a random part.
    pub fn open(path: &Path, name: &str) -> Result<Self> {
        Self::with(Store::open(path).map_err(|error| Error::E2e(format!("the vaults' store: {error}")))?, name)
    }

    /// Vaults kept in memory only (tests).
    pub fn in_memory(name: &str) -> Result<Self> {
        Self::with(Store::in_memory().map_err(|error| Error::E2e(format!("the vaults' store: {error}")))?, name)
    }

    fn with(store: Store, name: &str) -> Result<Self> {
        let streams = kernoid_vault::open(store, name, None).map_err(vault_error)?;
        Ok(Self { streams: Arc::new(Mutex::new(streams)) })
    }

    /// Runs `work` on the spaces, off the async runtime (the relay's requests and the store block).
    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut Streams) -> kernoid_vault::Result<T> + Send + 'static,
    ) -> Result<T> {
        let streams = self.streams.clone();
        tokio::task::spawn_blocking(move || {
            let mut streams = streams.lock().map_err(|_| Error::E2e("the vaults' store is poisoned".into()))?;
            work(&mut streams).map_err(vault_error)
        })
        .await
        .map_err(|error| Error::E2e(error.to_string()))?
    }

    /// Makes a vault in `parent` (`None`: the top of the store): a space founded at the account's relay, its name
    /// there, the account's recovery code sealed to its own key, and the directory naming the space. Needs the
    /// account's key unlocked and a login by token (the relay takes no app passwords). Returns the directory's id.
    pub async fn create(
        &self,
        client: &Client,
        e2e: &mut E2e,
        account: &str,
        parent: Option<&str>,
        name: &str,
    ) -> Result<String> {
        let own = e2e.need_unlocked()?.public();
        let relay = relay_url(client).ok_or_else(|| Error::E2e("this server keeps no vaults on spaces".into()))?;
        let founder =
            client.bearer().ok_or_else(|| Error::E2e("making a vault needs a login, not an app password".into()))?;
        let device = client.session.username.clone();
        let me = client.primary(FILENODE)?;
        let name = name.to_owned();
        let (space, code) = self
            .run(move |streams| kernoid_vault::found(streams, &relay, Some(&founder), Some(&device), &me, &name))
            .await?;
        let sealed = seal_code(&code, &[&own])?;
        let create = json!({ "create": { "v": {
            "@type": "Directory",
            "parentId": parent,
            "name": format!("k-{space}"),
            "kernoid:newVault": { "space": space.to_string(), "sealed": sealed },
        } } });
        let result = client.set(&USING, "FileNode", account, create, json!({})).await?;
        result
            .pointer("/created/v/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::Protocol("the server made nothing".into()))
    }

    /// Brings this device into the vault of `node` – with the account's recovery code of it, opened with the account's
    /// key – unless it is in already, then reads what is new. Returns whether this device has the vault now (false
    /// while no member gave the account a code).
    pub async fn enter(&self, client: &Client, e2e: &mut E2e, account: &str, node: &FileNode) -> Result<bool> {
        let space = space_id(node)?;
        let known = {
            let space = space.clone();
            self.run(move |streams| streams.has_space(&space)).await?
        };
        if !known {
            let relay = relay_url(client).ok_or_else(|| Error::E2e("this server keeps no vaults on spaces".into()))?;
            let wrapped = wrapped(client, account, &node.id).await?;
            let Some(sealed) = wrapped.sealed else { return Ok(false) };
            e2e.need_unlocked()?;
            let opened = message::decrypt(&decode(&sealed)?, &e2e.secrets(), &[])
                .map_err(|_| Error::E2e("the vault's code is not for your key".into()))?;
            let code: [u8; 32] = opened.data.try_into().map_err(|_| Error::E2e("not a recovery code".into()))?;
            let name = client.session.username.clone();
            self.run(move |streams| streams.recover(&relay, &space, &RecoveryCode(code), Some(&name)).map(drop))
                .await?;
            return Ok(true);
        }
        self.sync(node).await?;
        Ok(true)
    }

    /// Reads what is new in a vault this device has.
    pub async fn sync(&self, node: &FileNode) -> Result<()> {
        let space = space_id(node)?;
        self.run(move |streams| streams.sync(&space).map(drop)).await
    }

    /// The vault's name, once this device has it.
    pub async fn name(&self, node: &FileNode) -> Result<Option<String>> {
        let space = space_id(node)?;
        self.run(move |streams| kernoid_vault::name(streams, &space)).await
    }

    /// What lies in a directory of the vault – `None`: its top –, trashed entries included.
    pub async fn list(&self, node: &FileNode, directory: Option<&str>) -> Result<Vec<Entry>> {
        let (space, directory) = (space_id(node)?, stream(directory)?);
        self.run(move |streams| kernoid_vault::list(streams, &space, directory)).await
    }

    /// Makes a directory in a directory of the vault; returns its id.
    pub async fn make_directory(&self, node: &FileNode, parent: Option<&str>, name: &str) -> Result<String> {
        let (space, parent, name) = (space_id(node)?, stream(parent)?, name.to_owned());
        self.run(move |streams| kernoid_vault::make_directory(streams, &space, parent, &name).map(|s| s.to_string()))
            .await
    }

    /// Puts a file into a directory of the vault: a new file, or – `existing` – a new version of one. Returns its id.
    #[allow(clippy::too_many_arguments, reason = "a file with what describes it")]
    pub async fn put_file(
        &self,
        node: &FileNode,
        parent: Option<&str>,
        name: &str,
        data: Vec<u8>,
        media_type: Option<&str>,
        modified: Option<&str>,
        existing: Option<&str>,
    ) -> Result<String> {
        let (space, parent, existing) = (space_id(node)?, stream(parent)?, stream(existing)?);
        let (name, media_type, modified) =
            (name.to_owned(), media_type.map(str::to_owned), modified.map(str::to_owned));
        self.run(move |streams| {
            let info = FileInfo { media_type: media_type.as_deref(), modified: modified.as_deref() };
            kernoid_vault::put_file(streams, &space, parent, &name, &data, info, existing).map(|s| s.to_string())
        })
        .await
    }

    /// The content of a file of the vault: its newest version.
    pub async fn read_file(&self, node: &FileNode, file: &str) -> Result<Vec<u8>> {
        let (space, file) = (space_id(node)?, stream_id(file).map_err(vault_error)?);
        self.run(move |streams| kernoid_vault::read_file(streams, &space, &file)).await
    }

    /// Renames something in a directory of the vault.
    pub async fn rename(&self, node: &FileNode, parent: Option<&str>, entry: &str, name: &str) -> Result<()> {
        let (space, parent, entry, name) =
            (space_id(node)?, stream(parent)?, stream_id(entry).map_err(vault_error)?, name.to_owned());
        self.run(move |streams| kernoid_vault::rename(streams, &space, parent, entry, &name)).await
    }

    /// Moves something of the vault into its trash, or – `trashed` false – back.
    pub async fn set_trashed(&self, node: &FileNode, parent: Option<&str>, entry: &str, trashed: bool) -> Result<()> {
        let (space, parent, entry) = (space_id(node)?, stream(parent)?, stream_id(entry).map_err(vault_error)?);
        self.run(move |streams| kernoid_vault::set_trashed(streams, &space, parent, entry, trashed)).await
    }

    /// Moves something into another directory of the vault (`None`: its top), under its name there.
    pub async fn move_to(&self, node: &FileNode, from: Option<&str>, entry: &str, to: Option<&str>) -> Result<()> {
        let (space, from, to) = (space_id(node)?, stream(from)?, stream(to)?);
        let entry = stream_id(entry).map_err(vault_error)?;
        self.run(move |streams| kernoid_vault::move_to(streams, &space, from, entry, to)).await
    }

    /// Removes something of the vault for good: gone from its directory, and – where this device may purge – its
    /// streams with all below them removed at the relay.
    pub async fn remove(&self, node: &FileNode, parent: Option<&str>, entry: &str) -> Result<()> {
        let (space, parent, entry) = (space_id(node)?, stream(parent)?, stream_id(entry).map_err(vault_error)?);
        self.run(move |streams| kernoid_vault::remove(streams, &space, parent, entry)).await
    }

    /// The accounts that are members of the vault (their ids), this device having the vault.
    pub async fn members(&self, node: &FileNode) -> Result<Vec<String>> {
        let space = space_id(node)?;
        self.run(move |streams| kernoid_vault::members(streams, &space)).await
    }

    /// After sharing a vault: makes each person shared with a member – a person of the space with a recovery code
    /// sealed to their key. Groups and people without a key wait (**OPEN**: a group's members). Returns those who
    /// wait.
    pub async fn share(
        &self,
        client: &Client,
        e2e: &mut E2e,
        account: &str,
        node: &FileNode,
        people: &[Principal],
    ) -> Result<Vec<Principal>> {
        let space = space_id(node)?;
        let mut waiting = Vec::new();
        let mut update = serde_json::Map::new();
        for person in people {
            let keys: Vec<PublicKey> = match (person.kind.as_str(), &person.email) {
                ("individual", Some(email)) => {
                    e2e.lookup(client, std::slice::from_ref(email)).await?.into_values().flatten().collect()
                }
                _ => Vec::new(),
            };
            if keys.is_empty() {
                waiting.push(person.clone());
                continue;
            }
            let (space, id) = (space.clone(), person.id.clone());
            let Some(code) = self.run(move |streams| kernoid_vault::add_member(streams, &space, &id)).await? else {
                continue;
            };
            let recipients: Vec<&PublicKey> = keys.iter().collect();
            update.insert(format!("members/{}", person.id), Value::String(seal_code(&code, &recipients)?));
        }
        if !update.is_empty() {
            let change = json!({ "update": { node.id.as_str(): update } });
            client.set(&USING, "VaultKey", account, change, json!({})).await?;
        }
        Ok(waiting)
    }

    /// Ends an account's membership: its person leaves the space – what is written from now on is out of its reach –
    /// and its code at the server goes.
    pub async fn remove_member(&self, client: &Client, account: &str, node: &FileNode, member: &str) -> Result<()> {
        let (space, id) = (space_id(node)?, member.to_owned());
        self.run(move |streams| kernoid_vault::remove_member(streams, &space, &id)).await?;
        let change = json!({ "update": { node.id.as_str(): { format!("members/{member}"): null } } });
        client.set(&USING, "VaultKey", account, change, json!({})).await?;
        Ok(())
    }

    /// Copies an OpenPGP vault (RFC 0006, 6) into a new vault on a space beside it, with its name, directories, files
    /// and members; returns the new vault's id. The OpenPGP vault stays until whoever moved it has checked the copy
    /// and removes it (RFC 0010, 5).
    pub async fn move_vault(&self, client: &Client, e2e: &mut E2e, account: &str, old: &FileNode) -> Result<String> {
        let vault = old.vault.clone().filter(|vault| *vault == old.id && old.space.is_none());
        let vault = vault.ok_or_else(|| Error::E2e("not an OpenPGP vault".into()))?;
        let name = match &old.encrypted_name {
            Some(sealed) => e2e.open_name(client, account, &vault, sealed).await,
            None => None,
        }
        .ok_or_else(|| Error::E2e("the vault's key is not at hand".into()))?;
        let id = self.create(client, e2e, account, old.parent_id.as_deref(), &name).await?;
        let space = created_space(client, account, &id).await?;
        let new = FileNode { id: id.clone(), space, ..old.clone() };
        let mut pending: Vec<(String, Option<String>)> = vec![(vault.clone(), None)];
        while let Some((directory, into)) = pending.pop() {
            let mut children = crate::files::children(client, account, Some(&directory)).await?;
            e2e.open_names(client, account, &mut children).await;
            for child in children {
                if child.is_directory() {
                    let made = self.make_directory(&new, into.as_deref(), &child.name).await?;
                    pending.push((child.id.clone(), Some(made)));
                } else {
                    let data = e2e.download_from(client, account, &child).await?;
                    let media_type = child.media_type.as_deref();
                    self.put_file(
                        &new,
                        into.as_deref(),
                        &child.name,
                        data,
                        media_type,
                        child.modified.as_deref(),
                        None,
                    )
                    .await?;
                }
            }
        }
        let members = wrapped(client, account, &vault).await?.members;
        let own = client.primary(FILENODE)?;
        let others: Vec<&str> = members.iter().map(String::as_str).filter(|m| *m != own).collect();
        if !others.is_empty() {
            let people = crate::files::principals(client, &others).await?;
            self.share(client, e2e, account, &new, &people).await?;
        }
        Ok(id)
    }
}

/// The space a vault's directory names, as the server has it.
async fn created_space(client: &Client, account: &str, id: &str) -> Result<Option<String>> {
    let result = client
        .call(&USING, "FileNode/get", json!({ "accountId": account, "ids": [id], "properties": ["kernoid:space"] }))
        .await?;
    Ok(result.pointer("/list/0/kernoid:space").and_then(Value::as_str).map(str::to_owned))
}

/// A recovery code encrypted to OpenPGP keys, base64.
fn seal_code(code: &RecoveryCode, to: &[&PublicKey]) -> Result<String> {
    Ok(STANDARD.encode(message::encrypt(&code.0, to, None, false)?))
}

#[derive(Deserialize)]
struct Wrapped {
    #[serde(default)]
    sealed: Option<String>,
    #[serde(default)]
    members: Vec<String>,
}

async fn wrapped(client: &Client, account: &str, vault: &str) -> Result<Wrapped> {
    let result = client.call(&USING, "VaultKey/get", json!({ "accountId": account, "ids": [vault] })).await?;
    list::<Wrapped>(&result)?.into_iter().next().ok_or_else(|| Error::E2e("no such vault".into()))
}
