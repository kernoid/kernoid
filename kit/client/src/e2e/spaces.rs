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
use kernoid_crypt::{
    Domain, RecoveryCode,
    stream::{Permission, PersonId, StreamId},
};
use kernoid_e2e::{PublicKey, message};
use kernoid_replica::{SyncError, streams::Streams};
use kernoid_space_store::{Backend, Store, streams::Parent};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{E2e, OPENPGP, decode, list};
use crate::{
    Client, Error, FILENODE, Result,
    files::{FileNode, Principal},
};

const USING: [&str; 2] = [FILENODE, OPENPGP];
/// The capability that names the relay of vaults on spaces.
pub const SPACE_VAULTS: &str = "https://kernoid.dev/jmap/space-vaults";
/// The device setting under which its name is kept.
const DEVICE: &str = "vaults.device";

/// What directories and files say, as events of their streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Event {
    /// The vault's name, in the space stream.
    Vault { name: String },
    /// Something in a directory, or its new name; `trashed` while it is in the vault's trash.
    Entry {
        stream: StreamId,
        name: String,
        #[serde(default)]
        directory: bool,
        #[serde(default)]
        trashed: bool,
    },
    /// Gone from a directory: moved away or removed.
    Gone { stream: StreamId },
    /// A file's content: its original's parts.
    Version {
        parts: Vec<kernoid_base::Sha256Hash>,
        size: u64,
        #[serde(rename = "mediaType", default)]
        media_type: Option<String>,
        #[serde(default)]
        modified: Option<String>,
    },
}

/// Something in a directory of a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The stream it is: its id in the vault.
    pub id: String,
    pub name: String,
    pub directory: bool,
    /// In the vault's trash (still in its directory).
    pub trashed: bool,
    /// A file's size, type and time of its newest version.
    pub size: u64,
    pub media_type: Option<String>,
    pub modified: Option<String>,
}

fn vault_error(error: SyncError) -> Error {
    Error::E2e(format!("vault: {error}"))
}

fn stream_id(id: &str) -> Result<StreamId> {
    id.parse().map_err(|_| Error::E2e(format!("not a stream of a vault: {id}")))
}

fn space_id(node: &FileNode) -> Result<kernoid_base::SpaceId> {
    node.space
        .as_deref()
        .ok_or_else(|| Error::E2e("not a vault on a space".into()))?
        .parse()
        .map_err(|_| Error::Protocol("a space's id that is not one".into()))
}

/// The events of a stream, in order.
fn events(streams: &Streams, space: &kernoid_base::SpaceId, stream: &StreamId) -> Result<Vec<Event>> {
    let log = streams.log(space, stream).map_err(vault_error)?;
    Ok(log
        .ordered()
        .into_iter()
        .filter_map(|(_, event)| {
            // The log keeps the kind in its frame; the payload's other members beside it.
            let mut members = event.members.clone();
            members.insert("kind".into(), Value::String(event.kind.clone()));
            serde_json::from_value(Value::Object(members)).ok()
        })
        .collect())
}

/// What lies in a directory, from its events: the latest entry of each stream not gone since.
fn entries_of(streams: &Streams, space: &kernoid_base::SpaceId, directory: &StreamId) -> Result<Vec<Entry>> {
    let mut seen: Vec<(StreamId, String, bool, bool)> = Vec::new();
    for event in events(streams, space, directory)? {
        match event {
            Event::Entry { stream, name, directory, trashed } => {
                seen.retain(|(s, ..)| *s != stream);
                seen.push((stream, name, directory, trashed));
            }
            Event::Gone { stream } => seen.retain(|(s, ..)| *s != stream),
            _ => {}
        }
    }
    let mut entries = Vec::new();
    for (stream, name, directory, trashed) in seen {
        let mut entry =
            Entry { id: stream.to_string(), name, directory, trashed, size: 0, media_type: None, modified: None };
        if !directory && let Some(version) = latest_version(streams, space, &stream)? {
            entry.size = version.1;
            entry.media_type = version.2;
            entry.modified = version.3;
        }
        entries.push(entry);
    }
    entries
        .sort_by(|a, b| b.directory.cmp(&a.directory).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(entries)
}

type Version = (Vec<kernoid_base::Sha256Hash>, u64, Option<String>, Option<String>);

fn latest_version(streams: &Streams, space: &kernoid_base::SpaceId, file: &StreamId) -> Result<Option<Version>> {
    Ok(events(streams, space, file)?.into_iter().rev().find_map(|event| match event {
        Event::Version { parts, size, media_type, modified } => Some((parts, size, media_type, modified)),
        _ => None,
    }))
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

/// Whether the server keeps vaults on spaces: the relay it names for them.
/// Like every URL of the session, on the origin the session came from – the founder's token goes nowhere else.
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
        let stored = store.setting(None, DEVICE).map_err(|error| Error::E2e(error.to_string()))?;
        let device = match stored {
            Some(device) => device,
            None => {
                let mut stem: String = name
                    .to_lowercase()
                    .chars()
                    .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() { c } else { '-' })
                    .collect();
                stem.truncate(40);
                let stem = stem.trim_matches('-');
                let random: [u8; 6] = kernoid_base::random();
                let device = format!("{}-{}", if stem.is_empty() { "device" } else { stem }, hex(&random));
                store.set_setting(None, DEVICE, &device).map_err(|error| Error::E2e(error.to_string()))?;
                device
            }
        };
        let device = device.parse().map_err(|_| Error::E2e("a device name that is not one".into()))?;
        Ok(Self { streams: Arc::new(Mutex::new(Streams::open(Domain::KERNOID, device, store))) })
    }

    /// Runs `work` on the spaces, off the async runtime (the relay's requests and the store block).
    async fn run<T: Send + 'static>(&self, work: impl FnOnce(&mut Streams) -> Result<T> + Send + 'static) -> Result<T> {
        let streams = self.streams.clone();
        tokio::task::spawn_blocking(move || {
            let mut streams = streams.lock().map_err(|_| Error::E2e("the vaults' store is poisoned".into()))?;
            work(&mut streams)
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
            .run(move |streams| {
                let (space, code) =
                    streams.found(&relay, Some(&founder), Some(&device), Some(&me)).map_err(vault_error)?;
                let root = streams.space_stream(&space).map_err(vault_error)?;
                streams.write(&space, &root, &Event::Vault { name }).map_err(vault_error)?;
                Ok((space, code))
            })
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
            self.run(move |streams| streams.has_space(&space).map_err(vault_error)).await?
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
            let space = space.clone();
            self.run(move |streams| {
                streams.recover(&relay, &space, &RecoveryCode(code), Some(&name)).map_err(vault_error).map(drop)
            })
            .await?;
            return Ok(true);
        }
        self.sync(node).await?;
        Ok(true)
    }

    /// Reads what is new in a vault this device has.
    pub async fn sync(&self, node: &FileNode) -> Result<()> {
        let space = space_id(node)?;
        self.run(move |streams| streams.sync(&space).map(drop).map_err(vault_error)).await
    }

    /// The vault's name, once this device has it.
    pub async fn name(&self, node: &FileNode) -> Result<Option<String>> {
        let space = space_id(node)?;
        self.run(move |streams| {
            if !streams.has_space(&space).map_err(vault_error)? {
                return Ok(None);
            }
            let root = streams.space_stream(&space).map_err(vault_error)?;
            Ok(events(streams, &space, &root)?.into_iter().rev().find_map(|event| match event {
                Event::Vault { name } => Some(name),
                _ => None,
            }))
        })
        .await
    }

    /// What lies in a directory of the vault – `None`: its top –, trashed entries included.
    pub async fn list(&self, node: &FileNode, directory: Option<&str>) -> Result<Vec<Entry>> {
        let space = space_id(node)?;
        let directory = directory.map(stream_id).transpose()?;
        self.run(move |streams| {
            let directory = match directory {
                Some(directory) => directory,
                None => streams.space_stream(&space).map_err(vault_error)?,
            };
            entries_of(streams, &space, &directory)
        })
        .await
    }

    /// Makes a directory in a directory of the vault; returns its id.
    pub async fn make_directory(&self, node: &FileNode, parent: Option<&str>, name: &str) -> Result<String> {
        let space = space_id(node)?;
        let parent = parent.map(stream_id).transpose()?;
        let name = name.to_owned();
        self.run(move |streams| {
            let parent = parent_or_root(streams, &space, parent)?;
            let stream = streams.new_stream(&space, &Parent::Stream(parent.clone())).map_err(vault_error)?;
            let entry = Event::Entry { stream: stream.clone(), name, directory: true, trashed: false };
            streams.write(&space, &parent, &entry).map_err(vault_error)?;
            Ok(stream.to_string())
        })
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
        let space = space_id(node)?;
        let parent = parent.map(stream_id).transpose()?;
        let existing = existing.map(stream_id).transpose()?;
        let (name, media_type, modified) =
            (name.to_owned(), media_type.map(str::to_owned), modified.map(str::to_owned));
        self.run(move |streams| {
            let parent = parent_or_root(streams, &space, parent)?;
            let stream = match existing {
                Some(stream) => stream,
                None => {
                    let stream = streams.new_stream(&space, &Parent::Stream(parent.clone())).map_err(vault_error)?;
                    let entry = Event::Entry { stream: stream.clone(), name, directory: false, trashed: false };
                    streams.write(&space, &parent, &entry).map_err(vault_error)?;
                    stream
                }
            };
            let size = data.len() as u64;
            let parts = streams.put_original(&space, &stream, &data).map_err(vault_error)?;
            streams
                .write(&space, &stream, &Event::Version { parts, size, media_type, modified })
                .map_err(vault_error)?;
            Ok(stream.to_string())
        })
        .await
    }

    /// The content of a file of the vault: its newest version.
    pub async fn read_file(&self, node: &FileNode, file: &str) -> Result<Vec<u8>> {
        let space = space_id(node)?;
        let file = stream_id(file)?;
        self.run(move |streams| {
            let (parts, ..) =
                latest_version(streams, &space, &file)?.ok_or_else(|| Error::E2e("a file without content".into()))?;
            streams.original(&space, &file, &parts).map_err(vault_error)
        })
        .await
    }

    /// Renames something in a directory of the vault.
    pub async fn rename(&self, node: &FileNode, parent: Option<&str>, entry: &str, name: &str) -> Result<()> {
        let name = name.to_owned();
        self.change(node, parent, entry, move |e| e.name = name).await
    }

    /// Moves something of the vault into its trash, or – `trashed` false – back.
    pub async fn set_trashed(&self, node: &FileNode, parent: Option<&str>, entry: &str, trashed: bool) -> Result<()> {
        self.change(node, parent, entry, move |e| e.trashed = trashed).await
    }

    async fn change(
        &self,
        node: &FileNode,
        parent: Option<&str>,
        entry: &str,
        change: impl FnOnce(&mut Entry) + Send + 'static,
    ) -> Result<()> {
        let space = space_id(node)?;
        let parent = parent.map(stream_id).transpose()?;
        let stream = stream_id(entry)?;
        self.run(move |streams| {
            let parent = parent_or_root(streams, &space, parent)?;
            let mut found = entries_of(streams, &space, &parent)?
                .into_iter()
                .find(|e| e.id == stream.as_str())
                .ok_or_else(|| Error::E2e("no such entry in the directory".into()))?;
            change(&mut found);
            let event = Event::Entry { stream, name: found.name, directory: found.directory, trashed: found.trashed };
            streams.write(&space, &parent, &event).map_err(vault_error).map(drop)
        })
        .await
    }

    /// Moves something into another directory of the vault (`None`: its top), under its name there.
    pub async fn move_to(&self, node: &FileNode, from: Option<&str>, entry: &str, to: Option<&str>) -> Result<()> {
        let space = space_id(node)?;
        let (from, to) = (from.map(stream_id).transpose()?, to.map(stream_id).transpose()?);
        let stream = stream_id(entry)?;
        self.run(move |streams| {
            let from = parent_or_root(streams, &space, from)?;
            let to = parent_or_root(streams, &space, to)?;
            if from == to {
                return Ok(());
            }
            if to == stream || below(streams, &space, &stream, &to)? {
                return Err(Error::E2e("a directory cannot move below itself".into()));
            }
            let found = entries_of(streams, &space, &from)?
                .into_iter()
                .find(|e| e.id == stream.as_str())
                .ok_or_else(|| Error::E2e("no such entry in the directory".into()))?;
            streams.link_below(&space, &stream, &to).map_err(vault_error)?;
            let entry =
                Event::Entry { stream: stream.clone(), name: found.name, directory: found.directory, trashed: false };
            streams.write(&space, &to, &entry).map_err(vault_error)?;
            streams.write(&space, &from, &Event::Gone { stream }).map_err(vault_error).map(drop)
        })
        .await
    }

    /// Removes something of the vault for good: gone from its directory, and – where this device may purge – its
    /// streams with all below them removed at the relay.
    pub async fn remove(&self, node: &FileNode, parent: Option<&str>, entry: &str) -> Result<()> {
        let space = space_id(node)?;
        let parent = parent.map(stream_id).transpose()?;
        let stream = stream_id(entry)?;
        self.run(move |streams| {
            let parent = parent_or_root(streams, &space, parent)?;
            streams.write(&space, &parent, &Event::Gone { stream: stream.clone() }).map_err(vault_error)?;
            let me = streams.device_id(&space).map_err(vault_error)?;
            let roster = streams.roster(&space).map_err(vault_error)?;
            if roster.device(&me).is_some_and(|d| d.may(Permission::Purge)) {
                let mut below = vec![stream];
                while let Some(stream) = below.pop() {
                    for entry in entries_of(streams, &space, &stream)? {
                        below.push(stream_id(&entry.id)?);
                    }
                    streams.purge(&space, &stream).map_err(vault_error)?;
                }
            }
            Ok(())
        })
        .await
    }

    /// The accounts that are members of the vault (their ids), this device having the vault.
    pub async fn members(&self, node: &FileNode) -> Result<Vec<String>> {
        let space = space_id(node)?;
        self.run(move |streams| {
            let roster = streams.roster(&space).map_err(vault_error)?;
            Ok(roster.persons().filter_map(|p| p.name.clone()).collect())
        })
        .await
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
        let members = self.members(node).await?;
        let mut waiting = Vec::new();
        let mut update = serde_json::Map::new();
        for person in people.iter().filter(|person| !members.contains(&person.id)) {
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
            // A member who may share may add members; removing what is there stays with those who may purge.
            let (_, code) = self
                .run(move |streams| {
                    // The roster as the relay has it now: a record follows its newest one.
                    streams.sync(&space).map_err(vault_error)?;
                    streams.add_person(&space, Some(&id), &[Permission::Members]).map_err(vault_error)
                })
                .await?;
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
        let space = space_id(node)?;
        let id = member.to_owned();
        self.run(move |streams| {
            streams.sync(&space).map_err(vault_error)?;
            let roster = streams.roster(&space).map_err(vault_error)?;
            let persons: Vec<PersonId> =
                roster.persons().filter(|p| p.name.as_deref() == Some(id.as_str())).map(|p| p.id.clone()).collect();
            for person in persons {
                streams.remove_person(&space, &person).map_err(vault_error)?;
            }
            Ok(())
        })
        .await?;
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

fn parent_or_root(streams: &Streams, space: &kernoid_base::SpaceId, parent: Option<StreamId>) -> Result<StreamId> {
    match parent {
        Some(parent) => Ok(parent),
        None => streams.space_stream(space).map_err(vault_error),
    }
}

/// Whether `inner` lies somewhere below the directory `outer`.
fn below(streams: &Streams, space: &kernoid_base::SpaceId, outer: &StreamId, inner: &StreamId) -> Result<bool> {
    let mut pending = vec![outer.clone()];
    let mut seen = 0usize;
    while let Some(directory) = pending.pop() {
        seen += 1;
        if seen > 100_000 {
            return Ok(true);
        }
        for entry in entries_of(streams, space, &directory)?.into_iter().filter(|e| e.directory) {
            let stream = stream_id(&entry.id)?;
            if stream == *inner {
                return Ok(true);
            }
            pending.push(stream);
        }
    }
    Ok(false)
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
