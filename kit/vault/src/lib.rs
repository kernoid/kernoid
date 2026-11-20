// SPDX-License-Identifier: MIT
//! kernoid's vaults on spaces (RFC 0010, 5), on the foundation's streams ([`kernoid_replica::streams`]).
//!
//! A vault is a space of the relay's protocol 2. Its root directory is the space stream; every directory and file is a
//! stream of its own, linked below its directory. A directory's events say what lies in it ([`Event::Entry`],
//! [`Event::Gone`]) – the space stream also the vault's name ([`Event::Vault`]); a file's events are its versions
//! ([`Event::Version`]), whose contents are originals in parts. Moving links the stream below its new directory and
//! leaves the old one; removing for good purges the streams where the device may.
//!
//! Members are accounts: each is a person of the space named by the account's id, which the relay – the account's
//! kernoid – knows anyway. A member comes in with a recovery code of its person ([`add_member`]); how the code reaches
//! the account (sealed to its OpenPGP key, kept by the server) is the caller's.
//!
//! Everything here is synchronous: the relay's requests and the store block. `kernoid-client` runs it off its async
//! runtime; the web app (the feature `wasm`, [`wasm`]) in a worker.

#[cfg(feature = "wasm")]
pub mod wasm;

use kernoid_base::{Sha256Hash, SpaceId};
use kernoid_crypt::{
    RecoveryCode,
    stream::{Permission, PersonId, StreamId},
};
use kernoid_replica::{SyncError, streams::Streams};
use kernoid_space_store::streams::Parent;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Why something failed.
pub type Result<T> = std::result::Result<T, SyncError>;

fn invalid(message: impl Into<String>) -> SyncError {
    SyncError::State(message.into())
}

/// What directories and files say, as events of their streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Event {
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
    /// A file's content: its original's parts. (`type` belongs to the log's frame, hence `mediaType`.)
    Version {
        parts: Vec<Sha256Hash>,
        size: u64,
        #[serde(rename = "mediaType", default)]
        media_type: Option<String>,
        #[serde(default)]
        modified: Option<String>,
    },
}

/// Something in a directory of a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
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
    /// Which version a file's content is: the identity of its newest original's first part – another one tells a new
    /// version (a file sync compares it); empty for a directory.
    pub version: String,
}

/// A stream's id from its text.
pub fn stream_id(id: &str) -> Result<StreamId> {
    id.parse().map_err(|_| invalid(format!("not a stream of a vault: {id}")))
}

/// The events of a stream, in order.
fn events(streams: &Streams, space: &SpaceId, stream: &StreamId) -> Result<Vec<Event>> {
    let log = streams.log(space, stream)?;
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

fn root_or(streams: &Streams, space: &SpaceId, directory: Option<StreamId>) -> Result<StreamId> {
    match directory {
        Some(directory) => Ok(directory),
        None => streams.space_stream(space),
    }
}

/// What lies in a directory (`None`: the vault's top), from its events: the latest entry of each stream not gone
/// since – trashed entries included; directories first, then by name.
pub fn list(streams: &Streams, space: &SpaceId, directory: Option<StreamId>) -> Result<Vec<Entry>> {
    let directory = root_or(streams, space, directory)?;
    let mut seen: Vec<(StreamId, String, bool, bool)> = Vec::new();
    for event in events(streams, space, &directory)? {
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
        let mut entry = Entry {
            id: stream.to_string(),
            name,
            directory,
            trashed,
            size: 0,
            media_type: None,
            modified: None,
            version: String::new(),
        };
        if !directory && let Some(version) = latest_version(streams, space, &stream)? {
            entry.size = version.1;
            entry.media_type = version.2;
            entry.modified = version.3;
            entry.version = version.0.first().map(ToString::to_string).unwrap_or_default();
        }
        entries.push(entry);
    }
    entries
        .sort_by(|a, b| b.directory.cmp(&a.directory).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(entries)
}

type Version = (Vec<Sha256Hash>, u64, Option<String>, Option<String>);

fn latest_version(streams: &Streams, space: &SpaceId, file: &StreamId) -> Result<Option<Version>> {
    Ok(events(streams, space, file)?.into_iter().rev().find_map(|event| match event {
        Event::Version { parts, size, media_type, modified } => Some((parts, size, media_type, modified)),
        _ => None,
    }))
}

/// Founds a vault at a relay: the space with this device and the account's person (named by its id), the vault's
/// name, and the account's recovery code.
pub fn found(
    streams: &mut Streams,
    relay: &str,
    founder: Option<&str>,
    device_name: Option<&str>,
    account: &str,
    name: &str,
) -> Result<(SpaceId, RecoveryCode)> {
    let (space, code) = streams.found(relay, founder, device_name, Some(account))?;
    let root = streams.space_stream(&space)?;
    streams.write(&space, &root, &Event::Vault { name: name.to_owned() })?;
    Ok((space, code))
}

/// Renames the vault itself.
pub fn rename_vault(streams: &mut Streams, space: &SpaceId, name: &str) -> Result<()> {
    let root = streams.space_stream(space)?;
    streams.write(space, &root, &Event::Vault { name: name.to_owned() }).map(drop)
}

/// The vault's name, once this device has the vault.
pub fn name(streams: &Streams, space: &SpaceId) -> Result<Option<String>> {
    if !streams.has_space(space)? {
        return Ok(None);
    }
    let root = streams.space_stream(space)?;
    Ok(events(streams, space, &root)?.into_iter().rev().find_map(|event| match event {
        Event::Vault { name } => Some(name),
        _ => None,
    }))
}

/// Makes a directory in a directory of the vault; returns it.
pub fn make_directory(
    streams: &mut Streams,
    space: &SpaceId,
    parent: Option<StreamId>,
    name: &str,
) -> Result<StreamId> {
    let parent = root_or(streams, space, parent)?;
    let stream = streams.new_stream(space, &Parent::Stream(parent.clone()))?;
    let entry = Event::Entry { stream: stream.clone(), name: name.to_owned(), directory: true, trashed: false };
    streams.write(space, &parent, &entry)?;
    Ok(stream)
}

/// What describes a file's content.
#[derive(Debug, Clone, Default)]
pub struct FileInfo<'a> {
    pub media_type: Option<&'a str>,
    pub modified: Option<&'a str>,
}

/// Puts a file into a directory of the vault: a new one, or – `existing` – a new version of one. Returns it.
pub fn put_file(
    streams: &mut Streams,
    space: &SpaceId,
    parent: Option<StreamId>,
    name: &str,
    data: &[u8],
    info: FileInfo<'_>,
    existing: Option<StreamId>,
) -> Result<StreamId> {
    let parent = root_or(streams, space, parent)?;
    let stream = match existing {
        Some(stream) => stream,
        None => {
            let stream = streams.new_stream(space, &Parent::Stream(parent.clone()))?;
            let entry =
                Event::Entry { stream: stream.clone(), name: name.to_owned(), directory: false, trashed: false };
            streams.write(space, &parent, &entry)?;
            stream
        }
    };
    let parts = streams.put_original(space, &stream, data)?;
    let version = Event::Version {
        parts,
        size: data.len() as u64,
        media_type: info.media_type.map(str::to_owned),
        modified: info.modified.map(str::to_owned),
    };
    streams.write(space, &stream, &version)?;
    Ok(stream)
}

/// The content of a file of the vault: its newest version.
pub fn read_file(streams: &Streams, space: &SpaceId, file: &StreamId) -> Result<Vec<u8>> {
    let (parts, ..) = latest_version(streams, space, file)?.ok_or_else(|| invalid("a file without content"))?;
    streams.original(space, file, &parts)
}

fn find(streams: &Streams, space: &SpaceId, directory: &StreamId, stream: &StreamId) -> Result<Entry> {
    list(streams, space, Some(directory.clone()))?
        .into_iter()
        .find(|e| e.id == stream.as_str())
        .ok_or_else(|| invalid("no such entry in the directory"))
}

fn rewrite(
    streams: &mut Streams,
    space: &SpaceId,
    parent: Option<StreamId>,
    stream: StreamId,
    change: impl FnOnce(&mut Entry),
) -> Result<()> {
    let parent = root_or(streams, space, parent)?;
    let mut found = find(streams, space, &parent, &stream)?;
    change(&mut found);
    let event = Event::Entry { stream, name: found.name, directory: found.directory, trashed: found.trashed };
    streams.write(space, &parent, &event).map(drop)
}

/// Renames something in a directory of the vault.
pub fn rename(
    streams: &mut Streams,
    space: &SpaceId,
    parent: Option<StreamId>,
    entry: StreamId,
    name: &str,
) -> Result<()> {
    rewrite(streams, space, parent, entry, |e| e.name = name.to_owned())
}

/// Moves something of the vault into its trash, or – `trashed` false – back.
pub fn set_trashed(
    streams: &mut Streams,
    space: &SpaceId,
    parent: Option<StreamId>,
    entry: StreamId,
    trashed: bool,
) -> Result<()> {
    rewrite(streams, space, parent, entry, |e| e.trashed = trashed)
}

/// Whether `inner` lies somewhere below the directory `outer`.
fn below(streams: &Streams, space: &SpaceId, outer: &StreamId, inner: &StreamId) -> Result<bool> {
    let mut pending = vec![outer.clone()];
    let mut seen = 0usize;
    while let Some(directory) = pending.pop() {
        seen += 1;
        if seen > 100_000 {
            return Ok(true);
        }
        for entry in list(streams, space, Some(directory))?.into_iter().filter(|e| e.directory) {
            let stream = stream_id(&entry.id)?;
            if stream == *inner {
                return Ok(true);
            }
            pending.push(stream);
        }
    }
    Ok(false)
}

/// Moves something into another directory of the vault (`None`: its top), under its name.
pub fn move_to(
    streams: &mut Streams,
    space: &SpaceId,
    from: Option<StreamId>,
    entry: StreamId,
    to: Option<StreamId>,
) -> Result<()> {
    let from = root_or(streams, space, from)?;
    let to = root_or(streams, space, to)?;
    if from == to {
        return Ok(());
    }
    if to == entry || below(streams, space, &entry, &to)? {
        return Err(invalid("a directory cannot move below itself"));
    }
    let found = find(streams, space, &from, &entry)?;
    streams.link_below(space, &entry, &to)?;
    let event = Event::Entry { stream: entry.clone(), name: found.name, directory: found.directory, trashed: false };
    streams.write(space, &to, &event)?;
    streams.write(space, &from, &Event::Gone { stream: entry }).map(drop)
}

/// Removes something of the vault for good: gone from its directory, and – where this device may purge – its streams
/// with all below them removed at the relay.
pub fn remove(streams: &mut Streams, space: &SpaceId, parent: Option<StreamId>, entry: StreamId) -> Result<()> {
    let parent = root_or(streams, space, parent)?;
    streams.write(space, &parent, &Event::Gone { stream: entry.clone() })?;
    let me = streams.device_id(space)?;
    if streams.roster(space)?.device(&me).is_some_and(|d| d.may(Permission::Purge)) {
        let mut pending = vec![entry];
        while let Some(stream) = pending.pop() {
            for below in list(streams, space, Some(stream.clone()))? {
                pending.push(stream_id(&below.id)?);
            }
            streams.purge(space, &stream)?;
        }
    }
    Ok(())
}

/// The accounts that are members of the vault (their ids).
pub fn members(streams: &Streams, space: &SpaceId) -> Result<Vec<String>> {
    Ok(streams.roster(space)?.persons().filter_map(|p| p.name.clone()).collect())
}

/// How far a member may go – as the file store's grant says: read, edit, or edit and share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Reading only: the relay takes nothing written.
    Read,
    /// Writing (`write`).
    Edit,
    /// Writing, adding and removing members, purging (`write`, `members`, `purge`).
    Full,
}

impl Level {
    /// The level of the file store's rights: sharing is full, changing content is edit, else read.
    pub fn of(may_share: bool, may_change: bool) -> Self {
        if may_share {
            Level::Full
        } else if may_change {
            Level::Edit
        } else {
            Level::Read
        }
    }

    fn permissions(self) -> &'static [Permission] {
        match self {
            Level::Read => &[],
            Level::Edit => &[Permission::Write],
            Level::Full => &[Permission::Write, Permission::Members, Permission::Purge],
        }
    }

    /// The level permissions amount to.
    fn from_permissions(may: impl Fn(Permission) -> bool) -> Self {
        if may(Permission::Members) {
            Level::Full
        } else if may(Permission::Write) {
            Level::Edit
        } else {
            Level::Read
        }
    }
}

/// The accounts that are members of the vault with their levels (as their recovery devices carry them).
pub fn member_levels(streams: &Streams, space: &SpaceId) -> Result<Vec<(String, Level)>> {
    let roster = streams.roster(space)?;
    let mut out = Vec::new();
    for person in roster.persons() {
        let Some(name) = &person.name else { continue };
        let level = roster
            .devices_of(&person.id)
            .map(|d| Level::from_permissions(|p| d.may(p)))
            .max_by_key(|l| *l as u8)
            .unwrap_or(Level::Read);
        out.push((name.clone(), level));
    }
    Ok(out)
}

/// Makes an account a member at `level`: a person named by its id, and its recovery code – for the caller to hand to
/// the account (sealed to its key). Nothing happens for a member already there (`None`).
pub fn add_member(streams: &mut Streams, space: &SpaceId, account: &str, level: Level) -> Result<Option<RecoveryCode>> {
    streams.sync(space)?;
    if members(streams, space)?.iter().any(|m| m == account) {
        return Ok(None);
    }
    let (_, code) = streams.add_person(space, Some(account), level.permissions())?;
    Ok(Some(code))
}

/// What [`set_members`] did: the accounts that need a (new) recovery code, and those that left.
#[derive(Debug, Default)]
pub struct Membership {
    pub codes: Vec<(String, RecoveryCode)>,
    pub removed: Vec<String>,
}

/// Brings the vault's members in line with whom it is shared with: `wanted` – accounts with their levels –; `own`, the
/// caller's account, stays as it is. Who is no longer wanted leaves; who is new comes in; who has another level leaves
/// and comes in again with it (a person's permissions are fixed in the roster) – and so gets a new code, with which
/// their devices come in again ([`Streams::forget`]). Needs `members`.
pub fn set_members(
    streams: &mut Streams,
    space: &SpaceId,
    own: &str,
    wanted: &[(String, Level)],
) -> Result<Membership> {
    streams.sync(space)?;
    let current = member_levels(streams, space)?;
    let mut done = Membership::default();
    for (account, level) in &current {
        if account == own {
            continue;
        }
        match wanted.iter().find(|(a, _)| a == account) {
            None => {
                remove_member(streams, space, account)?;
                done.removed.push(account.clone());
            }
            Some((_, wanted_level)) if wanted_level != level => remove_member(streams, space, account)?,
            Some(_) => {}
        }
    }
    for (account, level) in wanted {
        if account == own {
            continue;
        }
        if let Some(code) = add_member(streams, space, account, *level)? {
            done.codes.push((account.clone(), code));
        }
    }
    Ok(done)
}

/// Ends an account's membership: its person leaves – what is written from now on is out of its reach.
pub fn remove_member(streams: &mut Streams, space: &SpaceId, account: &str) -> Result<()> {
    streams.sync(space)?;
    let roster = streams.roster(space)?;
    let persons: Vec<PersonId> =
        roster.persons().filter(|p| p.name.as_deref() == Some(account)).map(|p| p.id.clone()).collect();
    for person in persons {
        streams.remove_person(space, &person)?;
    }
    Ok(())
}

/// Reads what is new; a device removed from the vault – its person left, maybe to come in again at another level –
/// forgets it and says so (`false`), for the caller to come in again with the account's code.
pub fn sync(streams: &mut Streams, space: &SpaceId) -> Result<bool> {
    match streams.sync(space) {
        Ok(_) => Ok(true),
        Err(error) if Streams::is_removed(&error) => {
            streams.forget(space)?;
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// The device setting under which this device's name in its vaults is kept.
const DEVICE: &str = "vaults.device";

/// The spaces of vaults kept in `store`, reaching relays through `transport` (`None`: the platform's). This device's
/// name in them is made the first time – from `name` (e.g. the host's) and a random part – and kept in the store.
pub fn open(
    store: kernoid_space_store::Store,
    name: &str,
    transport: Option<std::sync::Arc<dyn kernoid_replica::transport::Transport>>,
) -> Result<Streams> {
    use kernoid_space_store::Backend;
    let device = match store.setting(None, DEVICE)? {
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
            let random: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let device = format!("{}-{random}", if stem.is_empty() { "device" } else { stem });
            store.set_setting(None, DEVICE, &device)?;
            device
        }
    };
    let device = device.parse().map_err(|_| invalid("a device name that is not one"))?;
    let domain = kernoid_crypt::Domain::KERNOID;
    Ok(match transport {
        Some(transport) => Streams::with_transport(domain, device, store, transport),
        None => Streams::open(domain, device, store),
    })
}
