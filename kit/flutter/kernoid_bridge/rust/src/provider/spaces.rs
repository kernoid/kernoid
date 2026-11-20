// SPDX-License-Identifier: MIT
//! Vaults on spaces in the shells (RFC 0010, 5): what lies in one is shown in the system's file manager as the app shows
//! it. The shell is a device of its own in each vault – its sealed store written by it alone –, come in with the code
//! the app hands it when the app enters the vault (`shell-codes.sealed`); the app's login kept for the shell names both
//! (`Kernoid::give_shell_vaults`).
//!
//! An entry of a vault is an item whose id is `s|<vault's directory>|<stream>`; the vault's directory keeps the store's
//! id and shows the vault's name. A shell that may only read sees nothing it could change.

use kernoid_client::{
    Client,
    e2e::{Entry, Level, Vaults},
    files::{self, FileNode},
};
use serde_json::{Value, json};

use crate::api::kernoid::{KernoidError, ShellVaults, read_codes};

fn error(message: &str) -> KernoidError {
    KernoidError { unauthorized: false, message: message.to_owned() }
}

/// A shell's vaults: its store and where the codes come from.
pub(crate) struct ShellSpaces {
    pub vaults: Vaults,
    codes: String,
    key: [u8; 32],
}

impl ShellSpaces {
    pub fn open(given: &ShellVaults) -> Result<Self, KernoidError> {
        let key = given.key().ok_or_else(|| error("the shell's vaults have no key"))?;
        let path = std::path::Path::new(&given.store);
        let vaults = match Vaults::open_sealed(path, key, "files") {
            Ok(vaults) => vaults,
            // Sealed under another key: the vaults come again from the relay, with the codes.
            Err(_) => {
                let _ = std::fs::remove_file(path);
                Vaults::open_sealed(path, key, "files")?
            }
        };
        Ok(ShellSpaces { vaults, codes: given.codes.clone(), key })
    }

    /// Whether the shell has the vault of `node` now – reading what is new, or coming in with the code the app handed
    /// it.
    pub async fn ready(&self, client: &Client, node: &FileNode) -> bool {
        if node.space.is_none() {
            return false;
        }
        if self.vaults.has(node).await.unwrap_or(false) {
            return self.vaults.sync(node).await.is_ok();
        }
        let codes = read_codes(&self.codes, &self.key);
        let Some((_, code)) = codes.get(&node.id) else { return false };
        let code: Option<[u8; 32]> = (0..code.len())
            .step_by(2)
            .filter_map(|i| code.get(i..i + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok()))
            .collect::<Vec<u8>>()
            .try_into()
            .ok();
        match code {
            Some(code) => self.vaults.enter_with_code(client, node, code).await.is_ok(),
            None => false,
        }
    }
}

/// The parts of an entry's id: the vault's directory and the stream.
pub(crate) fn parse(id: &str) -> Option<(&str, &str)> {
    let rest = id.strip_prefix("s|")?;
    rest.split_once('|')
}

pub(crate) fn entry_id(vault: &str, stream: &str) -> String {
    format!("s|{vault}|{stream}")
}

/// The vault's directory as the store has it, with its space.
pub(crate) async fn vault_node(client: &Client, store: &str, vault: &str) -> Result<FileNode, KernoidError> {
    let node = files::get(client, store, vault).await?;
    if node.space.is_none() {
        return Err(error("not a vault on a space"));
    }
    Ok(node)
}

/// An entry as the shells see an item: rights from how far the shell may go in the vault.
fn item(vault: &str, parent: &str, entry: &Entry, level: Level) -> Value {
    let write = level != Level::Read;
    json!({
        "id": entry_id(vault, &entry.id),
        "parent": parent,
        "name": entry.name,
        "directory": entry.directory,
        "size": entry.size,
        "modified": entry.modified,
        "mediaType": entry.media_type,
        "role": null,
        "version": format!("{}|{}|{}", entry.version, parent, entry.name),
        "rights": { "read": true, "add": write && entry.directory, "rename": write, "delete": write, "write": write },
        "vault": vault,
        "locked": false,
    })
}

/// What lies in a directory of the vault – `directory` none: its top –, trashed entries left out.
pub(crate) async fn list(
    spaces: &ShellSpaces,
    vault: &FileNode,
    directory: Option<&str>,
) -> Result<Vec<Value>, KernoidError> {
    let level = spaces.vaults.level(vault).await?;
    let parent = directory.map_or_else(|| vault.id.clone(), |d| entry_id(&vault.id, d));
    Ok(spaces
        .vaults
        .list(vault, directory)
        .await?
        .iter()
        .filter(|e| !e.trashed)
        .map(|e| item(&vault.id, &parent, e, level))
        .collect())
}

/// Every entry of the vault, as items – what a shell's full listing and the changes compare.
pub(crate) async fn all(spaces: &ShellSpaces, vault: &FileNode) -> Result<Vec<Value>, KernoidError> {
    let mut out = Vec::new();
    let mut pending: Vec<Option<String>> = vec![None];
    while let Some(directory) = pending.pop() {
        for value in list(spaces, vault, directory.as_deref()).await? {
            if value["directory"].as_bool() == Some(true)
                && let Some((_, stream)) = value["id"].as_str().and_then(parse)
            {
                pending.push(Some(stream.to_owned()));
            }
            out.push(value);
        }
    }
    Ok(out)
}

/// An entry by its stream, with the directory it lies in (none: the vault's top).
pub(crate) async fn find(
    spaces: &ShellSpaces,
    vault: &FileNode,
    stream: &str,
) -> Result<(Entry, Option<String>), KernoidError> {
    let mut pending: Vec<Option<String>> = vec![None];
    while let Some(directory) = pending.pop() {
        for entry in spaces.vaults.list(vault, directory.as_deref()).await? {
            if entry.id == stream {
                return Ok((entry, directory));
            }
            if entry.directory {
                pending.push(Some(entry.id.clone()));
            }
        }
    }
    Err(error("no such item in the vault"))
}

/// The item of an entry.
pub(crate) async fn entry_item(spaces: &ShellSpaces, vault: &FileNode, stream: &str) -> Result<Value, KernoidError> {
    let (entry, directory) = find(spaces, vault, stream).await?;
    let level = spaces.vaults.level(vault).await?;
    let parent = directory.map_or_else(|| vault.id.clone(), |d| entry_id(&vault.id, &d));
    Ok(item(&vault.id, &parent, &entry, level))
}

/// The directory an item names as a parent inside a vault: its stream, or none for the vault's directory itself.
pub(crate) fn directory_of(vault: &str, parent: &str) -> Option<String> {
    if parent == vault { None } else { parse(parent).map(|(_, stream)| stream.to_owned()) }
}
