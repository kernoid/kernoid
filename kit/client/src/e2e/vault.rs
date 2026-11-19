// SPDX-License-Identifier: MIT
//! Vaults (RFC 0006, 6): directories whose content only their members read. A vault has an OpenPGP key of its own,
//! made here; its secret key goes to the server only wrapped – encrypted to the key of each member (`VaultKey/get`,
//! `/set`). Inside, files are encrypted to the vault's key before they are uploaded, and names are an id with the real
//! name encrypted beside it (`kernoid:encryptedName`). Everything here needs the account's own key unlocked. Like the
//! web app, a file is encrypted in one piece in memory (**OPEN**: in pieces, for very large files).

use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use kernoid_e2e::{Kind, PublicKey, SecretKey, message};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use super::{E2e, OPENPGP, decode, list};
use crate::{
    Client, Error, FILENODE, Result,
    files::{FileNode, Principal, media_type},
};

const USING: [&str; 2] = [FILENODE, OPENPGP];

/// A random UUID (version 4), as the web app's `crypto.randomUUID()`.
fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the system's random numbers");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// A name for a node inside a vault: an id, unique among its siblings.
fn opaque_name() -> String {
    format!("k-{}", random_uuid())
}

#[derive(Deserialize)]
struct WrappedKey {
    #[serde(default)]
    sealed: Option<String>,
    #[serde(default)]
    members: Vec<String>,
}

impl E2e {
    /// Whether vaults can be made here: the server has them and the tenant does not forbid them.
    pub fn vaults_allowed(&self) -> bool {
        self.available && self.settings.policy.vaults != "forbidden"
    }

    pub(crate) fn need_unlocked(&self) -> Result<&SecretKey> {
        self.current.as_ref().ok_or_else(|| Error::E2e("unlock your key first".into()))
    }

    /// What the server keeps of a vault's key for this account, and who has a copy.
    async fn wrapped(client: &Client, account: &str, vault: &str) -> Result<WrappedKey> {
        let result = client.call(&USING, "VaultKey/get", json!({ "accountId": account, "ids": [vault] })).await?;
        list::<WrappedKey>(&result)?.into_iter().next().ok_or_else(|| Error::E2e("no such vault".into()))
    }

    /// The vault's key: its wrapped secret fetched once and unwrapped with the account's key. `None` while no member
    /// gave this account a copy.
    async fn vault_key(&mut self, client: &Client, account: &str, vault: &str) -> Result<Option<SecretKey>> {
        if let Some(key) = self.vaults.get(vault) {
            return Ok(Some(key.clone()));
        }
        self.need_unlocked()?;
        let Some(sealed) = Self::wrapped(client, account, vault).await?.sealed else {
            return Ok(None);
        };
        let Ok(opened) = message::decrypt(&decode(&sealed)?, &self.secrets(), &[]) else {
            return Ok(None);
        };
        let key = SecretKey::import(&opened.data)?;
        self.vaults.insert(vault.to_owned(), key.clone());
        Ok(Some(key))
    }

    async fn need_vault_key(&mut self, client: &Client, account: &str, vault: &str) -> Result<SecretKey> {
        self.need_unlocked()?;
        self.vault_key(client, account, vault)
            .await?
            .ok_or_else(|| Error::E2e("no member gave you this vault's key yet".into()))
    }

    /// Fills in the real names of nodes in vaults whose key is at hand; the others stay `locked`, named by their id.
    pub async fn open_names(&mut self, client: &Client, account: &str, nodes: &mut [FileNode]) {
        for node in nodes.iter_mut() {
            let (Some(vault), Some(sealed)) = (node.vault.clone(), node.encrypted_name.clone()) else { continue };
            node.locked = true;
            if let Some(name) = self.open_name(client, account, &vault, &sealed).await {
                node.name = name;
                node.locked = false;
            }
        }
    }

    /// The real name of a node in a vault (`kernoid:encryptedName`) – `None` while the vault's key is not at hand.
    pub async fn open_name(&mut self, client: &Client, account: &str, vault: &str, sealed: &str) -> Option<String> {
        self.current.as_ref()?;
        let key = self.vault_key(client, account, vault).await.ok().flatten()?;
        decode(sealed)
            .ok()
            .and_then(|bytes| message::decrypt(&bytes, &[&key], &[]).ok())
            .and_then(|opened| String::from_utf8(opened.data).ok())
    }

    /// A name for a node in a vault: the id it gets as `name` and the real name encrypted, for
    /// `kernoid:encryptedName`.
    pub async fn name_in(
        &mut self,
        client: &Client,
        account: &str,
        vault: &str,
        name: &str,
    ) -> Result<(String, String)> {
        let key = self.need_vault_key(client, account, vault).await?;
        Ok((opaque_name(), seal(&key.public(), name)?))
    }

    /// Content for a vault: encrypted to its key and signed with the account's, as a file's blob there is.
    pub async fn seal_content(
        &mut self,
        client: &Client,
        account: &str,
        vault: &str,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let key = self.need_vault_key(client, account, vault).await?;
        let signer = self.need_unlocked()?.clone();
        let public = key.public();
        tokio::task::spawn_blocking(move || message::encrypt(&data, &[&public], Some(&signer), false))
            .await
            .map_err(|error| Error::E2e(error.to_string()))?
            .map_err(Into::into)
    }

    /// The content of a file of a vault, decrypted.
    pub async fn open_content(
        &mut self,
        client: &Client,
        account: &str,
        vault: &str,
        sealed: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let key = self.need_vault_key(client, account, vault).await?;
        let opened = tokio::task::spawn_blocking(move || message::decrypt(&sealed, &[&key], &[]))
            .await
            .map_err(|error| Error::E2e(error.to_string()))??;
        Ok(opened.data)
    }

    /// Moves or renames a node within its vault: a new id for its name, the real name encrypted anew.
    pub async fn move_in(
        &mut self,
        client: &Client,
        account: &str,
        vault: &str,
        id: &str,
        parent: &str,
        name: &str,
    ) -> Result<()> {
        let (opaque, sealed) = self.name_in(client, account, vault, name).await?;
        let update =
            json!({ "update": { id: { "parentId": parent, "name": opaque, "kernoid:encryptedName": sealed } } });
        client.set(&USING, "FileNode", account, update, json!({})).await?;
        Ok(())
    }

    /// Makes a vault in `parent` (`None`: the top of the store): its key here, the secret wrapped for the account's own
    /// key, the name encrypted. Returns its id.
    pub async fn create_vault(
        &mut self,
        client: &Client,
        account: &str,
        parent: Option<&str>,
        name: &str,
    ) -> Result<String> {
        let own = self.need_unlocked()?.public();
        let address = format!("vault-{}@vault.invalid", random_uuid());
        // A post-quantum key takes a moment to make.
        let key = tokio::task::spawn_blocking(move || SecretKey::generate(Kind::Pqc, &[address.as_str()]))
            .await
            .map_err(|error| Error::E2e(error.to_string()))??;
        let public = key.public();
        let sealed = message::encrypt(key.export()?.as_bytes(), &[&own], None, false)?;
        let create = json!({ "create": { "v": {
            "@type": "Directory",
            "parentId": parent,
            "name": opaque_name(),
            "kernoid:encryptedName": seal(&public, name)?,
            "kernoid:newVault": { "publicKey": STANDARD.encode(public.to_bytes()?), "sealed": STANDARD.encode(sealed) },
        } } });
        let result = client.set(&USING, "FileNode", account, create, json!({})).await?;
        let id = created_id(&result, "v")?;
        self.vaults.insert(id.clone(), key);
        Ok(id)
    }

    /// A directory inside a vault.
    pub async fn create_directory_in(
        &mut self,
        client: &Client,
        account: &str,
        vault: &str,
        parent: &str,
        name: &str,
    ) -> Result<()> {
        self.make_directory_in(client, account, vault, parent, name).await.map(drop)
    }

    /// A directory inside a vault; returns its id.
    pub async fn make_directory_in(
        &mut self,
        client: &Client,
        account: &str,
        vault: &str,
        parent: &str,
        name: &str,
    ) -> Result<String> {
        let (opaque, sealed) = self.name_in(client, account, vault, name).await?;
        let create = json!({ "create": { "d": {
            "@type": "Directory", "parentId": parent, "name": opaque, "kernoid:encryptedName": sealed,
        } } });
        let result = client.set(&USING, "FileNode", account, create, json!({})).await?;
        created_id(&result, "d")
    }

    /// Renames a node in a vault: a new id for a name, the real one encrypted anew.
    pub async fn rename_in(&mut self, client: &Client, account: &str, node: &FileNode, name: &str) -> Result<()> {
        let vault = node.vault.as_deref().ok_or_else(|| Error::E2e("not in a vault".into()))?;
        let key = self.need_vault_key(client, account, vault).await?;
        let update = json!({ "update": { node.id.as_str(): {
            "name": opaque_name(), "kernoid:encryptedName": seal(&key.public(), name)?,
        } } });
        client.set(&USING, "FileNode", account, update, json!({})).await?;
        Ok(())
    }

    /// Uploads a file into a directory of a vault, encrypted here to the vault's key and signed with the account's;
    /// `existing` (a file of the same real name) gets the new content.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_into(
        &mut self,
        client: &Client,
        account: &str,
        vault: &str,
        parent: &str,
        path: &Path,
        existing: Option<&FileNode>,
        progress: impl FnMut(u64, u64) + Send + 'static,
    ) -> Result<()> {
        let key = self.need_vault_key(client, account, vault).await?;
        let signer = self.need_unlocked()?.clone();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::Protocol("the file name is not UTF-8".into()))?
            .to_owned();
        let data = tokio::fs::read(path).await?;
        let modified = tokio::fs::metadata(path)
            .await?
            .modified()
            .ok()
            .map(|time| jiff::Timestamp::try_from(time).map(|time| format!("{time:.0}")).ok());
        let public = key.public();
        let sealed = tokio::task::spawn_blocking(move || message::encrypt(&data, &[&public], Some(&signer), false))
            .await
            .map_err(|error| Error::E2e(error.to_string()))??;
        let size = sealed.len() as u64;
        let upload =
            client.upload(account, "application/octet-stream", std::io::Cursor::new(sealed), size, progress).await?;
        let kind = media_type(&name);
        match existing.filter(|node| !node.is_directory()) {
            Some(node) => {
                let update = json!({ "update": { node.id.as_str(): {
                    "blobId": upload.blob_id, "mediaType": kind, "modified": modified,
                } } });
                client.set(&USING, "FileNode", account, update, json!({})).await?;
            }
            None => {
                let create = json!({ "create": { "f": {
                    "@type": "File", "parentId": parent, "name": opaque_name(),
                    "kernoid:encryptedName": seal(&key.public(), &name)?,
                    "blobId": upload.blob_id, "mediaType": kind, "modified": modified,
                } } });
                client.set(&USING, "FileNode", account, create, json!({})).await?;
            }
        }
        Ok(())
    }

    /// Downloads a file of a vault and decrypts it here; returns its content.
    pub async fn download_from(&mut self, client: &Client, account: &str, node: &FileNode) -> Result<Vec<u8>> {
        let vault = node.vault.as_deref().ok_or_else(|| Error::E2e("not in a vault".into()))?;
        let blob = node.blob_id.as_deref().ok_or_else(|| Error::E2e("not a file".into()))?;
        self.need_vault_key(client, account, vault).await?;
        let mut sealed = Vec::new();
        client.download(account, blob, "encrypted", "application/octet-stream", &mut sealed, &mut |_, _| {}).await?;
        self.open_content(client, account, vault, sealed).await
    }

    /// Downloads a file of a vault, decrypted, into `path`.
    pub async fn save_from(&mut self, client: &Client, account: &str, node: &FileNode, path: &Path) -> Result<()> {
        let data = self.download_from(client, account, node).await?;
        let mut file = tokio::fs::File::create(path).await?;
        file.write_all(&data).await?;
        file.flush().await?;
        Ok(())
    }

    /// After sharing a vault: gives its key to every person shared with who has a key of their own and no copy yet.
    /// Groups and people without a key wait (**OPEN**: a group's members, as in the web app). Returns those who wait.
    pub async fn give_vault_keys(
        &mut self,
        client: &Client,
        account: &str,
        vault: &str,
        people: &[Principal],
    ) -> Result<Vec<Principal>> {
        let key = self.need_vault_key(client, account, vault).await?;
        let members = Self::wrapped(client, account, vault).await?.members;
        let secret = key.export()?;
        let mut waiting = Vec::new();
        let mut update = serde_json::Map::new();
        for person in people.iter().filter(|person| !members.contains(&person.id)) {
            let keys: Vec<PublicKey> = match (person.kind.as_str(), &person.email) {
                ("individual", Some(email)) => {
                    self.lookup(client, std::slice::from_ref(email)).await?.into_values().flatten().collect()
                }
                _ => Vec::new(),
            };
            if keys.is_empty() {
                waiting.push(person.clone());
                continue;
            }
            let recipients: Vec<&PublicKey> = keys.iter().collect();
            let wrapped = message::encrypt(secret.as_bytes(), &recipients, None, false)?;
            update.insert(format!("members/{}", person.id), Value::String(STANDARD.encode(wrapped)));
        }
        if !update.is_empty() {
            let change = json!({ "update": { vault: update } });
            client.set(&USING, "VaultKey", account, change, json!({})).await?;
        }
        Ok(waiting)
    }
}

/// A name encrypted to a vault's key, base64.
fn seal(vault: &PublicKey, name: &str) -> Result<String> {
    Ok(STANDARD.encode(message::encrypt(name.as_bytes(), &[vault], None, false)?))
}

/// The id of what a `…/set` made under `key`.
fn created_id(result: &Value, key: &str) -> Result<String> {
    result
        .pointer(&format!("/created/{key}/id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Protocol("the server made nothing".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_in_a_vault_are_random_ids() {
        let (a, b) = (opaque_name(), opaque_name());
        assert_ne!(a, b);
        assert_eq!(a.len(), 2 + 36);
        assert!(a.starts_with("k-") && a.as_bytes()[2 + 14] == b'4');
    }
}
