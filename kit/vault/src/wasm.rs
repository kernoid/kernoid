// SPDX-License-Identifier: MIT
//! The web app's view (`@kernoid/vault`): [`WebVaults`] keeps the spaces of an account's vaults in a store in memory,
//! which the page saves as bytes (IndexedDB) after each change and gives back when it opens them again. The relay is
//! reached through a function of the page – synchronous, so it runs in a worker (a synchronous `XMLHttpRequest`):
//! `send(method, url, headers, body)` returns `{ status, body }`, `headers` being pairs and `body` a `Uint8Array` or
//! null. Identities and names go in and out as text, lists as JSON.

use std::sync::Arc;

use js_sys::{Array, Function, Reflect, Uint8Array};
use kernoid_base::SpaceId;
use kernoid_crypt::RecoveryCode;
use kernoid_replica::{SyncError, streams::Streams, transport::Transport};
use kernoid_space_store::Store;
use wasm_bindgen::prelude::*;

use crate::{FileInfo, stream_id};

fn js(error: SyncError) -> JsError {
    JsError::new(&error.to_string())
}

fn space(text: &str) -> Result<SpaceId, JsError> {
    text.parse().map_err(|_| JsError::new("not a space"))
}

fn stream(text: Option<String>) -> Result<Option<kernoid_crypt::stream::StreamId>, JsError> {
    text.as_deref().map(stream_id).transpose().map_err(js)
}

/// The relay reached through the page's function.
struct PageTransport(Function);

impl Transport for PageTransport {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String> {
        let pairs = Array::new();
        for (name, value) in headers {
            pairs.push(&Array::of2(&JsValue::from_str(name), &JsValue::from_str(value)));
        }
        let body = body.map_or(JsValue::NULL, |body| Uint8Array::from(&body[..]).into());
        let answer = self
            .0
            .call4(&JsValue::NULL, &JsValue::from_str(method), &JsValue::from_str(url), &pairs, &body)
            .map_err(|error| error.as_string().unwrap_or_else(|| format!("{error:?}")))?;
        let status = Reflect::get(&answer, &JsValue::from_str("status"))
            .ok()
            .and_then(|status| status.as_f64())
            .ok_or("an answer without a status")?;
        let body = Reflect::get(&answer, &JsValue::from_str("body")).map_err(|_| "an answer without a body")?;
        let body = if body.is_null() || body.is_undefined() { Vec::new() } else { Uint8Array::new(&body).to_vec() };
        Ok((status as u16, body))
    }
}

/// A space founded: its identity and the founder's recovery code.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Founded {
    space: String,
    code: Vec<u8>,
}

#[wasm_bindgen]
impl Founded {
    #[wasm_bindgen(getter)]
    pub fn space(&self) -> String {
        self.space.clone()
    }

    /// The recovery code's 32 bytes – for sealing to the account's key, never to be shown.
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> Vec<u8> {
        self.code.clone()
    }
}

/// The vaults on spaces of one account in this browser.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebVaults {
    streams: Streams,
}

#[wasm_bindgen]
impl WebVaults {
    /// The vaults of `saved` (bytes of [`WebVaults::save`], or none the first time), this browser named after `name`,
    /// reaching relays through `send`.
    #[wasm_bindgen(constructor)]
    pub fn new(saved: Option<Vec<u8>>, name: &str, send: Function) -> Result<WebVaults, JsError> {
        let store = match saved {
            Some(bytes) if !bytes.is_empty() => Store::from_bytes(&bytes),
            _ => Store::in_memory(),
        }
        .map_err(|error| JsError::new(&error.to_string()))?;
        let streams = crate::open(store, name, Some(Arc::new(PageTransport(send)))).map_err(js)?;
        Ok(WebVaults { streams })
    }

    /// The whole store, for the page to keep.
    pub fn save(&mut self) -> Result<Vec<u8>, JsError> {
        self.streams.store_mut().to_bytes().map_err(|error| JsError::new(&error.to_string()))
    }

    /// Founds a vault at `relay` for `account` (its id), named `name` – `founder`: the login's token, or none where
    /// the page's session cookie goes with the request.
    pub fn found(
        &mut self,
        relay: &str,
        founder: Option<String>,
        device_name: &str,
        account: &str,
        name: &str,
    ) -> Result<Founded, JsError> {
        let (space, code) =
            crate::found(&mut self.streams, relay, founder.as_deref(), Some(device_name), account, name).map_err(js)?;
        Ok(Founded { space: space.to_string(), code: code.0.to_vec() })
    }

    #[wasm_bindgen(js_name = hasSpace)]
    pub fn has_space(&self, space_id: &str) -> Result<bool, JsError> {
        self.streams.has_space(&space(space_id)?).map_err(js)
    }

    /// Comes into a vault with a recovery code of the account's person.
    pub fn recover(&mut self, relay: &str, space_id: &str, code: Vec<u8>, device_name: &str) -> Result<(), JsError> {
        let code: [u8; 32] = code.try_into().map_err(|_| JsError::new("not a recovery code"))?;
        self.streams.recover(relay, &space(space_id)?, &RecoveryCode(code), Some(device_name)).map(drop).map_err(js)
    }

    /// Reads what is new in a vault; false when this browser was removed from it and forgot it – it comes in again
    /// with the account's code.
    pub fn sync(&mut self, space_id: &str) -> Result<bool, JsError> {
        crate::sync(&mut self.streams, &space(space_id)?).map_err(js)
    }

    pub fn name(&self, space_id: &str) -> Result<Option<String>, JsError> {
        crate::name(&self.streams, &space(space_id)?).map_err(js)
    }

    #[wasm_bindgen(js_name = renameVault)]
    pub fn rename_vault(&mut self, space_id: &str, name: &str) -> Result<(), JsError> {
        crate::rename_vault(&mut self.streams, &space(space_id)?, name).map_err(js)
    }

    /// What lies in a directory (`None`: the top), as JSON: `[{ id, name, directory, trashed, size, mediaType,
    /// modified }]`.
    pub fn list(&self, space_id: &str, directory: Option<String>) -> Result<String, JsError> {
        let entries = crate::list(&self.streams, &space(space_id)?, stream(directory)?).map_err(js)?;
        serde_json::to_string(&entries).map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = makeDirectory)]
    pub fn make_directory(&mut self, space_id: &str, parent: Option<String>, name: &str) -> Result<String, JsError> {
        crate::make_directory(&mut self.streams, &space(space_id)?, stream(parent)?, name)
            .map(|s| s.to_string())
            .map_err(js)
    }

    /// Puts a file – a new one, or a new version of `existing` –; returns its id.
    #[wasm_bindgen(js_name = putFile)]
    #[allow(clippy::too_many_arguments, reason = "a file with what describes it")]
    pub fn put_file(
        &mut self,
        space_id: &str,
        parent: Option<String>,
        name: &str,
        data: Vec<u8>,
        media_type: Option<String>,
        modified: Option<String>,
        existing: Option<String>,
    ) -> Result<String, JsError> {
        let info = FileInfo { media_type: media_type.as_deref(), modified: modified.as_deref() };
        crate::put_file(&mut self.streams, &space(space_id)?, stream(parent)?, name, &data, info, stream(existing)?)
            .map(|s| s.to_string())
            .map_err(js)
    }

    #[wasm_bindgen(js_name = readFile)]
    pub fn read_file(&self, space_id: &str, file: &str) -> Result<Vec<u8>, JsError> {
        crate::read_file(&self.streams, &space(space_id)?, &stream_id(file).map_err(js)?).map_err(js)
    }

    pub fn rename(&mut self, space_id: &str, parent: Option<String>, entry: &str, name: &str) -> Result<(), JsError> {
        let entry = stream_id(entry).map_err(js)?;
        crate::rename(&mut self.streams, &space(space_id)?, stream(parent)?, entry, name).map_err(js)
    }

    #[wasm_bindgen(js_name = setTrashed)]
    pub fn set_trashed(
        &mut self,
        space_id: &str,
        parent: Option<String>,
        entry: &str,
        trashed: bool,
    ) -> Result<(), JsError> {
        let entry = stream_id(entry).map_err(js)?;
        crate::set_trashed(&mut self.streams, &space(space_id)?, stream(parent)?, entry, trashed).map_err(js)
    }

    #[wasm_bindgen(js_name = moveTo)]
    pub fn move_to(
        &mut self,
        space_id: &str,
        from: Option<String>,
        entry: &str,
        to: Option<String>,
    ) -> Result<(), JsError> {
        let entry = stream_id(entry).map_err(js)?;
        crate::move_to(&mut self.streams, &space(space_id)?, stream(from)?, entry, stream(to)?).map_err(js)
    }

    pub fn remove(&mut self, space_id: &str, parent: Option<String>, entry: &str) -> Result<(), JsError> {
        let entry = stream_id(entry).map_err(js)?;
        crate::remove(&mut self.streams, &space(space_id)?, stream(parent)?, entry).map_err(js)
    }

    /// The accounts that are members, as JSON: their ids.
    pub fn members(&self, space_id: &str) -> Result<String, JsError> {
        let members = crate::members(&self.streams, &space(space_id)?).map_err(js)?;
        serde_json::to_string(&members).map_err(|error| JsError::new(&error.to_string()))
    }

    /// How far this browser may go in the vault: `read`, `edit` or `full`.
    #[wasm_bindgen(js_name = myLevel)]
    pub fn my_level(&self, space_id: &str) -> Result<String, JsError> {
        let level = crate::my_level(&self.streams, &space(space_id)?).map_err(js)?;
        serde_json::to_value(level)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(|| JsError::new("a level"))
    }

    /// The members with their levels, as JSON: `[[account, "read" | "edit" | "full"]]`.
    #[wasm_bindgen(js_name = memberLevels)]
    pub fn member_levels(&self, space_id: &str) -> Result<String, JsError> {
        let levels = crate::member_levels(&self.streams, &space(space_id)?).map_err(js)?;
        serde_json::to_string(&levels).map_err(|error| JsError::new(&error.to_string()))
    }

    /// Brings the members in line with `wanted` (JSON `[[account, level]]`); `own` stays. As JSON: `{ codes: [[account,
    /// [bytes]]], removed: [account] }` – the codes to seal to the accounts' keys.
    #[wasm_bindgen(js_name = setMembers)]
    pub fn set_members(&mut self, space_id: &str, own: &str, wanted: &str) -> Result<String, JsError> {
        let wanted: Vec<(String, crate::Level)> =
            serde_json::from_str(wanted).map_err(|error| JsError::new(&error.to_string()))?;
        let done = crate::set_members(&mut self.streams, &space(space_id)?, own, &wanted).map_err(js)?;
        let codes: Vec<(String, Vec<u8>)> = done.codes.into_iter().map(|(a, c)| (a, c.0.to_vec())).collect();
        serde_json::to_string(&serde_json::json!({ "codes": codes, "removed": done.removed }))
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&mut self, space_id: &str, account: &str) -> Result<(), JsError> {
        crate::remove_member(&mut self.streams, &space(space_id)?, account).map_err(js)
    }
}
