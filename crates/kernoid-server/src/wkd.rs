// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Web Key Directory (draft-koch-openpgp-webkey-service; RFC 0006, 4.4), both ways. kernoid serves the keys in use
//! of its accounts – the direct method on a tenant's verified domain itself
//! (`https://<domain>/.well-known/openpgpkey/hu/<hash>`), the advanced one on `openpgpkey.<domain>`
//! (`/.well-known/openpgpkey/<domain>/hu/<hash>`) – and asks other domains' directories for the keys of their
//! addresses (`Lookup`, behind JMAP's `OpenPgpKey/lookup`). Unknown addresses, accounts without a key and domains that
//! are no tenant's get the same `404`.

use std::{future::Future, pin::Pin};

use axum::{
    Extension,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use kernoid_identity::openpgp::wkd_hash;
use serde::Deserialize;

use crate::{AppState, Problem, forwarded::Client};

/// Keys one answer carries at most – an address has one key in use, but several accounts may share a local part
/// spelled differently.
const MAX_KEYS: usize = 8;

#[derive(Debug, Deserialize)]
pub(crate) struct LocalPart {
    l: Option<String>,
}

fn not_found() -> Response {
    Problem::new(StatusCode::NOT_FOUND).detail("no key here").into_response()
}

/// The domain a request names: `openpgpkey.<domain>` for the advanced method, else the host itself.
fn host_domain(client: Option<&Client>) -> Option<(String, bool)> {
    let host = client?.host.as_deref()?.to_ascii_lowercase();
    match host.strip_prefix("openpgpkey.") {
        Some(domain) => Some((domain.to_owned(), true)),
        None => Some((host, false)),
    }
}

async fn keys(state: &AppState, domain: &str, hash: &str, local: Option<&str>) -> Response {
    if !state.identity.wkd_domain(domain).await.unwrap_or(false) {
        return not_found();
    }
    // With `l=` the local part is given (and must fit the hash); without, every local part with a key is tried.
    let locals = match local {
        Some(local) if wkd_hash(local) == hash => vec![local.to_owned()],
        Some(_) => return not_found(),
        None => match state.identity.wkd_local_parts(domain).await {
            Ok(locals) => locals.into_iter().filter(|local| wkd_hash(local) == hash).collect(),
            Err(error) => {
                tracing::warn!(%error, "listing the local parts with keys");
                return Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
            }
        },
    };
    let mut body = Vec::new();
    for local in locals.iter().take(MAX_KEYS) {
        match state.identity.wkd_keys(domain, local).await {
            Ok(keys) => keys.iter().for_each(|key| body.extend_from_slice(key)),
            Err(error) => {
                tracing::warn!(%error, "reading keys for the Web Key Directory");
                return Problem::new(StatusCode::SERVICE_UNAVAILABLE).into_response();
            }
        }
    }
    if body.is_empty() {
        return not_found();
    }
    (
        [(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "max-age=3600")],
        [(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
        body,
    )
        .into_response()
}

/// `GET /.well-known/openpgpkey/hu/<hash>` – the direct method, on the domain itself.
pub(crate) async fn direct(
    State(state): State<AppState>,
    client: Option<Extension<Client>>,
    Path(hash): Path<String>,
    Query(query): Query<LocalPart>,
) -> Response {
    match host_domain(client.as_deref()) {
        Some((domain, false)) => keys(&state, &domain, &hash, query.l.as_deref()).await,
        _ => not_found(),
    }
}

/// `GET /.well-known/openpgpkey/<domain>/hu/<hash>` – the advanced method, on `openpgpkey.<domain>`.
pub(crate) async fn advanced(
    State(state): State<AppState>,
    client: Option<Extension<Client>>,
    Path((domain, hash)): Path<(String, String)>,
    Query(query): Query<LocalPart>,
) -> Response {
    match host_domain(client.as_deref()) {
        Some((host, true)) if host.eq_ignore_ascii_case(&domain) => {
            keys(&state, &domain.to_ascii_lowercase(), &hash, query.l.as_deref()).await
        }
        _ => not_found(),
    }
}

/// `GET /.well-known/openpgpkey/policy` and `/.well-known/openpgpkey/<domain>/policy`: an empty policy – the
/// directory exists (WKD, 4.5) – for a tenant's domain only.
pub(crate) async fn policy(
    State(state): State<AppState>,
    client: Option<Extension<Client>>,
    domain: Option<Path<String>>,
) -> Response {
    let Some((host, advanced)) = host_domain(client.as_deref()) else { return not_found() };
    if advanced != domain.is_some() || domain.as_ref().is_some_and(|d| !d.eq_ignore_ascii_case(&host)) {
        return not_found();
    }
    if !state.identity.wkd_domain(&host).await.unwrap_or(false) {
        return not_found();
    }
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "").into_response()
}

/// Looks up the keys of an outside address in its domain's Web Key Directory – advanced method first, then direct
/// (WKD, 3.1) – through the outbound client: HTTPS, public addresses only.
#[derive(Debug, Clone)]
pub struct Lookup {
    client: reqwest::Client,
}

impl Lookup {
    pub fn new() -> Self {
        Self { client: kernoid_oidc::outbound::client(false) }
    }

    async fn fetch(&self, url: &str) -> Option<Vec<u8>> {
        let response = self.client.get(url).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        if response.content_length().is_some_and(|length| length > 256 * 1024) {
            return None;
        }
        let body = response.bytes().await.ok()?;
        (body.len() <= 256 * 1024 && !body.is_empty()).then(|| body.to_vec())
    }
}

impl Default for Lookup {
    fn default() -> Self {
        Self::new()
    }
}

/// Splits concatenated binary keys of a WKD answer into single keys.
fn split_keys(body: &[u8]) -> Vec<Vec<u8>> {
    kernoid_e2e::PublicKey::parse_many(body).iter().filter_map(|key| key.to_bytes().ok()).take(MAX_KEYS).collect()
}

impl kernoid_jmap::KeyDirectory for Lookup {
    fn lookup<'a>(&'a self, address: &'a str) -> Pin<Box<dyn Future<Output = Vec<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let Some((local, domain)) = address.rsplit_once('@') else { return Vec::new() };
            let (hash, domain) = (wkd_hash(local), domain.to_ascii_lowercase());
            let local = url::form_urlencoded::byte_serialize(local.as_bytes()).collect::<String>();
            let advanced = format!("https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={local}");
            let direct = format!("https://{domain}/.well-known/openpgpkey/hu/{hash}?l={local}");
            let body = match self.fetch(&advanced).await {
                Some(body) => Some(body),
                None => self.fetch(&direct).await,
            };
            body.map(|body| split_keys(&body)).unwrap_or_default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_names_the_method() {
        let client = |host: &str| Client { address: [127, 0, 0, 1].into(), host: Some(host.to_owned()), https: true };
        assert_eq!(host_domain(Some(&client("openpgpkey.Firma.de"))), Some(("firma.de".to_owned(), true)));
        assert_eq!(host_domain(Some(&client("firma.de"))), Some(("firma.de".to_owned(), false)));
        assert_eq!(host_domain(None), None);
    }

    #[test]
    fn concatenated_keys_are_split() {
        let one = kernoid_e2e::SecretKey::generate(kernoid_e2e::Kind::Compatible, &["a@x.example"]).unwrap();
        let two = kernoid_e2e::SecretKey::generate(kernoid_e2e::Kind::Pqc, &["a@x.example"]).unwrap();
        let mut body = one.public().to_bytes().unwrap();
        body.extend(two.public().to_bytes().unwrap());
        let keys = split_keys(&body);
        assert_eq!(keys.len(), 2);
        assert_eq!(kernoid_e2e::PublicKey::parse(&keys[1]).unwrap().fingerprint(), two.fingerprint());
        assert!(split_keys(b"not a key").is_empty());
    }
}
