// SPDX-License-Identifier: MIT
//! How requests reach a relay. Natively through ureq (feature `native`, on by default): rustls on AWS-LC with
//! post-quantum key exchange preferred and the system's trust store. Elsewhere – a web page's worker, which has no
//! sockets – the program gives a [`Transport`] of its own ([`crate::streams::Streams::with_transport`]).

use std::sync::Arc;

/// What a transport must be to go between threads – everywhere but in a web page, which has one.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub trait Threads: Send + Sync {}
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
impl<T: Send + Sync> Threads for T {}
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub trait Threads {}
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
impl<T> Threads for T {}

/// Sends one request and returns the status and the body of the answer, or why it could not be sent.
pub trait Transport: Threads {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String>;
}

/// The transport of this platform: ureq natively, none without the feature `native`.
pub fn default_transport() -> Arc<dyn Transport> {
    #[cfg(feature = "native")]
    return Arc::new(Https::new(std::time::Duration::from_secs(300)));
    #[cfg(not(feature = "native"))]
    return Arc::new(Nowhere);
}

/// Without a transport of the platform: every request fails.
#[cfg(not(feature = "native"))]
struct Nowhere;

#[cfg(not(feature = "native"))]
impl Transport for Nowhere {
    fn send(&self, _: &str, url: &str, _: &[(&str, &str)], _: Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String> {
        Err(format!("{url}: no transport on this platform"))
    }
}

/// HTTPS through ureq.
#[cfg(feature = "native")]
#[derive(Debug)]
pub struct Https {
    agent: ureq::Agent,
}

#[cfg(feature = "native")]
impl Https {
    /// The largest answer read: a page of envelopes with originals.
    const MAX_RESPONSE: u64 = 512 * 1024 * 1024;

    pub fn new(timeout: std::time::Duration) -> Self {
        use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::PlatformVerifier)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .build();
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .tls_config(tls)
            .build()
            .into();
        Https { agent }
    }
}

#[cfg(feature = "native")]
impl Transport for Https {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String> {
        let mut builder = ureq::http::Request::builder().method(method).uri(url);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = match body {
            Some(body) => self.agent.run(builder.body(body).map_err(|e| e.to_string())?),
            None => self.agent.run(builder.body(()).map_err(|e| e.to_string())?),
        };
        let mut response = response.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(Self::MAX_RESPONSE)
            .read_to_vec()
            .map_err(|e| format!("its answer: {e}"))?;
        Ok((status, body))
    }
}
