// SPDX-License-Identifier: MIT
//! How requests reach a relay. Natively through reqwest (feature `native`, on by default), the SDK's HTTP client:
//! rustls on AWS-LC with post-quantum key exchange preferred and the system's trust store. Elsewhere – a web page's worker, which has no
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

/// The transport of this platform: reqwest natively, none without the feature `native`.
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

/// HTTPS through reqwest – the SDK's HTTP client, so that the kit has one: rustls on AWS-LC with post-quantum key
/// exchange preferred and the system's trust store. Its requests run on a small runtime of its own (one thread, made at
/// the first request), so that a synchronous caller may wait for them from any thread – also from the blocking threads
/// of another tokio runtime, as the SDK calls it.
#[cfg(feature = "native")]
#[derive(Debug)]
pub struct Https {
    client: reqwest::Client,
    runtime: std::sync::OnceLock<Result<tokio::runtime::Runtime, String>>,
}

#[cfg(feature = "native")]
impl Https {
    /// The largest answer read: a page of envelopes with originals.
    const MAX_RESPONSE: usize = 512 * 1024 * 1024;

    pub fn new(timeout: std::time::Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()
            // Building fails only when TLS cannot be set up; then every request says so.
            .unwrap_or_else(|_| reqwest::Client::new());
        Https { client, runtime: std::sync::OnceLock::new() }
    }

    fn runtime(&self) -> Result<&tokio::runtime::Runtime, String> {
        self.runtime
            .get_or_init(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("kernoid-spaces-https")
                    .enable_all()
                    .build()
                    .map_err(|e| format!("the runtime of HTTPS: {e}"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

#[cfg(feature = "native")]
impl Drop for Https {
    fn drop(&mut self) {
        // Without waiting: the transport may be dropped inside async code, where a runtime must not block.
        if let Some(Ok(runtime)) = self.runtime.take() {
            runtime.shutdown_background();
        }
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
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let exchange = async move {
            let mut response = request.send().await.map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|e| format!("its answer: {e}"))? {
                if body.len() + chunk.len() > Self::MAX_RESPONSE {
                    return Err("its answer: larger than the limit".to_owned());
                }
                body.extend_from_slice(&chunk);
            }
            Ok((status, body))
        };
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        self.runtime()?.spawn(async move {
            // The caller may have stopped waiting; nothing to do then.
            let _ = sender.send(exchange.await);
        });
        receiver.recv().map_err(|_| "the request was dropped".to_owned())?
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A server that answers one request with `answer`, returning what it was sent.
    fn serve_once(answer: &'static [u8]) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/x", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buffer = [0u8; 4096];
            while !String::from_utf8_lossy(&seen).contains("ping") {
                let n = stream.read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buffer[..n]);
            }
            stream.write_all(answer).unwrap();
            seen
        });
        (url, handle)
    }

    #[test]
    fn a_request_and_its_answer() {
        let (url, server) = serve_once(b"HTTP/1.1 409 Conflict\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong");
        let https = Https::new(std::time::Duration::from_secs(10));
        let (status, body) = https.send("PUT", &url, &[("x-kernoid", "1")], Some(b"ping".to_vec())).unwrap();
        assert_eq!((status, body.as_slice()), (409, b"pong".as_slice()));
        let seen = String::from_utf8(server.join().unwrap()).unwrap().to_ascii_lowercase();
        assert!(seen.starts_with("put /v1/x http/1.1") && seen.contains("x-kernoid: 1"), "{seen}");
    }

    #[test]
    fn from_the_blocking_threads_of_another_runtime_and_dropped_in_async_code() {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (url, server) = serve_once(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
            let https = std::sync::Arc::new(Https::new(std::time::Duration::from_secs(10)));
            let sending = https.clone();
            let answer = tokio::task::spawn_blocking(move || sending.send("POST", &url, &[], Some(b"ping".to_vec())))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(answer, (200, b"ok".to_vec()));
            server.join().unwrap();
            drop(https);
        });
    }

    #[test]
    fn nothing_listening_is_an_error() {
        let https = Https::new(std::time::Duration::from_secs(5));
        assert!(https.send("GET", "http://127.0.0.1:9/", &[], None).is_err());
    }
}
