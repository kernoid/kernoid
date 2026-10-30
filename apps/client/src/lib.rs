// SPDX-License-Identifier: MIT
//! kernoid's Rust SDK for clients. JMAP (RFC 8620) over HTTPS: the session, method calls with result references,
//! uploads, downloads and the push stream. Typed calls for mail, files, calendars, contacts and principals are in the
//! submodules; end-to-end encrypted mail in `e2e` (RFC 0006), finding a server in `srv`, iCalendar and vCard files in
//! `transfer`. Everything is async on tokio; the terminal app and the apps share it.

pub mod calendars;
pub mod contacts;
pub mod e2e;
pub mod files;
pub mod mail;
pub mod oidc;
pub mod push;
pub mod srv;
pub mod transfer;

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use base64::Engine;
use futures_util::{Stream, StreamExt, TryStreamExt};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub const CORE: &str = "urn:ietf:params:jmap:core";
pub const MAIL: &str = "urn:ietf:params:jmap:mail";
pub const SUBMISSION: &str = "urn:ietf:params:jmap:submission";
pub const CALENDARS: &str = "urn:ietf:params:jmap:calendars";
pub const CONTACTS: &str = "urn:ietf:params:jmap:contacts";
pub const FILENODE: &str = "urn:ietf:params:jmap:filenode";
/// kernoid's extension for the versions of a file (`FileVersion/get`).
pub const FILE_VERSIONS: &str = "https://kernoid.dev/jmap/file-versions";
/// kernoid's extension for links to files for people without an account (`FileLink/*`).
pub const FILE_LINKS: &str = "https://kernoid.dev/jmap/file-links";
pub const PRINCIPALS: &str = "urn:ietf:params:jmap:principals";
pub const VACATION: &str = "urn:ietf:params:jmap:vacationresponse";

/// What went wrong talking to the server.
#[derive(Debug)]
pub enum Error {
    /// The address and password were not accepted (401).
    Unauthorized,
    /// The server answered with another status than expected; with the detail of its problem, if it sent one.
    Status(u16, Option<String>),
    /// The connection failed or broke.
    Transport(String),
    /// A method call failed (RFC 8620, 3.6.2) or a request was refused as a whole (3.6.1).
    Method { kind: String, description: Option<String> },
    /// A change of `*/set` was refused (RFC 8620, 5.3).
    Set { kind: String, description: Option<String> },
    /// The answer was not what JMAP says it is.
    Protocol(String),
    /// Reading or writing a local file.
    Io(std::io::Error),
    /// End-to-end encryption: unlocking the key, encrypting, decrypting (RFC 0006).
    E2e(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "the address or password was not accepted"),
            Self::Status(status, Some(detail)) => write!(f, "the server answered {status}: {detail}"),
            Self::Status(status, None) => write!(f, "the server answered {status}"),
            Self::Transport(error) => write!(f, "connection: {error}"),
            Self::Method { kind, description: Some(description) }
            | Self::Set { kind, description: Some(description) } => {
                write!(f, "{kind}: {description}")
            }
            Self::Method { kind, description: None } | Self::Set { kind, description: None } => write!(f, "{kind}"),
            Self::Protocol(error) => write!(f, "unexpected answer: {error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::E2e(error) => write!(f, "end-to-end encryption: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error.to_string())
    }
}

impl From<kernoid_e2e::Error> for Error {
    fn from(error: kernoid_e2e::Error) -> Self {
        Self::E2e(error.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// An account in the session (RFC 8620, 2): the user's own, one shared with them, or a drive of their tenant.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub name: String,
    #[serde(default)]
    pub is_personal: bool,
    #[serde(default)]
    pub is_read_only: bool,
    #[serde(default)]
    pub account_capabilities: Map<String, Value>,
    /// kernoid marks the accounts that are drives – folders the tenant owns (RFC 0005).
    #[serde(default, rename = "kernoid:drive")]
    pub drive: bool,
}

/// The session resource (RFC 8620, 2).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    #[serde(default)]
    pub capabilities: Map<String, Value>,
    pub accounts: BTreeMap<String, Account>,
    #[serde(default)]
    pub primary_accounts: BTreeMap<String, String>,
    pub username: String,
    pub api_url: String,
    pub download_url: String,
    pub upload_url: String,
    #[serde(default)]
    pub event_source_url: String,
    #[serde(default)]
    pub state: String,
}

impl Session {
    /// The user's own account for a capability.
    pub fn primary(&self, capability: &str) -> Option<&str> {
        self.primary_accounts.get(capability).map(String::as_str)
    }

    /// The accounts that have a capability, the primary one first, then by name.
    pub fn accounts_with(&self, capability: &str) -> Vec<(&str, &Account)> {
        let primary = self.primary(capability);
        let mut out: Vec<_> = self
            .accounts
            .iter()
            .filter(|(_, account)| account.account_capabilities.contains_key(capability))
            .map(|(id, account)| (id.as_str(), account))
            .collect();
        out.sort_by(|a, b| (Some(a.0) != primary, &a.1.name).cmp(&(Some(b.0) != primary, &b.1.name)));
        out
    }
}

/// The responses to one request, in order: name, arguments, call id.
#[derive(Debug, Clone)]
pub struct Responses(pub Vec<(String, Value, String)>);

impl Responses {
    /// The (first) response to a call id.
    pub fn get(&self, id: &str) -> Option<&Value> {
        self.0.iter().find(|(_, _, call)| call == id).map(|(_, value, _)| value)
    }

    /// The (first) response to a call id, as `T`.
    pub fn parse<T: serde::de::DeserializeOwned>(&self, id: &str) -> Result<T> {
        let value = self.get(id).ok_or_else(|| Error::Protocol(format!("no response to {id}")))?;
        serde_json::from_value(value.clone()).map_err(|error| Error::Protocol(format!("{id}: {error}")))
    }
}

/// The scheme and authority of an absolute URL (`https://host:port`), and the rest (path and query, at least `/`).
pub fn split_origin(url: &str) -> Option<(&str, &str)> {
    let (scheme, after) = url.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) {
        return None;
    }
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    if end == 0 {
        return None;
    }
    let origin = &url[..scheme.len() + 3 + end];
    let rest = &after[end..];
    Some((origin, if rest.is_empty() { "/" } else { rest }))
}

/// The host of an origin, without port and brackets.
fn host(origin: &str) -> &str {
    let authority = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    authority.split_once(':').map_or(authority, |(host, _)| host)
}

/// Whether plain HTTP to this origin stays on this machine: loopback addresses, `localhost` and `*.localhost`.
pub fn is_local(origin: &str) -> bool {
    let host = host(origin).to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback())
}

/// Percent-encodes everything but RFC 3986's unreserved characters, for the variables of URL templates.
pub fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Where to find the session for what the user gave: a server (`https://host`, with or without a path) or, without
/// one, the domain of the address – `https://<domain>/.well-known/jmap` (RFC 8620, 2.2).
pub fn session_url(server: Option<&str>, address: &str) -> Result<String> {
    let server = match server {
        Some(server) if server.contains("://") => server.trim_end_matches('/').to_owned(),
        Some(server) => format!("https://{}", server.trim_end_matches('/')),
        None => {
            let domain = address
                .rsplit_once('@')
                .map(|(_, domain)| domain)
                .filter(|domain| !domain.is_empty())
                .ok_or_else(|| Error::Protocol("give a server, or an address with a domain".into()))?;
            format!("https://{domain}")
        }
    };
    let (_, path) = split_origin(&server).ok_or_else(|| Error::Protocol(format!("not a URL: {server}")))?;
    Ok(if path == "/" { format!("{server}/.well-known/jmap") } else { server })
}

/// How a connection is made.
#[derive(Debug, Clone)]
pub struct Options {
    /// Allow plain HTTP to hosts other than this machine (the password would travel readable).
    pub allow_http: bool,
    /// Who is asking, in `User-Agent` (`kernoid-tui/0.2.0`).
    pub user_agent: String,
}

impl Default for Options {
    fn default() -> Self {
        Self { allow_http: false, user_agent: concat!("kernoid-client/", env!("CARGO_PKG_VERSION")).into() }
    }
}

/// A logged-in JMAP client: the session and the credentials, sent only to the origin the session came from.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    /// A client without overall timeout, for transfers and the push stream.
    streaming: reqwest::Client,
    /// `Basic …` or `Bearer …`; shared by the clones, so that a renewed access token reaches them all.
    authorization: std::sync::Arc<std::sync::RwLock<String>>,
    origin: String,
    session_url: String,
    pub session: Session,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").field("origin", &self.origin).field("username", &self.session.username).finish()
    }
}

/// The problem detail of an error answer (RFC 9457), if it has one.
fn problem_detail(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    value.get("detail").or_else(|| value.get("description")).and_then(Value::as_str).map(str::to_owned)
}

/// An HTTP client: TLS through reqwest's rustls on AWS-LC with the system's trust store (rustls-platform-verifier),
/// post-quantum key exchange preferred (the feature `prefer-post-quantum` of `rustls`); redirects followed up to five
/// times – reqwest drops the credentials on a redirect to another host.
fn http(origin: &str, user_agent: &str, timeout: Option<Duration>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(Duration::from_secs(15))
        .user_agent(user_agent);
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    // `*.localhost` is this machine (RFC 6761), but not every system's resolver knows it.
    let name = host(origin);
    if name.ends_with(".localhost") {
        builder = builder.resolve(name, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    }
    Ok(builder.build()?)
}

impl Client {
    /// Fetches the session at `session_url` with HTTP Basic – the address and an app password.
    pub async fn connect(session_url: &str, username: &str, password: &str, options: &Options) -> Result<Self> {
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        Self::open(session_url, username, format!("Basic {credentials}"), options).await
    }

    /// Fetches the session at `session_url` with an OpenID Connect access token of kernoid with the scope
    /// `urn:kernoid:data` – from [`oidc`]. Renew it with [`Client::set_access_token`] before it expires.
    pub async fn connect_with_token(session_url: &str, access_token: &str, options: &Options) -> Result<Self> {
        Self::open(session_url, "", format!("Bearer {access_token}"), options).await
    }

    /// A new access token for this client and its clones (after [`oidc::refresh`]).
    pub fn set_access_token(&self, access_token: &str) {
        *self.authorization.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = format!("Bearer {access_token}");
    }

    fn authorization(&self) -> String {
        self.authorization.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    async fn open(session_url: &str, username: &str, authorization: String, options: &Options) -> Result<Self> {
        let (origin, _) =
            split_origin(session_url).ok_or_else(|| Error::Protocol(format!("not a URL: {session_url}")))?;
        let origin = origin.to_owned();
        if !origin.starts_with("https://")
            && !(options.allow_http && origin.starts_with("http://"))
            && !is_local(&origin)
        {
            return Err(Error::Protocol(format!("{origin} is not HTTPS; the password would travel readable")));
        }
        let mut client = Self {
            http: http(&origin, &options.user_agent, Some(Duration::from_secs(120)))?,
            streaming: http(&origin, &options.user_agent, None)?,
            authorization: std::sync::Arc::new(std::sync::RwLock::new(authorization)),
            origin,
            session_url: session_url.to_owned(),
            session: Session {
                capabilities: Map::new(),
                accounts: BTreeMap::new(),
                primary_accounts: BTreeMap::new(),
                username: username.to_owned(),
                api_url: String::new(),
                download_url: String::new(),
                upload_url: String::new(),
                event_source_url: String::new(),
                state: String::new(),
            },
        };
        client.session = client.fetch_session(session_url).await?;
        Ok(client)
    }

    /// Fetches the session again (after a `StateChange` of the session, or to see new accounts).
    pub async fn refresh_session(&mut self) -> Result<()> {
        self.session = self.fetch_session(&self.session_url.clone()).await?;
        Ok(())
    }

    async fn fetch_session(&self, url: &str) -> Result<Session> {
        let response = self
            .http
            .get(url)
            .header("authorization", self.authorization())
            .header("accept", "application/json")
            .send()
            .await?;
        let body = check(response, 200).await?;
        serde_json::from_str(&body).map_err(|error| Error::Protocol(format!("the session: {error}")))
    }

    /// The origin this client talks to.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// A URL of the session on the origin the session came from – the credentials go nowhere else. A server that
    /// serves its API on another host is not supported (OPEN).
    fn here(&self, url: &str) -> String {
        match split_origin(url) {
            Some((_, rest)) => format!("{}{rest}", self.origin),
            None if url.starts_with('/') => format!("{}{url}", self.origin),
            None => format!("{}/{url}", self.origin),
        }
    }

    /// The user's own account for a capability.
    pub fn primary(&self, capability: &str) -> Result<String> {
        self.session
            .primary(capability)
            .map(str::to_owned)
            .ok_or_else(|| Error::Method { kind: "accountNotFound".into(), description: Some(capability.into()) })
    }

    /// Runs method calls; the first method error fails them all.
    pub async fn request(&self, using: &[&str], calls: Vec<(&str, Value, &str)>) -> Result<Responses> {
        let mut capabilities = vec![CORE];
        capabilities.extend(using.iter().filter(|capability| **capability != CORE));
        let calls: Vec<Value> = calls.into_iter().map(|(name, arguments, id)| json!([name, arguments, id])).collect();
        let body = json!({ "using": capabilities, "methodCalls": calls }).to_string();
        let response = self
            .http
            .post(self.here(&self.session.api_url))
            .header("authorization", self.authorization())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await?;
        let status = response.status().as_u16();
        let text = limited_text(response, 64 << 20).await?;
        if status == 401 {
            return Err(Error::Unauthorized);
        }
        let value: Value = serde_json::from_str(&text).map_err(|_| Error::Status(status, problem_detail(&text)))?;
        if status != 200 {
            // A request refused as a whole (RFC 8620, 3.6.1) is a problem with a type.
            let kind = value.get("type").and_then(Value::as_str).unwrap_or("serverFail");
            let kind = kind.rsplit(':').next().unwrap_or(kind).to_owned();
            return Err(Error::Method { kind, description: problem_detail(&text) });
        }
        let responses = value
            .get("methodResponses")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Protocol("no methodResponses".into()))?;
        let mut out = Vec::with_capacity(responses.len());
        for response in responses {
            let (Some(name), Some(arguments), Some(id)) =
                (response.get(0).and_then(Value::as_str), response.get(1), response.get(2).and_then(Value::as_str))
            else {
                return Err(Error::Protocol("a malformed method response".into()));
            };
            if name == "error" {
                return Err(Error::Method {
                    kind: arguments.get("type").and_then(Value::as_str).unwrap_or("serverFail").to_owned(),
                    description: arguments.get("description").and_then(Value::as_str).map(str::to_owned),
                });
            }
            out.push((name.to_owned(), arguments.clone(), id.to_owned()));
        }
        Ok(Responses(out))
    }

    /// One method call; its response.
    pub async fn call(&self, using: &[&str], name: &str, arguments: Value) -> Result<Value> {
        let responses = self.request(using, vec![(name, arguments, "0")]).await?;
        responses.get("0").cloned().ok_or_else(|| Error::Protocol(format!("no response to {name}")))
    }

    /// `<type>/set` (RFC 8620, 5.3); the first refused change fails it. `extra` adds arguments
    /// (`onDestroyRemoveChildren`, `onExists`).
    pub async fn set(&self, using: &[&str], kind: &str, account: &str, change: Value, extra: Value) -> Result<Value> {
        let mut arguments = json!({ "accountId": account });
        for source in [change, extra] {
            if let (Some(target), Value::Object(source)) = (arguments.as_object_mut(), source) {
                target.extend(source);
            }
        }
        let result = self.call(using, &format!("{kind}/set"), arguments).await?;
        set_error(&result)?;
        Ok(result)
    }

    /// The URL a blob is downloaded from (RFC 8620, 6.2).
    pub fn download_url(&self, account: &str, blob: &str, name: &str, kind: &str) -> String {
        let url = self
            .session
            .download_url
            .replace("{accountId}", &encode(account))
            .replace("{blobId}", &encode(blob))
            .replace("{name}", &encode(name))
            .replace("{type}", &encode(kind));
        self.here(&url)
    }

    /// Downloads a blob into `out`; `progress` hears the bytes so far and the whole, if the server said it.
    pub async fn download(
        &self,
        account: &str,
        blob: &str,
        name: &str,
        kind: &str,
        out: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> Result<u64> {
        let url = self.download_url(account, blob, name, kind);
        let response = self.streaming.get(url).header("authorization", self.authorization()).send().await?;
        let status = response.status().as_u16();
        if status == 401 {
            return Err(Error::Unauthorized);
        }
        if status != 200 {
            let body = limited_text(response, 16 << 20).await.unwrap_or_default();
            return Err(Error::Status(status, problem_detail(&body)));
        }
        let total = response.content_length();
        let mut body = response.bytes_stream();
        let mut done = 0;
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            out.write_all(&chunk).await?;
            done += chunk.len() as u64;
            progress(done, total);
        }
        out.flush().await?;
        if total.is_some_and(|total| total != done) {
            return Err(Error::Transport("the download broke off".into()));
        }
        Ok(done)
    }

    /// Uploads content of `size` bytes (RFC 8620, 6.1); `progress` hears the bytes sent so far.
    pub async fn upload(
        &self,
        account: &str,
        kind: &str,
        content: impl AsyncRead + Send + 'static,
        size: u64,
        mut progress: impl FnMut(u64, u64) + Send + 'static,
    ) -> Result<Upload> {
        let url = self.here(&self.session.upload_url.replace("{accountId}", &encode(account)));
        let mut done = 0;
        let stream = tokio_util::io::ReaderStream::with_capacity(content, 256 << 10).inspect_ok(move |chunk| {
            done += chunk.len() as u64;
            progress(done, size);
        });
        let response = self
            .streaming
            .post(url)
            .header("authorization", self.authorization())
            .header("content-type", kind)
            .header("content-length", size.to_string())
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await?;
        let body = check(response, 201).await?;
        serde_json::from_str(&body).map_err(|error| Error::Protocol(format!("the upload: {error}")))
    }

    /// Opens the push stream (RFC 8620, 7.3) for all types, with a ping each `ping` seconds: its bytes as they come.
    pub async fn event_source(
        &self,
        ping: u64,
    ) -> Result<impl Stream<Item = std::io::Result<bytes::Bytes>> + Send + Unpin + use<>> {
        let url = self
            .session
            .event_source_url
            .replace("{types}", "*")
            .replace("{closeafter}", "no")
            .replace("{ping}", &ping.to_string());
        let response = self
            .streaming
            .get(self.here(&url))
            .header("authorization", self.authorization())
            .header("accept", "text/event-stream")
            .send()
            .await?;
        match response.status().as_u16() {
            200 => Ok(response.bytes_stream().map_err(std::io::Error::other)),
            401 => Err(Error::Unauthorized),
            status => Err(Error::Status(status, None)),
        }
    }
}

/// The body of an answer, refused beyond `limit` bytes.
async fn limited_text(response: reqwest::Response, limit: usize) -> Result<String> {
    let mut body = response.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        if out.len() + chunk.len() > limit {
            return Err(Error::Protocol(format!("an answer of more than {limit} bytes")));
        }
        out.extend_from_slice(&chunk);
    }
    String::from_utf8(out).map_err(|_| Error::Protocol("an answer that is not UTF-8".into()))
}

/// The body of an answer with the status expected; else the error it amounts to.
async fn check(response: reqwest::Response, expected: u16) -> Result<String> {
    let status = response.status().as_u16();
    let body = limited_text(response, 16 << 20).await.unwrap_or_default();
    match status {
        401 => Err(Error::Unauthorized),
        status if status == expected || (expected == 201 && status == 200) => Ok(body),
        status => Err(Error::Status(status, problem_detail(&body))),
    }
}

/// The first refused change of a `*/set` response, as an error.
pub fn set_error(result: &Value) -> Result<()> {
    for key in ["notCreated", "notUpdated", "notDestroyed"] {
        if let Some(first) = result.get(key).and_then(Value::as_object).and_then(|failed| failed.values().next()) {
            return Err(Error::Set {
                kind: first.get("type").and_then(Value::as_str).unwrap_or("serverFail").to_owned(),
                description: first.get("description").and_then(Value::as_str).map(str::to_owned),
            });
        }
    }
    Ok(())
}

/// The answer to an upload (RFC 8620, 6.1).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Upload {
    pub account_id: String,
    pub blob_id: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    pub size: u64,
}

/// `#ids` referring to the `/ids` of a query call (RFC 8620, 3.7).
pub fn ids_of(call: &str, name: &str) -> Value {
    json!({ "resultOf": call, "name": name, "path": "/ids" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert_eq!(split_origin("https://a.example/jmap/api"), Some(("https://a.example", "/jmap/api")));
        assert_eq!(split_origin("http://[::1]:8080"), Some(("http://[::1]:8080", "/")));
        assert_eq!(split_origin("https://a.example?x"), Some(("https://a.example", "?x")));
        assert_eq!(split_origin("/jmap/api"), None);
        assert_eq!(split_origin("https:///x"), None);
        assert!(is_local("http://localhost:8080"));
        assert!(is_local("http://login.example.localhost"));
        assert!(is_local("http://127.0.0.1:1"));
        assert!(is_local("http://[::1]:1"));
        assert!(!is_local("http://example.org"));
        assert!(!is_local("http://localhost.example.org"));
    }

    #[test]
    fn session_urls() {
        assert_eq!(session_url(None, "a@firma.example").unwrap(), "https://firma.example/.well-known/jmap");
        assert_eq!(session_url(Some("login.example"), "a").unwrap(), "https://login.example/.well-known/jmap");
        assert_eq!(session_url(Some("http://localhost:8080/"), "a").unwrap(), "http://localhost:8080/.well-known/jmap");
        assert_eq!(session_url(Some("https://x/jmap/session"), "a").unwrap(), "https://x/jmap/session");
        assert!(session_url(None, "nodomain").is_err());
    }

    #[test]
    fn encoding() {
        assert_eq!(encode("a b/ä.txt"), "a%20b%2F%C3%A4.txt");
        assert_eq!(encode("text/plain"), "text%2Fplain");
    }

    #[test]
    fn set_errors() {
        assert!(set_error(&json!({ "created": { "a": {} } })).is_ok());
        let error = set_error(&json!({ "notUpdated": { "x": { "type": "forbidden", "description": "no" } } }));
        assert!(matches!(error, Err(Error::Set { kind, .. }) if kind == "forbidden"));
    }
}
