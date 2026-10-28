// SPDX-License-Identifier: MIT
//! JMAP (RFC 8620) over HTTP: the session, method calls with result references, uploads, downloads and the push
//! stream – the only way this app talks to kernoid. Typed calls for mail, files, calendars, contacts and principals
//! are in the submodules.

pub mod calendars;
pub mod contacts;
pub mod files;
pub mod mail;
pub mod push;
pub mod srv;

use std::{collections::BTreeMap, fmt, io::Read, time::Duration};

use base64::Engine;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ureq::{
    Agent,
    config::RedirectAuthHeaders,
    tls::{RootCerts, TlsConfig},
};

pub const CORE: &str = "urn:ietf:params:jmap:core";
pub const MAIL: &str = "urn:ietf:params:jmap:mail";
pub const SUBMISSION: &str = "urn:ietf:params:jmap:submission";
pub const CALENDARS: &str = "urn:ietf:params:jmap:calendars";
pub const CONTACTS: &str = "urn:ietf:params:jmap:contacts";
pub const FILENODE: &str = "urn:ietf:params:jmap:filenode";
/// kernoid's extension for the versions of a file (`FileVersion/get`).
pub const FILE_VERSIONS: &str = "https://kernoid.dev/jmap/file-versions";
pub const PRINCIPALS: &str = "urn:ietf:params:jmap:principals";

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
        }
    }
}

impl std::error::Error for Error {}

impl From<ureq::Error> for Error {
    fn from(error: ureq::Error) -> Self {
        Self::Transport(error.to_string())
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
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Allow plain HTTP to hosts other than this machine (the password would travel readable).
    pub allow_http: bool,
}

/// A logged-in JMAP client: the session and the credentials, sent only to the origin the session came from.
#[derive(Clone)]
pub struct Client {
    agent: Agent,
    /// An agent without overall timeout, for transfers and the push stream.
    streaming: Agent,
    authorization: String,
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

fn agent(timeout: Option<Duration>) -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        .redirect_auth_headers(RedirectAuthHeaders::SameHost)
        .max_redirects(5)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(timeout)
        .user_agent(concat!("kernoid-tui/", env!("CARGO_PKG_VERSION")))
        .tls_config(TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build())
        .build()
        .new_agent()
}

impl Client {
    /// Fetches the session at `session_url` with HTTP Basic – the address and an app password.
    pub fn connect(session_url: &str, username: &str, password: &str, options: &Options) -> Result<Self> {
        let (origin, _) =
            split_origin(session_url).ok_or_else(|| Error::Protocol(format!("not a URL: {session_url}")))?;
        let origin = origin.to_owned();
        if !origin.starts_with("https://")
            && !(options.allow_http && origin.starts_with("http://"))
            && !is_local(&origin)
        {
            return Err(Error::Protocol(format!("{origin} is not HTTPS; the password would travel readable")));
        }
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        let mut client = Self {
            agent: agent(Some(Duration::from_secs(120))),
            streaming: agent(None),
            authorization: format!("Basic {credentials}"),
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
        client.session = client.fetch_session(session_url)?;
        Ok(client)
    }

    /// Fetches the session again (after a `StateChange` of the session, or to see new accounts).
    pub fn refresh_session(&mut self) -> Result<()> {
        self.session = self.fetch_session(&self.session_url.clone())?;
        Ok(())
    }

    fn fetch_session(&self, url: &str) -> Result<Session> {
        let mut response = self
            .agent
            .get(url)
            .header("authorization", &self.authorization)
            .header("accept", "application/json")
            .call()?;
        let body = check(&mut response, 200)?;
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
    pub fn request(&self, using: &[&str], calls: Vec<(&str, Value, &str)>) -> Result<Responses> {
        let mut capabilities = vec![CORE];
        capabilities.extend(using.iter().filter(|capability| **capability != CORE));
        let calls: Vec<Value> = calls.into_iter().map(|(name, arguments, id)| json!([name, arguments, id])).collect();
        let body = json!({ "using": capabilities, "methodCalls": calls }).to_string();
        let mut response = self
            .agent
            .post(self.here(&self.session.api_url))
            .header("authorization", &self.authorization)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .send(body)?;
        let status = response.status().as_u16();
        let text = response.body_mut().with_config().limit(64 << 20).read_to_string()?;
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
    pub fn call(&self, using: &[&str], name: &str, arguments: Value) -> Result<Value> {
        let responses = self.request(using, vec![(name, arguments, "0")])?;
        responses.get("0").cloned().ok_or_else(|| Error::Protocol(format!("no response to {name}")))
    }

    /// `<type>/set` (RFC 8620, 5.3); the first refused change fails it. `extra` adds arguments
    /// (`onDestroyRemoveChildren`, `onExists`).
    pub fn set(&self, using: &[&str], kind: &str, account: &str, change: Value, extra: Value) -> Result<Value> {
        let mut arguments = json!({ "accountId": account });
        for source in [change, extra] {
            if let (Some(target), Value::Object(source)) = (arguments.as_object_mut(), source) {
                target.extend(source);
            }
        }
        let result = self.call(using, &format!("{kind}/set"), arguments)?;
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
    pub fn download(
        &self,
        account: &str,
        blob: &str,
        name: &str,
        kind: &str,
        out: &mut dyn std::io::Write,
        progress: &mut dyn FnMut(u64, Option<u64>),
    ) -> Result<u64> {
        let url = self.download_url(account, blob, name, kind);
        let mut response = self.streaming.get(url).header("authorization", &self.authorization).call()?;
        let status = response.status().as_u16();
        if status == 401 {
            return Err(Error::Unauthorized);
        }
        if status != 200 {
            let body = response.body_mut().read_to_string().unwrap_or_default();
            return Err(Error::Status(status, problem_detail(&body)));
        }
        let total = response.body().content_length();
        let mut reader = response.body_mut().with_config().limit(u64::MAX).reader();
        let mut buffer = vec![0; 256 << 10];
        let mut done = 0;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            out.write_all(&buffer[..read])?;
            done += read as u64;
            progress(done, total);
        }
        if total.is_some_and(|total| total != done) {
            return Err(Error::Transport("the download broke off".into()));
        }
        Ok(done)
    }

    /// Uploads content of `size` bytes (RFC 8620, 6.1); `progress` hears the bytes sent so far.
    pub fn upload(
        &self,
        account: &str,
        kind: &str,
        content: impl Read,
        size: u64,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<Upload> {
        let url = self.here(&self.session.upload_url.replace("{accountId}", &encode(account)));
        let mut reader = Progress { inner: content, done: 0, total: size, progress };
        let mut response = self
            .streaming
            .post(url)
            .header("authorization", &self.authorization)
            .header("content-type", kind)
            .header("content-length", size.to_string())
            .send(ureq::SendBody::from_reader(&mut reader))?;
        let body = check(&mut response, 201)?;
        serde_json::from_str(&body).map_err(|error| Error::Protocol(format!("the upload: {error}")))
    }

    /// Opens the push stream (RFC 8620, 7.3) for all types, with a ping each `ping` seconds.
    pub fn event_source(&self, ping: u64) -> Result<impl Read + use<>> {
        let url = self
            .session
            .event_source_url
            .replace("{types}", "*")
            .replace("{closeafter}", "no")
            .replace("{ping}", &ping.to_string());
        let response = self
            .streaming
            .get(self.here(&url))
            .header("authorization", &self.authorization)
            .header("accept", "text/event-stream")
            .call()?;
        match response.status().as_u16() {
            200 => Ok(response.into_body().into_with_config().limit(u64::MAX).reader()),
            401 => Err(Error::Unauthorized),
            status => Err(Error::Status(status, None)),
        }
    }
}

/// A reader that tells how far it got.
struct Progress<'a, R> {
    inner: R,
    done: u64,
    total: u64,
    progress: &'a mut dyn FnMut(u64, u64),
}

impl<R: Read> Read for Progress<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.done += read as u64;
        (self.progress)(self.done, self.total);
        Ok(read)
    }
}

/// The body of an answer with the status expected; else the error it amounts to.
fn check(response: &mut ureq::http::Response<ureq::Body>, expected: u16) -> Result<String> {
    let status = response.status().as_u16();
    let body = response.body_mut().with_config().limit(16 << 20).read_to_string().unwrap_or_default();
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
