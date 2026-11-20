// SPDX-License-Identifier: MIT
//! S3 and S3-compatible object storage (Garage, MinIO, Ceph): kernoid's own small client over reqwest – requests
//! signed with AWS Signature Version 4 (header authentication, the payload's SHA-256 signed too), `PutObject`,
//! `GetObject` with ranges, `HeadObject`, `DeleteObject`, `ListObjectsV2`, `CopyObject` and multipart uploads. Written
//! from AWS's documentation of these operations and of Signature Version 4.
//!
//! **Addressing:** an endpoint of one's own (self-hosted storage) is addressed by path, `<endpoint>/<bucket>/<key>`;
//! AWS by the bucket's own host, `https://<bucket>.s3.<region>.amazonaws.com/<key>` – by path if the bucket's name has
//! a dot, which a certificate of `*.s3.<region>.amazonaws.com` does not cover.
//!
//! **TLS** is rustls on AWS-LC with the system's trust store, post-quantum key exchange preferred (RFC 0006, 2); plain
//! HTTP only with `allow_http`. Redirects are not followed. Requests that fail on the way, or with 500, 502, 503 or 504,
//! are tried again twice – except completing a multipart upload, which is not idempotent.

use std::{fmt, ops::Range, sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{Method, StatusCode};
use sha2::{Digest, Sha256};

use super::{Body, BoxFuture, ObjectError, Objects, Upload};
use crate::S3Config;

/// SHA-256 of nothing: the payload of requests without a body.
const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// How often a request is tried, and how long to wait before each further try.
const RETRIES: [Duration; 2] = [Duration::from_millis(200), Duration::from_millis(1000)];

/// An S3 bucket.
#[derive(Clone)]
pub struct S3Objects {
    inner: Arc<Inner>,
}

struct Inner {
    client: reqwest::Client,
    config: S3Config,
    /// `scheme://host[:port]`.
    origin: String,
    /// The value of the `Host` header: the host, and the port unless it is the scheme's.
    host: String,
    /// The path before a key's: `/<bucket>` (with the endpoint's own path before it) by path, empty by host.
    root: String,
}

impl fmt::Debug for S3Objects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Objects")
            .field("origin", &self.inner.origin)
            .field("root", &self.inner.root)
            .field("config", &self.inner.config)
            .finish()
    }
}

/// What a request sends besides its method.
struct Request<'a> {
    method: Method,
    /// The key, or none for the bucket.
    key: Option<&'a str>,
    /// Query parameters, not yet encoded.
    query: Vec<(&'a str, String)>,
    /// Further headers to sign and send, names in lower case.
    headers: Vec<(&'static str, String)>,
    body: Bytes,
    retry: bool,
}

impl<'a> Request<'a> {
    fn new(method: Method, key: Option<&'a str>) -> Self {
        Request { method, key, query: Vec::new(), headers: Vec::new(), body: Bytes::new(), retry: true }
    }
}

impl S3Objects {
    /// A client of the bucket `config` names.
    pub fn new(config: &S3Config) -> Result<Self, ObjectError> {
        let invalid = |message: &str| ObjectError::Invalid(message.to_owned());
        if config.bucket.is_empty() || config.bucket.contains('/') {
            return Err(invalid("the bucket's name is empty or has a slash"));
        }
        let (url, by_path) = match &config.endpoint {
            Some(endpoint) => (endpoint.trim_end_matches('/').to_owned(), true),
            None if config.bucket.contains('.') => (format!("https://s3.{}.amazonaws.com", config.region), true),
            None => (format!("https://{}.s3.{}.amazonaws.com", config.bucket, config.region), false),
        };
        let url = reqwest::Url::parse(&url).map_err(|error| ObjectError::Invalid(format!("the endpoint: {error}")))?;
        match url.scheme() {
            "https" => {}
            "http" if config.allow_http => {}
            "http" => return Err(invalid("the endpoint is plain HTTP, which `allow_http` does not allow")),
            _ => return Err(invalid("the endpoint is neither HTTPS nor HTTP")),
        }
        if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
            return Err(invalid("the endpoint has a query, a fragment or credentials"));
        }
        let host_name = url.host_str().ok_or_else(|| invalid("the endpoint has no host"))?;
        let host = match url.port() {
            Some(port) => format!("{host_name}:{port}"),
            None => host_name.to_owned(),
        };
        let origin = format!("{}://{host}", url.scheme());
        let own_path = url.path().trim_end_matches('/');
        let root = if by_path { format!("{own_path}/{}", encode(&config.bucket, false)) } else { own_path.to_owned() };
        let client = reqwest::Client::builder()
            .user_agent(concat!("kernoid-blob/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!config.allow_http)
            .build()
            .map_err(|error| ObjectError::Invalid(format!("the HTTP client: {error}")))?;
        Ok(S3Objects { inner: Arc::new(Inner { client, config: config.clone(), origin, host, root }) })
    }
}

impl Inner {
    /// The canonical path of `key`, or of the bucket.
    fn path(&self, key: Option<&str>) -> Result<String, ObjectError> {
        let Some(key) = key else { return Ok(format!("{}/", self.root)) };
        // `.` and `..` would be taken away by the URL; an empty key names the bucket.
        if key.is_empty() || key.split('/').any(|part| part == "." || part == "..") {
            return Err(ObjectError::Invalid(format!("the key {key:?} cannot be sent")));
        }
        Ok(format!("{}/{}", self.root, encode(key, true)))
    }

    /// Sends `request`, signed, and tries it again if it failed on the way or the service was busy.
    async fn send(&self, request: &Request<'_>) -> Result<reqwest::Response, ObjectError> {
        let path = self.path(request.key)?;
        let mut query: Vec<(String, String)> =
            request.query.iter().map(|(name, value)| (encode(name, false), encode(value, false))).collect();
        query.sort();
        let query = query.iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join("&");
        let url =
            if query.is_empty() { format!("{}{path}", self.origin) } else { format!("{}{path}?{query}", self.origin) };
        let payload = if request.body.is_empty() { EMPTY.to_owned() } else { hex(&Sha256::digest(&request.body)) };
        let mut attempt = 0;
        loop {
            let date = jiff::Timestamp::now().strftime("%Y%m%dT%H%M%SZ").to_string();
            let mut headers: Vec<(&str, String)> = vec![
                ("host", self.host.clone()),
                ("x-amz-content-sha256", payload.clone()),
                ("x-amz-date", date.clone()),
            ];
            headers.extend(request.headers.iter().map(|(name, value)| (*name, value.clone())));
            headers.sort();
            let authorization =
                authorization(&self.config, &date, request.method.as_str(), &path, &query, &headers, &payload);
            let mut builder = self.client.request(request.method.clone(), &url).header("authorization", authorization);
            for (name, value) in headers.iter().filter(|(name, _)| *name != "host") {
                builder = builder.header(*name, value);
            }
            if !request.body.is_empty() || request.method == Method::PUT || request.method == Method::POST {
                builder = builder.body(request.body.clone());
            }
            let result = builder.send().await;
            let again = request.retry
                && attempt < RETRIES.len()
                && match &result {
                    Ok(response) => matches!(response.status().as_u16(), 500 | 502 | 503 | 504),
                    Err(error) => !error.is_builder(),
                };
            if !again {
                return result.map_err(|error| ObjectError::Transport(error.to_string()));
            }
            tokio::time::sleep(RETRIES[attempt]).await;
            attempt += 1;
        }
    }

    /// Sends `request` and returns the response if its status is one of `expected`.
    async fn expect(&self, request: &Request<'_>, expected: &[StatusCode]) -> Result<reqwest::Response, ObjectError> {
        let response = self.send(request).await?;
        if expected.contains(&response.status()) { Ok(response) } else { Err(failed(response).await) }
    }

    /// Sends `request` and returns the body of a 200 – which may still carry an error (S3 says so for `CopyObject` and
    /// `CompleteMultipartUpload`).
    async fn text(&self, request: &Request<'_>) -> Result<String, ObjectError> {
        let response = self.expect(request, &[StatusCode::OK]).await?;
        let body = response.text().await.map_err(|error| ObjectError::Transport(error.to_string()))?;
        if body.contains("<Error>") {
            return Err(ObjectError::Service { status: 200, message: error_message(&body) });
        }
        Ok(body)
    }
}

/// The error a response that is not one of the expected says.
async fn failed(response: reqwest::Response) -> ObjectError {
    let status = response.status();
    if status == StatusCode::NOT_FOUND {
        return ObjectError::NotFound;
    }
    let body = response.text().await.unwrap_or_default();
    ObjectError::Service { status: status.as_u16(), message: error_message(&body) }
}

/// S3's code and message from an error document, or the start of whatever it is.
fn error_message(body: &str) -> String {
    match (element(body, "Code"), element(body, "Message")) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code,
        _ => body.chars().take(200).collect(),
    }
}

impl Objects for S3Objects {
    fn put(&self, key: &str, bytes: Bytes) -> BoxFuture<'_, Result<(), ObjectError>> {
        let key = key.to_owned();
        Box::pin(async move {
            let request = Request { body: bytes, ..Request::new(Method::PUT, Some(&key)) };
            self.inner.expect(&request, &[StatusCode::OK]).await.map(drop)
        })
    }

    fn get(&self, key: &str, range: Option<Range<u64>>) -> BoxFuture<'_, Result<Body, ObjectError>> {
        let key = key.to_owned();
        Box::pin(async move {
            let mut request = Request::new(Method::GET, Some(&key));
            if let Some(range) = &range {
                if range.start >= range.end {
                    return Err(ObjectError::Invalid(format!("the range {range:?} is empty")));
                }
                request.headers.push(("range", format!("bytes={}-{}", range.start, range.end - 1)));
            }
            let expected = if range.is_some() { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK };
            let response = self.inner.expect(&request, &[expected]).await?;
            let body =
                response.bytes_stream().map(|part| part.map_err(|error| ObjectError::Transport(error.to_string())));
            Ok(Box::pin(body) as Body)
        })
    }

    fn head(&self, key: &str) -> BoxFuture<'_, Result<u64, ObjectError>> {
        let key = key.to_owned();
        Box::pin(async move {
            let response = self.inner.expect(&Request::new(Method::HEAD, Some(&key)), &[StatusCode::OK]).await?;
            response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|length| length.to_str().ok()?.parse().ok())
                .ok_or_else(|| ObjectError::Service { status: 200, message: "no Content-Length".into() })
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, Result<(), ObjectError>> {
        let key = key.to_owned();
        Box::pin(async move {
            let request = Request::new(Method::DELETE, Some(&key));
            match self.inner.expect(&request, &[StatusCode::NO_CONTENT, StatusCode::OK]).await {
                Ok(_) | Err(ObjectError::NotFound) => Ok(()),
                Err(error) => Err(error),
            }
        })
    }

    fn list(&self, prefix: &str) -> BoxFuture<'_, Result<Vec<String>, ObjectError>> {
        let prefix = prefix.to_owned();
        Box::pin(async move {
            let (mut keys, mut token) = (Vec::new(), None::<String>);
            loop {
                let mut request = Request::new(Method::GET, None);
                request.query = vec![("list-type", "2".into()), ("prefix", prefix.clone())];
                if let Some(token) = token.take() {
                    request.query.push(("continuation-token", token));
                }
                let body = self.inner.text(&request).await?;
                keys.extend(elements(&body, "Key"));
                match element(&body, "NextContinuationToken") {
                    Some(next) if element(&body, "IsTruncated").as_deref() == Some("true") => token = Some(next),
                    _ => break,
                }
            }
            keys.sort();
            Ok(keys)
        })
    }

    fn copy(&self, from: &str, to: &str) -> BoxFuture<'_, Result<(), ObjectError>> {
        let (from, to) = (from.to_owned(), to.to_owned());
        Box::pin(async move {
            self.inner.path(Some(&from))?;
            let mut request = Request::new(Method::PUT, Some(&to));
            let source = format!("/{}/{}", encode(&self.inner.config.bucket, false), encode(&from, true));
            request.headers.push(("x-amz-copy-source", source));
            self.inner.text(&request).await.map(drop)
        })
    }

    fn upload(&self, key: &str) -> BoxFuture<'_, Result<Box<dyn Upload>, ObjectError>> {
        let key = key.to_owned();
        Box::pin(async move {
            let mut request = Request::new(Method::POST, Some(&key));
            request.query = vec![("uploads", String::new())];
            let body = self.inner.text(&request).await?;
            let id = element(&body, "UploadId")
                .ok_or_else(|| ObjectError::Service { status: 200, message: "no UploadId".into() })?;
            Ok(Box::new(S3Upload { inner: self.inner.clone(), key, id, parts: Vec::new() }) as Box<dyn Upload>)
        })
    }
}

/// A multipart upload: its id and the ETags of the parts sent.
struct S3Upload {
    inner: Arc<Inner>,
    key: String,
    id: String,
    parts: Vec<String>,
}

impl Upload for S3Upload {
    fn part(&mut self, bytes: Bytes) -> BoxFuture<'_, Result<(), ObjectError>> {
        Box::pin(async move {
            let number = self.parts.len() + 1;
            let mut request = Request { body: bytes, ..Request::new(Method::PUT, Some(&self.key)) };
            request.query = vec![("partNumber", number.to_string()), ("uploadId", self.id.clone())];
            let response = self.inner.expect(&request, &[StatusCode::OK]).await?;
            let tag = response
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|tag| tag.to_str().ok())
                .ok_or_else(|| ObjectError::Service { status: 200, message: "a part without ETag".into() })?;
            self.parts.push(tag.to_owned());
            Ok(())
        })
    }

    fn complete(self: Box<Self>) -> BoxFuture<'static, Result<(), ObjectError>> {
        Box::pin(async move {
            let mut xml = String::from("<CompleteMultipartUpload>");
            for (index, tag) in self.parts.iter().enumerate() {
                xml.push_str(&format!(
                    "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
                    index + 1,
                    escape(tag)
                ));
            }
            xml.push_str("</CompleteMultipartUpload>");
            let mut request =
                Request { body: Bytes::from(xml), retry: false, ..Request::new(Method::POST, Some(&self.key)) };
            request.query = vec![("uploadId", self.id.clone())];
            self.inner.text(&request).await.map(drop)
        })
    }

    fn abort(self: Box<Self>) -> BoxFuture<'static, Result<(), ObjectError>> {
        Box::pin(async move {
            let mut request = Request::new(Method::DELETE, Some(&self.key));
            request.query = vec![("uploadId", self.id.clone())];
            match self.inner.expect(&request, &[StatusCode::NO_CONTENT, StatusCode::OK]).await {
                Ok(_) | Err(ObjectError::NotFound) => Ok(()),
                Err(error) => Err(error),
            }
        })
    }
}

/// The `Authorization` header of Signature Version 4: `headers` sorted, names in lower case, `query` canonical.
fn authorization(
    config: &S3Config,
    date: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, String)],
    payload: &str,
) -> String {
    let names = headers.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(";");
    let mut canonical = format!("{method}\n{path}\n{query}\n");
    for (name, value) in headers {
        canonical.push_str(&format!("{name}:{}\n", value.trim()));
    }
    canonical.push_str(&format!("\n{names}\n{payload}"));
    let day = &date[..8];
    let scope = format!("{day}/{}/s3/aws4_request", config.region);
    let to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac(format!("AWS4{}", config.secret_access_key).as_bytes(), day.as_bytes());
    for part in [config.region.as_str(), "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    let signature = hex(&hmac(&key, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
        config.access_key_id
    )
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// URI-encodes as Signature Version 4 asks: every byte but `A-Z a-z 0-9 - _ . ~` (and `/` in a path).
fn encode(text: &str, path: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') || (path && byte == b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The text of every element `<name>…</name>` in `xml`, unescaped – S3's answers have no attributes on the elements
/// read here, and no CDATA.
fn elements(xml: &str, name: &str) -> Vec<String> {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else { break };
        found.push(unescape(&after[..end]));
        rest = &after[end + close.len()..];
    }
    found
}

fn element(xml: &str, name: &str) -> Option<String> {
    elements(xml, name).into_iter().next()
}

/// XML's five entities and character references.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';') else { break };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .map(|hex| u32::from_str_radix(hex, 16))
                .or_else(|| entity.strip_prefix('#').map(str::parse))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> S3Config {
        S3Config {
            bucket: "examplebucket".into(),
            region: "us-east-1".into(),
            endpoint: None,
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            allow_http: false,
        }
    }

    /// AWS's example of signing a GET request in the Authorization header (Signature Version 4 for S3).
    #[test]
    fn signs_as_aws_documents() {
        let headers = vec![
            ("host", "examplebucket.s3.amazonaws.com".to_owned()),
            ("range", "bytes=0-9".to_owned()),
            ("x-amz-content-sha256", EMPTY.to_owned()),
            ("x-amz-date", "20130524T000000Z".to_owned()),
        ];
        let header = authorization(&example(), "20130524T000000Z", "GET", "/test.txt", "", &headers, EMPTY);
        assert_eq!(
            header,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn addresses_by_path_or_by_host() {
        let aws = S3Objects::new(&example()).unwrap();
        assert_eq!(
            (aws.inner.origin.as_str(), aws.inner.root.as_str()),
            ("https://examplebucket.s3.us-east-1.amazonaws.com", "")
        );
        let dotted = S3Objects::new(&S3Config { bucket: "a.b".into(), ..example() }).unwrap();
        assert_eq!(
            (dotted.inner.origin.as_str(), dotted.inner.root.as_str()),
            ("https://s3.us-east-1.amazonaws.com", "/a.b")
        );
        let own = S3Config { endpoint: Some("http://localhost:3900/".into()), allow_http: true, ..example() };
        let own = S3Objects::new(&own).unwrap();
        assert_eq!((own.inner.host.as_str(), own.inner.root.as_str()), ("localhost:3900", "/examplebucket"));
        assert_eq!(own.inner.path(Some("a b/ü")).unwrap(), "/examplebucket/a%20b/%C3%BC");
        assert!(own.inner.path(Some("a/../b")).is_err());
        let plain = S3Config { endpoint: Some("http://localhost:3900".into()), ..example() };
        assert!(matches!(S3Objects::new(&plain), Err(ObjectError::Invalid(_))));
        assert!(!format!("{own:?}").contains("EXAMPLEKEY"));
    }

    #[test]
    fn reads_s3s_answers() {
        let listing = "<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>a&amp;b</Key></Contents>\
                       <Contents><Key>c&#x20;d&#33;</Key></Contents><NextContinuationToken>t/1=</NextContinuationToken>\
                       </ListBucketResult>";
        assert_eq!(elements(listing, "Key"), ["a&b", "c d!"]);
        assert_eq!(element(listing, "NextContinuationToken").as_deref(), Some("t/1="));
        let error = "<Error><Code>NoSuchKey</Code><Message>The key does not exist</Message></Error>";
        assert_eq!(error_message(error), "NoSuchKey: The key does not exist");
        assert_eq!(unescape("x &unknown; y &"), "x &unknown; y &");
    }

    /// Against real object storage, e.g. Garage from deploy/compose; ignored unless asked for:
    ///
    /// KERNOID_TEST_S3=http://localhost:3900 KERNOID_TEST_S3_REGION=garage KERNOID_TEST_S3_BUCKET=kernoid \
    /// KERNOID_TEST_S3_KEY=… KERNOID_TEST_S3_SECRET=… cargo test -p kernoid-blob --features s3 -- --ignored
    #[tokio::test]
    #[ignore = "needs S3-compatible object storage"]
    async fn against_real_object_storage() {
        let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name}"));
        let config = S3Config {
            bucket: var("KERNOID_TEST_S3_BUCKET"),
            region: var("KERNOID_TEST_S3_REGION"),
            endpoint: Some(var("KERNOID_TEST_S3")),
            access_key_id: var("KERNOID_TEST_S3_KEY"),
            secret_access_key: var("KERNOID_TEST_S3_SECRET"),
            allow_http: true,
        };
        let store = S3Objects::new(&config).unwrap();
        let prefix = format!("kernoid-blob-test-{}", crate::hex_suffix());
        super::super::tests::behaves(&store, &prefix).await;
        let wrong = S3Objects::new(&S3Config { secret_access_key: "wrong".into(), ..config }).unwrap();
        assert!(matches!(wrong.list("x").await, Err(ObjectError::Service { status: 403, .. })));
    }
}
