// SPDX-License-Identifier: AGPL-3.0-or-later
//! The module `clamav`: content checked for malware by ClamAV's daemon, clamd, before kernoid keeps it – uploads
//! and files of tenants that switched the module on, and mail to or from their accounts (`kernoid_store::scan`).
//!
//! kernoid speaks clamd's own protocol (`INSTREAM`, see clamd(8)): the content goes to the daemon in chunks, each
//! with its length as four bytes in network order, and a chunk of length zero ends it; the daemon answers
//! `stream: OK` or `stream: <name> FOUND`. clamd takes at most its `StreamMaxLength` (25 MiB by default) – content
//! larger than `max_size` is kept unscanned, so keep the two the same.
//!
//! ```toml
//! [modules.clamav]
//! enabled = true
//! address = "clamav:3310"          # or "unix:/run/clamav/clamd.sock"
//! max_size = 26214400              # bytes; clamd's StreamMaxLength
//! timeout_seconds = 120            # for one scan
//! refuse_unchecked = true          # refuse content while clamd cannot be asked (else keep it unscanned)
//! ```

use std::{path::PathBuf, sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::{StreamExt, future::BoxFuture, stream::BoxStream};
use kernoid_module::{Context, Job, Module, Shutdown};
use kernoid_store::scan::{Scanner, Verdict};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const NAME: &str = "clamav";
/// clamd's `StreamMaxLength` by default.
pub const DEFAULT_MAX_SIZE: u64 = 25 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
/// The largest chunk sent at once.
const CHUNK: usize = 1024 * 1024;
/// How often a worker asks whether clamd answers, to say so in the log before content is refused.
const PING_EVERY: Duration = Duration::from_secs(300);

/// Where clamd listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// `host:port`.
    Tcp(String),
    /// `unix:<path>`.
    Unix(PathBuf),
}

/// A clamd to ask.
#[derive(Debug, Clone)]
pub struct ClamAv {
    pub address: Address,
    pub max_size: u64,
    pub timeout: Duration,
    pub refuse_unchecked: bool,
}

trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

impl ClamAv {
    /// From the module's table (`[modules.clamav]` without `enabled`).
    pub fn from_config(config: &toml::Table) -> Result<Self, String> {
        for key in config.keys() {
            if !["address", "max_size", "timeout_seconds", "refuse_unchecked"].contains(&key.as_str()) {
                return Err(format!("unknown setting {key}"));
            }
        }
        let address = match config.get("address").and_then(toml::Value::as_str) {
            Some(path) if path.starts_with("unix:") => Address::Unix(PathBuf::from(path.trim_start_matches("unix:"))),
            Some(host) if host.rsplit_once(':').is_some_and(|(_, port)| port.parse::<u16>().is_ok()) => {
                Address::Tcp(host.to_owned())
            }
            _ => return Err("address is host:port or unix:<path>".into()),
        };
        let number = |key: &str| match config.get(key) {
            None => Ok(None),
            Some(toml::Value::Integer(n)) if *n > 0 => Ok(Some(*n as u64)),
            Some(_) => Err(format!("{key} is a positive number")),
        };
        let refuse_unchecked = match config.get("refuse_unchecked") {
            None => true,
            Some(toml::Value::Boolean(refuse)) => *refuse,
            Some(_) => return Err("refuse_unchecked is true or false".into()),
        };
        Ok(Self {
            address,
            max_size: number("max_size")?.unwrap_or(DEFAULT_MAX_SIZE),
            timeout: number("timeout_seconds")?.map_or(DEFAULT_TIMEOUT, Duration::from_secs),
            refuse_unchecked,
        })
    }

    async fn connect(&self) -> Result<Box<dyn Connection>, String> {
        let connection: Box<dyn Connection> = match &self.address {
            Address::Tcp(address) => Box::new(tokio::net::TcpStream::connect(address).await.map_err(describe)?),
            Address::Unix(path) => Box::new(tokio::net::UnixStream::connect(path).await.map_err(describe)?),
        };
        Ok(connection)
    }

    /// Whether clamd answers.
    pub async fn ping(&self) -> Result<(), String> {
        let exchange = async {
            let mut connection = self.connect().await?;
            connection.write_all(b"zPING\0").await.map_err(describe)?;
            match reply(&mut connection).await?.as_str() {
                "PONG" => Ok(()),
                other => Err(format!("clamd answered {other:?}")),
            }
        };
        tokio::time::timeout(self.timeout, exchange).await.map_err(|_| "clamd did not answer in time".to_owned())?
    }

    /// Scans `content` to its end.
    pub async fn scan_stream(&self, content: BoxStream<'static, Bytes>) -> Result<Verdict, String> {
        let exchange = async {
            let mut connection = self.connect().await?;
            let sent = send(&mut connection, content).await;
            // clamd answers even when it stopped reading (too much content): its answer says more than the error.
            let answer = reply(&mut connection).await;
            match (sent, answer) {
                (_, Ok(answer)) => verdict(&answer),
                (Err(error), Err(_)) | (Ok(()), Err(error)) => Err(error),
            }
        };
        tokio::time::timeout(self.timeout, exchange).await.map_err(|_| "clamd did not answer in time".to_owned())?
    }
}

fn describe(error: std::io::Error) -> String {
    format!("clamd: {error}")
}

async fn send(connection: &mut Box<dyn Connection>, mut content: BoxStream<'static, Bytes>) -> Result<(), String> {
    connection.write_all(b"zINSTREAM\0").await.map_err(describe)?;
    while let Some(chunk) = content.next().await {
        for piece in chunk.chunks(CHUNK) {
            connection.write_all(&(piece.len() as u32).to_be_bytes()).await.map_err(describe)?;
            connection.write_all(piece).await.map_err(describe)?;
        }
    }
    connection.write_all(&[0; 4]).await.map_err(describe)?;
    connection.flush().await.map_err(describe)
}

/// clamd's answer, up to its terminating NUL.
async fn reply(connection: &mut Box<dyn Connection>) -> Result<String, String> {
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    while answer.len() < 4096 {
        match connection.read(&mut byte).await.map_err(describe)? {
            0 => break,
            _ if byte[0] == 0 => break,
            _ => answer.push(byte[0]),
        }
    }
    if answer.is_empty() {
        return Err("clamd closed the connection without an answer".into());
    }
    Ok(String::from_utf8_lossy(&answer).trim().to_owned())
}

/// `stream: OK`, `stream: <name> FOUND`, anything else is an error.
fn verdict(answer: &str) -> Result<Verdict, String> {
    let answer = answer.strip_prefix("stream:").map(str::trim).unwrap_or(answer);
    if answer == "OK" {
        Ok(Verdict::Clean)
    } else if let Some(name) = answer.strip_suffix(" FOUND") {
        Ok(Verdict::Infected(name.trim().to_owned()))
    } else {
        Err(format!("clamd answered {answer:?}"))
    }
}

impl Scanner for ClamAv {
    fn module(&self) -> &'static str {
        NAME
    }

    fn max_size(&self) -> u64 {
        self.max_size
    }

    fn refuse_unchecked(&self) -> bool {
        self.refuse_unchecked
    }

    fn scan(&self, content: BoxStream<'static, Bytes>) -> BoxFuture<'static, Result<Verdict, String>> {
        let clamav = self.clone();
        Box::pin(async move { clamav.scan_stream(content).await })
    }
}

/// The module: its configuration checked at the start, a worker job that says in the log when clamd does not answer.
/// The scanning itself is the [`ClamAv`] the process sets on its blob store (`scanner`).
#[derive(Debug)]
pub struct ClamAvModule;

impl ClamAvModule {
    /// The scanner for the blob store, from the module's table.
    pub fn scanner(config: &toml::Table) -> Result<Arc<dyn Scanner>, String> {
        Ok(Arc::new(ClamAv::from_config(config)?))
    }
}

impl Module for ClamAvModule {
    fn name(&self) -> &'static str {
        NAME
    }

    fn check(&self, config: &toml::Table) -> Result<(), String> {
        ClamAv::from_config(config).map(drop)
    }

    fn jobs(&self, context: &Context) -> Vec<Job> {
        let Ok(clamav) = ClamAv::from_config(&context.config) else { return Vec::new() };
        vec![Box::new(move |shutdown: Shutdown| {
            Box::pin(async move {
                let mut answering = true;
                loop {
                    match clamav.ping().await {
                        Ok(()) if !answering => {
                            tracing::info!("clamd answers again");
                            answering = true;
                        }
                        Ok(()) => {}
                        Err(error) => {
                            tracing::warn!(%error, "clamd does not answer");
                            answering = false;
                        }
                    }
                    tokio::select! {
                        () = shutdown.cancelled() => return Ok(()),
                        () = tokio::time::sleep(PING_EVERY) => {}
                    }
                }
            })
        })]
    }
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use tokio::net::TcpListener;

    use super::*;

    fn once(content: Bytes) -> BoxStream<'static, Bytes> {
        Box::pin(stream::once(async move { content }))
    }

    const EICAR: &str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /// A clamd that knows one malware: the EICAR test file.
    async fn fake_clamd() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (mut connection, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut command = Vec::new();
                    let mut byte = [0u8; 1];
                    while connection.read_exact(&mut byte).await.is_ok() && byte[0] != 0 {
                        command.push(byte[0]);
                    }
                    if command == b"zPING" {
                        connection.write_all(b"PONG\0").await.unwrap();
                        return;
                    }
                    let mut content = Vec::new();
                    loop {
                        let mut length = [0u8; 4];
                        connection.read_exact(&mut length).await.unwrap();
                        let length = u32::from_be_bytes(length) as usize;
                        if length == 0 {
                            break;
                        }
                        let mut chunk = vec![0; length];
                        connection.read_exact(&mut chunk).await.unwrap();
                        content.extend_from_slice(&chunk);
                    }
                    let found = content.windows(EICAR.len()).any(|window| window == EICAR.as_bytes());
                    let answer: &[u8] = if found { b"stream: Eicar-Signature FOUND\0" } else { b"stream: OK\0" };
                    connection.write_all(answer).await.unwrap();
                });
            }
        });
        address
    }

    fn table(toml: &str) -> toml::Table {
        toml::from_str(toml).unwrap()
    }

    #[tokio::test]
    async fn clamd_tells_clean_from_infected() {
        let clamav = ClamAv::from_config(&table(&format!("address = \"{}\"", fake_clamd().await))).unwrap();
        clamav.ping().await.unwrap();
        assert_eq!(clamav.scan_stream(once(Bytes::from_static(b"hello"))).await.unwrap(), Verdict::Clean);
        let pieces = Box::pin(stream::iter([
            Bytes::from_static(b"Subject: hi\r\n\r\n"),
            Bytes::from(EICAR.as_bytes()[..20].to_vec()),
            Bytes::from(EICAR.as_bytes()[20..].to_vec()),
        ]));
        assert_eq!(clamav.scan_stream(pieces).await.unwrap(), Verdict::Infected("Eicar-Signature".into()));
    }

    #[tokio::test]
    async fn an_absent_clamd_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let clamav = ClamAv::from_config(&table(&format!("address = \"{address}\""))).unwrap();
        assert!(clamav.ping().await.is_err());
        assert!(clamav.scan_stream(once(Bytes::from_static(b"hello"))).await.is_err());
    }

    /// Against a real clamd: `CLAMD_ADDRESS=127.0.0.1:3310 cargo test -p kernoid-clamav -- --ignored`.
    #[tokio::test]
    #[ignore = "needs clamd"]
    async fn a_real_clamd_finds_the_eicar_file() {
        let address = std::env::var("CLAMD_ADDRESS").expect("CLAMD_ADDRESS");
        let clamav = ClamAv::from_config(&table(&format!("address = \"{address}\""))).unwrap();
        clamav.ping().await.unwrap();
        assert_eq!(clamav.scan_stream(once(Bytes::from_static(b"hello"))).await.unwrap(), Verdict::Clean);
        let found = clamav.scan_stream(once(Bytes::from_static(EICAR.as_bytes()))).await.unwrap();
        assert!(matches!(found, Verdict::Infected(ref name) if name.contains("Eicar")), "{found:?}");
    }

    #[test]
    fn the_configuration_is_checked() {
        let clamav = ClamAv::from_config(&table("address = \"unix:/run/clamd.sock\"")).unwrap();
        assert_eq!(clamav.address, Address::Unix("/run/clamd.sock".into()));
        assert_eq!(
            (clamav.max_size, clamav.timeout, clamav.refuse_unchecked),
            (DEFAULT_MAX_SIZE, DEFAULT_TIMEOUT, true)
        );
        for wrong in [
            "",
            "address = \"clamav\"",
            "address = \"clamav:3310\"\nmax_size = 0",
            "address = \"clamav:3310\"\nport = 1",
        ] {
            assert!(ClamAv::from_config(&table(wrong)).is_err(), "{wrong:?}");
        }
    }

    #[test]
    fn answers_are_read() {
        assert_eq!(verdict("stream: OK"), Ok(Verdict::Clean));
        assert_eq!(verdict("stream: Win.Test.EICAR_HDB-1 FOUND"), Ok(Verdict::Infected("Win.Test.EICAR_HDB-1".into())));
        assert!(verdict("INSTREAM size limit exceeded. ERROR").is_err());
    }
}
