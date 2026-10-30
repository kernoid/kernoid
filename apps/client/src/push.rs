// SPDX-License-Identifier: MIT
//! Push over EventSource (RFC 8620, 7.3): a task that listens to the stream and tells which types changed; after a
//! break it connects again, waiting longer each time (up to a minute).

use std::{collections::BTreeSet, time::Duration};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

use crate::Client;

/// What the stream tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Push {
    /// The types whose state changed, in any account (`Email`, `Mailbox`, `FileNode` …).
    Changed(BTreeSet<String>),
    /// The stream broke; it is being opened again.
    Lost(String),
    /// The stream is open (again).
    Connected,
}

/// The events of an `text/event-stream` (HTML, 9.2): name and data of each, as they arrive.
#[derive(Debug)]
pub struct Events<R> {
    reader: BufReader<R>,
}

impl<R: AsyncRead + Unpin> Events<R> {
    pub fn new(reader: R) -> Self {
        Self { reader: BufReader::new(reader) }
    }

    /// The next event; `None` when the stream ends.
    pub async fn next(&mut self) -> Option<std::io::Result<(String, String)>> {
        let (mut name, mut data) = (String::new(), Vec::<String>::new());
        let mut line = String::new();
        loop {
            line.clear();
            match self.reader.read_line(&mut line).await {
                Ok(0) => return None,
                Ok(_) => {}
                Err(error) => return Some(Err(error)),
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                if data.is_empty() && name.is_empty() {
                    continue;
                }
                let name = if name.is_empty() { "message".to_owned() } else { std::mem::take(&mut name) };
                return Some(Ok((name, data.join("\n"))));
            }
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "event" => name = value.to_owned(),
                "data" => data.push(value.to_owned()),
                _ => {}
            }
        }
    }
}

/// The types a `StateChange` names (RFC 8620, 7.1).
pub fn changed_types(data: &str) -> BTreeSet<String> {
    let Ok(value) = serde_json::from_str::<Value>(data) else { return BTreeSet::new() };
    value
        .get("changed")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|accounts| accounts.values())
        .filter_map(Value::as_object)
        .flat_map(|types| types.keys().cloned())
        .collect()
}

/// Listens in a task of its own (on the current tokio runtime) until `out` returns false.
pub fn listen(client: Client, out: impl Fn(Push) -> bool + Send + 'static) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut wait = Duration::from_secs(2);
        loop {
            match client.event_source(60).await {
                Ok(stream) => {
                    if !out(Push::Connected) {
                        return;
                    }
                    wait = Duration::from_secs(2);
                    let mut events = Events::new(tokio_util::io::StreamReader::new(stream));
                    while let Some(event) = events.next().await {
                        let Ok((name, data)) = event else { break };
                        if name != "state" {
                            continue;
                        }
                        let types = changed_types(&data);
                        if !types.is_empty() && !out(Push::Changed(types)) {
                            return;
                        }
                    }
                    if !out(Push::Lost("the stream ended".into())) {
                        return;
                    }
                }
                Err(error) => {
                    if !out(Push::Lost(error.to_string())) {
                        return;
                    }
                }
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(Duration::from_secs(60));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn events() {
        let stream = ": hello\n\nevent: state\ndata: {\"@type\":\"StateChange\",\ndata: \"changed\":{\"a\":{\"Email\":\"1\",\"Mailbox\":\"2\"}}}\n\nevent: ping\ndata: {\"interval\":60}\n\n";
        let mut reader = Events::new(stream.as_bytes());
        let mut events = Vec::new();
        while let Some(event) = reader.next().await {
            events.push(event.unwrap());
        }
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "state");
        let types: Vec<_> = changed_types(&events[0].1).into_iter().collect();
        assert_eq!(types, ["Email", "Mailbox"]);
        assert_eq!(events[1].0, "ping");
        assert!(changed_types(&events[1].1).is_empty());
    }
}
