// SPDX-License-Identifier: MIT
//! Programs built on kernoid in kernoid's native library (RFC 0011, 4). An app has one Rust library: a program's app
//! builds its own crate on this one, registers its [`Program`] when it loads, and its Dart code reaches it through
//! kernoid's generated API (`programCall`, `programWatch`) – bytes in, bytes out, in whatever encoding the program
//! chooses. kernoid's feature packages keep calling kernoid's API, from the same library.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, RwLock};

use crate::api::kernoid::Kernoid;
use crate::frb_generated::StreamSink;

/// What a program answers: its bytes, or why it could not.
pub type Reply<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

/// A program's part of the native library.
pub trait Program: Send + Sync {
    /// Answers one call – `account` is the signed-in account the app called it with, none before anyone signs in.
    fn call<'a>(&'a self, account: Option<&'a Kernoid>, method: &'a str, input: Vec<u8>) -> Reply<'a>;

    /// Starts sending to `sink` until the sink is closed; by default the program sends nothing.
    fn watch(&self, account: Option<&Kernoid>, method: &str, input: Vec<u8>, sink: Sink) -> Result<(), String> {
        let _ = (account, input, sink);
        Err(format!("{method} sends nothing"))
    }
}

/// Where a program's stream goes.
pub struct Sink(StreamSink<Vec<u8>>);

impl Sink {
    pub(crate) fn new(sink: StreamSink<Vec<u8>>) -> Self {
        Sink(sink)
    }

    /// Sends `bytes`; `false` once Dart stopped listening.
    pub fn add(&self, bytes: Vec<u8>) -> bool {
        self.0.add(bytes).is_ok()
    }
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sink")
    }
}

fn programs() -> &'static RwLock<HashMap<String, Arc<dyn Program>>> {
    static PROGRAMS: OnceLock<RwLock<HashMap<String, Arc<dyn Program>>>> = OnceLock::new();
    PROGRAMS.get_or_init(Default::default)
}

/// Registers `program` under `name` – the program's crate does it when its library loads.
pub fn register(name: &str, program: Arc<dyn Program>) {
    programs().write().unwrap_or_else(|e| e.into_inner()).insert(name.to_owned(), program);
}

pub(crate) fn find(name: &str) -> Result<Arc<dyn Program>, String> {
    programs()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(name)
        .cloned()
        .ok_or_else(|| format!("no program {name} in this library"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::program::program_call;

    struct Echo;

    impl Program for Echo {
        fn call<'a>(&'a self, account: Option<&'a Kernoid>, method: &'a str, input: Vec<u8>) -> Reply<'a> {
            Box::pin(async move {
                match method {
                    "echo" if account.is_none() => Ok(input),
                    _ => Err(format!("no method {method}")),
                }
            })
        }
    }

    #[tokio::test]
    async fn a_registered_program_answers_and_others_are_refused() {
        register("test-echo", Arc::new(Echo));
        let answer = program_call("test-echo".into(), "echo".into(), b"hi".to_vec()).await.unwrap();
        assert_eq!(answer, b"hi");
        let refused = program_call("test-echo".into(), "nothing".into(), vec![]).await.unwrap_err();
        assert_eq!(refused.message, "no method nothing");
        assert!(!refused.unauthorized);
        let missing = program_call("unknown".into(), "echo".into(), vec![]).await.unwrap_err();
        assert_eq!(missing.message, "no program unknown in this library");
    }
}
