// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid in the terminal: mail, files, calendars and contacts over JMAP. The protocols are kernoid's Rust SDK
//! (`kernoid-client`, here as `jmap`); the writing of messages (`compose`) and forms are a library, so they can be
//! tested apart from the screen.

pub mod compose;
pub mod config;
pub mod forms;

pub use kernoid_client as jmap;

use std::{future::Future, sync::LazyLock};

/// The runtime the SDK's calls run on: the screen waits for each (`block`), the push stream and transfers run on it
/// in the background.
pub static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("kernoid-tui-io")
        .build()
        .expect("a tokio runtime")
});

/// Waits for a call of the SDK.
pub fn block<F: Future>(future: F) -> F::Output {
    RUNTIME.block_on(future)
}
