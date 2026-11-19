// SPDX-License-Identifier: MIT
//! The Rust side of kernoid's apps. Dart sees `api` (through flutter_rust_bridge, `frb_generated`); kernoid's Rust SDK
//! (`kernoid-client`) speaks JMAP with kernoid. The system's file shells call `provider`.

pub mod api;
mod frb_generated;
pub mod provider;
