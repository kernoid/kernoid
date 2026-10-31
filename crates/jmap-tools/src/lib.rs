/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! JMAP objects with JSON Pointer querying and patching, for calcard's JSCalendar and JSContact. Taken over from
//! Stalwart's `crates/jmap-tools` (v1.0.1, commit 23b6975, 2026-10-28), as it is. Files under other licences (`json`)
//! keep their headers.

// Taken over as it is: kernoid's workspace lints are not applied to Stalwart's code.
#![allow(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]

mod json;
mod pointer;

pub use json::key::Key;
pub use json::object_vec::{ObjectAsVec, ObjectAsVec as Map};
pub use json::value::{Element, Null, Property, Value};
pub use pointer::{
    JsonPointer, JsonPointerHandler, JsonPointerItem, JsonPointerIter, PointerDepth,
};
