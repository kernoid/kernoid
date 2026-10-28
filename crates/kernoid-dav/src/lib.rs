// SPDX-License-Identifier: AGPL-3.0-or-later
//! CalDAV and CardDAV (RFC 0004, 8.1) on the calendars and contacts of `kernoid-groupware`: the protocol taken over
//! from Stalwart (`proto`), the server kernoid's own.

mod node;
mod path;
mod props;
#[allow(clippy::all, missing_debug_implementations)]
pub mod proto;
pub mod query;
mod schedule;
mod server;

pub use path::BASE;
pub(crate) use server::Error;
pub use server::{Dav, DavRequest, DavResponse};

pub use kernoid_groupware::PROD_ID;
