// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mail authentication, kernoid's own, written from the RFCs (not from mail-auth's): SPF (`spf`, RFC 7208), DKIM
//! signing and verifying (`dkim`, RFC 6376 with RFC 8301 and RFC 8463), DMARC (`dmarc`, RFC 7489 with the tree walk of
//! DMARCbis in place of a public suffix list), ARC (`arc`, RFC 8617), iprev (`iprev`, RFC 8601, 3) and the headers
//! that report them (`results`: `Authentication-Results`, RFC 8601, and `Received-SPF`, RFC 7208, 9.1). What they
//! share: tag lists (`tags`, RFC 6376, 3.2) and a message's header fields with their canonical forms (`message`,
//! RFC 6376, 3.4). DNS goes through [`crate::Dns`] and its caches; signatures through aws-lc-rs.
//!
//! Security-relevant and part of the external audit before 1.0 – change it only with tests.

pub mod arc;
pub mod dkim;
pub mod dmarc;
pub mod iprev;
pub mod message;
pub mod results;
pub mod spf;
pub mod tags;

pub use dkim::{DkimOutput, DkimResult};
pub use dmarc::{DmarcOutput, DmarcResult};
pub use iprev::{IprevOutput, IprevResult};
pub use spf::{SpfOutput, SpfResult};
