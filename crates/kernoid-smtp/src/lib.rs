// SPDX-License-Identifier: AGPL-3.0-or-later
//! kernoid's SMTP. With the feature `server` (by default): kernoid as the MX of its tenants' domains (RFC 0002, 9) – an
//! SMTP server that accepts mail for their addresses, checks it (iprev, SPF, DKIM, ARC, DMARC, a basic spam filter) and
//! stores it at once, relaying nothing –, submission, and the queue's sending. Always: the client ([`client`]), which
//! delivers the queue and submits kernoid's own messages through a relay – identity alone (`kernoid-server` without
//! mail) takes this crate without the feature, to send its codes.

pub mod client;
pub mod proto;

// The server's part, at the crate's root as before; without the feature, none of it is built.
#[cfg(feature = "server")]
include!("server.rs");
