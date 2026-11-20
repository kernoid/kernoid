// SPDX-License-Identifier: AGPL-3.0-or-later
//! SMTP on the wire, kernoid's own, written from the RFCs: commands as the server reads them (`request`, RFC 5321,
//! 4.1, with the parameters of RFC 1870, 3461, 4954, 6152, 6531 and 3030), the message after `DATA` and `BDAT`
//! (`data`, RFC 5321, 4.5.2 and RFC 3030), and replies as the client reads them, `EHLO`'s among them (`reply`, RFC
//! 5321, 4.2, enhanced status codes of RFC 2034/3463). Everything is read from bytes in pieces as they arrive; nothing
//! here does I/O. Part of the external audit before 1.0 – change it only with tests.

pub mod data;
pub mod reply;
pub mod request;

pub use data::{BdatReceiver, DataReceiver, Discard};
pub use reply::{
    EXT_8BIT_MIME, EXT_AUTH, EXT_BINARY_MIME, EXT_CHUNKING, EXT_DSN, EXT_ENHANCED_STATUS_CODES, EXT_PIPELINING,
    EXT_REQUIRE_TLS, EXT_SIZE, EXT_SMTP_UTF8, EXT_START_TLS, Ehlo, MAX_REPLY, Reply, ReplyError,
};
pub use request::{
    AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2, Error, MAX_LINE, MailFrom, RcptTo, Request, RequestReceiver,
};
