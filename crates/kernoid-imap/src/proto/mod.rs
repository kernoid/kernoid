// SPDX-License-Identifier: AGPL-3.0-or-later
//! IMAP on the wire, written for kernoid from RFC 9051 and RFC 3501 and the RFCs of the extensions it offers (RFC 0002,
//! 11.2): the client's bytes cut into commands with their literals (`frame`), the commands (`request`) and their
//! parser (`parse`), sequence sets (`sequence`), mailbox names in modified UTF-7 (`utf7`) and the writing of responses
//! (`response`).

pub(crate) mod frame;
pub(crate) mod parse;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod sequence;
pub(crate) mod utf7;
