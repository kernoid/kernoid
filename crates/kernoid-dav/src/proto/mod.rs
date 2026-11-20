// SPDX-License-Identifier: AGPL-3.0-or-later
//! The protocol of WebDAV (RFC 4918, with RFC 3744, 4331, 5397, 5689 and 6578), CalDAV (RFC 4791, 6638, 7809) and
//! CardDAV (RFC 6352) as kernoid speaks it: request bodies read into typed requests, responses written as XML, and the
//! headers WebDAV adds to HTTP. Both servers use it – calendars and contacts at `/dav/` (`crate::Dav`) and files at
//! `/webdav/` (`kernoid-server`).
//!
//! - [`xml`] reads a body into a tree (namespaces resolved; DTDs refused; only the predefined entities and character
//!   references; bounded in size, depth and number of elements) and writes responses with one XML declaration and
//!   fixed prefixes declared on the root.
//! - [`schema::property`] names the properties and their values, [`schema::request`] the requests (`PROPFIND`,
//!   `PROPPATCH`, `MKCOL`/`MKCALENDAR`, `LOCK`, the reports), [`schema::response`] the responses (multi-status, error
//!   bodies with their preconditions, the scheduling response).
//! - [`headers`] reads `Depth`, `Timeout`, `If`, `Lock-Token`, `Destination` and `Overwrite`.
//!
//! What a server does with a request is not decided here.

pub mod headers;
pub mod names;
pub mod schema;
pub mod types;
pub mod xml;

pub use headers::{Depth, IfCondition, IfList, RequestHeaders, Timeout};

/// Why a request body could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The body is larger than [`xml::MAX_BODY`].
    TooLarge,
    /// The body is not UTF-8.
    NotUtf8,
    /// A document type declaration: refused, as are entities other than XML's own.
    Dtd,
    /// An entity reference other than the five XML predefines, or a character reference to no character.
    Entity,
    /// Nested deeper or with more elements than allowed.
    TooComplex,
    /// Not well-formed XML.
    Malformed(String),
    /// Well-formed, but not the request the method expects (another root, a missing element, a bad value).
    Invalid(&'static str),
    /// A report kernoid does not know (RFC 3253, 3.6: `supported-report`).
    UnsupportedReport,
    /// A collation kernoid does not know (RFC 4791, 7.5.1; RFC 6352, 8.3.1: `supported-collation`).
    UnsupportedCollation,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("the body is too large"),
            Self::NotUtf8 => f.write_str("the body is not UTF-8"),
            Self::Dtd => f.write_str("document type declarations are refused"),
            Self::Entity => f.write_str("unknown entity"),
            Self::TooComplex => f.write_str("the document is nested too deep or has too many elements"),
            Self::Malformed(reason) => write!(f, "not well-formed: {reason}"),
            Self::Invalid(reason) => write!(f, "invalid request: {reason}"),
            Self::UnsupportedReport => f.write_str("unsupported report"),
            Self::UnsupportedCollation => f.write_str("unsupported collation"),
        }
    }
}

impl std::error::Error for Error {}
