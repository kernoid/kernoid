// SPDX-License-Identifier: MIT
//! Internet mail, kernoid's own library written from the RFCs: messages read with the byte ranges of their parts
//! (RFC 5322; MIME: RFC 2045–2049; RFC 2183, RFC 2231, RFC 6532), header fields in their forms – unstructured text
//! with encoded words, addresses and groups, dates, message ids –, bodies without their transfer encoding and in UTF-8
//! from their charsets, what a reader shows (RFC 8621, 4.1.4), base subjects (RFC 5256), and messages written.
//!
//! ```
//! let raw = b"From: =?utf-8?q?J=C3=BCrgen?= <j@example.org>\r\nSubject: Hello\r\n\r\nHi!\r\n";
//! let message = kernoid_mime::Message::parse(raw).unwrap();
//! assert_eq!(message.from().unwrap().first().unwrap().name(), Some("Jürgen"));
//! assert_eq!(message.root().body_text(0).as_deref(), Some("Hi!\r\n"));
//!
//! let reply = kernoid_mime::MessageBuilder::new()
//!     .from(("Alice", "alice@example.org"))
//!     .to(["j@example.org"])
//!     .subject("Re: Hello")
//!     .text_body("Hi Jürgen")
//!     .write();
//! assert!(kernoid_mime::Message::parse(&reply).is_some());
//! ```

pub mod address;
pub mod body;
pub mod build;
pub mod charset;
pub mod date;
pub mod header;
pub mod message;
pub mod params;
pub mod subject;
pub mod transfer;
pub mod words;

pub use address::{Address, AddressList, Group, Mailbox};
pub use body::html_to_text;
pub use build::{Body, MessageBuilder, Part};
pub use date::DateTime;
pub use header::{Header, Headers};
pub use message::{Kind, MAX_DEPTH, Message, MessageRef, PartRef};
pub use params::ContentType;
pub use subject::base_subject;
pub use transfer::Encoding;
