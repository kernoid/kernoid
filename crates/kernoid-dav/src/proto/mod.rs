/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! WebDAV, CalDAV and CardDAV requests and responses, taken over from Stalwart's `crates/dav-proto` (v0.16.27,
//! RFC 0004 8.1): the XML tokenizer and parsers of request bodies and headers, the writers of multistatus and other
//! responses. Changed for kernoid: Stalwart's internal types replaced (`types.rs`), the conversion of request headers
//! for Stalwart's tracing and the archived (rkyv) dead properties left out.

use calcard::vcard::VCardVersion;

pub mod parser;
pub mod requests;
pub mod responses;
pub mod schema;
pub mod types;

pub fn xml_pretty_print(xml_string: &str) -> String {
    // Create a reader
    let mut reader = quick_xml::Reader::from_str(xml_string);
    let mut writer = quick_xml::Writer::new_with_indent(std::io::Cursor::new(Vec::new()), b' ', 2);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(event) => {
                writer.write_event(event).unwrap();
            }
            Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
        }
        buf.clear();
    }

    let result = writer.into_inner().into_inner();
    String::from_utf8(result).unwrap()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RequestHeaders<'x> {
    pub uri: &'x str,
    pub depth: Depth,
    pub timeout: Timeout,
    pub content_type: Option<&'x str>,
    pub destination: Option<&'x str>,
    pub lock_token: Option<&'x str>,
    pub vcard_version: Option<VCardVersion>,
    pub no_schedule_reply: bool,
    pub if_schedule_tag: Option<u32>,
    pub overwrite_fail: bool,
    pub no_timezones: bool,
    pub ret: Return,
    pub depth_no_root: bool,
    pub if_: Vec<If<'x>>,
    pub range: Option<ByteRange>,
    pub if_range: Option<&'x str>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ByteRange {
    Offset { start: u64, end: Option<u64> },
    Suffix(u64),
}

pub struct ResourceState<T: AsRef<str>> {
    pub resource: Option<T>,
    pub etag: T,
    pub state_token: T,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum Return {
    Minimal,
    Representation,
    #[default]
    Default,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct If<'x> {
    pub resource: Option<&'x str>,
    pub list: Vec<Condition<'x>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Condition<'x> {
    StateToken { is_not: bool, token: &'x str },
    ETag { is_not: bool, tag: &'x str },
    Exists { is_not: bool },
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum Timeout {
    Infinite,
    Second(u64),
    #[default]
    None,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum Depth {
    Zero,
    One,
    Infinity,
    #[default]
    None,
}

/*


Implemented:

RFC4918 - HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV)
RFC5689 - Extended MKCOL for Web Distributed Authoring and Versioning (WebDAV)
RFC6578 - Collection Synchronization for Web Distributed Authoring and Versioning (WebDAV)
RFC3744 - Web Distributed Authoring and Versioning (WebDAV) Access Control Protocol
RFC4331 - Quota and Size Properties for Distributed Authoring and Versioning (DAV) Collections
RFC5397 - WebDAV Current Principal Extension
RFC8144 - Use of the Prefer Header Field in Web Distributed Authoring and Versioning (WebDAV)
RFC4791 - Calendaring Extensions to WebDAV (CalDAV)
RFC7809 - Calendaring Extensions to WebDAV (CalDAV) Time Zones by Reference
RFC6638 - Scheduling Extensions to CalDAV
RFC6352 - CardDAV vCard Extensions to Web Distributed Authoring and Versioning (WebDAV)
RFC6764 - Locating Services for Calendaring Extensions to WebDAV (CalDAV) and vCard Extensions to WebDAV (CardDAV)

Out of scope:

RFC5842 - Binding Extensions to Web Distributed Authoring and Versioning (WebDAV)
RFC4316 - Datatypes for Web Distributed Authoring and Versioning (WebDAV) Properties
RFC4709 - Mounting Web Distributed Authoring and Versioning (WebDAV) Servers
RFC3648 - Web Distributed Authoring and Versioning (WebDAV) Ordered Collections Protocol
RFC4437 - Web Distributed Authoring and Versioning (WebDAV) Redirect Reference Resources
RFC8607 - Calendaring Extensions to WebDAV (CalDAV) Managed Attachments
RFC5995 - Using POST to Add Members to Web Distributed Authoring and Versioning (WebDAV) Collections
RFC3253 - Versioning Extensions to WebDAV (Web Distributed Authoring and Versioning)
RFC5323 - Web Distributed Authoring and Versioning (WebDAV) SEARCH


*/
