// SPDX-License-Identifier: AGPL-3.0-or-later
//! Paths below `/dav/` (RFC 0004, 8.1): principals, the calendar and address book homes with their collections and
//! objects. Segments are percent-encoded in hrefs and decoded when read.

use uuid::Uuid;

/// Where kernoid serves DAV.
pub const BASE: &str = "/dav";

/// What a path names, before it is looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Root,
    Principals,
    Principal(Uuid),
    CalendarHome(Uuid),
    /// A calendar, `inbox` or `outbox`, or `shared-<id>`, by its segment.
    Calendar(Uuid, String),
    CalendarObject(Uuid, String, String),
    AddressbookHome(Uuid),
    Addressbook(Uuid, String),
    Contact(Uuid, String, String),
}

/// Reads a request path; `None` if it is not below [`BASE`] or not a path kernoid knows.
pub fn parse(path: &str) -> Option<Target> {
    let rest = path.strip_prefix(BASE)?;
    if !(rest.is_empty() || rest.starts_with('/')) {
        return None;
    }
    let segments: Vec<String> =
        rest.split('/').filter(|segment| !segment.is_empty()).map(decode).collect::<Option<_>>()?;
    let id = |segment: &String| Uuid::parse_str(segment).ok();
    Some(match segments.as_slice() {
        [] => Target::Root,
        [kind] if kind == "principals" => Target::Principals,
        [kind, account] if kind == "principals" => Target::Principal(id(account)?),
        [kind, account] if kind == "calendars" => Target::CalendarHome(id(account)?),
        [kind, account, collection] if kind == "calendars" => Target::Calendar(id(account)?, collection.clone()),
        [kind, account, collection, object] if kind == "calendars" => {
            Target::CalendarObject(id(account)?, collection.clone(), object.clone())
        }
        [kind, account] if kind == "addressbooks" => Target::AddressbookHome(id(account)?),
        [kind, account, collection] if kind == "addressbooks" => Target::Addressbook(id(account)?, collection.clone()),
        [kind, account, collection, object] if kind == "addressbooks" => {
            Target::Contact(id(account)?, collection.clone(), object.clone())
        }
        _ => return None,
    })
}

/// The path of a `Destination` header (COPY, MOVE): an absolute URL or a path.
pub fn destination(value: &str) -> Option<Target> {
    let path = match value.find("://") {
        Some(scheme) => &value[value[scheme + 3..].find('/').map(|slash| scheme + 3 + slash)?..],
        None => value,
    };
    parse(path)
}

fn decode(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let decoded = String::from_utf8(out).ok()?;
    (!decoded.contains('/')).then_some(decoded)
}

/// A segment for an href: everything but unreserved characters and a few safe ones percent-encoded.
pub fn encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~@+=,".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn principal(account: Uuid) -> String {
    format!("{BASE}/principals/{account}/")
}

pub fn calendar_home(account: Uuid) -> String {
    format!("{BASE}/calendars/{account}/")
}

pub fn addressbook_home(account: Uuid) -> String {
    format!("{BASE}/addressbooks/{account}/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_read_and_written() {
        let account = Uuid::from_u128(7);
        assert_eq!(parse("/dav"), Some(Target::Root));
        assert_eq!(parse("/dav/"), Some(Target::Root));
        assert_eq!(parse("/davx"), None);
        assert_eq!(parse(&principal(account)), Some(Target::Principal(account)));
        let object = format!("{}work/{}", calendar_home(account), encode("a b%.ics"));
        assert_eq!(object, format!("/dav/calendars/{account}/work/a%20b%25.ics"));
        assert_eq!(parse(&object), Some(Target::CalendarObject(account, "work".into(), "a b%.ics".into())));
        assert_eq!(parse("/dav/calendars/not-a-uuid/"), None);
        assert_eq!(parse(&format!("/dav/calendars/{account}/a%2Fb/")), None);
        assert_eq!(
            destination(&format!("https://login.example/dav/addressbooks/{account}/home/x.vcf")),
            Some(Target::Contact(account, "home".into(), "x.vcf".into()))
        );
    }
}
