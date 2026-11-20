// SPDX-License-Identifier: AGPL-3.0-or-later
//! The vocabulary of the protocols: namespaces, properties and their values ([`property`]), requests ([`request`]) and
//! responses ([`response`]), and the text matching of queries.

pub mod property;
pub mod request;
pub mod response;

use super::Error;

/// The namespaces kernoid writes, each with its fixed prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace {
    /// `DAV:` (RFC 4918).
    Dav,
    /// `urn:ietf:params:xml:ns:caldav` (RFC 4791).
    CalDav,
    /// `urn:ietf:params:xml:ns:carddav` (RFC 6352).
    CardDav,
    /// `http://calendarserver.org/ns/` – Apple's, for `getctag`.
    CalendarServer,
    /// `http://apple.com/ns/ical/` – Apple's calendar colour and order.
    AppleIcal,
}

impl Namespace {
    pub const ALL: [Namespace; 5] = [Self::Dav, Self::CalDav, Self::CardDav, Self::CalendarServer, Self::AppleIcal];

    pub fn uri(self) -> &'static str {
        match self {
            Self::Dav => "DAV:",
            Self::CalDav => "urn:ietf:params:xml:ns:caldav",
            Self::CardDav => "urn:ietf:params:xml:ns:carddav",
            Self::CalendarServer => "http://calendarserver.org/ns/",
            Self::AppleIcal => "http://apple.com/ns/ical/",
        }
    }

    pub fn prefix(self) -> &'static str {
        match self {
            Self::Dav => "D",
            Self::CalDav => "C",
            Self::CardDav => "CARD",
            Self::CalendarServer => "CS",
            Self::AppleIcal => "A",
        }
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|ns| ns.uri() == uri)
    }
}

/// A collation of text matches (RFC 4790; RFC 4791, 7.5; RFC 6352, 8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Collation {
    /// `i;octet`: byte for byte.
    Octet,
    /// `i;ascii-casemap`: ASCII letters without case – the default.
    #[default]
    AsciiCasemap,
    /// `i;unicode-casemap` (RFC 5051): all letters without case (kernoid compares lowercased text).
    UnicodeCasemap,
}

impl Collation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Octet => "i;octet",
            Self::AsciiCasemap => "i;ascii-casemap",
            Self::UnicodeCasemap => "i;unicode-casemap",
        }
    }

    pub fn parse(value: &str) -> Result<Self, Error> {
        match value.trim() {
            "i;octet" => Ok(Self::Octet),
            "i;ascii-casemap" => Ok(Self::AsciiCasemap),
            "i;unicode-casemap" => Ok(Self::UnicodeCasemap),
            _ => Err(Error::UnsupportedCollation),
        }
    }
}

/// How a `text-match` compares (RFC 6352, 10.5.4; CalDAV's only substring).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MatchType {
    Equals,
    #[default]
    Contains,
    StartsWith,
    EndsWith,
}

/// A `text-match` of a query.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TextMatch {
    pub text: String,
    pub match_type: MatchType,
    pub collation: Collation,
    /// `negate-condition="yes"`.
    pub negate: bool,
}

impl TextMatch {
    pub fn matches(&self, value: &str) -> bool {
        let (value, text) = match self.collation {
            Collation::Octet => (value.to_owned(), self.text.clone()),
            Collation::AsciiCasemap => (value.to_ascii_lowercase(), self.text.to_ascii_lowercase()),
            Collation::UnicodeCasemap => (value.to_lowercase(), self.text.to_lowercase()),
        };
        let found = match self.match_type {
            MatchType::Equals => value == text,
            MatchType::Contains => value.contains(&text),
            MatchType::StartsWith => value.starts_with(&text),
            MatchType::EndsWith => value.ends_with(&text),
        };
        found != self.negate
    }

    pub(crate) fn from_element(element: &super::xml::Element) -> Result<Self, Error> {
        let match_type = match element.attr("match-type").map(str::trim) {
            None | Some("contains") => MatchType::Contains,
            Some("equals") => MatchType::Equals,
            Some("starts-with") => MatchType::StartsWith,
            Some("ends-with") => MatchType::EndsWith,
            Some(_) => return Err(Error::Invalid("unknown match-type")),
        };
        Ok(Self {
            text: element.text(),
            match_type,
            collation: element.attr("collation").map(Collation::parse).transpose()?.unwrap_or_default(),
            negate: element.attr("negate-condition").is_some_and(|value| value.trim() == "yes"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_matches_by_collation_and_type() {
        let text =
            |text: &str, match_type, collation, negate| TextMatch { text: text.into(), match_type, collation, negate };
        assert!(text("ONC", MatchType::Contains, Collation::AsciiCasemap, false).matches("Once"));
        assert!(!text("ONC", MatchType::Contains, Collation::Octet, false).matches("Once"));
        assert!(text("ÄR", MatchType::StartsWith, Collation::UnicodeCasemap, false).matches("ärger"));
        assert!(!text("ÄR", MatchType::StartsWith, Collation::AsciiCasemap, false).matches("ärger"));
        assert!(text("org", MatchType::EndsWith, Collation::AsciiCasemap, false).matches("carol@example.org"));
        assert!(text("x", MatchType::Equals, Collation::AsciiCasemap, true).matches("y"));
        assert!(!text("y", MatchType::Equals, Collation::AsciiCasemap, true).matches("Y"));
        assert_eq!(Collation::parse("i;nope"), Err(Error::UnsupportedCollation));
    }
}
