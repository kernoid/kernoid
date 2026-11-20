// SPDX-License-Identifier: MIT
//! vCards (RFC 6350): read in 4.0, 3.0 (RFC 2426) and 2.1, written in 4.0 or 3.0. A card keeps its properties as
//! written; writing it in the other version changes only what differs between them – inline media (`data:` URIs ↔
//! `ENCODING=b`), the preferred value (`PREF` ↔ `TYPE=pref`), telephone URIs, and the kind and members of a group
//! (`KIND`/`MEMBER` ↔ Apple's `X-ADDRESSBOOKSERVER-*`).

use std::fmt;

use crate::content::{self, Error, Property};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    V2_1,
    V3_0,
    V4_0,
}

impl Version {
    /// `4.0`, `3.0`, `2.1` (quotes and spaces allowed).
    pub fn try_parse(text: &str) -> Option<Version> {
        match text.trim().trim_matches('"').trim() {
            "4.0" | "4" => Some(Version::V4_0),
            "3.0" | "3" => Some(Version::V3_0),
            "2.1" => Some(Version::V2_1),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Version::V2_1 => "2.1",
            Version::V3_0 => "3.0",
            Version::V4_0 => "4.0",
        }
    }
}

/// A vCard: the version it was written in and its properties (without `BEGIN`, `END` and `VERSION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VCard {
    pub version: Version,
    pub properties: Vec<Property>,
}

impl Default for VCard {
    fn default() -> Self {
        VCard { version: Version::V4_0, properties: Vec::new() }
    }
}

impl VCard {
    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties.iter().find(|property| property.is(name))
    }

    pub fn properties<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> + 'a {
        self.properties.iter().filter(move |property| property.is(name))
    }

    /// A property's value as text.
    pub fn text(&self, name: &str) -> Option<String> {
        self.property(name).map(Property::as_text)
    }

    pub fn uid(&self) -> Option<String> {
        self.text("UID").map(|uid| uid.trim().to_owned()).filter(|uid| !uid.is_empty())
    }

    /// Replaces every property of the name with this one.
    pub fn set(&mut self, property: Property) {
        let name = property.name.clone();
        match self.properties.iter().position(|known| known.name == name) {
            Some(position) => {
                self.properties[position] = property;
                let mut first = true;
                self.properties.retain(|known| {
                    if known.name != name {
                        return true;
                    }
                    std::mem::replace(&mut first, false)
                });
            }
            None => self.properties.push(property),
        }
    }

    /// The card as text in a version (4.0 or 3.0; 2.1 is written as 3.0).
    pub fn write(&self, version: Version) -> String {
        let version = if version == Version::V2_1 { Version::V3_0 } else { version };
        let properties: Vec<Property> = match version {
            Version::V4_0 => to_v4(&self.properties),
            _ => to_v3(&self.properties),
        };
        let mut out = String::new();
        let mut all = vec![Property::new("VERSION", version.as_str())];
        all.extend(properties);
        content::write_block(&mut out, "VCARD", &all, |_| {});
        out
    }
}

impl fmt::Display for VCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.write(self.version))
    }
}

/// Every vCard of a text; anything else at the top is an error.
pub fn parse_all(text: &str) -> Result<Vec<VCard>, Error> {
    let blocks = content::parse_blocks(text)?;
    if blocks.iter().any(|block| block.name != "VCARD") {
        return Err(Error("not a vCard".into()));
    }
    Ok(blocks
        .into_iter()
        .map(|block| {
            let version = block
                .properties
                .iter()
                .find(|property| property.is("VERSION"))
                .and_then(|property| Version::try_parse(&property.value))
                .unwrap_or(Version::V3_0);
            VCard {
                version,
                properties: block.properties.into_iter().filter(|property| !property.is("VERSION")).collect(),
            }
        })
        .collect())
}

/// The one vCard of a text.
pub fn parse(text: &str) -> Result<VCard, Error> {
    let mut all = parse_all(text)?;
    match all.len() {
        1 => Ok(all.remove(0)),
        0 => Err(Error("not a vCard".into())),
        _ => Err(Error("more than one vCard".into())),
    }
}

const MEDIA: [&str; 4] = ["PHOTO", "LOGO", "SOUND", "KEY"];

fn to_v4(properties: &[Property]) -> Vec<Property> {
    let mut out = Vec::with_capacity(properties.len());
    for property in properties {
        let mut property = property.clone();
        match property.name.as_str() {
            "X-ADDRESSBOOKSERVER-KIND" => {
                property.name = "KIND".into();
                property.value = property.value.to_ascii_lowercase();
            }
            "X-ADDRESSBOOKSERVER-MEMBER" => property.name = "MEMBER".into(),
            _ => {}
        }
        // Inline media as a data URI.
        if MEDIA.contains(&property.name.as_str())
            && (property.has_param_value("ENCODING", "b") || property.has_param_value("ENCODING", "BASE64"))
        {
            let kind = property.param("TYPE").map(str::to_ascii_lowercase);
            let media = match (property.name.as_str(), kind.as_deref()) {
                (_, Some(kind)) if kind.contains('/') => kind.to_owned(),
                ("SOUND", Some(kind)) => format!("audio/{kind}"),
                ("KEY", Some(kind)) => format!("application/{kind}"),
                (_, Some(kind)) => format!("image/{kind}"),
                _ => "application/octet-stream".to_owned(),
            };
            let data: String = property.value.chars().filter(|c| !c.is_whitespace()).collect();
            property.value = format!("data:{media};base64,{data}");
            property.remove_param("ENCODING");
            property.remove_param("TYPE");
        }
        // `TYPE=pref` as `PREF=1`.
        if property.has_param_value("TYPE", "pref") {
            let types: Vec<String> =
                property.param_values("TYPE").filter(|t| !t.eq_ignore_ascii_case("pref")).map(str::to_owned).collect();
            property.set_param_values("TYPE", types);
            if property.param("PREF").is_none() {
                property.set_param("PREF", "1");
            }
        }
        if property.is("TEL") && property.value.trim_start().get(..4).is_some_and(|s| s.eq_ignore_ascii_case("tel:")) {
            property.set_param("VALUE", "uri");
        }
        out.push(property);
    }
    if !out.iter().any(|property| property.is("FN")) {
        let name = out
            .iter()
            .find(|property| property.is("N"))
            .map(|n| {
                let fields = n.fields();
                let given = fields.get(1).cloned().unwrap_or_default();
                let family = fields.first().cloned().unwrap_or_default();
                format!("{given} {family}").trim().to_owned()
            })
            .filter(|name| !name.is_empty())
            .or_else(|| out.iter().find(|property| property.is("ORG")).and_then(|org| org.fields().into_iter().next()))
            .or_else(|| out.iter().find(|property| property.is("EMAIL")).map(Property::as_text))
            .unwrap_or_default();
        out.insert(0, Property::text("FN", &name));
    }
    out
}

fn to_v3(properties: &[Property]) -> Vec<Property> {
    let mut out = Vec::with_capacity(properties.len());
    for property in properties {
        let mut property = property.clone();
        match property.name.as_str() {
            "KIND" => {
                property.name = "X-ADDRESSBOOKSERVER-KIND".into();
            }
            "MEMBER" => property.name = "X-ADDRESSBOOKSERVER-MEMBER".into(),
            _ => {}
        }
        if MEDIA.contains(&property.name.as_str())
            && let Some(rest) = property.value.strip_prefix("data:")
            && let Some((media, data)) = rest.split_once(";base64,")
        {
            let kind = media.rsplit('/').next().unwrap_or(media).to_ascii_uppercase();
            property.value = data.to_owned();
            property.remove_param("VALUE");
            property.remove_param("MEDIATYPE");
            property.set_param("ENCODING", "b");
            if !kind.is_empty() {
                property.set_param("TYPE", kind);
            }
        }
        if let Some(pref) = property.param("PREF").map(str::to_owned) {
            property.remove_param("PREF");
            if pref.trim() == "1" {
                let mut types: Vec<String> = property.param_values("TYPE").map(str::to_owned).collect();
                types.push("pref".into());
                property.set_param_values("TYPE", types);
            }
        }
        if property.is("TEL") {
            if let Some(number) = property.value.trim_start().strip_prefix("tel:") {
                property.value = number.to_owned();
            }
            property.remove_param("VALUE");
        }
        out.push(property);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards_read_and_write_in_both_versions() {
        let v3 = "BEGIN:VCARD\r\nVERSION:3.0\r\nN:Doe;Jane;;;\r\nFN:Jane Doe\r\nEMAIL;TYPE=INTERNET,WORK,pref:jane@example.org\r\n\
            TEL;TYPE=CELL:+49 170 1\r\nPHOTO;ENCODING=b;TYPE=JPEG:AAAA\r\n BBBB\r\nX-ADDRESSBOOKSERVER-KIND:group\r\nEND:VCARD\r\n";
        let card = parse(v3).unwrap();
        assert_eq!(card.version, Version::V3_0);
        let v4 = card.write(Version::V4_0);
        assert!(v4.contains("VERSION:4.0\r\n"), "{v4}");
        assert!(v4.contains("EMAIL;TYPE=INTERNET,WORK;PREF=1:jane@example.org"), "{v4}");
        assert!(v4.contains("PHOTO:data:image/jpeg;base64,AAAABBBB"), "{v4}");
        assert!(v4.contains("KIND:group"), "{v4}");
        let back = parse(&v4).unwrap().write(Version::V3_0);
        assert!(back.contains("PHOTO;ENCODING=b;TYPE=JPEG:AAAABBBB"), "{back}");
        assert!(back.contains("EMAIL;TYPE=INTERNET,WORK,pref:jane@example.org"), "{back}");
        assert!(back.contains("X-ADDRESSBOOKSERVER-KIND:group"), "{back}");

        let no_name = parse("BEGIN:VCARD\r\nVERSION:3.0\r\nN:Doe;John;;;\r\nEND:VCARD\r\n").unwrap();
        assert!(no_name.write(Version::V4_0).contains("FN:John Doe"));
        assert_eq!(
            parse_all("BEGIN:VCARD\r\nFN:a\r\nEND:VCARD\r\nBEGIN:VCARD\r\nFN:b\r\nEND:VCARD\r\n").unwrap().len(),
            2
        );
        assert!(parse("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n").is_err());
        assert!(parse("not a card").is_err());
        assert_eq!(Version::try_parse("\"3.0\""), Some(Version::V3_0));
    }
}
