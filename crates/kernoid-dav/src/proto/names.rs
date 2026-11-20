// SPDX-License-Identifier: AGPL-3.0-or-later
//! The names of iCalendar components, properties and parameters and of vCard properties and parameters as CalDAV and
//! CardDAV requests carry them (filters, partial retrieval) – upper case, any name, kernoid's own types in place of the
//! enumerations Stalwart's protocol took from calcard.

use super::schema::AttributeValue;

macro_rules! name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(pub String);

        impl $name {
            pub fn new(name: &str) -> Self {
                $name(name.trim().to_ascii_uppercase())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AttributeValue for $name {
            fn from_str(s: &str) -> Option<Self> {
                (!s.trim().is_empty()).then(|| $name::new(s))
            }
        }
    };
}

name!(
    /// An iCalendar component (`VEVENT`).
    ICalendarComponentType
);
name!(
    /// An iCalendar property (`DTSTART`).
    ICalendarProperty
);
name!(
    /// An iCalendar parameter (`PARTSTAT`).
    ICalendarParameterName
);
name!(
    /// A vCard property (`EMAIL`).
    VCardProperty
);
name!(
    /// A vCard parameter (`TYPE`).
    VCardParameterName
);

/// iCalendar and vCard values in the tests' JSON: their text.
#[cfg(test)]
pub mod text {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T: std::fmt::Display, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub mod ical {
        use super::*;

        pub fn serialize<S: Serializer>(value: &kernoid_pim::Component, serializer: S) -> Result<S::Ok, S::Error> {
            super::serialize(value, serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<kernoid_pim::Component, D::Error> {
            let text = String::deserialize(deserializer)?;
            kernoid_pim::ical::parse(&text).map_err(serde::de::Error::custom)
        }
    }

    pub mod vcard {
        use super::*;

        pub fn serialize<S: Serializer>(value: &kernoid_pim::vcard::VCard, serializer: S) -> Result<S::Ok, S::Error> {
            super::serialize(value, serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<kernoid_pim::vcard::VCard, D::Error> {
            let text = String::deserialize(deserializer)?;
            kernoid_pim::vcard::parse(&text).map_err(serde::de::Error::custom)
        }
    }
}
