// SPDX-License-Identifier: AGPL-3.0-or-later
//! The names of iCalendar components, properties and parameters and of vCard properties and parameters as CalDAV and
//! CardDAV requests carry them (filters, partial retrieval): upper case, any name.

macro_rules! name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(name: &str) -> Self {
                $name(name.trim().to_ascii_uppercase())
            }

            pub fn as_str(&self) -> &str {
                &self.0
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
