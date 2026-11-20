// SPDX-License-Identifier: MIT
//! kernoid's library of calendars and contacts.
//!
//! - [`ical`]: iCalendar objects (RFC 5545) as a tree of components whose properties keep their values as written;
//!   [`content`] is the line syntax iCalendar and vCard share, [`time`] its dates, times and durations.
//! - [`expand`]: the instances of an object – recurrence rules ([`recur`]), dates, exceptions and overrides – in their
//!   time zones ([`tz`]: IANA, Windows and prefixed names, `VTIMEZONE`s read and written).
//! - [`vcard`]: vCards (RFC 6350; 2.1 and 3.0 read, 3.0 written on request).
//! - [`jscalendar`] and [`jscontact`]: JSCalendar (RFC 8984, as JMAP for Calendars writes it: `recurrenceRule`,
//!   `organizerCalendarAddress`) and JSContact (RFC 9553) as JSON objects, converted from and to iCalendar and vCard
//!   (RFC 9555, draft-ietf-calext-jscalendar-icalendar).
//! - [`jmap`]: JSON Pointers and JMAP's `PatchObject` (RFC 8620).

pub mod content;
pub mod expand;
pub mod ical;
pub mod jmap;
pub mod jscalendar;
pub mod jscontact;
pub mod recur;
pub mod time;
pub mod tz;
pub mod vcard;

pub use content::{Error, Param, Property};
pub use ical::Component;
pub use time::{Duration, Time};
