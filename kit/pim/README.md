<!-- SPDX-License-Identifier: MIT -->
# kernoid-pim

Calendars and contacts of [kernoid](https://kernoid.dev) – its own library, written from the RFCs, the one the server
stores and schedules with and the SDK reads and writes files with:

- **iCalendar** (RFC 5545; `ical`, `content`, `time`): components kept with their properties as written, so that
  what is not understood (`X-` properties, other vendors' parameters) goes back out unchanged; lines folded at 75
  octets, parameters quoted and caret-encoded (RFC 6868).
- **Recurrences** (`recur`, `expand`): `RRULE` with every part (`BYSETPOS`, `BYWEEKNO`, `WKST`, …), `RDATE`, `EXDATE`
  and overrides (`RECURRENCE-ID`), in their time zones – a time the clocks skip moves on, `UNTIL` in UTC is an
  instant; floating times and dates in the zone the caller gives.
- **Time zones** (`tz`): IANA names, names behind a prefix (`/mozilla.org/…/Europe/Berlin`), Windows names as Outlook
  writes them, and a calendar's own `VTIMEZONE` as a POSIX rule; `VTIMEZONE`s written for IANA zones with yearly
  `RRULE`s.
- **vCard** (RFC 6350; `vcard`): 4.0, 3.0 and 2.1 read – with quoted-printable and its `CHARSET` –, 4.0 or 3.0
  written.
- **JSCalendar and JSContact** (RFC 8984 as JMAP for Calendars writes it, RFC 9553; `jscalendar`, `jscontact`): JSON
  objects converted from and to iCalendar and vCard (RFC 9555, draft-ietf-calext-jscalendar-icalendar), what has no
  property of its own kept in `iCalProps`/`iCalComponents` and `vCardProps`.
- **JMAP** (RFC 8620; `jmap`): JSON Pointers and `PatchObject`.

```rust
let calendar = kernoid_pim::ical::parse(text)?;
let instances = kernoid_pim::expand::expand(&calendar, &jiff::tz::TimeZone::UTC, None, 1000);
let events = kernoid_pim::jscalendar::from_icalendar(&calendar);
let back = kernoid_pim::jscalendar::to_icalendar(&events, "-//example//EN")?.to_string();
```

Its dependencies are [jiff](https://crates.io/crates/jiff) and serde_json. OPEN: `RSCALE` and `SKIP` (RFC 7529) are
kept but not applied; `RANGE=THISANDFUTURE` is read as one instance; a zone only a calendar defines becomes UTC in
JSCalendar (no `timeZones`); historic rules of such a zone are not kept.
