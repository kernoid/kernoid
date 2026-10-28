<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0004 – Calendars and contacts

- **Status:** draft, 2026-10-24; implemented: sections 1–7 (`kernoid-groupware`, migration 0031), 8.1 (`kernoid-dav`),
  8.2 (`kernoid-jmap`) and 9
- **Scope:** how calendars, events, address books and contacts are stored (sections 1–6), how invitations travel
  (scheduling, section 7), how programs reach them (CalDAV, CardDAV, JMAP: section 8), and how they are shared and
  administered (section 9).

The model follows the protocols clients speak: CalDAV ([RFC 4791](https://www.rfc-editor.org/rfc/rfc4791)) with
scheduling ([RFC 6638](https://www.rfc-editor.org/rfc/rfc6638)), CardDAV
([RFC 6352](https://www.rfc-editor.org/rfc/rfc6352)), JMAP for Contacts
([RFC 9610](https://www.rfc-editor.org/rfc/rfc9610)) and JMAP for Calendars
([draft-ietf-jmap-calendars](https://datatracker.ietf.org/doc/draft-ietf-jmap-calendars/), a draft – revision 33 on
2026-10-24). Statements about Stalwart refer to its source as of v0.16.27 (`crates/dav-proto`, `crates/dav`,
`crates/groupware`, `crates/jmap`).

## 1. What is kernoid's and what is taken over

- **iCalendar and vCard** are parsed, written, expanded (recurrences) and converted to JSCalendar
  ([RFC 8984](https://www.rfc-editor.org/rfc/rfc8984)) and JSContact ([RFC 9553](https://www.rfc-editor.org/rfc/rfc9553))
  by [calcard](https://crates.io/crates/calcard) (Apache-2.0 OR MIT, by Stalwart Labs) – kernoid has no parser of
  its own for these formats.
- **The WebDAV, CalDAV and CardDAV protocol** – parsing requests and writing responses in XML, and headers – is
  taken over from Stalwart (`crates/dav-proto`), as it is, like IMAP's (RFC 0002, 11.2). So is the logic of
  **scheduling** (`crates/groupware/src/scheduling`: what an organizer or attendee sends when an event changes, and
  how a received message changes an event), and the filters of CalDAV and CardDAV queries
  (`crates/dav/src/calendar/query.rs`, `card/query.rs`, `calendar/freebusy.rs`). Everything that stores is
  kernoid's: Stalwart's storage is its own key-value store.
- Taken-over files keep `AGPL-3.0-only`, their copyright and a note of their origin (RFC 0001, licences).

## 2. Data, not events; the account's store

Like mail (RFC 0002, 1), calendars and contacts are **data**: events change constantly, and a log of every change
could never forget a deleted event. What an administrator decides (sharing, section 9) is events.

- **Who has them:** every account with the service `mail` (RFC 0003, 4). Invitations need an address of the account
  (section 7), and the mailbox is where they arrive. **OPEN:** calendars and contacts for accounts without a mailbox
  (an own service `groupware`).
- They live in the account's **mail store** (`mail_accounts`, RFC 0002, 2): changes take its row first, take its
  next `modseq` and count towards its **quota** – one quota for mail, calendars and contacts. The first use creates
  a calendar "Calendar" and an address book "Contacts", each the account's default. **OPEN:** default names in the
  tenant's language.
- **Changes** are journaled in `groupware_changes`: `(account, modseq, type, id, collection, resource name,
  created/updated/destroyed)`, type being `calendar`, `event`, `notification`, `addressbook` or `contact`. The
  collection and resource name are kept so that a sync of one collection (8.1) finds what left it. Journal rows age
  out with the mail journal (`mail.changes_kept_days`, `changes_floor`), and every change notifies `kernoid_mail`
  (RFC 0002, 11.1).

## 3. Content

An event's iCalendar object and a contact's vCard are **sealed in PostgreSQL** with the tenant's key – the same
sealing as objects in object storage (RFC 0001, 6), bound to `tenants/<tenant>/calendar/<account>/<id>` or
`…/contacts/<account>/<id>`. They are small, and a calendar query reads many of them at once, which object storage
would make slow. A sealed value names its key, so rotation (`kernoid keys rotate`) leaves it readable.

What PostgreSQL holds in the clear is what finding needs, protected like the rest of the database (RFC 0002, 1):

- **events:** the `UID`, the kind of component (`VEVENT`, `VTODO`), the **span** – from the start of the first
  instance to the end of the last, open-ended for a recurrence without end – as a `tstzrange` with a GiST index, and
  whether the account organizes it;
- **contacts:** the `UID`, the kind (`individual`, `group`, …), and the email addresses (lower case), for finding a
  contact by address.

Everything else – text matches, exact times of recurring instances – is decided in kernoid after opening the
candidates the index finds. Recurrences are expanded by calcard; for objects whose start is in UTC kernoid expands
in UTC, since calcard 0.3.14 would place their instances in the calendar's time zone (**OPEN:** report upstream). Limits: 1 MiB per object; at most 3 000 instances of a recurrence are expanded for one
query (the rest is not matched).

## 4. Calendars and events

| Calendar | Notes |
|---|---|
| `id` | UUIDv7, the JMAP id |
| `resource_name` | its name in the calendar home, as `MKCALENDAR` chose it; the id when made otherwise. `inbox`, `outbox` and `shared-…` are reserved |
| `name`, `description`, `color`, `sort_order` | as in JMAP and CalDAV (`displayname`, `calendar-description`, Apple's `calendar-color` and `calendar-order`) |
| `timezone` | an IANA name, the default for floating times (`calendar-timezone`) |
| `components` | which components it takes: `VEVENT`, `VTODO` or both (`supported-calendar-component-set`) |
| `is_default` | the calendar invitations land in (section 7); exactly one per account |
| `is_subscribed`, `is_visible` | the owner's display settings (JMAP) |
| `dead_properties` | properties clients set that kernoid does not know (WebDAV), kept as they are; Apple's `calendar-color` and `calendar-order` also set `color` and `sort_order` |

| Event | Notes |
|---|---|
| `id` | UUIDv7, the JMAP id |
| `calendar_id` | one calendar; JMAP's `calendarIds` with more than one is refused (**OPEN**) |
| `resource_name` | its name in the CalDAV collection, as the client chose it (`<uid>.ics` when made through JMAP); unique in the calendar |
| `uid` | unique per calendar, as CalDAV requires; a recurring event and its exceptions are one object |
| `data` | the sealed iCalendar object (section 3) |
| `span`, `component`, `organized` | the index of section 3 |
| `schedule_tag` | RFC 6638's `Schedule-Tag`, moved on when scheduling changes the event (section 7) |

An event's **ETag** is the `modseq` of its last change.

## 5. Address books and contacts

| Address book | Notes |
|---|---|
| `id`, `resource_name` | as for calendars |
| `name`, `description`, `sort_order`, `dead_properties` | |
| `is_default` | exactly one per account |
| `is_subscribed` | |

| Contact | Notes |
|---|---|
| `id`, `addressbook_id`, `resource_name`, `uid` | as for events |
| `data` | the sealed vCard (version 3 or 4 as the client sent it) |
| `kind`, `emails` | the index of section 3 |

## 6. Notifications

When scheduling changes an event (section 7), a **notification** records it for the account – which event, what
changed, by whom – as JMAP's `CalendarEventNotification`. Notifications are destroyed by the account (or after 30
days).

## 7. Scheduling

Invitations follow iTIP ([RFC 5546](https://www.rfc-editor.org/rfc/rfc5546)) carried by mail, iMIP
([RFC 6047](https://www.rfc-editor.org/rfc/rfc6047)); the server schedules, as CalDAV scheduling (RFC 6638) and
JMAP (`sendSchedulingMessages`) expect.

- **Sending.** When an account creates, changes or deletes an event it organizes – or answers one as an attendee –
  through CalDAV or JMAP, kernoid works out the iTIP messages (`REQUEST`, `CANCEL`, `REPLY`, …, with Stalwart's
  logic) and sends each as an email from the account's address through the queue (RFC 0002, 10.2): a text part, the
  iTIP object as `text/calendar; method=…`, and the same as an attachment `invite.ics`. An attendee or organizer with
  `SCHEDULE-AGENT=CLIENT` is left to the client. Recipients that are accounts of the installation get the email
  delivered at once and the message applied to their calendars – the queue would only send it back to kernoid.
- **Receiving.** A delivered email (RFC 0002, 9.4) with a `text/calendar` part that carries a method is also
  applied to the recipient's calendars – but only if **the sender is who the iTIP message says**: the `From`
  address is the organizer (for `REQUEST`, `ADD`, `CANCEL`) or the attendee who answers (`REPLY`), and the email
  passed DMARC for that address, or was sent by an account of the instance. Then:
  - a `REQUEST` for an unknown event adds it to the default calendar with the recipient's participation
    `NEEDS-ACTION`; for a known one it updates it;
  - a `REPLY` updates that attendee's participation in the organizer's event;
  - a `CANCEL` marks the event (or instance) cancelled.
  Each such change writes a notification (section 6). The email itself stays in the mailbox either way.
- **Schedule-Tag** (RFC 6638, 3.2) changes whenever scheduling changes an event, so that a client's change based on
  an older version is refused (`If-Schedule-Tag-Match`).
- **Free/busy:** CalDAV's `free-busy-query` report on one's own calendars, and the scheduling outbox's free/busy
  request for accounts of the same tenant whose calendars the asking account may see free/busy of (section 9).
- **OPEN:** answers by link in the email (RSVP over HTTP), the scheduling inbox listing received messages (they are
  applied at once instead), texts of the invitation email in other languages, alarms by email (`VALARM` with
  `ACTION:EMAIL`; display alarms are the clients').

## 8. Access protocols

All protocols log in like mail programs (RFC 0002, 11): an app password, or the account's password if it needs no
second factor; JMAP also takes a kernoid session.

### 8.1 CalDAV and CardDAV

At `/dav/` of every instance host, with `/.well-known/caldav` and `/.well-known/carddav` pointing there
([RFC 6764](https://www.rfc-editor.org/rfc/rfc6764)); HTTP Basic authentication over HTTPS. In `kernoid-dav`.

- **Paths:** `/dav/principals/<account>/`, the calendar home `/dav/calendars/<account>/` with one collection per
  calendar, `inbox/` and `outbox/` for scheduling, and the address book home `/dav/addressbooks/<account>/` –
  `<account>` being the account's id.
- **Methods:** `OPTIONS`, `PROPFIND`, `PROPPATCH`, `MKCOL` (extended, [RFC 5689](https://www.rfc-editor.org/rfc/rfc5689)),
  `MKCALENDAR`, `GET`, `HEAD`, `PUT`, `DELETE`, `COPY`, `MOVE`, `REPORT`, and `POST` to the outbox.
- **Reports:** `calendar-query`, `calendar-multiget`, `free-busy-query`, `addressbook-query`, `addressbook-multiget`,
  `sync-collection` ([RFC 6578](https://www.rfc-editor.org/rfc/rfc6578)), `expand-property`, `principal-match`,
  `principal-property-search`, `acl-principal-prop-set`.
- **Tags:** an ETag is the `modseq` of the resource's last change (section 4); a collection's sync token is
  `urn:kernoid:sync:<modseq>`, its CTag (`getctag`, which some clients still read) the same number. A sync reads
  `groupware_changes` from the token; a token older than the journal answers `valid-sync-token` and the client
  starts over.
- **Rights** show as WebDAV ACL ([RFC 3744](https://www.rfc-editor.org/rfc/rfc3744)) properties
  (`current-user-privilege-set`, `acl`), read-only: sharing is changed through JMAP, the web app or the
  administration API (section 9). No locks (`LOCK`, class 2): calendar and address book clients do not need them.
- **OPEN:** `calendar-auto-schedule`'s inbox items (7), DAV sharing extensions (Apple's `calendarserver-sharing`),
  managed attachments ([RFC 8607](https://www.rfc-editor.org/rfc/rfc8607)).

### 8.2 JMAP

The capabilities `urn:ietf:params:jmap:calendars` and `urn:ietf:params:jmap:contacts` join mail's (RFC 0002, 11.1),
with the same states (one `modseq` per account) and push.

- **Contacts (RFC 9610):** `AddressBook/get`, `/changes`, `/set`; `ContactCard/get`, `/changes`, `/query`,
  `/queryChanges` (`cannotCalculateChanges`), `/set`, `/copy`. Contacts are stored as vCard and converted with calcard.
- **Calendars (the draft):** `Calendar/get`, `/changes`, `/set`; `CalendarEvent/get`, `/changes`, `/query`, `/set`,
  `/parse`; `CalendarEventNotification/get`, `/changes`, `/set` (destroy only); `ParticipantIdentity/get` (the
  account's addresses). `CalendarEvent/query` expands recurrences when asked (`expandRecurrences`), with the limit of
  section 3. Events are stored as iCalendar and converted with calcard. The draft still changes: kernoid follows
  what calcard implements and records deviations here:
  - the objects are JSCalendar 2.0 as calcard writes them – a recurrence is `recurrenceRule` (one rule), not
    `recurrenceRules`;
  - with `expandRecurrences`, each instance has the id `<event id>.<start in seconds since 1970>`; `CalendarEvent/get`
    answers it with the event's properties, its override applied, `recurrenceId`, `baseEventId`, `utcStart` and
    `utcEnd`. Instances are read-only (**OPEN:** changing one instance; for now through the event's
    `recurrenceOverrides`);
  - `shareWith` is null: sharing is changed through the administration API (section 9). **OPEN:** JMAP Sharing.

## 9. Sharing and administration

Who may use whose calendars and address books is administration, so it is events on the owning account
(`account.collection_access_set`, `account.collection_access_removed`), projected into `collection_access`, like
mail's access (RFC 0002, 12.2). A grant names

- the **grantee**: an account or a group of the same tenant;
- the **collection**: one calendar or address book;
- the **rights**, one of these levels, each including the ones before:
  - calendars: `freebusy` (see when the owner is busy), `read`, `rsvp` (also answer invitations the owner is
    invited to), `write` (change events), `admin` (also share the calendar, rename or delete it);
  - address books: `read`, `write`, `admin`.

JMAP's `myRights` follow from the level (`mayReadFreeBusy`, `mayReadItems`, `mayRSVP`, `mayWriteAll` and
`mayWriteOwn`, `mayUpdatePrivate`, `mayAdmin`, `mayDelete`; for address books `mayRead`, `mayWrite`, `mayAdmin`,
`mayDelete`). A user's level on a collection is the highest of the grants to it and its groups; the owner has
`admin`.

- **Who may grant:** the owner and grantees with `admin`, for that collection; administrators with
  `accounts.manage`, for any account of the tenant (shared mailboxes' calendars, e.g. a room).
- **How it shows:** JMAP lists the owner's account in the session with only the collections shared. CalDAV and
  CardDAV show shared collections in the grantee's own home, as `shared-<collection id>/` – clients that know only
  one home see them there. Free/busy of a calendar shared at `freebusy` counts in free/busy requests (7), and nothing
  else of it is visible.
- **Administration API and CLI:** listing an account's calendars and address books, grants, and import and export
  of whole collections as iCalendar (`.ics`) and vCard (`.vcf`) files – `accounts.manage`, like mail (RFC 0002,
  12.3).
- **OPEN:** the tenant's directory as a read-only address book (JMAP principals, [RFC 9670](https://www.rfc-editor.org/rfc/rfc9670)),
  free/busy visible to the whole tenant by default, resources (rooms) that accept invitations on their own.
