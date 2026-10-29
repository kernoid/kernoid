---
title: Calendars and contacts
nav_order: 5.8
permalink: /calendars/
---

# Calendars and contacts

Every account with mail has calendars and address books beside its mailbox: a calendar "Calendar" and an address
book "Contacts" exist from the first use, and the account makes more as it likes. Programs reach them over CalDAV
and CardDAV. The design is [RFC 0004](https://github.com/kernoid/kernoid/blob/main/rfcs/0004-calendars-and-contacts.md).

## Connecting a program

Calendar and address book programs find kernoid by the instance's host name: `/.well-known/caldav` and
`/.well-known/carddav` lead to `/dav/`. Log in with the account's address and an **app password** (`kernoid account
app-password add`, or `POST /v1/account/app-passwords`) – or the account's password if it needs no second factor.

| Program | What to enter |
|---|---|
| Apple Calendar and Contacts (macOS, iOS) | account type CalDAV or CardDAV, "manual"; server: the instance's host name, e.g. `login.example.org` |
| Thunderbird | new calendar → on the network → the address and `https://login.example.org/`; it lists the calendars to add |
| DAVx⁵ (Android) | "login with URL and user name": `https://login.example.org/` |
| Others | the calendar home `https://login.example.org/dav/calendars/<account id>/`, the address book home `https://login.example.org/dav/addressbooks/<account id>/` |

## JMAP

The same calendars and contacts are in JMAP – the session at `/.well-known/jmap` lists the capabilities
`urn:ietf:params:jmap:calendars` and `urn:ietf:params:jmap:contacts`: `AddressBook`, `ContactCard` (JSContact,
[RFC 9610](https://www.rfc-editor.org/rfc/rfc9610)), `Calendar`, `CalendarEvent` (JSCalendar, the draft
[JMAP for Calendars](https://datatracker.ietf.org/doc/draft-ietf-jmap-calendars/)), `CalendarEventNotification` and
`ParticipantIdentity`. `CalendarEvent/query` expands recurring events into their instances on request
(`expandRecurrences` with `after` and `before`). Accounts that share calendars or address books with the user appear
as accounts of their own. With `sendSchedulingMessages`, changes send invitations as CalDAV's do.

## What is there

- **CalDAV** ([RFC 4791](https://www.rfc-editor.org/rfc/rfc4791)) and **CardDAV**
  ([RFC 6352](https://www.rfc-editor.org/rfc/rfc6352)): creating, renaming and deleting calendars and address books,
  events, tasks and contacts, queries by time and text, `multiget`, `free-busy-query`, and synchronisation by token
  ([RFC 6578](https://www.rfc-editor.org/rfc/rfc6578)).
- Colours and order set by Apple's programs are kept; any other property a program sets is kept as it is.
- **Time zones:** a calendar can name one; times without a zone are read in it.
- **Limits:** 1 MiB per event or contact; at most 3 000 instances of a recurring event per query.
- **Quota:** events and contacts count towards the account's quota, with its mail.
- **Content** – the events and contacts themselves – is encrypted with the tenant's key in the database.

## Sharing

A calendar or address book can be shared with another account or a group of the tenant, at one level: for calendars
`freebusy`, `read`, `rsvp`, `write` or `admin`; for address books `read`, `write` or `admin`. Shared collections
appear in the other account's own home as `shared-<id>`; programs that see only one home find them there.
Free/busy requests of a program's scheduling outbox answer for accounts whose calendars the asking account may see.

Sharing is changed through the administration API and the CLI (`accounts.manage`), and by the owner itself; CalDAV's
own ACL method is not offered – programs show the access but do not change it.

## Invitations

When an account creates, changes or deletes an event it organizes – or answers one it is invited to – kernoid sends
the invitation, update, cancellation or answer by email from the account's address (iTIP over iMIP,
[RFC 6047](https://www.rfc-editor.org/rfc/rfc6047)): a short text, the event for calendar programs, and the same as an
attachment `invite.ics`. Accounts of the same installation get it at once. The text is in the language of the
emails kernoid writes for the sending account – German or English, see
[Administration]({{ '/administration/#the-language-of-kernoids-emails' | relative_url }}).

Invitations that arrive by email are applied to the recipient's calendars – a new event lands in the default
calendar, an answer updates the organizer's event, a cancellation marks the event cancelled – but only when the
sender is who the invitation says and that is shown: the message passed DMARC, or a logged-in account sent it. The
email stays in the mailbox either way.

{: .note }
OPEN: invitation texts in languages other than German and English, answers by link in the email.
