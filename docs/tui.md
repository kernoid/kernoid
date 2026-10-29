---
title: Terminal app
nav_order: 5.95
permalink: /tui/
---

# Terminal app

`kernoid-tui` is kernoid's app for the terminal: mail, files, calendars and contacts, by keyboard. Like the
[web app]({{ '/app/' | relative_url }}) it is a first-party app under the MIT licence and talks to kernoid only
through JMAP – it shares no code with the server and works against any kernoid installation.

| Part | What it does |
|---|---|
| Mail | the mailboxes of the account and of shared mailboxes it may use; conversations (threads) – or single emails, `t` switches – with full-text search; reading a whole conversation (HTML emails as plain text – nothing is loaded or run), attachments saved to disk, writing, replying, replying to all and forwarding (with the attachments) in your editor, attaching files, keeping drafts, flagging, marking read or unread, moving, deleting (to the trash; in the trash for good); new mail appears by itself |
| Files | the account's own files, the tenant's drives and what others share; folders, downloads and uploads of any size with progress (a file of the same name gets the upload as new content, the old one stays as a version), a file's versions – saving an earlier one, or restoring it –, details, sharing folders with people and groups (read, edit, or edit and share – as in the web app), new folders, renaming, deleting (to the trash) |
| Calendar | the account's calendars and those shared with it, two weeks at a time; repeating events as their instances, all-day events, place, participants with their answers, description; making, changing and deleting events – participants are invited by email; one event of a series on its own, or the whole series –, answering invitations (accept, maybe, decline); events the organizer called off are shown cancelled |
| Contacts | the cards of the account's address books with search; name, organisation, addresses, phone numbers, notes; making, changing and deleting contacts; writing an email to a contact |

Not yet (`OPEN`): more than one address, phone number or organisation per contact (the editor shows
the first; saving keeps only those), `.ics` and `.vcf` files, finding the server through DNS on Windows (there is no
`/etc/resolv.conf`; give `--server`).

**Logging in with OpenID Connect** stays `OPEN` on purpose. A terminal app would use the device authorization grant
(RFC 8628) – the app shows a code, the user confirms it in a browser – and then send the access token to JMAP. Both
halves are missing on the server: kernoid's provider has no device authorization endpoint, and JMAP, IMAP and
CalDAV accept a kernoid session or HTTP Basic, not an OAuth bearer token (IMAP and SMTP do, with the scope `mail`). An app
password, revocable on its own and limited to programs, is the way until then.

## Building

It lives in `apps/tui/` – a Cargo workspace of its own, apart from the server's, with its own `Cargo.lock`. Rust from
`rust-toolchain.toml`; no OpenSSL (TLS through rustls, certificates checked by the operating system's verifier).

```sh
cd apps/tui
cargo build --release --locked
./target/release/kernoid-tui --help
```

## Logging in

The app logs in like a mail program: with the account's address and an **app password**, made in the account settings
(`POST /v1/account/app-passwords`) or by the operator (`kernoid account app-password add <account> <name>`). The
account's own password works too, but only for an account that needs no second factor.

```sh
kernoid-tui --address alice@firma.example --server https://login.firma.example
```

- **Server:** `--server` (or `KERNOID_SERVER`) names the instance – the host that serves `/.well-known/jmap`. Without
  it, the app tries the domain of the address (`https://firma.example/.well-known/jmap`), and when that serves no
  JMAP, the servers the domain's SRV records name (`_jmap._tcp.firma.example`, RFC 8620, 2.2), asked of the name
  servers in `/etc/resolv.conf`. An operator publishes, for instance,
  `_jmap._tcp.firma.example. 3600 IN SRV 0 1 443 login.firma.example.` The app sends the password only to the host it
  logs in to: links in the session that name another host are followed on that host.
- **Password:** never as an argument. In this order: the environment variable `KERNOID_PASSWORD`, the output of
  `--password-command` (its first line), or asked for on the terminal. A command reaches the system keychain or a
  password manager:

  ```sh
  # macOS keychain: store once, then let the app read it
  security add-generic-password -s kernoid -a alice@firma.example -w
  kernoid-tui -a alice@firma.example --password-command 'security find-generic-password -s kernoid -a alice@firma.example -w'
  # Linux (libsecret): secret-tool store --label kernoid service kernoid account alice@firma.example
  kernoid-tui -a alice@firma.example --password-command 'secret-tool lookup service kernoid account alice@firma.example'
  # pass
  kernoid-tui -a alice@firma.example --password-command 'pass show kernoid/alice'
  ```

- **HTTPS only:** plain HTTP is allowed to this machine (`localhost`, `*.localhost`, loopback addresses) – for trying
  kernoid out – and elsewhere only with `--allow-http`, as the password would travel readable.
- `--check` logs in, lists the accounts of the session and quits – to check the settings.

### Settings file

`~/.config/kernoid/tui.toml` (or `$XDG_CONFIG_HOME/kernoid/tui.toml`, or the file `KERNOID_TUI_CONFIG` or `--config`
names) saves typing; the command line wins over it.

```toml
address = "alice@firma.example"
server = "https://login.firma.example"
password_command = "security find-generic-password -s kernoid -a alice@firma.example -w"
downloads = "/Users/alice/Downloads/kernoid"   # default: the download directory
# allow_http = false
```

## Keys

`?` shows them in the app.

| Where | Keys |
|---|---|
| Everywhere | `1`–`4` or `Tab`: Mail, Files, Calendar, Contacts · `g` or `F5`: load again (in Files also the session: stores shared since) · `?` help · `q` or `Ctrl-C` quit |
| Lists | `j`/`k` or arrows · `Enter` or `l` open · `h` or `←` back · `PgUp`/`PgDn` |
| Mail | `c` write · `/` search (`Esc` clears) · `r` reply · `R` reply to all · `f` forward · `m` move · `d` delete · `u` read/unread · `s` flag · `t` conversations or single emails · `a` next account (in the mailboxes) |
| Reading | `Space`/`PgDn` scroll · `n`/`p` next/previous · `A` attachments (`Enter` saves) · `Esc` back |
| Files | `Enter` open a folder, or a file's versions · `←`/`Backspace` up · `d` download · `u` upload · `v` versions (`Enter` save, `r` restore) · `i` details · `S` share a folder · `n` new folder · `R` rename · `D` delete |
| Sharing | `a` add a person or group (by name or address) · `Enter` next level · `x` remove · `s` save · `Esc` cancel |
| Calendar | `[`/`]` or `←`/`→` a week back or on · `t` today · `Enter` details · `n` new · `e` edit (a series: all of it) · `E` edit this one of a series · `D` delete (a series: `o` this one, `y` all) · `a` accept · `m` maybe · `x` decline |
| Contacts | `/` search · `n` new · `e` or `Enter` edit · `D` delete · `c` write to the contact |

Downloads ask where to save, starting with the download directory; a name that is taken there gets a number. A file
is written as `<name>.part` and renamed once complete.

## Writing

Messages are written in `$VISUAL` or `$EDITOR` (`vi` without either), as text: header lines, a blank line, the
message.

```text
From: Alice Example <alice@firma.example>
To: Bob <bob@firma.example>
Cc:
Bcc:
Subject: Plans for Friday
Attach: ~/Documents/agenda.pdf

Hi Bob, …
```

`From` is one of the addresses the account may send as. Each `Attach:` line names a file to attach; a forward lists
the original's attachments as `Attached:` lines – remove one to leave it out. Once the editor closes, the app asks:
`s` send, `d` keep as a draft, `e` edit again, `c` drop. Sending stores the message in Drafts and submits it; once
sent it moves to Sent (RFC 8621, 7.5). The text goes into a file of the system's temporary directory, readable only
by you, removed once the editor closed.

## Conversations

The list shows a mailbox's conversations, newest first: the people in each, the number of its messages, the subject
of the newest. Opening one shows all its messages, oldest first – also those in other mailboxes, such as your
replies in Sent; a reply answers the newest. Moving, deleting, flagging and marking read act on the conversation's
messages in the mailbox shown; your replies in Sent stay where they are.

## Events and contacts

They are written in the editor too:

```text
Title: Budget review
Calendar: Calendar
Start: 2026-10-29 10:00
End: 2026-10-29 11:00
All day: no
Time zone: Europe/Berlin
Repeat: none
Location: Room 2
Participants: bob@firma.example, carol@x.example

Please bring the numbers.
```

`#` lines are hints (the calendars to choose from, the repetitions). All-day events take dates (`2026-10-29`); the
end is the last day. A new event gets this machine's time zone. Participants are invited by email when it is saved,
and hear of changes and of its deletion; changing an event keeps their answers unless its time changes. Only the
organizer changes an event – those invited answer it; deleting an invitation removes it from your calendar without
telling the organizer (decline for that). Contacts have `Name`, `Email`, `Phone`, `Organization`, `Address book` and
a note after the blank line. Something the server did not take, or that could not be read, opens again with `e`.

## Protocols

| What | Protocol |
|---|---|
| Session, requests, uploads, downloads | JMAP Core (RFC 8620), HTTP Basic |
| Mail | JMAP Mail (RFC 8621): `Mailbox`, `Email`, `Identity`, `EmailSubmission` |
| Threads | `Email/query` with `collapseThreads`, `Thread/get` (RFC 8621, 3) |
| Files | JMAP for files ([draft-ietf-jmap-filenode-19](https://datatracker.ietf.org/doc/draft-ietf-jmap-filenode/)): `FileNode` with `shareWith`; kernoid's `FileVersion/get` (`https://kernoid.dev/jmap/file-versions`); principals (RFC 9670) to find people and groups |
| Calendars | JMAP for Calendars (draft-ietf-jmap-calendars): `Calendar`, `CalendarEvent/query` with `expandRecurrences`, `CalendarEvent/set` with `sendSchedulingMessages` (invitations, answers, cancellations through iTIP) |
| Contacts | JMAP for Contacts (RFC 9610): `AddressBook`, `ContactCard` (`/set` too) |
| Finding the server | SRV records `_jmap._tcp` (RFC 8620, 2.2), DNS messages through hickory-proto |
| Push | the event source of RFC 8620, 7.3 – the app opens it again after a break (the dot next to the address shows whether it is open) |
