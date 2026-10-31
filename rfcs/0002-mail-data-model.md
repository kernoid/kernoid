<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0002 – Mail data model

- **Status:** draft, 2026-10-24; implemented: sections 1–8 (`kernoid-mail`, migration 0023), 9 (`kernoid-smtp`,
  migration 0024), 10 (migrations 0025 and 0026), 11 (`kernoid-jmap`, `kernoid-imap`, migration 0027), 12 (migration 0028) and 13 (migration 0029);
  the grant on `mailbox_expunged` (6, migration 0033). Since 0.2: sending as a group (10.1, migration 0034), SRS
  (10.6, migration 0035), DKIM with Ed25519 and changing keys (10.3, migration 0036), the vacation response (9.1,
  migration 0041), the settings of a mail store (2, 13.2, migrations 0045 and 0047), held submissions (11.1,
  migration 0046), and the malware check through the hook of the module `clamav` (9.1, `kernoid-clamav`)
- **Scope:** how mailboxes, emails and threads are stored, how changes are tracked for JMAP and IMAP, where content
  lives, how quotas are counted, how mail from other servers arrives (SMTP, section 9), how mail is sent (section
  10), how mail programs reach it (JMAP, IMAP, POP3: section 11), how mail is shared and administered
  (section 12), and how it is searched, kept and moved (section 13).

The model follows JMAP Mail ([RFC 8621](https://www.rfc-editor.org/rfc/rfc8621)) on top of the JMAP core
([RFC 8620](https://www.rfc-editor.org/rfc/rfc8620)), and keeps what IMAP4rev2
([RFC 9051](https://www.rfc-editor.org/rfc/rfc9051)) with CONDSTORE/QRESYNC
([RFC 7162](https://www.rfc-editor.org/rfc/rfc7162)) needs: UIDs per mailbox and modification sequences. Statements
about Stalwart refer to its source as of v0.16.27 (`crates/email`); kernoid takes over its approach to threading,
not its storage layer, which is built on Stalwart's own key-value store.

## 1. Mail is data, not events

RFC 0001 (section 3) keeps identity and administration as events and content as data. Mail is data: a mailbox
receives thousands of emails, flags change constantly, and an append-only log of every `$seen` would grow without
bound and could not forget a deleted email. So:

- **Administration of mail is events** – what an administrator decides about an account: its quota
  (`account.mail_quota_set`), shared mailboxes and who may use whose mail (section 12).
- **The mail itself is tables** in PostgreSQL – mailboxes, emails, threads – changed in ordinary transactions.
- **Content is in object storage**, sealed with the tenant's key like every object (RFC 0001, section 6): the raw
  message as received, one object per email under `tenants/<tenant>/mail/<account>/<email>`.

What PostgreSQL holds of an email is what listing, sorting, threading and (later) search need: addresses, subject,
date, size, a preview, keywords. It is not sealed by kernoid; it is protected like the rest of the database (access,
encryption at rest by the operator). **OPEN:** whether some of it (subject, preview) should be sealed in the
database as well – it would rule out sorting and searching in PostgreSQL.

## 2. Mail accounts

Every account with the service `mail` (RFC 0003, 4) has one mail store, created when it is first used: `mail_accounts` holds its tenant,
the **modification sequence** (`modseq`) and the bytes used. The first use also creates the default mailboxes.

The row also holds the store's **settings**, changed by its owner (`GET`/`PUT /v1/account/mail-settings`) – data,
not events:

- `trash_retention_days`: how long its Trash keeps emails; none means the tenant's days (13.2).
- `default_from`: the address new emails come from in the web app; it must be one the account may send from (10.1).
- `undo_send_seconds`: how long the web app holds what it sends so that it can be taken back (0–30, 0 by default;
  11.1).
- `mailbox_names`: names the account gives the stores it reaches – its own and shared ones – shown instead of their
  addresses; each account names them for itself (`PUT /v1/account/mail-settings/mailbox-names/{account}`).

All changes to an account's mail take its `mail_accounts` row (`FOR UPDATE`) first. Changes to one account are thus
one after another; changes to different accounts do not wait for each other. A delivery to many recipients changes
each account in its own transaction.

## 3. Mailboxes

| Field | Notes |
|---|---|
| `id` | UUIDv7, the JMAP id |
| `parent_id` | another mailbox of the account, or none |
| `name` | 1–255 characters, no control characters and no `/` (the hierarchy separator kernoid's IMAP will use); unique among siblings |
| `role` | `inbox`, `drafts`, `sent`, `archive`, `junk`, `trash` – the names of the IANA registry RFC 8621 uses; each role at most once per account |
| `sort_order` | as in JMAP |
| `is_subscribed` | IMAP subscriptions and JMAP `isSubscribed` |
| `uid_validity`, `uid_next` | IMAP: UIDs of a mailbox only grow; `uid_validity` is set once when the mailbox is created |

- **Default mailboxes:** Inbox, Drafts, Sent, Archive, Junk and Trash with these roles. Clients show them in their own
  language by role.
- A mailbox with the role `inbox` cannot be destroyed – delivery needs it. A mailbox with children cannot be
  destroyed; one with emails only if the caller says what happens to them (JMAP `onDestroyRemoveEmails`): emails in
  no other mailbox are destroyed, the others only leave it.
- Moving a mailbox below itself or one of its descendants is refused.
- Counts (`totalEmails`, `unreadEmails`, `totalThreads`, `unreadThreads`) are computed when asked, not stored.

## 4. Emails

| Field | Notes |
|---|---|
| `id` | UUIDv7, the JMAP id; also names the object with the raw message |
| `thread_id` | set once (JMAP `threadId` is immutable, RFC 8621, 4.1.1) |
| `size` | bytes of the raw message |
| `received_at` | when kernoid received it (or the date an import gives) |
| `sent_at` | the `Date` header, if any |
| `message_id`, `in_reply_to`, `references` | from the headers, for threading and clients |
| `subject`, `from`, `to`, `cc`, `bcc`, `reply_to`, `sender` | parsed with mail-parser; addresses as JSON lists of `{name, email}` |
| `preview` | at most 256 characters of the text, as JMAP `preview` |
| `has_attachment` | |
| `keywords` | JMAP keywords, IMAP flags: `$seen`, `$flagged`, `$answered`, `$draft` and others; lower case, since they are case-insensitive |

An email is in **one or more mailboxes** (`email_mailboxes`, JMAP `mailboxIds`), and has a UID in each – a new UID
whenever it is added to a mailbox, so IMAP clients see a move as expunge plus a new message. An email in no mailbox
does not exist: removing the last one destroys it.

- **Import** (`import_email`) parses the message with [mail-parser](https://crates.io/crates/mail-parser) (Apache-2.0
  OR MIT, by Stalwart Labs), refuses what is too large (`mail.max_message_size`) or over the quota, writes the sealed
  object, then the rows. Delivery and JMAP `Email/import` both go through it.
- **Keywords** follow IMAP's flag syntax ([RFC 9051](https://www.rfc-editor.org/rfc/rfc9051), `atom`): 1–255
  printable ASCII characters without `( ) { ] % * " \` and space.
- **Destroying** an email removes its rows and hands its object to garbage collection (section 7).
- Copying an email to **another account** (JMAP `Email/copy`) imports the raw message again: accounts of different
  tenants have different keys, and an object belongs to one account. **OPEN:** sharing one object between accounts of
  a tenant (a message to many recipients is stored once per recipient).

## 5. Threads

Threading works like Stalwart's (`crates/email/src/message/ingest.rs`): two emails are in one thread if their
**base subjects are the same** – the subject without `Re:`, `Fwd:` and the like, as mail-parser's `thread_name`
gives it – **and they share a message id**: their own `Message-ID`, an `In-Reply-To`, a `References` or a
`Resent-Message-ID`. Each email's ids are kept with a hash of its base subject (`email_thread_refs`); a new email
joins the thread of the earliest email that matches, or starts a new one.

Unlike Stalwart, kernoid does **not merge threads** when a new email matches emails of several: `threadId` would
change, which RFC 8621 does not allow. The email joins the earliest of them. A thread ends when its last email is
destroyed.

## 6. Changes and states

Every change takes the account's next `modseq` and writes one row per changed object to `mail_changes`:
`(account, modseq, type, id, created/updated/destroyed)`, type being `mailbox`, `email` or `thread`.

- **JMAP state strings** are the `modseq` of the last change; `*/changes` reads the journal from a given state: an
  object created and destroyed in between is left out, one created is reported as created even if it changed later.
  A change of an email changes the state of its mailboxes too, since their counts change (RFC 8621, 2).
- **IMAP** uses the same counter: an email's `MODSEQ` in a mailbox is the `modseq` of its last change there
  (`email_mailboxes.modseq`); a mailbox's `HIGHESTMODSEQ` is the account's.
- **Retention:** the worker removes journal rows older than `mail.changes_kept_days` (30). A state older than the
  oldest row kept (`mail_accounts.changes_floor`) gets JMAP's `cannotCalculateChanges` (RFC 8620, 5.2) and
  the client starts over.
- IMAP's `VANISHED` (QRESYNC) needs the UIDs that left a mailbox: `mailbox_expunged` keeps them with their modseq
  for as long as the journal (11.2).

## 7. Content and garbage

Object storage is not transactional. So that an email is never in the database without its object, and no object
stays behind without an email:

1. Before the object is written, a row in `blob_garbage` names it, due in an hour.
2. The object is written.
3. The transaction that adds the email removes that row.

If kernoid stops between 1 and 3, the worker removes the object an hour later. Destroying an email writes the row
with its object due at once, in the transaction that removes the email. The worker (`collect_garbage`, one process
at a time) deletes due objects and their rows. Files use the same table (RFC 0005, 5).

A **held submission** (11.1) works the same way: its message (`submissions/<id>`) is named in `blob_garbage` before
it is written, and the transaction that records the submission takes it back. Taking the submission back or sending
it marks the object due at once, in the transaction that changes its state.

## 8. Quotas

- An account's quota is administration: `account.mail_quota_set` (bytes, or none for the tenant's default), kept in
  `accounts.mail_quota`. A tenant's default quota (`tenant.default_mail_quota_set`, `tenants.default_mail_quota`)
  holds for every account without its own, shared mailboxes included; without either there is no limit.
- What counts is the size of the raw messages, each email once, however many mailboxes it is in. An import that
  would go over the quota is refused (JMAP `overQuota`); destroying emails frees the space.

## 9. Receiving mail (SMTP)

kernoid is the MX of its tenants' domains: an SMTP server ([RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)) that
accepts mail for their addresses and stores it at once. It relays nothing: mail for other domains is refused.

### 9.1 The server

- Its own process role, `smtp`, part of `all`, on `smtp.listen` (port 25). Requests are parsed with
  [smtp-proto](https://crates.io/crates/smtp-proto) (Apache-2.0 OR MIT, by Stalwart Labs); the session follows
  Stalwart's (`crates/smtp/src/inbound`) and is marked as derived from it.
- **Extensions:** `PIPELINING`, `8BITMIME`, `SMTPUTF8`, `SIZE`, `ENHANCEDSTATUSCODES`, `CHUNKING` (`BDAT`) and
  `STARTTLS` when kernoid has certificates (its own, or from ACME – the same as for HTTPS). No `AUTH` on the MX: who
  logs in to send uses submission.
- **Limits:** message size (`mail.max_message_size`), recipients per message (`smtp.max_recipients`, 100), concurrent
  sessions (`smtp.max_connections`), a timeout per command, and at most `smtp.max_received` (50) `Received` headers
  against loops.
- **OPEN:** the PROXY protocol, for a server behind a TCP load balancer – without it, kernoid must see the client's
  address itself, which every check below depends on.
- **Vacation response:** JMAP's `VacationResponse` (RFC 8621, 8) of each account, kept in `vacation_responses`
  (data, changed by the owner): while it is on, delivery runs it after the account's script as a generated Sieve
  `vacation` (RFC 5230) – sieve-rs decides whom to answer, `sieve_vacation_sent` that it is once per sender –, but
  not for junk or what the script discarded.
- **Malware:** when a tenant of a recipient (or the tenant of an SRS bounce) switched on a scanning module
  (`clamav`), the message is checked after `DATA` and before it is accepted: malware is refused with `554 5.7.1`
  (the sending server bounces it, nothing is stored), a scanner that does not answer gives `451` unless it is set to
  let content through. Submission and IMAP `APPEND` check the same way for the sender's tenant; JMAP builds messages
  from uploads, which were checked.

### 9.2 Recipients

`RCPT TO` is answered from the directory, so that nobody gets a bounce later:

- An address of an **account** with the service `mail` (RFC 0003) – also with a subaddress (`alice+news@…`, RFC 0001
  3) – delivers to it; without the service, the address is unknown.
- An address of a **group** delivers to each of its members that has mail: groups are distribution lists (`group.address_added`,
  `group.address_removed`; group addresses are in `addresses` like account addresses, one owner per address in the
  installation).
- Unknown addresses are refused (`550 5.1.1`), and so are deactivated accounts and tenants (`550 5.2.1`) and domains
  kernoid does not serve (`550 5.7.1`, no relaying). An account already at its quota is told to try later
  (`452 4.2.2`).
- **OPEN:** who may write to a group (anyone, the tenant, its members); a catch-all address; recipient checks
  slowed down against address harvesting.

### 9.3 Checks

With [mail-auth](https://crates.io/crates/mail-auth) (Apache-2.0 OR MIT, by Stalwart Labs):

- **iprev** (does the client's address resolve back to a name that resolves to it), **SPF** for `HELO` and `MAIL
  FROM` ([RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)), **DKIM** ([RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)),
  **ARC** ([RFC 8617](https://www.rfc-editor.org/rfc/rfc8617); now historic, still checked for mail through
  mailing lists), **DMARC** ([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)).
- The results go into an `Authentication-Results` header ([RFC 8601](https://www.rfc-editor.org/rfc/rfc8601)) and a
  `Received-SPF` header; any `Authentication-Results` claiming kernoid's host name that arrives with the message is
  not trusted.
- **DMARC `p=reject`** with a failing result is refused (`550 5.7.1`); `p=quarantine` goes to Junk.
- **A basic spam filter** adds up a score from these results and from the message (no `Message-ID`, no `Date`, a
  missing `From`, a sender name that claims a local domain the checks do not support) and files mail at or above
  `smtp.junk_score` in Junk, with an `X-Spam-Status` header. **OPEN:** a learning filter (Bayes) and DNS block
  lists – they are what Stalwart's spam filter has beyond this, partly under its enterprise licence.
- **OPEN:** DKIM2 (an IETF draft), and DMARC aggregate reports (they need sending).

### 9.4 Delivery

- After the data, kernoid adds `Received`, `Authentication-Results` and `Received-SPF` and delivers to every
  recipient before it answers – there is no queue for incoming mail: `250` means stored.
- **Sieve** ([RFC 5228](https://www.rfc-editor.org/rfc/rfc5228)) with sieve-rs
  (by Stalwart Labs; 1.0.2 taken over into `crates/sieve` under AGPL-3.0-only after it left crates.io): an account's active script decides – `keep`, `fileinto` (with `:create`),
  `discard`, flags (`imap4flags`), and `redirect` and `vacation` through the queue (10.6). Scripts are stored per
  account (`sieve_scripts`), checked when saved, at most one active. Managing scripts (ManageSieve, JMAP Sieve) comes
  with the protocols.
- **Duplicates:** a delivery whose `Message-ID` the account received in the last seven days is skipped, as Stalwart
  does. This also makes a retry safe: if a recipient cannot be stored for now (quota, a database error), kernoid
  answers `451` or `452` for the whole message and the sender's server tries again – the recipients that have it
  already skip it.

## 10. Sending mail

### 10.1 Submission

- Accounts send through **submission** ([RFC 6409](https://www.rfc-editor.org/rfc/rfc6409)) on port 587 with
  `STARTTLS` and on port 465 with TLS from the start ([RFC 8314](https://www.rfc-editor.org/rfc/rfc8314)), in the
  same `smtp` role; without certificates kernoid offers no submission. `AUTH` (`PLAIN`, `LOGIN`) only over TLS.
- **Credentials:** an **app password** – made per device, shown once; 120 random bits, so a SHA-256 hash is enough,
  as for tokens (`account.app_password_added`, `account.app_password_removed`; the hash in `account_app_passwords`).
  Resetting an account's second factors removes its app passwords too: the devices are lost. The account's
  own password works only for accounts that need no second factor: a password alone must not get around the second
  factor a login in the browser asks for. Failed attempts count like failed logins (RFC 0001, 7). `OAUTHBEARER`
  (RFC 7628) and `XOAUTH2` take an access token of kernoid with the scope `mail`, of an account with mail – and, if
  the program names a user, that user's.
- **Senders:** `MAIL FROM` and every address in `From` must be addresses of the account, or of an account it may
  send as (12.2), or of a group whose members may send as it (`group.send_as_set`, 9.2). **OPEN:** limits on how much
  an account sends.
- kernoid adds `Received`, and `Message-ID` and `Date` if they are missing, and delivers: to local recipients at
  once, as in 9.4 but without the spam filter; to everyone else through the queue, which signs with DKIM (10.3).

### 10.2 The queue

Outgoing mail waits in PostgreSQL – `outbound_messages` with the sealed message in object storage, and
`outbound_recipients` with each recipient's state – so that any worker can deliver it and nothing is lost when a
process stops.

- A worker takes the recipients of one domain that are due, for a lease of a few minutes (`FOR UPDATE SKIP LOCKED`),
  delivers them in one connection and writes each result.
- **Retries:** after 2, 5, 15 and 30 minutes, then hourly, then every four hours, for `smtp.queue_days` (5). A
  permanent refusal (`5xx`) ends at once.
- **Bounces:** a recipient that fails for good is reported to the sender as a delivery status notification
  ([RFC 3464](https://www.rfc-editor.org/rfc/rfc3464)) in their inbox. Mail with an empty `MAIL FROM` gets no bounce.
  **OPEN:** warnings for mail still waiting after hours.
- **Log:** the worker logs every attempt – delivered, deferred, or failed for good and bounced – with the recipient's domain
  only, never the address.
- **Routes:** the domain's MX records in order of preference, or the domain itself without them; a null MX
  ([RFC 7505](https://www.rfc-editor.org/rfc/rfc7505)) refuses mail for good. With `[smtp.relay]`, all mail for other
  servers goes to that relay instead, over TLS and with `AUTH` – for operators whose network cannot send on port 25.

### 10.3 DKIM

Every verified domain of a tenant gets DKIM keys ([RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)) of two
algorithms, made by the worker and sealed with the main key in `dkim_keys`: RSA with 2048 bits (selectors
`kernoid1`, `kernoid2`, …) and Ed25519 ([RFC 8463](https://www.rfc-editor.org/rfc/rfc8463); `kernoid-ed1`, …).
Mail is signed with every active key of its `From` domain when it leaves the queue – so replies of Sieve and bounces
are signed as well; receivers that do not know Ed25519 ignore that signature and check the RSA one.

A key is `next`, `active` or `retired`; per domain and algorithm one may be active and one next. A domain's first RSA
key is active at once (as before, so a domain signs from the start); every later key – the first Ed25519 key, or
one an administrator asks for (`domains.manage`, REST, GraphQL, CLI) – is `next` until DNS shows its record: the
worker looks every five minutes and, in one transaction, retires the active key of the algorithm and activates the
new one. Mail is never signed with a key whose record is not out. Retired keys stay in the table (the runtime role
cannot delete); their records may go once mail signed with them has arrived. The records to publish – of active and
next keys – are part of the DNS check (10.5). **OPEN:** rotating on a schedule, and removing retired keys.

### 10.4 Transport security

- Without anything published by the receiving domain, kernoid uses `STARTTLS` whenever it is offered and does not
  check the certificate (opportunistic TLS, [RFC 7435](https://www.rfc-editor.org/rfc/rfc7435)); without
  `STARTTLS` it sends in plain text.
- **MTA-STS** ([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)): a domain's policy is fetched over HTTPS (public
  addresses only, like every outbound request) and kept in `mta_sts_policies` for its `max_age`. In `enforce` mode
  kernoid delivers only to MX hosts the policy names, over TLS with a certificate valid for that host.
- **DANE** ([RFC 7672](https://www.rfc-editor.org/rfc/rfc7672)): when the MX host's TLSA records are signed
  (DNSSEC), TLS is required and the certificate must match them; DANE goes before MTA-STS. The lookup of TLSA records
  with DNSSEC and the matching of certificates are taken over from Stalwart
  (`crates/smtp/src/outbound/dane`).
- The relay is always reached over TLS with a valid certificate.
- Every TLS connection – outgoing and incoming, SMTP, IMAP and POP3 alike – prefers a post-quantum key exchange
  (RFC 0006, 2).

### 10.5 DNS checks

For each verified domain, kernoid says what to publish and whether it is published:

| Record | Expected |
|---|---|
| MX | `smtp.hostname` |
| SPF (TXT on the domain) | `v=spf1 mx -all`, or `smtp.spf` if set (for a relay) |
| DKIM (TXT at `<selector>._domainkey.<domain>`) | the public key of each active and next key |
| DMARC (TXT at `_dmarc.<domain>`) | a record (kernoid suggests `v=DMARC1; p=quarantine`) |

The check reads DNS when asked; it changes nothing. **OPEN:** setting the records automatically (a module, see the
1.0 plan), and serving kernoid's own MTA-STS policy.

### 10.6 Sieve that sends

With the queue, the Sieve actions of 9.4 that need sending work: `redirect` sends the message on with the original
sender rewritten by SRS into an address of the account's domain (`SRS0=<hash>=<day>=<domain>=<local>@…`, the hash an
HMAC-SHA256 in base32 with the installation's secret in `srs_secret`, good for 21 days) – so that SPF holds at the
next server and bounces find the original sender: the MX takes such an address only from an empty sender and
sends the bounce on through the queue; an empty sender stays empty. `vacation`
([RFC 5230](https://www.rfc-editor.org/rfc/rfc5230)) answers each sender at most once in `:days` (seven by default)
and never to mailing lists, automatic mail or an empty sender (sieve-rs builds the reply; whom it went to is kept in
`sieve_vacation_sent`). **OPEN:** `reject` and `notify`, and the `duplicate` test (RFC 7352), which sees nothing
as seen before.

## 11. Access protocols

Every protocol logs in the same way as submission (10.1): an app password, or the account's password if it needs
no second factor; IMAP and submission also take an access token with the scope `mail` (`OAUTHBEARER`, `XOAUTH2`),
JMAP also takes a kernoid session. Programs over HTTP (JMAP, and CalDAV, CardDAV and WebDAV, RFC 0004 and 0005) may
also log in with a username or a verified contact address where the tenant allows them (RFC 0003); IMAP, POP3 and
submission take addresses only. Without a login, JMAP and DAV answer `401` with a `Basic` challenge, so that
programs ask for an address and an app password – but a request from a page's script (`Sec-Fetch-Mode` other than
`navigate`, or the header `kernoid-csrf`) gets a `Bearer` challenge, so that the browser does not open its own login
box. **OPEN:** JMAP with kernoid's OpenID Connect tokens. Each protocol sees the account's own mail store and the
stores shared with it (section 12).

### 11.1 JMAP

[RFC 8620](https://www.rfc-editor.org/rfc/rfc8620) and [RFC 8621](https://www.rfc-editor.org/rfc/rfc8621), at
`/.well-known/jmap` of every instance host, in `kernoid-jmap` – kernoid's own code on `serde_json`.

- **Capabilities** for mail: core, mail, submission, vacationresponse, websocket, blob
  ([RFC 9404](https://www.rfc-editor.org/rfc/rfc9404)) and principals ([RFC 9670](https://www.rfc-editor.org/rfc/rfc9670));
  calendars, contacts and files are in RFC 0004 and 0005. Methods: `Core/echo`; `Mailbox/get`, `/changes`, `/query`,
  `/queryChanges`, `/set`; `Email/get`, `/changes`, `/query`, `/queryChanges`, `/set`, `/import`, `/parse`;
  `Thread/get`, `/changes`; `Identity/get`, `/changes`; `EmailSubmission/set`, `/get`; `SearchSnippet/get`;
  `VacationResponse/get`, `/set`; `Blob/upload`, `/get`, `/lookup`; `Principal/get`, `/query`. Result references
  (`#…`) follow RFC 8620, 3.7.
- **States** are the account's modification sequence (section 6), one for all types. `*/queryChanges` and
  `Identity/changes` answer `cannotCalculateChanges`; clients query or get again.
- **Queries** filter and sort the account's emails in kernoid; text in messages is found through the index of
  13.1. **OPEN:** moving the whole query into SQL for very large mailboxes.
- **Blobs:** an email's blob is its raw message; each body part has a blob of its own. Uploads stay a day
  (`jmap_uploads`, in object storage like everything else).
- **Identities** are the account's addresses, with its display name, and in the account's own store also the
  addresses of groups whose members may send as them (`group.send_as_set`, 10.1), with the group's name. They cannot
  be changed yet (**OPEN**).
- **EmailSubmission** sends a stored email with the checks of 10.1: to local recipients at once, to everyone else
  through the queue. Each submission is a row in `email_submissions` with its `send_at` and `undo_status`.
- **Held submissions** (since 0.2; RFC 8621, 7): a submission with `HOLDFOR` or `HOLDUNTIL`
  ([RFC 4865](https://www.rfc-editor.org/rfc/rfc4865), `FUTURERELEASE` in `submissionExtensions`) is held for at most
  60 seconds (`maxDelayedSend`). It is checked at once, its message is kept sealed in object storage
  (`submissions/<id>`, section 7), and it is `pending` until `send_at` – nothing is delivered or queued. Until then
  the owner may set `undoStatus` to `canceled`; then it is `canceled` and the message is garbage. The worker sends
  due submissions (every two seconds, `FOR UPDATE SKIP LOCKED`, so no submission goes out twice) and sets them
  `final`; one sent at once is `final` from the start. The account's `undo_send_seconds` (0–30, section 2) is the web
  app's setting: how long it holds what it sends, offering to take it back; JMAP itself allows up to 60 seconds.
- **Push:** an EventSource stream (`/jmap/eventsource`) sends a `StateChange` whenever the account's state moves; so
  does JMAP over WebSocket ([RFC 8887](https://www.rfc-editor.org/rfc/rfc8887), `/jmap/ws`, since 0.2), which also
  carries requests. Every change to an account's mail notifies PostgreSQL's channel `kernoid_mail` (`NOTIFY`) in its
  transaction, so that any process serving the stream hears of it – no further service. **OPEN:** push
  subscriptions to a URL (`PushSubscription`, RFC 8620, 7.2) – designed in RFC 0007.
- **VacationResponse** (RFC 8621, 8, since 0.2) reads and changes the account's vacation response (9.1).
- **Original view:** `/jmap/view/{account}/{blob}` serves an HTML email as its sender laid it out, as a page of its
  own in a sandbox – its styles and embedded images, no scripts, no forms, nothing loaded from elsewhere.

### 11.2 IMAP

IMAP4rev2 ([RFC 9051](https://www.rfc-editor.org/rfc/rfc9051)) and, since many programs still speak only that,
IMAP4rev1 ([RFC 3501](https://www.rfc-editor.org/rfc/rfc3501)), on port 143 with `STARTTLS` and 993 with TLS, in
the process role `imap` (part of `all`) when `[imap]` is configured, in `kernoid-imap`. Login only over TLS
(`LOGIN`, `AUTHENTICATE PLAIN`); without certificates there is no IMAP.

- The parser of requests and the writer of responses are taken over from Stalwart (`crates/imap-proto`), and so is
  what `FETCH` reads from a message (`ENVELOPE`, `BODYSTRUCTURE`, sections; from `crates/imap/src/op/fetch.rs`); the
  server is kernoid's own, on the mail store.
- **Extensions:** `IDLE`, `MOVE`, `UIDPLUS`, `CONDSTORE`, `QRESYNC`, `ENABLE`, `NAMESPACE`, `SPECIAL-USE`,
  `LIST-EXTENDED`, `LIST-STATUS`, `ESEARCH`, `SEARCHRES`, `WITHIN`, `BINARY`, `MULTIAPPEND`, `LITERAL+`, `SASL-IR`,
  `UTF8=ACCEPT`, `ID`, `UNSELECT`, `STATUS=SIZE`, `CHILDREN`, `ACL` and `RIGHTS=` (12.2), `SORT`, `SORT=DISPLAY`,
  `THREAD`, `QUOTA` and `QUOTA=RES-STORAGE`. Before login: `AUTH=PLAIN`, `AUTH=OAUTHBEARER` and `AUTH=XOAUTH2` over
  TLS, `STARTTLS` and `LOGINDISABLED` without.
- **Mailboxes:** the hierarchy separator is `/`; a mailbox's name is its path in the tree, and the inbox is `INBOX`
  wherever JMAP put it. `CREATE` makes missing parents; `DELETE` removes the emails of the mailbox (an email in no
  other mailbox is destroyed) and refuses a mailbox with children.
- **Flags** are the JMAP keywords: `\Seen` is `$seen`, `\Flagged` `$flagged`, `\Answered` `$answered`, `\Draft`
  `$draft`, and `\Deleted` is kept as `$deleted` until `EXPUNGE` removes the email from the mailbox (and destroys it
  if it is in no other). `\Recent` is never set.
- **UIDs** are those of section 3; `MODSEQ` is the modification sequence of the email in the mailbox,
  `HIGHESTMODSEQ` the account's state (section 6), `VANISHED` reads `mailbox_expunged`.
- `IDLE` waits for the same notifications as JMAP's push; a session that says nothing for `imap.timeout_seconds`
  (30 minutes) is logged out.
- `SEARCH` evaluates its criteria in kernoid on the selected mailbox, text through the index of 13.1; only `HEADER`
  reads the messages.
- `SORT` (also `SORT=DISPLAY`) and `THREAD` (RFC 5256) on the summaries: `REFERENCES` gives kernoid's threads
  (5), each oldest first as one chain; `ORDEREDSUBJECT` groups by base subject. `QUOTA` (RFC 9208): one root, `""`,
  for all of the account's mailboxes, `STORAGE` in KiB – none without a quota.
- **OPEN:** `COMPRESS`, `OBJECTID`, `PREVIEW`; renaming `INBOX` (RFC 9051 moves its
  messages into the new mailbox).

### 11.3 POP3

[RFC 1939](https://www.rfc-editor.org/rfc/rfc1939) with `CAPA`, `STLS` and `SASL PLAIN`
([RFC 5034](https://www.rfc-editor.org/rfc/rfc5034)), on port 110 and 995 when `imap.pop3_listen` or
`imap.pop3_tls_listen` is set (off by default), in the `imap` role: the inbox only, as it was at login. `UIDL` is the
email's id; `DELE`d messages leave the inbox at `QUIT` (an email in no other mailbox is destroyed).

## 12. Sharing and administration

### 12.1 Shared mailboxes

A **shared mailbox** (`info@`, `support@`) is an account of the kind `shared`: it has addresses, a mail store, a
quota and Sieve scripts like any account, but nobody logs in as it – it has no password, app passwords, second
factors or links to identity providers, and every way of logging in refuses it. People reach it through access
granted to them (12.2). Administrators make it (`account.shared_added`, kept in `accounts.kind`); renaming,
addresses, deactivating and quotas are those of accounts.

### 12.2 Access

Who may use whose mail is administration, so it is events on the owning account (`account.mail_access_set`,
`account.mail_access_removed`), projected into `mail_access`. A grant names

- the **grantee**: an account or a group of the same tenant – a group's members get the access while they are
  members;
- the **scope**: the whole store, or one mailbox of it (not its children);
- the **rights**, as IMAP ACL rights ([RFC 4314](https://www.rfc-editor.org/rfc/rfc4314)): `l` see the mailbox,
  `r` read, `s` keep `\Seen`, `w` other keywords, `i` add emails, `p` post (unused), `k` create mailboxes in it, `x`
  delete or rename it, `t` delete emails (`\Deleted`), `e` expunge, `a` change the access;
- **send as**, for the whole store only: the grantee may send from the owner's addresses (submission, JMAP
  `EmailSubmission`).

A user's rights on a mailbox are the union of the grants for the whole store and for that mailbox, to them and to
their groups; the owner has every right. JMAP's `myRights` follow from them (`mayReadItems` = `r`, `mayAddItems` =
`i`, `mayRemoveItems` = `t` and `e`, `maySetSeen` = `s`, `maySetKeywords` = `w`, `mayCreateChild` = `k`,
`mayRename` and `mayDelete` = `x`, `mayAdmin` = `a`, `maySubmit` = send as).

Who may grant: an administrator with `accounts.manage`, for any account of the tenant; the owner, for its own store
(sharing its mailboxes with colleagues); and a user with `a` on a mailbox, for that mailbox. Only administrators
grant on shared mailboxes' stores as a whole, and only they grant send as. A grant on a mailbox that is later
destroyed stays without effect until it is removed.

How the protocols show it:

- **JMAP:** the session lists every store the user may use besides its own (`isPersonal: false`, `isReadOnly` when
  no right allows a change), with `urn:ietf:params:jmap:submission` when it may send as the owner. Methods check
  the rights per mailbox: a user sees only mailboxes with `l` and emails in a mailbox with `r`. The owner shares single
  mailboxes with `shareWith` ([RFC 9670](https://www.rfc-editor.org/rfc/rfc9670), 4): principal id → MailboxRights
  with `mayShare` (`a`), shown only to who may share. **OPEN:** `*/changes` of a store shared only in part name
  emails the user cannot read (they answer `notFound`); `ShareNotification`; sharing by others than the owner.
- **IMAP:** stores shared with the user are in the shared namespace `Shared/<address of the owner>/…`; `ACL`
  ([RFC 4314](https://www.rfc-editor.org/rfc/rfc4314)) shows and changes grants per mailbox (`MYRIGHTS`, `GETACL`,
  `LISTRIGHTS`, `SETACL`, `DELETEACL`); identifiers are addresses of accounts and `$<group name>` for groups. The
  rights of a whole-store grant appear on each mailbox; `SETACL` changes only the grant on that mailbox. Shared
  mailboxes carry no special use (a client must not take another's `Sent` for its own) and are always subscribed;
  `COPY` and `MOVE` between stores store the message anew. **OPEN:** subscriptions of one's own to shared mailboxes.
- **Submission** accepts an owner's addresses in `MAIL FROM` and `From` from a grantee with send as.

### 12.3 Administration API

Everything the CLI does with mail is also in the administration API (REST and GraphQL, RFC 0001), with the
permissions of RFC 0001: `accounts.manage` for an account's mail (quota, mailboxes, Sieve scripts, access, importing
messages) and for shared mailboxes; `tenant.manage` for the tenant's default quota; `instance.read` for the queue of
outgoing mail. Users see and change their own: the stores shared with them, and the access to their own store.

## 13. Search, retention, import and export

### 13.1 Search

Searching message text uses PostgreSQL's full-text search – no further service (RFC 0001).

- Each email has `body_search`, a `tsvector` of its text parts (HTML as text) and the names of its attachments, at
  most 512 KiB of text, made at import with the configuration `simple`: words lower case, no stemming, the same for
  every language. **OPEN:** language-specific configurations (stemming) chosen per tenant.
- The vector holds the words of the text, not the text; like the summary (section 1), it is protected like the
  rest of the database, not sealed by kernoid.
- Emails stored before the index existed get theirs from the worker (`index_mail`, one process at a time, in
  batches); until then they are not found by their text.
- A search for text matches whole words and word beginnings (`lunc` finds *lunch*), every word of the query.
  JMAP's `body` and IMAP's `BODY` use the index; JMAP's `text` and IMAP's `TEXT` also look at subject and
  addresses; `from`, `to`, `cc`, `bcc` and `subject` look at the summary in PostgreSQL. IMAP's `HEADER` still reads
  the messages. **OPEN:** IMAP's substring semantics for text (RFC 9051 matches substrings; the index matches words).
- `SearchSnippet/get` marks the words found in subject and preview.

### 13.2 Retention

A tenant may have emails in its accounts' Trash and Junk removed after some days (`tenant.mail_retention_set`, per
role; none by default). Since 0.2 an account may set its own days for its Trash (`trash_retention_days`, section
2); they go before the tenant's. The days count from when an email entered the mailbox (`email_mailboxes.added_at`).
The worker (`apply_retention`, one process at a time) removes such emails from the mailbox; an email in no other
mailbox is destroyed. **OPEN:** retention for other mailboxes, per account for Junk, and holding mail against removal
(legal hold).

### 13.3 Import and export

A mailbox is exported and imported as **mbox** (mboxrd: lines starting with `From ` quoted with `>`), the format
mail programs and other servers read and write.

- The `From ` line carries the sender and when the email was received; an import sets the received time from it.
- Keywords travel in headers kernoid adds at export and reads (and removes) at import: `Status: RO` for `$seen`,
  `X-Status` with `A` (`$answered`), `F` (`$flagged`), `T` (`$draft`) and `D` (`$deleted`), and `X-Keywords` for
  the others – as Dovecot and Thunderbird do.
- Operators export and import with the CLI (a whole account as one mbox file per mailbox); administrators with the
  API (`accounts.manage`), one mailbox at a time. Users have their mail through IMAP and JMAP.
- Moving whole accounts from other providers (IMAP, Microsoft 365, Google) is the migration module of 1.0, not this.

## 14. Open

- **OPEN:** encryption of emails at rest with a key of the account (S/MIME, OpenPGP) – Stalwart offers it; not before
  1.0.
