<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Changelog

What changes from release to release, for those who run kernoid and those who build on it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org) –
before 1.0, a minor version (0.2) may change the API and the configuration, and says how to upgrade here.

## [Unreleased]

### Added

- **Relay quota** per tenant (`tenant.relay_quota_set`, migration 0055): REST `/v1/relay/quota`, GraphQL `relayQuota`
  and `setRelayQuota`, `kernoid relay quota`; an envelope beyond it is refused.
- **Mail without the service mail:** `[mail.notification_relay]` sends kernoid's own messages (registration codes)
  through the operator's relay where kernoid keeps no mail – identity alone can register people by email. The SMTP
  client is a crate of its own (`kernoid-smtp-client`).
- **Services per tenant** (RFC 0008, 4; `tenant.service_switched`, migration 0056): the operator switches mail,
  calendars, files or the relay off for one tenant – REST `/v1/tenant/services`, GraphQL `tenantServices` and
  `setTenantService`, `kernoid tenant service`. Its accounts no longer see it; nothing is removed.
- **A built-in identity taken over** by a kernoid of its own: the steps in "Building on kernoid", checked by
  `scripts/profile-check.sh` (RFC 0009, 7).
- **Strings per feature package:** `kernoid_mail`, `_calendar`, `_contacts` and `_files` keep their own (`l.mailText.…`);
  `kernoid_l10n` only those they share. Features of other programs give the shell their delegates
  (`KFeature.localizationsDelegates`).
- **Post-quantum hybrid keys** for the foundation (`kernoid_crypt::pq`, RFC 0010, 6): X-Wing (ML-KEM-768 + X25519)
  to seal to, Ed25519 + ML-DSA-65 to sign, both from one seed; X-Wing checked against the draft's test vectors.
- **Streams** (RFC 0012): spaces as many logs joined by a tree of hybrid post-quantum keys – `kernoid_crypt::stream`
  (roster, person keys, stream keys per generation, records, read and write tokens), the relay's protocol 2 below
  `/relay/<scheme>/v2/` (migration 0057), `kernoid_space_store::streams` (schema version 2) and
  `kernoid_replica::streams::Streams` (found, invite, join, follow, write, share, renew when due, originals in parts,
  remove devices and persons, recover, purge). Protocol 1 stays beside it.
- **Vaults on spaces** (RFC 0010, 5): a new vault is a space of the relay's protocol 2, kept end to end through streams
  – `kernoid_client::e2e::Vaults` (make, enter with the account's recovery code of it, directories and files as streams,
  move, rename, versions, trash, share, remove members, move an OpenPGP vault onto a space). The file store keeps only
  its directory, naming the space (`kernoid:space`, migration 0058); destroyed, the worker removes the space. The JMAP
  session names the relay (`https://kernoid.dev/jmap/space-vaults`). The replica adds persons with a recovery code
  (`Streams::add_person`) and links a stream below another (`link_below`).
- **Vaults on spaces in the web app:** the crate `kernoid-vault` (MIT) holds the vaults' model for the SDK and, as
  WebAssembly (`@kernoid/vault`, `kit/vault/scripts/build-wasm.sh`), for the web app – in a worker, SQLite in memory
  kept in IndexedDB. New vaults are made there, OpenPGP vaults can be moved onto a space, sharing makes members. The
  replica reaches relays through a `Transport` (ureq natively, feature `native`), the store can be kept as bytes
  (`kernoid-space-store`, feature `serialize`), and the relay takes the web app's session cookie of a founder.
- **Vaults on spaces everywhere:** the file sync keeps them in step (`Folder::sync_all`; state version 2), the terminal
  app opens them (folders, saving decrypted, uploads, new folders, renaming, deleting into the vault's trash), and
  every app renames them. Sharing follows the level of each share (`kernoid_vault::set_members`: read, edit, full) –
  a member at another level comes in again with a new code, their devices forget the vault and come in by themselves
  (`Streams::forget`). A device without `write` makes its own person's stream at the relay.

### Changed

- **The relay follows files:** `[services] relay` is on wherever files are unless set – vaults live there. An account
  that founds a space on an open relay is recorded as its founder.
- **The replica talks TLS with rustls on AWS-LC**, post-quantum key exchange preferred and the system's trust store –
  no longer ring and webpki-roots.
- **kernoid-auth:** sessions in PostgreSQL (`PgSessions`, feature `postgres`, on by default) – a table in the program's
  database with migrations of their own; ids stored only as hashes.

## [0.5.0] – DATE

kernoid becomes the core of a suite of building blocks ([RFC 0008](rfcs/0008-suite-and-building-blocks.md)–0011): an
installation runs only the services it wants, down to identity alone or a relay alone; other programs log in with
kernoid or build its identity in; the foundation of end-to-end encrypted spaces – aktujo's core – is kernoid's, with a
relay; and the parts apps use are one kit under MIT, Flutter packages included. Upgrade by pulling the image
`ghcr.io/kernoid/kernoid:0.5.0` (the Helm chart and the crates follow the version): migrations 0052 to 0054 add tables
and a function, and installations that keep mail, calendars and files change nothing in their configuration. The web
SDK, login UI and web app are AGPL now (below). Apps on the kit take its crates 0.5.0; kernoid's app takes the kit's
Flutter packages from this release.

### Added

- **Services** (`[services]`: `mail`, `calendars`, `files`, all on by default): a service that is off serves no routes
  (JMAP's capabilities, REST and GraphQL operations, CalDAV/CardDAV, WebDAV, mail programs' autoconfiguration, the
  Web Key Directory), runs no background work and is hidden in the web app; `[smtp]` and `[imap]` need `mail`.
  Calendars and contacts may run without mail. `GET /v1/services` says what an installation runs.
- **Identity alone without object storage:** `[blob] kind = "database"` keeps objects – pictures of accounts – in
  PostgreSQL (`blob_objects`, sealed like every object, up to 4 MiB each), for installations without mail and files.
- **kernoid-auth** (AGPL, on crates.io): other programs' servers log in with kernoid – or any OpenID provider – with
  PKCE, keep sessions of their own, check access tokens and take back-channel logout; routes and an extractor for axum
  ([Building on kernoid](https://kernoid.dev/building-on-kernoid/)). The client of external identity providers kernoid
  uses for its tenants is the same code now.
- **kernoid built in:** `kernoid_server::embedded` starts kernoid's identity in another program's process; the
  program's routes join kernoid's, `Session` says who is logged in. `kernoid-server` has the features `mail`,
  `calendars` and `files` (on by default) – without them, nothing of those is compiled in. `database.schema` puts
  kernoid's tables into a schema of their own (migration 0053 grants its use).
- **The foundation** ([RFC 0010](rfcs/0010-foundation.md)): aktujo's core – originals by their hash, the event log of a
  space, the keys of its members, a device's spaces in SQLite, the replica – as `kernoid-base`, `-blob`, `-log`,
  `-crypt`, `-space-store` and `-replica` in the kit (MIT, on crates.io), for kernoid, aktujo, notenwart and spezado.
- **The relay** (`[services] relay = true`, migration 0054): kernoid keeps end-to-end encrypted spaces below
  `/relay/<program>/v1/` – it checks signatures and member lists, never content; envelopes larger than 64 KiB go to
  object storage. Spaces are founded by accounts (their token in `kernoid-session`) or, on a relay open for a tenant
  (`relay.open_for_tenant`), by anyone; `relay.domains` names the programs. A tenant's spaces in REST
  (`/v1/relay/spaces`), GraphQL and the CLI (`kernoid relay`).
- The claim `urn:kernoid:tenant` – the account's tenant – in ID tokens, JWT access tokens and userinfo answers.
- **The app kit** ([RFC 0011](rfcs/0011-app-kit.md)): kernoid's apps as Flutter packages in `kit/flutter/` (MIT) –
  `kernoid_shell` (the frame, `KFeature`, `runKernoidApp`), `kernoid_mail`, `kernoid_calendar`, `kernoid_contacts`,
  `kernoid_files`, `kernoid_ui`, `kernoid_l10n` and `kernoid_bridge` (the Rust side, on the kit's SDK by path). An app
  shows the features its server offers. kernoid/apps is the app around them.
- RFCs 0008 (the suite: building blocks, services, licences), 0009 (kernoid's identity in other servers), 0010 (the
  foundation of end-to-end encrypted spaces) and 0011 (the app kit).

### Changed

- **The kit:** the Rust SDK, kernoid-e2e and kernoid-sync move from `apps/` to `kit/`, one Cargo workspace under MIT
  with one lock file; CI checks that nothing in it is under another licence or reaches a server crate. The terminal
  app moves to `tui/`.
- **Licence:** the web SDK, the login UI and the web app (`web/`) are AGPL-3.0-or-later now, like the server – no app
  under MIT uses them (RFC 0008, 6). A web app under another licence logs in with any OpenID Connect library.
- **JMAP:** an account's mail and its calendars and contacts are separate in the session (`Caller::calendars`), so
  that each follows its service.

## [0.4.0] – 2026-11-19

Dates and times move from chrono, which is no longer maintained, to Jiff 1.0. No migration and no change to the
configuration; times in the APIs stay RFC 3339 and change only in how UTC is written (below). Upgrade by pulling the
image `ghcr.io/kernoid/kernoid:0.4.0` (the Helm chart and the crates follow the version). The Rust SDK changes its API –
hence 0.4 –: apps that use it take kernoid-client and kernoid-sync 0.4.0 and Jiff's types.

### Changed

- Dates and times with [Jiff](https://github.com/BurntSushi/jiff) 1.0 in place of chrono and chrono-tz, which are no
  longer maintained (RUSTSEC-2026-0543, RUSTSEC-2026-0555) – in the server, the Rust SDK, kernoid-sync and the terminal
  app. Times in the APIs stay RFC 3339 in UTC; where one was written with `+00:00` (GraphQL's `DateTime`, SCIM's
  `meta.lastModified`), it is now written with `Z`.
- **Rust SDK, breaking:** `calendars::Event::starts` and `ends`, and the window of `calendars::instances`, are
  `jiff::Timestamp`; `calendars::EventForm` (`start`, `end`, `was`) and `mail::Vacation` (`from`, `until`) hold
  `jiff::civil::DateTime` – before, chrono's types. Apps on the SDK change with it.

## [0.3.1] – 2026-11-14

A security fix for kernoid-sync, and Stalwart's Sieve interpreter and libraries taken over from its v1.1.0 with the
mail parser they need. No migration and no change to the configuration; the API changes only where noted below
(`hasAttachment`, IMAP `BINARY`). Upgrade by pulling the image `ghcr.io/kernoid/kernoid:0.3.1` (the Helm chart and
the crates follow the version); apps that use the Rust SDK should take kernoid-sync 0.3.1.

### Changed

- Stalwart's Sieve interpreter, calcard and jmap-tools taken over again, now from Stalwart v1.1.0 (before: sieve-rs
  1.0.2 from crates.io, calcard and jmap-tools 1.0.1), and the server reads mail with mail-parser 1.0 and writes it
  with mail-builder 2.0. mail-parser 1.0 is a rewrite with fixes kernoid sees: MIME boundaries are no longer matched
  inside a line (which cut body parts short), inline images of `multipart/related` are no longer binary attachments,
  and header names with whitespace inside are no longer read as the known field – kernoid now sees the same From and
  Subject as DKIM and DMARC do.
- `hasAttachment` (JMAP, and the summary kept of new mail) follows RFC 8621: inline media shown in the body no longer
  count as attachments. The summary of mail stored before keeps its value.
- IMAP `BINARY[…]` returns a text part without its transfer encoding, in its own charset, as RFC 3516 defines it;
  before, text came converted to UTF-8.
- `BODY[HEADER.FIELDS …]` and `headers` (JMAP) give header names as the message spells them.

### Security

- kernoid-sync builds SQLite 3.54.1 (rusqlite 0.41.1, libsqlite3-sys 0.39.1) instead of 3.53.2, which could return
  uninitialised memory when it opened a database with a crafted `-wal` file beside it (RUSTSEC-2026-0459,
  CVE-2026-119375). kernoid-sync opens only its own state database, kept outside the synced folder.

## [0.3.0] – 2026-11-04

The file sync of kernoid's apps grows up: `kernoid-sync` keeps moves as moves, goes on with transfers that broke off,
keeps vaults in step and knows the file systems' rules for names – the apps keep folders of a computer in step with it
and bring the stores into Finder, Android's Files and Explorer. The server is unchanged but for the web app, which no
longer shows a vault's encrypted size – no migration, no change to the API or the configuration; upgrade by pulling the
image `ghcr.io/kernoid/kernoid:0.3.0` (the Helm chart and the crates follow the version). For those who build on the
Rust SDK: new public fields of `kernoid_sync::Report` and `plan::Remote`/`Local`, and kernoid-sync's state database is
upgraded when it is opened.

### Added

- kernoid-sync keeps moves as moves – on the server (a node's id at another path) and in the folder (a file's inode
  at another path) –, goes on with downloads that broke off (HTTP ranges) and sends files over 8 MiB in pieces joined
  on the server (`Blob/upload`), not sending again the pieces already there; keeps vaults in step with the account's
  key (`Folder::sync_with`) and leaves a vault whose key is not at hand as it is; and leaves out names the folder's
  file system cannot hold (`Names`: Windows' rules, names that differ only in case). Its state database is upgraded on
  opening, and is shared behind a lock, so that a round runs on any thread of a runtime (an app's). New public fields of
  `Report` (`moved`, `locked`) and of `plan::Remote`/`Local` (`vault`, `file`).
- The Rust SDK: `Client::download_from` (from a byte on, an HTTP range) and `Client::join` (uploads joined into one
  blob, RFC 9404); for vaults `E2e::open_name`, `name_in`, `seal_content`, `open_content`, `move_in` and
  `make_directory_in` (which returns the new directory's id).

### Fixed

- The web app showed the size of a vault's encrypted content as the file's size; it shows none there now.

## [0.2.3] – 2026-11-04

A patch release for kernoid's apps: the Rust SDK opens vaults, so the apps read and write end-to-end encrypted folders
as the web app does. The server is unchanged – no migration, no change to the API or the configuration; the image
`ghcr.io/kernoid/kernoid:0.2.3` follows the version, as do the Helm chart and the crates.

### Added

- The Rust SDK opens vaults (RFC 0006, 6) as the web app does: `E2e::create_vault`, `create_directory_in`,
  `upload_into` (encrypted to the vault's key, signed with the account's), `download_from`/`save_from` (decrypted
  here), `rename_in`, `open_names` (real names where the vault's key is at hand, `FileNode::locked` elsewhere) and
  `give_vault_keys` after sharing; `FileNode` carries `vault`, `vault_key` and `encrypted_name`, and `Policy` the
  tenant's rule for `vaults`. New public fields of `FileNode` and `Policy`: code that builds them field by field needs
  the new ones.

## [0.2.2] – 2026-10-31

A patch release for kernoid's apps: the Rust SDK manages mail folders, and the apps' login now changes the account's
name, picture, language and mail settings without a browser. No migration and no change to the configuration; the API
only accepts more (the apps' access token on four settings) – upgrade by pulling the image
`ghcr.io/kernoid/kernoid:0.2.2` (the Helm chart and the crates follow the version).

### Added

- The Rust SDK manages mail folders: `mail::create_mailbox`, `rename_mailbox`, `move_mailbox`, `destroy_mailbox`
  (with or without its emails) and `empty_mailbox`.
- kernoid's apps change the account's everyday settings themselves: an access token with the scope `urn:kernoid:data`
  now also reaches its name, picture, language and mail settings (`PATCH /v1/account`, `/v1/account/avatar`,
  `/v1/account/language`, `/v1/account/mail-settings`, `/v1/avatars`) – never the password, second factors, passkeys,
  app passwords or sessions, and app passwords none of them (RFC 0001). The Rust SDK has them in `account`.

## [0.2.1] – 2026-10-31

A patch release, chiefly for the Rust SDK: kernoid's apps forward the attachments of end-to-end encrypted mail with
it. Two libraries of Stalwart Labs left crates.io for Stalwart's repository; kernoid now carries them itself. No
migration, no change to the API or the configuration – upgrade by pulling the image `ghcr.io/kernoid/kernoid:0.2.1`
(the Helm chart and the crates follow the version).

### Added

- The Rust SDK forwards the attachments of an end-to-end encrypted email: `Email::decrypted_attachments` holds them in
  memory, `E2e::send_with`/`keep_with` put them inside the encrypted message, and `mail::attach_bytes` uploads one for
  a message that does not go encrypted – never written to disk decrypted.

### Changed

- calcard, the library for iCalendar, vCard, JSCalendar and JSContact, moved into Stalwart's repository after 0.3.14;
  kernoid takes over its v1.0.1 (`crates/calcard`, `crates/jmap-tools`, `AGPL-3.0-only`). Recurrences with a start in
  UTC keep their time without a workaround, and `CONFERENCE` is written with `VALUE=URI` (RFC 7986).
- sieve-rs, the Sieve interpreter, was withdrawn from crates.io when it moved into Stalwart's repository; kernoid
  takes over the 1.0.2 it used (`crates/sieve`, `AGPL-3.0-only`), unchanged.

## [0.2.0] – 2026-10-30

The core completed, still a pre-release. Files gain public links and drop boxes, uploads in pieces, versions shared
across stores and search in their content; mail gains SRS, sending as a group, IMAP `SORT`/`THREAD`/`QUOTA`, OAuth for
mail programs and the vacation response; kernoid answers LDAP for older software. End-to-end encryption (RFC 0006)
comes to mail, vaults and encrypted calendars and address books – in the web app and the terminal app –, with
post-quantum keys and TLS. The first modules: virus scanning (ClamAV) and video calls (Jitsi). Kubernetes gets an
operator with a Helm chart, and the image runs on `linux/arm64` too. The Rust SDK `kernoid-client`, `kernoid-sync` and
`kernoid-e2e` are on crates.io (MIT), and kernoid's apps (`kernoid/apps`, MIT) release their 0.2.0 with it.

### Added

- kernoid's own apps sign in with OpenID Connect: every instance has a client for them built in (migration 0051,
  `kernoid_apps_client_id` in the discovery document), usable by every account of the instance; access tokens with the
  new scope `urn:kernoid:data` reach JMAP, CalDAV, CardDAV and WebDAV. Loopback redirect URIs match on any port
  (RFC 8252, 7.3). The Rust SDK logs in with it (`kernoid_client::oidc`) – and keeps a login for a restart
  (`Saved`, the refresh token only) and revokes it (RFC 7009).
- The audit log: the events of the tenant or the instance, newest first and for one object – `GET /v1/audit`,
  GraphQL `auditLog`, and a page in the web app's administration (with an account's history).
- An account's addresses – the primary one and its aliases: `GET /v1/accounts/{id}/addresses`, GraphQL
  `accountAddresses`, listed in the administration with "make primary" and "remove".
- Programs over HTTP – JMAP, WebDAV, CalDAV and CardDAV – log in with a username or verified contact address too,
  where the tenant allows them, as at the login page; IMAP, POP3 and SMTP still take addresses only (usernames are
  unique per instance, and those protocols do not name one).
- Sending as a group: a group may let its members send from its addresses (`PUT /v1/groups/{id}/send-as`, GraphQL
  `setGroupSendAs`, a switch in the administration); they appear among the members' JMAP identities, and submission
  accepts them.
- SRS for forwarded mail: a Sieve `redirect` keeps the original sender, rewritten into an address of the account's
  domain; bounces to it go on to the original sender (migration 0035, the secret in `srs_secret`). Before, the
  forwarding account was the sender and bounces ended with it.
- IMAP `SORT` (with `SORT=DISPLAY`), `THREAD` (`REFERENCES`, `ORDEREDSUBJECT`) and `QUOTA` (`GETQUOTAROOT`,
  `GETQUOTA`).
- `OAUTHBEARER` and `XOAUTH2` for IMAP and SMTP submission: an access token of kernoid with the new scope `mail`
  (shown at consent as "Read and send your email") logs a mail program in.
- JMAP over WebSocket (RFC 8887) at `/jmap/ws`: requests and push on one connection.
- Mailboxes shared with JMAP's `shareWith` (RFC 9670) by their owner; `myRights` says `mayShare`.
- DKIM with Ed25519 (RFC 8463) beside RSA, and changing keys: a new key (`kernoid tenant dkim-rotate`,
  `POST /v1/tenant/domains/{domain}/dkim-rotate`, GraphQL `rotateDkimKey`, the administration's domains page) signs
  once DNS shows its record, and the old one stops (migration 0036). Existing domains get an Ed25519 key that signs
  once its record (`kernoid-ed1._domainkey`, shown by the DNS check) is published.
- Changing kernoid's SAML key: a new key is in the metadata beside the old one and signs once activated
  (`kernoid saml-key`, `/v1/instance/saml-keys`, GraphQL `samlKeys`/`addSamlKey`/`activateSamlKey`, the
  administration's signing keys page; migration 0037).
- Links to files and folders for people without an account, with expiry and password: made in the web app or with
  kernoid's JMAP extension `FileLink/*`, opened at `/app/link.html#<token>` (`/v1/links/…`; migration 0038).
- JMAP Blob Management (RFC 9404): `Blob/upload` joins uploaded pieces, `Blob/get`, `Blob/lookup`. The web app
  uploads files over 16 MiB in pieces and sends a piece again when its connection breaks.
- Searching inside text files (JMAP `body` and `text`, the web app's new search box in Files), and emptying the file
  trash after a tenant's number of days (`kernoid tenant files-retention`, `/v1/tenant/files-retention`, GraphQL,
  the administration's settings; migration 0039).
- WebDAV `COPY` and `MOVE` between stores – one's own files, drives, what others share – where the rights allow;
  before, file managers got 502 and copied themselves.
- SAML single logout in the HTTP-POST binding, and at OpenID Connect `end_session`: an application's logout of a
  session from a SAML provider logs out at the provider too, then returns to the application.
- The first module, `clamav` (docs: Modules): content of tenants that switch it on is checked for malware by ClamAV's
  daemon before kernoid keeps it – uploads and files while they are stored (refused with HTTP 422, WebDAV 403), mail
  at the MX and at submission before it is accepted (`554 5.7.1`), IMAP `APPEND`. `deploy/compose` has the service
  `clamav` (profile `clamav`). Tenants see and switch the modules the installation offers with
  `GET /v1/tenant/modules`, GraphQL `tenantModules`, and in the administration's settings; only modules the
  installation has switched on can be switched on.
- The web app's calendar shows a week or a day besides a month, and changes or deletes one event of a series on its
  own (JMAP `recurrenceOverrides`) – or, as before, the whole series. The terminal app does the same (`E`, and `o`
  when deleting).
- JMAP `FileNode/copy` (RFC 8620, 5.4): nodes – a directory with what it holds – copied from another store the
  caller reads, a file's copy sharing its content; `onSuccessDestroyOriginal` moves them. The web app copies and
  moves files and folders between one's own files, team folders and what others share.
- The web app's administration keeps an account's Sieve scripts: written, checked by kernoid (its compile errors
  shown), switched on or off, removed.
- Links to a folder can let people add files – beside viewing, or as a drop box that hides what is in it (`mayRead`,
  `mayAdd` on `FileLink`; `POST /v1/links/{token}/files`; migration 0042). A name already taken gets a number;
  nothing is replaced. The web app makes them (Link → "People can") and its link page uploads with progress. Whoever
  made the link gets one email naming what came in, once nothing more has come for two minutes (migration 0043).
- The account page lists the services one logs in with, links further ones and unlinks them
  (`/v1/account/idp-links`, `/v1/account/idp-providers`; SDK `idpLinks`, `linkableProviders`, `unlinkIdp`). The last
  way to log in is never unlinked.
- The terminal app answers the mouse: a click chooses a tab or a row (a second one opens it), the wheel moves
  through lists and scrolls messages.
- The terminal app makes and removes links to files and folders – to view, to view and add, or a drop box; with an
  expiry and a password (`L`) –, edits the vacation response in the editor (`V`), searches a store's files by name
  and content (`/`), and copies and moves files and folders, also between stores (`m`).
- The Kubernetes operator makes an Ingress to the `api` role when the `Kernoid` asks for one (`ingress`: hosts,
  class, TLS Secret, annotations); its ClusterRole may now manage Ingresses.
- A Helm chart for the Kubernetes operator (`deploy/helm/kernoid-operator`): the CustomResourceDefinition and the
  operator, for every namespace or one (a Role instead of the ClusterRole); CI lints it and checks its
  CustomResourceDefinition, and pushes it with each release to `oci://ghcr.io/kernoid/charts/kernoid-operator`.
- Emails kernoid writes itself – invitations, notices of files added through links – are in German or English: the
  account's choice (account page, `/v1/account/language`, `kernoid account language`), else the tenant's
  (Administration → Settings, `/v1/tenant/language`, GraphQL `setTenantLanguage`, `kernoid tenant language`), else
  English (migration 0044).
- The web app's administration saves an account's mailbox as an mbox file and imports one into it (up to 2 MiB in
  the browser; larger ones with `kernoid mail import-mbox`).
- The web app shows an HTML email in its original layout too ("Original" beside "Readable"): served as a page of its
  own (`/jmap/view`) in a sandbox – its styles and embedded images, no scripts, no forms, nothing loaded from
  elsewhere, so no tracking pixels.
- A vacation response for every account: JMAP `VacationResponse` (RFC 8621, 8) and a section in the web app's account
  page; delivery answers as a Sieve `vacation` does, after the account's own script (migration 0041).
- The terminal app saves an event as an `.ics` file and the contacts listed as a `.vcf` file, and imports both (`X`,
  `I`; through calcard, as kernoid stores them; imported events invite nobody).
- The terminal app keeps every address, phone number and organisation of a contact, with their labels (`(work)`,
  `(private)`, for phones also `(mobile)` …) – one line each in the editor; before, it showed the first and saving
  kept only that.
- The web app shows new mail as a notification of the browser while it is open in the background (switched on in
  the account page, kept per browser).
- The web app on a phone: the page no longer runs wider than the screen – the sections scroll in a row of their own,
  the files view shows its stores above the folder, the mail view its mailboxes and "Write" above the list.
- Kubernetes: the operator `kernoid-operator` (in the image; `deploy/kubernetes`, docs: Operations) runs kernoid as a
  resource `Kernoid` describes – the schema migrated with a new image before the processes are replaced, one
  Deployment and Service per role, non-root pods with a read-only root filesystem.
- Images for `linux/arm64` besides `linux/amd64`, built on runners of each architecture.
- `scripts/upgrade-check.sh`: an installation of a release, with mail and a file in it, upgraded to a new image and
  checked; CI runs it from the last release for every image of `main`.
- The directory over LDAP (docs: Directory, RFC 0003, 8): each tenant's people and groups at `o=<tenant id>`, read
  only, for software that reads users from a directory – `inetOrgPerson` and `groupOfNames` with `mail`, `member` and
  `memberOf`. Binds over LDAPS or StartTLS with the login name or DN and an app password (or the password without a
  second factor); a new process role `ldap` and the table `[ldap]`.
- The module `jitsi` (docs: Modules): video meetings in a Jitsi Meet with JWT authentication. A calendar event in the
  web app gets a meeting with one button; its link goes into the event (`virtualLocations`, iCalendar `CONFERENCE`)
  and its description, and sends whoever opens it on to Jitsi with a token kernoid signed for that room – the
  meeting's owner as moderator –, to the login, or (with `guests = true`) in as a guest (migration 0040).
- `http.public_port`: instances reached on a port other than 443 or 80 name it in their issuer and links (JMAP);
  `deploy/compose` sets 8080.

- The web app's mail: folders of one's own, nested, renamed, moved and deleted; emails moved by dragging them – also
  several at once – onto a folder; the Trash marked, emptied with one button and kept as long as the account chooses
  (`GET/PUT /v1/account/mail-settings`; retention takes the account's days over the tenant's); writing with formatting,
  sent as HTML with the plain text alongside, from a default sender the account chooses; attachments shown in place.
- Sending later and taking back (JMAP, RFC 8621, 7): a submission held with `HOLDFOR` or `HOLDUNTIL` (up to 60
  seconds; `maxDelayedSend`, `FUTURERELEASE`) is `pending` until its time – nothing is delivered or queued –, can be
  `canceled` until then, and is sent by the worker (every two seconds). The web app says when an email is sent and,
  if the account chose to wait 5 or 10 seconds (`undo_send_seconds` of the mail settings; off by default), offers to
  take it back – the writing window opens again. Migration 0046.
- Shared mailboxes in the web app: each one the account may use appears with its folders beside its own, marked
  private or shared, under its address or a name the account gives it (`PUT
  /v1/account/mail-settings/mailbox-names/{account}`; migration 0047) – the address shows on hover; writing
  offers the addresses it may send as, and such an email is kept in and sent from the shared mailbox.
- Pictures of accounts (`PUT/DELETE /v1/account/avatar`, `GET /v1/avatars`, `GET /v1/avatars/{account}`; PNG, JPEG or
  WebP up to 1 MiB, sealed like files, seen by the tenant); everyone else shows their initials. Migration 0045.
- A new look for the web app: icons throughout, IBM Plex Sans, a comfortable or compact density, the theme as icons,
  the account's menu behind its picture, a bar at the bottom on phones.

- Post-quantum key exchange (RFC 0006, 2): every TLS connection kernoid makes or takes – HTTPS, SMTP, IMAP, POP3,
  LDAP, PostgreSQL, ACME, the operator's and the terminal app's – prefers the hybrid X25519MLKEM768 over X25519.
  Clients without ML-KEM connect as before.
- End-to-end encryption with OpenPGP (RFC 0006; docs: Mail, Files, Calendars and contacts): content only its owners
  can read. Keys are made by the account's client – post-quantum (RFC 9980) or compatible – and kernoid keeps their
  public part and copies of the secret key only as the client protected them (migration 0048). The JMAP extension
  `https://kernoid.dev/jmap/openpgp` (`OpenPgpKey/*`, `E2eSettings/*`); the Web Key Directory serves the keys in use,
  and mail sent through the queue carries Autocrypt. `apps/e2e` (MIT) is the library behind it, `@kernoid/e2e` in the
  web app as WebAssembly.
- End-to-end encrypted mail: an account that switches it on gets incoming mail encrypted to its key after Sieve, the
  spam filter and the malware scan (PGP/MIME, the subject protected after RFC 9788); the worker encrypts what it
  stored before. The web app and the terminal app read such mail, and send encrypted and signed when every recipient
  has a key – known locally or from their Web Key Directory.
- Vaults: directories only their members can read (migration 0049). Names and content are encrypted in the browser;
  sharing a vault hands its key to the members who have one. WebDAV and the content search leave vaults out.
- Encrypted calendars and address books (migration 0050): a new collection can be made encrypted; its events and
  contacts are encrypted in the browser. CalDAV and CardDAV do not show such collections, and their events send no
  invitations.
- The tenant's policy for end-to-end encryption – mail, vaults, calendars and address books each allowed, required or
  forbidden – and recovery through the tenant's recovery key, made in the administrator's browser
  (`GET /v1/accounts/{id}/e2e-recovery-copy`; REST, GraphQL, CLI and the administration).
- kernoid's Rust SDK, `kernoid-client` (`apps/client`, MIT): JMAP for mail, files, calendars and contacts, push,
  end-to-end encrypted mail, finding a server through DNS and `.ics`/`.vcf` files – async on tokio, made from the
  terminal app's protocol layer. The terminal app and kernoid's apps use it.
- `kernoid-sync` (`apps/sync`, MIT): a folder kept in step with a file store – changes read from the journal, the
  folder scanned, a change on both sides kept as a copy, deletions carried over to the trash; the state in SQLite.

### Changed

- The terminal app is licensed under the AGPL-3.0-or-later like the server (it was MIT) and built on the Rust SDK;
  its MIT code lives on in the SDK. It goes into no app store, so the AGPL costs it nothing.
- A tenant's requirement of a second factor now holds for its accounts' data too: JMAP (the web app's mail,
  calendar, contacts and files), CalDAV, CardDAV, WebDAV and the modules' routes take a session only with the factor
  (after the grace period), and an app password can only be added with it. A session from a password alone opens the
  account page, which asks for the factor.
- The web app and the login UI are written in Svelte 5 (they were Solid and plain TypeScript); they look and behave
  as before. The administration's requests are typed from the OpenAPI document.
- kernoid carries the login UI and the web app in its binary. `http.login_ui` and `http.web_app` have no default any
  more: set, they name a directory with a build to serve instead (development); the image no longer has
  `/usr/share/kernoid/login` and `/usr/share/kernoid/app`.
- OpenAPI: the mail grant, an account's linked identity provider and the tenant's login policy are the schemas
  `MailGrantView`, `IdpLinkView` and `TenantPolicy` – they had the names of other schemas, so the document described
  them wrong.
- The web app's content security policy allows WebAssembly (`'wasm-unsafe-eval'`) and `blob:` images and media, for
  end-to-end encryption.
- The worker logs every delivery attempt – delivered, deferred or bounced – with the recipient's domain (never the
  address); before, successful deliveries left no trace above debug.

### Upgrading from 0.1

- Take the new `deploy/compose` with the new image: the 0.1 image refuses the module settings the new compose file
  passes (`[modules.clamav]` did not exist).
- `kernoid migrate` adds migrations 0034 to 0051 (CI's upgrade check runs them from 0.1.0 with mail and files in it).
- DKIM: each domain gets an Ed25519 key beside its RSA key – publish the new TXT record `kernoid-ed1._domainkey`
  that the domain's DNS check shows; mail is signed with it once DNS has it.
- A configuration that set `http.login_ui` or `http.web_app` to the image's old paths must drop them: those
  directories are gone, and the built-in login UI and web app serve instead.
- The image is `ghcr.io/kernoid/kernoid:0.2.0` (or `:0.2`), for `linux/amd64` and `linux/arm64`; set
  `KERNOID_IMAGE` to it where 0.1.0 was named.
- Nothing else changes by itself: LDAP, ClamAV and Jitsi stay off until configured; end-to-end encryption is allowed
  for every tenant but on for no account until it makes a key and switches it on.

### Fixed

- `CalendarEvent/query` with `expandRecurrences` returns a single event as itself – its own id, no `baseEventId` –
  and only recurring events as instances; clients showed every event as repeating. `CalendarEvent/set` refuses a
  `start` that is not a LocalDateTime (`invalidProperties`) instead of storing the event without one.
- A new screen of the login page puts the focus on its first field; it went to the heading.
- WebDAV answers began with two XML declarations – not well-formed, and file managers (macOS Finder, Windows) refused
  to connect.
- An account with only a password in a tenant that requires a second factor got a page that reloaded without end: the
  login now asks for the second factor (or has one set up), and the web app no longer sends such a session back to the
  login.
- The web app's lists said they were empty ("No links yet.") while still loading; they say "Loading" now. On a phone,
  file rows show their actions below the name, the search box of Files has a row of its own, the administration's
  pages are one row that scrolls, and the open section stays in sight.
- Linking a provider to one's account needs a recent login, as adding a passkey or an app password does: a session
  taken over could otherwise add a lasting way in. So does confirming a proposed link (the login page always logs in
  for it).
- An event of a series moved to another time kept its recurrence id only as the new time: JMAP showed it without
  the changes of its override; and an override without a duration of its own lasted to the end of its day in
  iCalendar – it now takes the series' duration.
- The web app shows PDFs and other files in place: its viewer asks for downloads with `inline=1` – they were sent as
  attachments, which browsers saved instead of showing.
- A download whose content cannot be read answers with a problem (500) instead of an empty, broken response.
- So does an mbox export whose first email cannot be read (503, "stored content could not be read"); an email that
  cannot be read later on ends the export and is logged.

### Known gaps

Marked `OPEN` in the documentation, among them: uploads resumed after the page was closed, search in PDF and Office
files, single logout from the administration's sign-out, who may read the LDAP directory, links and groups in vaults,
invitations from encrypted calendars, post-quantum signatures in OpenPGP, Web Push while the web app is closed.

## [0.1.0] – 2026-10-28

The first release, a pre-release. kernoid runs an organisation's email, logins and files as one system on PostgreSQL and
S3-compatible object storage, in one container image. It is for trying out and testing – not yet for data that must
not be lost: there has been no external security audit (planned before 1.0), and the formats may still change.

### Identity and login

- Instances, tenants (each with its own domains, verified over DNS), accounts, groups, roles (built in, a tenant's
  own, instance roles), projects with roles, authorizations and grants to other tenants – identity and administration
  as events, the audit trail as data ([RFC 0001](rfcs/0001-data-and-event-model.md)).
- Accounts with a mailbox, external accounts for logins only, shared mailboxes, team folders; logins by address,
  username or verified contact address; services (mail, files) per account with the tenant's rules and approval;
  registration ([RFC 0003](rfcs/0003-accounts-logins-services.md)).
- Passwords (Argon2id), TOTP, passkeys (also as the only factor), recovery codes, a second factor required per
  tenant or application, device tokens against lock-outs, sessions in an HttpOnly cookie or as bearer tokens.
- OpenID Connect provider: authorization code with PKCE, refresh tokens, consent and `offline_access`, opaque or JWT
  access tokens, introspection, front- and back-channel logout, signing keys that rotate by themselves.
- Logging in with other OpenID Connect and SAML 2.0 providers (signed requests, encrypted assertions, single logout),
  SCIM 2.0 for directories, ACME for certificates.
- The administration API in REST (OpenAPI) and GraphQL, with the same permission checks; the operator's CLI.

### Mail

- The MX with SPF, DKIM, DMARC, ARC and iprev, a basic spam filter, Sieve, groups as distribution lists; submission
  with app passwords; the queue in PostgreSQL with DKIM signing, MTA-STS and DANE, bounces; DNS checks of the
  tenant's records ([RFC 0002](rfcs/0002-mail-data-model.md)).
- JMAP Mail with push, IMAP4rev2/rev1, POP3 (off by default); shared mailboxes and access per mailbox; full-text
  search, retention of trash and junk, mbox import and export; autoconfiguration for mail programs.

### Calendars and contacts

- CalDAV and CardDAV, JMAP Calendars and Contacts, invitations over iTIP/iMIP, sharing of calendars and address books
  ([RFC 0004](rfcs/0004-calendars-and-contacts.md)).

### Files

- Each account's files and the tenant's team folders (drives), JMAP FileNode, WebDAV (class 1 and 2) for the file
  managers of operating systems, sharing with people and groups, versions, files of any size streamed in sealed
  parts ([RFC 0005](rfcs/0005-files.md)).

### Apps (MIT)

- The web app at `/app/`: mail, calendar, contacts, files with previews of images, audio, video, PDF and text, the
  account (second factors, app passwords, how to connect programs), administration of the tenant and the instance;
  light, dark or as the system; German and English.
- The login UI at `/login`, the TypeScript SDK `@kernoid/sdk`, the terminal app `kernoid-tui` (`apps/tui`).

### Security

- Content is encrypted per tenant before it reaches object storage; two database roles keep the runtime from
  changing events.
- Downloads carry `nosniff` and a sandboxing Content-Security-Policy, so uploaded HTML or SVG cannot run scripts on
  the instance's origin.

### Known gaps

Marked `OPEN` in the documentation, among them: public links to files, resumable uploads, SRS for forwarded mail,
OAUTHBEARER and LDAP, IMAP `SORT` and `THREAD`, a week and a day view, an audit log in the web app, a Kubernetes
operator – planned for 0.2.

[Unreleased]: https://github.com/kernoid/kernoid/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kernoid/kernoid/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/kernoid/kernoid/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/kernoid/kernoid/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/kernoid/kernoid/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/kernoid/kernoid/releases/tag/v0.2.0
[0.1.0]: https://github.com/kernoid/kernoid/releases/tag/v0.1.0
