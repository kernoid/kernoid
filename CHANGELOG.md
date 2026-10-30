<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Changelog

What changes from release to release, for those who run kernoid and those who build on it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org) –
before 1.0, a minor version (0.2) may change the API and the configuration, and says how to upgrade here.

## [Unreleased]

### Added

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

### Changed

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
- `kernoid migrate` adds migrations 0034 to 0050 (CI's upgrade check runs them from 0.1.0 with mail and files in it).
- DKIM: each domain gets an Ed25519 key beside its RSA key – publish the new TXT record `kernoid-ed1._domainkey`
  that the domain's DNS check shows; mail is signed with it once DNS has it.
- A configuration that set `http.login_ui` or `http.web_app` to the image's old paths must drop them: those
  directories are gone, and the built-in login UI and web app serve instead.
- Nothing else changes by itself: LDAP, ClamAV and Jitsi stay off until configured; end-to-end encryption is allowed
  for every tenant but on for no account until it makes a key and switches it on.

### Fixed

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

[Unreleased]: https://github.com/kernoid/kernoid/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kernoid/kernoid/releases/tag/v0.1.0
