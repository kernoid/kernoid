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
- `http.public_port`: instances reached on a port other than 443 or 80 name it in their issuer and links (JMAP);
  `deploy/compose` sets 8080.

### Fixed

- The web app shows PDFs and other files in place: its viewer asks for downloads with `inline=1` – they were sent as
  attachments, which browsers saved instead of showing.
- A download whose content cannot be read answers with a problem (500) instead of an empty, broken response.

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
