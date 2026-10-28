<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Changelog

What changes from release to release, for those who run kernoid and those who build on it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org) –
before 1.0, a minor version (0.2) may change the API and the configuration, and says how to upgrade here.

## [Unreleased]

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
