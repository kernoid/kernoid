<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Credits

kernoid stands on the work of others. This file names the two projects whose roles it takes over and what it took
from each; every file says the same in its SPDX header and its first lines. The libraries kernoid builds on are in
`Cargo.lock`, `kit/Cargo.lock`, `tui/Cargo.lock`, `operator/Cargo.lock` and `web/pnpm-lock.yaml`, each with its own licence.

## Stalwart

[Stalwart](https://github.com/stalwartlabs/stalwart) by Stalwart Labs LLC – mail and collaboration server. Code was
taken from **v0.16.27**, once, and changed for kernoid; it is not merged again – except the Sieve interpreter, which
moved into the repository from crates.io and is taken over as it is, now from **v1.1.0** (commit `e7cde9b`,
2026-11-09). calcard and jmap-tools were taken over the same way until 2026-11-20; kernoid's own `kernoid-pim`
(`kit/pim`, MIT, written anew) replaced them, and with them the scheduling and the query filters derived from
Stalwart's. Only files under `AGPL-3.0-only OR
LicenseRef-SEL` were taken, under `AGPL-3.0-only`, with Stalwart's copyright (`2020 Stalwart Labs LLC`); nothing under
the Stalwart Enterprise License, which `scripts/check-sel.sh` enforces.

**Taken over** – Stalwart's code, adapted where kernoid's types differ:

| In kernoid | From Stalwart |
|---|---|
| `crates/kernoid-imap/src/proto/` | `crates/imap-proto` – IMAP requests and responses |
| `crates/kernoid-dav/src/proto/` | `crates/dav-proto` – WebDAV, CalDAV and CardDAV requests and responses (the names in its filters are kernoid's, `names.rs`) |
| `crates/sieve/` | `crates/sieve` – the Sieve interpreter (sieve-rs), before on crates.io; without its tests, which live in a repository of Stalwart's that is not public |

**Derived** – written for kernoid's storage, following Stalwart's logic:

| In kernoid | From Stalwart |
|---|---|
| `crates/kernoid-mail/src/thread.rs` | threading in `crates/email/src/message/ingest.rs` |
| `crates/kernoid-imap/src/message.rs` | `FETCH` in `crates/imap/src/op/fetch.rs` |
| `crates/kernoid-smtp/src/session.rs`, `message.rs` | the inbound session (`crates/smtp/src/inbound`) and `queue_message` |
| `crates/kernoid-smtp/src/client.rs`, `crates/kernoid-smtp/src/mta_sts.rs`, `dane.rs` | the outbound client, MTA-STS and DANE (`crates/smtp/src/outbound`) |

**Libraries** of Stalwart Labs that kernoid uses as they are: `mail-parser`, `mail-auth`, `mail-builder`,
`smtp-proto` (Apache-2.0 OR MIT).

## ZITADEL

[ZITADEL](https://github.com/zitadel/zitadel) – identity and access management. kernoid's identity follows
its concepts; **no code was ported so far**, so no file is derived from ZITADEL's source. Code written while reading
that source would be marked as derived and be `AGPL-3.0-only`.

| In kernoid | ZITADEL's concept |
|---|---|
| instances and tenants (RFC 0001) | instances and organizations |
| `crates/kernoid-events` | the event store – written from its documentation |
| `crates/kernoid-identity/src/project.rs`, project grants | projects, roles, project grants |
| `crates/kernoid-oidc/src/flow.rs` | the claim with project roles (like `urn:zitadel:iam:org:project:roles`) |
| `crates/kernoid-oidc/src/keys.rs` | the life cycle of web keys |
| `crates/kernoid-server/src/oidc.rs` | the paths of the OpenID Connect endpoints |
| `crates/kernoid-server/src/admin/` | the header naming the tenant administered (like `x-zitadel-orgid`) |
| logins (RFC 0003) | login names and linking accounts of identity providers |

## Others

- **Specifications** kernoid implements are cited where they are used: the RFCs of the IETF, the JMAP drafts, OpenID
  and SAML.
- **IBM Plex** (SIL OFL 1.1) is the typeface of the brand, the documentation and the web app.
- **[falkoss/starterpack](https://github.com/falkoss/starterpack)** gave the repository its shape (REUSE, DCO,
  documentation).
