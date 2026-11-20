<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Credits

kernoid stands on the work of others. This file names the two projects whose roles it takes over and what it took
from each; every file says the same in its SPDX header and its first lines. The libraries kernoid builds on are in
`Cargo.lock`, `kit/Cargo.lock`, `tui/Cargo.lock`, `operator/Cargo.lock` and `web/pnpm-lock.yaml`, each with its own licence.

## Stalwart

[Stalwart](https://github.com/stalwartlabs/stalwart) by Stalwart Labs LLC – mail and collaboration server. Code was
taken from **v0.16.27** (and calcard, jmap-tools and the Sieve interpreter from **v1.1.0**, commit `e7cde9b`) under
`AGPL-3.0-only`, never anything under the Stalwart Enterprise License (`scripts/check-sel.sh`). By 2026-11-20 all of it
was replaced by kernoid's own code, written from the RFCs: the IMAP and DAV protocols, the SMTP session, client, DANE
and MTA-STS, threading, the Sieve interpreter (`kernoid-sieve`), scheduling, the CalDAV and CardDAV query filters, and
calcard and jmap-tools (`kit/pim`, `kernoid-pim`, MIT). No file of kernoid is taken over or derived from Stalwart's
any more.

**Libraries** of Stalwart Labs that kernoid uses as they are: `mail-parser`, `mail-builder` (Apache-2.0 OR MIT).
`mail-auth` and `smtp-proto` were used until 2026-11-20; mail authentication and SMTP on the wire are kernoid's own
since (`kernoid_smtp::auth`, `kernoid_smtp::proto`), written from the RFCs, not from their source.

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
- **[bergshamra](https://github.com/kushaldas/bergshamra)** (BSD-2-Clause) verified and decrypted kernoid's SAML
  messages until 2026-11-20. kernoid's own XML signatures and encryption (`crates/kernoid-oidc/src/saml/`) replaced
  it; they were written from the W3C Recommendations and SAML 2.0, without reading bergshamra's source – nothing of it
  was taken over.
- **IBM Plex** (SIL OFL 1.1) is the typeface of the brand, the documentation and the web app.
- **[falkoss/starterpack](https://github.com/falkoss/starterpack)** gave the repository its shape (REUSE, DCO,
  documentation).
