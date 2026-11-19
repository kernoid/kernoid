<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0008 – The suite: building blocks, services and licences

- **Status:** draft, 2026-11-19; the direction decided by the maintainer the same day, the mechanism a proposal.
  Implemented with 0.5.0 as far as section 7 says.
- **Scope:** what kernoid is to the programs built on it, how the repository is laid out for that, which parts an
  installation may leave out, and which licence each part carries. [0009](0009-kernoid-in-other-servers.md) says how
  another server uses kernoid's identity, [0010](0010-foundation.md) what the foundation of end-to-end encrypted spaces
  is, [0011](0011-app-kit.md) how apps are put together from kernoid's packages.

## 1. Decisions

The maintainer decided (2026-11-19):

1. **kernoid is the core of a suite** – identity, mail, calendars and contacts, files, and the foundation that
   end-to-end encrypted data of every kind stands on. Other programs build on it instead of beside it: aktujo
   (documents, the archive, signing) is an add-on to kernoid; notenwart and spezado are systems built on kernoid's
   crates, and use aktujo for reading documents and, spezado, for keeping them safe.
2. **Everything is a building block.** Crates and Flutter packages, all in this repository. The repository
   `kernoid/apps` holds only kernoid's own apps, which take the packages from here.
3. **As small as wished.** An installation runs only what it wants: identity alone, a relay alone, or everything.
4. **Licences:** AGPL-3.0-or-later wherever possible. MIT only for what an app under MIT uses – kernoid's apps and the
   apps of the programs built on kernoid –, and as little of it as possible.
5. **The files, JMAP and end-to-end parts** that aktujo has built so far become kernoid's ([0010](0010-foundation.md));
   aktujo keeps what is about documents.
6. **Order:** kernoid 0.5.0 completes this and works; then aktujo moves onto it, then notenwart and spezado.

## 2. Layers

| Layer | What | Licence | Where |
|---|---|---|---|
| **Kit** | what apps use: the Rust SDK, end-to-end encryption, file sync, the foundation's device side, Flutter packages | MIT | `kit/` |
| **Server crates** | identity, OpenID Connect, mail, calendars and contacts, files, the relay, protocols, modules, the server | AGPL | `crates/` |
| **Programs of kernoid** | the binary with its roles, the operator, the terminal app, the web app and login UI | AGPL | `crates/kernoid`, `operator/`, `tui/`, `web/` |
| **Programs on kernoid** | aktujo, notenwart, spezado – their own repositories | their own | elsewhere |

A crate of the kit never depends on a server crate – the kit is a Cargo workspace of its own, so that a path to a
server crate cannot slip in, and `cargo deny` allows only permissive licences there. A server crate may depend on the
kit.

## 3. The repository

```
crates/            server crates (AGPL), one Cargo workspace – as before
kit/               the kit (MIT), one Cargo workspace
  client/          kernoid-client – the Rust SDK (was apps/client)
  e2e/             kernoid-e2e – OpenPGP for mail and vaults (was apps/e2e)
  sync/            kernoid-sync – keeping a folder in step with a file store (was apps/sync)
  base/ blob/ log/ crypt/ space-store/ replica/   the foundation's device side (0010)
  flutter/         Flutter packages (0011)
tui/               kernoid-tui (AGPL, was apps/tui), a workspace of its own
operator/          kernoid-operator (AGPL)
web/               TypeScript SDK, login UI, web app (AGPL)
```

`apps/` goes away in this repository: the word belongs to `kernoid/apps`. The three MIT crates that were Cargo
workspaces of their own each become members of the one workspace `kit/`, with one lock file.

## 4. Services

A **service** is a part of kernoid an installation may leave out. Identity is always there; the others are named in
the configuration:

```toml
[services]
mail = true        # mail store, SMTP, IMAP/POP3, JMAP Mail, Sieve
calendars = true   # calendars and contacts: JMAP, CalDAV, CardDAV, scheduling
files = true       # file stores, drives, WebDAV, JMAP FileNode, links
relay = false      # hosting end-to-end encrypted spaces (0010)
```

The default keeps today's installations as they are: mail, calendars and files on, the relay off. A service that is
off:

- serves **no routes** – its JMAP capabilities are missing from the session, its REST and GraphQL operations answer
  `404`, WebDAV, CalDAV, CardDAV and the autoconfiguration of mail programs are not there;
- runs **no jobs** in the worker and opens **no ports**: its tables of configuration (`[smtp]`, `[imap]`) are refused at
  start, with a message, and a role that only it needs (`smtp`, `imap`, `relay`) does nothing;
- is **not offered**: the web app, the login UI and the administration hide it, and `GET /v1/services` (anyone may
  read it) names what is on, so that apps and other servers can ask;
- keeps its **tables**: the schema of every service is migrated, whatever is on (one history, [0009](0009-kernoid-in-other-servers.md),
  section 4). Switching a service on later needs no migration.

Per tenant and account, what RFC 0003 says still holds (services of an account, the tenant's rules); a service that
is off for the installation is off for every tenant.

**Calendars** need the store of mail (RFC 0004 keeps them in the account's mail store), not the mail service: with
`mail = false` and `calendars = true`, accounts have a mail store without mailboxes, SMTP or IMAP.

## 5. Small installations

- **Identity alone:** `[services]` all `false`, the roles `api` and `worker`. It needs PostgreSQL; **object storage is
  not needed**: with `[blob] kind = "database"` the few objects identity keeps (pictures of accounts) are stored in
  PostgreSQL (`blob_objects`), sealed like any other, up to 4 MiB each. `database` is refused while mail or files is on
  (implemented in 0.5.0); with the relay, see [0010](0010-foundation.md).
- **A relay alone:** `relay = true`, the others `false`, the roles `api`, `worker` and `relay` (or `all`). Spaces are
  founded by accounts of the installation, or by anyone when the relay is open ([0010](0010-foundation.md), section 4).
- **Everything:** as today.

kernoid still needs only PostgreSQL and, where content is kept, S3-compatible storage (whitepaper, Data).

## 6. Licences

| Part | Licence | Why |
|---|---|---|
| `crates/**`, `crates/kernoid`, `tui/`, `operator/` | AGPL-3.0-or-later (files taken over from Stalwart or derived from Zitadel: AGPL-3.0-only, as before) | the server and its programs |
| `web/sdk`, `web/login`, `web/app` | **AGPL-3.0-or-later** (was MIT) | no MIT app uses them; served by the server |
| `kit/client`, `kit/e2e`, `kit/sync` | MIT | kernoid's apps use them |
| `kit/base`, `-blob`, `-log`, `-crypt`, `-space-store`, `-replica` | MIT | the apps of programs on kernoid use them ([0010](0010-foundation.md)) |
| `kit/flutter/**` | MIT | kernoid's apps are made of them ([0011](0011-app-kit.md)) |
| the relay's server side, `kernoid-auth`, identity for other servers | AGPL | only servers use them ([0009](0009-kernoid-in-other-servers.md), [0010](0010-foundation.md)) |
| API descriptions (`docs/_data/openapi.json`, `docs/api/`) | MIT | others generate clients from them (starter pack) |
| documentation text and RFCs | CC BY 4.0 | as before |

The earlier decision that the web SDK and the login UI are MIT (RFC 0001, 2026-10-23) is replaced by this table:
nothing under MIT uses them. Changing their licence is the rights holder's: every commit in this repository is the
maintainer's (checked 2026-11-19, `git log`); code taken over from others keeps its licence.

**Checks** (CI): the kit's `cargo deny` allows only permissive licences and no crate of `crates/`; every file of
`kit/` carries `MIT`, every other source file a licence of the table (REUSE); a kit crate's `Cargo.toml` says
`license = "MIT"`.

## 7. 0.5.0

kernoid 0.5.0 is done when:

1. the repository is laid out as section 3 says, with the licences of section 6 and their checks;
2. the services of section 4 can be switched off, and identity alone and a relay alone run – each tested in CI;
3. identity can be built into another server and used by one beside it ([0009](0009-kernoid-in-other-servers.md));
4. the foundation is part of kernoid, and the relay is a role ([0010](0010-foundation.md));
5. the Flutter packages are here and `kernoid/apps` is only the apps ([0011](0011-app-kit.md));
6. everything that worked in 0.4 still works, and an installation of 0.4 upgrades to 0.5 (CI's job `upgrade`).

## 8. Open

- **OPEN:** Flutter packages on pub.dev, or only by a git reference ([0011](0011-app-kit.md)).
- **OPEN:** a service per tenant that the installation leaves on but a tenant cannot see at all (today: the
  services of RFC 0003 per account).
- **OPEN:** identity on SQLite for very small servers ([0009](0009-kernoid-in-other-servers.md), section 6).
