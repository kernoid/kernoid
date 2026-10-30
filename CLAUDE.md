<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# CLAUDE.md – kernoid

Notes for working on this repository with an AI assistant – and for anyone new to it. The design is in the
[whitepaper](https://github.com/kernoid/whitepaper); this file says how the code is laid out and which rules hold.

## Layout

A Cargo workspace; one binary (`crates/kernoid`), one container image (which carries the operator's binary too). The
configuration decides which **roles** a process takes on (`kernoid_config::Role`); add a role there when a component
can run on its own.

| Crate | Depends on | Holds |
|---|---|---|
| `kernoid-config` | – | `Config`, `Role`, `Secret` |
| `kernoid-store` | config | PostgreSQL pool, `MIGRATOR` (all migrations, one history), `migrate` (owner → runtime grants), `BlobStore`, `TenantKeys`, `crypto`, `lock` (advisory locks for work one process does at a time), `garbage` (objects to remove once nothing needs them), `parts` (content of any size streamed in sealed parts of 8 MiB), `scan` (the hook of a malware scanner: content of tenants that switched its module on is scanned as `parts` stores it, mail with `check_bytes` before it is accepted) |
| `kernoid-events` | sqlx | `EventStore`: append with expected sequence, load an aggregate, read all by cursor; `projection::{Projection, Runner}` |
| `kernoid-identity` | events, store | `Identity`: instance, tenant and account aggregates with inline read models (`instances`, `instance_domains`, `tenants`, `tenant_domains`, `tenant_modules`, `accounts`, `addresses`), `account_passwords`, `DomainName`, `Address`, DNS verification (`TxtLookup`), `authenticate`, sessions, TOTP (`mfa`), passkeys (`passkey`, webauthn-rs), groups (`group`), roles and permissions (`role`: built in, a tenant's own, instance roles), projects and authorizations (`project`), app passwords and mail logins (`app_password`), shared mailboxes, grants on mail and quotas (`mail_access`), files quotas, drives and grants on files (`files_quota`), logins by address, username or contact address (`login`), services and their rules (`services`), registration (`registration`), end-to-end encryption (`openpgp`, RFC 0006: accounts' OpenPGP keys and the protected copies of their secret keys – read through `kernoid-e2e` –, mail encrypted on arrival, the tenant's policy and recovery key, what WKD serves), administration with permission checks (`admin`, used by REST and GraphQL alike) |
| `kernoid-oidc` | events, identity, store | `Oidc`: applications (aggregate, in a project), admin functions with permission checks (`admin`), external identity providers of a tenant or the whole instance (`federation`: OpenID Connect via `external`, SAML 2.0 via `saml` with kernoid's SAML key, encrypted assertions and single logout), outbound requests only to public addresses (`outbound`), signing keys (one aggregate per instance), authorize → finish/decline → token (code, refresh with rotation) → userinfo, revoke, end_session, discovery, JWKS, `clean_up` |
| `kernoid-mail` | store | `Mail`: the mail store of each account (RFC 0002) – mailboxes with roles and IMAP UIDs, emails imported with mail-parser (raw message sealed in object storage, summary in PostgreSQL), threads (`thread.rs`, derived from Stalwart), keywords, quotas, the journal of changes (`changes`) for JMAP and IMAP, who may use whose mail (`access`: `Rights`, `Access` from the grants in `mail_access`), full-text search and retention (`search`), mbox (`mbox`), delivery of incoming mail (`deliver`: recipients, duplicates) and Sieve (`scripts`, sieve-rs), the queue of outgoing mail (`outbox`, which adds Autocrypt), encryption on arrival and of mail stored before (`e2e`, RFC 0006, 5.2, through `kernoid-e2e`), uploads, and `MailEvents` (PostgreSQL `LISTEN` on `kernoid_mail`, which every change `NOTIFY`s) |
| `kernoid-smtp` | config, identity, mail, oidc, groupware | `Server`: the MX (RFC 0002, 9) and submission (10.1, `submission.rs`) – the session (`session.rs`, derived from Stalwart; requests parsed by smtp-proto), checks with mail-auth (iprev, SPF, DKIM, ARC, DMARC; `dns`: the resolvers – one validating DNSSEC – with caches tests fill), headers and delivery (`message.rs`, derived from Stalwart), the basic spam filter (`spam`), invitations in delivered mail handed to `kernoid-groupware` when DMARC passed or the sender is logged in; sending (10): `outbound` (the worker delivering the queue, with the client `client.rs` derived from Stalwart), `dkim` (keys and signing), `mta_sts` and `dane` (derived from Stalwart), `dsn` (bounces), `dns_check` |
| `kernoid-files` | store | `Files`: the file store of each account and drive (RFC 0005) – its own store beside the mail store (`file_accounts`: row, modseq, quota), directories and files in `file_nodes` with names unique among siblings and a depth of at most 64 (`node`), the Trash made at the first use, contents and versions in `file_contents` stored in parts (`content`, `kernoid_store::parts`; uploads taken over, copies share parts), who may do what (`access`: `Rights`, `FileAccess`, `View` from `file_access`) – every change takes the `FileAccess` of whoever acts –, WebDAV locks (`locks`), the journal (`changes`), vaults – what lies in one stays in it, names there are encrypted – and their members' wrapped keys (`vault`, RFC 0006, 6); every change `NOTIFY`s `kernoid_mail` |
| `kernoid-jmap` | mail, groupware, files, identity | `Jmap`: JMAP Core and Mail (RFC 0002, 11.1) on the mail store – the session object, requests with result references (`request`), `Mailbox/*` (`mailbox`), `Email/get`/`parse` (`email`), `Email/query` (`query`, in kernoid, not SQL), `Email/set`/`import` (`email_set`, built with mail-builder), threads, identities, submissions, snippets (`other`), blobs (`blob`); JMAP for Contacts (`contacts`) and Calendars (`calendars`) on `kernoid-groupware`, JSContact and JSCalendar through calcard (`js`; single events are wrapped in a `Group` for calcard); JMAP for files (`files`, draft-ietf-jmap-filenode-19: `FileNode/*` with rights and `shareWith`, kernoid's `FileVersion/get`, direct writes, downloads in ranges), principals (`principals`, RFC 9670), kernoid's end-to-end extension (`openpgp`: `OpenPgpKey/*`, `E2eSettings/*`, RFC 0006, 4.3; keys of outside addresses through the server's `KeyDirectory`); a `Caller` says which services the account has – mail methods need `mail`, a file store needs `files` or a grant; HTTP and the push stream are the server's (`jmap.rs`) |
| `kernoid-imap` | config, identity, mail | `Server`: IMAP4rev2/rev1 (RFC 0002, 11.2) and POP3 (11.3, `pop3`) – the protocol taken over from Stalwart's imap-proto (`proto`, as it is), the session (`session`), mailbox names (`folders`) and commands on them (`mailboxes`), the selected mailbox with its updates, `FETCH`, `STORE`, `COPY`/`MOVE`, `EXPUNGE` (`selected`), `ACL` (`acl`), `SEARCH` in kernoid (`search`), flags ↔ keywords (`flags`), what `FETCH` reads from a message (`message.rs`, derived from Stalwart) |
| `kernoid-ldap` | config, identity | `Server`: the directory over LDAPv3 (RFC 0003, 8), read only – messages through ldap3_proto (feature `strict`, else it drops a search's attributes), the session (binds over TLS with `program_login`, StartTLS, Who am I?), the tree of a tenant with filters, scopes and attributes (`tree`, from `Identity::directory`) |
| `kernoid-groupware` | mail, store | `Groupware`: calendars and contacts of each account (RFC 0004) in its mail store (`kernoid_mail::StoreChange`: the same row, modseq and quota) – calendars and events (`calendar`, `event`), address books and contacts (`addressbook`, `contact`), iCalendar/vCard parsed and indexed with calcard (`ical`; the span of an event's instances as a `tstzrange`), content sealed with the tenant's key in PostgreSQL, the journal for JMAP and DAV sync (`changes`), levels of access from `collection_access` (`access`), calendar users (`principal`), import and export (`transfer`), encrypted collections – their entries the apps' OpenPGP messages, refused as plain iCalendar or vCard (`sealed`, RFC 0006, 7); scheduling (RFC 0004, 7): iTIP logic taken over from Stalwart (`scheduling`, as it is), applied to the store (`itip`), sent as iMIP through the queue or delivered at once to local accounts (`send`), notifications (`notification`) |
| `kernoid-dav` | groupware | `Dav`: CalDAV and CardDAV (RFC 0004, 8.1) – the protocol taken over from Stalwart's dav-proto (`proto`, as it is, its test requests in `resources/`), paths (`path`), what a path names with the user's level (`node`), properties (`props`), the server (`server`), query filters, partial retrieval and free/busy (`query`, derived from Stalwart), the scheduling outbox (`schedule`) |
| `kernoid-module` | store, events | `Module` trait, `Registry` (from `[modules.<name>]`), `Context` (with `Sessions`: the core's logins for a module's routes) |
| `kernoid-jitsi` | module | the module `jitsi`: meetings (`jitsi_rooms`), HS256 tokens for Jitsi Meet, routes below `/modules/jitsi/` that know who is logged in through `kernoid_module::Sessions` (`kernoid_server::ModuleSessions`) |
| `kernoid-clamav` | module, store | the module `clamav`: `ClamAv`, a client of clamd's `INSTREAM` protocol and the `kernoid_store::scan::Scanner` the process sets on its blob store |
| `kernoid-server` | config, store, identity, oidc | router with REST + OpenAPI (utoipa), GraphQL (async-graphql; `graphql/admin.rs`), the administration routes (`admin/`, extractor `AdminSession`, header `kernoid-tenant`), SCIM 2.0 (`scim.rs`), mail administration for REST and GraphQL (`mail_admin.rs`, `admin/mail.rs`, `graphql/mail.rs`), CalDAV and CardDAV over HTTP (`dav.rs`, logging in like JMAP with `jmap::MailCaller`), registration (`registration.rs`), logins and services (`admin/logins.rs`, `graphql/logins.rs`), identity provider endpoints (`federation.rs`), `openapi()`, `graphql_schema()`, problem details, request ids, metrics, trusted-proxy `Client`; `serve` (plain or TLS), `serve_with` and `acme` (certificates from an ACME CA, kept in PostgreSQL, served by SNI), `certificate_files` (the mail protocols' certificates from files, `mail.tls`, read again when they change), files administration – quotas, drives, grants (`files_admin.rs`, `admin/files.rs`, `graphql/files.rs`), WebDAV for files at `/webdav/` (`webdav.rs`, XML through `kernoid_dav::proto`); the Web Key Directory, served and asked (`wkd.rs`, RFC 0006, 4.4); uploads, direct writes and WebDAV have their own body limit and timeout (transfers) |
| `kernoid` | all | CLI (`serve`, `migrate`, `openapi`, `graphql-schema`, `keys`, `instance`, `tenant`, `account`, `project`, `app`, `signing-key`, `acme`, `mail`, `collections`, `files`), logging and OTLP traces, roles `api`, `worker` (every worker job safe in several processes), `smtp`, `imap` and `ldap`, one shutdown for all tasks; `MODULES` lists the compiled-in modules |

`web/` (pnpm workspace, MIT; Node 26, TypeScript 7) holds the TypeScript SDK (`web/sdk`, `@kernoid/sdk`, no runtime
dependencies), the login UI (`web/login`) and the web app (`web/app`: mail, calendar, contacts and files over JMAP; the
account and the administration over the REST API, typed from `docs/_data/openapi.json` with openapi-typescript and
openapi-fetch – `pnpm --filter @kernoid/app run api`, checked in CI), both Vite + Svelte 5 without SvelteKit. kernoid
embeds the builds (rust-embed, `login_ui.rs`) and serves them at `/login` and `/app`; `http.login_ui`/`http.web_app`
name a directory to serve instead (development). The image builds them in a Node stage before the binary. They talk to the server only through the API – never import
server code, and keep dependencies exact (`package.json` without ranges, `pnpm-lock.yaml`), at least two weeks old
(`minimumReleaseAge` in `pnpm-workspace.yaml`) – except the smallest version that fixes a security advisory, taken at
once as for crates (an `overrides` entry, named with the advisory in the commit) –, without install scripts of
dependencies (pnpm's default).

`apps/client` (MIT) is kernoid's Rust SDK `kernoid-client`, async on tokio with reqwest (rustls on AWS-LC, post-quantum
key exchange preferred): the session, method calls, uploads, downloads and push (`lib.rs`, `push.rs`); mail with
threads, files with versions, sharing and links, calendars with scheduling, contacts (`mail`, `files`, `calendars`,
`contacts`); end-to-end encrypted mail on `kernoid-e2e` (`e2e`); finding the server through `_jmap._tcp` (`srv`, DNS
messages by hickory-proto, over tokio's sockets); iCalendar and vCard files through calcard (`transfer`); logging in with OpenID Connect as kernoid's apps do –
PKCE, the built-in client of the apps, the scope `urn:kernoid:data`, refresh (`oidc`; `Client::connect_with_token`,
`set_access_token`). Tests run
against a recording HTTP server (`tests/`). A **Cargo workspace of its own** with its own `Cargo.lock`, not a member of
the server's: the server's workspace sets `license = "AGPL-3.0-or-later"` for its crates and shares one lock file, and
a member could depend on `kernoid-*` by a path without anyone noticing – apart, the SDK cannot reach server code at
all. Its requirements are minimum versions, as a library's; its `Cargo.lock` pins them (at least two weeks old,
`apps/tui/scripts/check-age.py --dir=apps/client`). It logs in with HTTP Basic (an address and an app password) and
sends the credentials only to the origin it logged in to. It is on crates.io with `kernoid-e2e` and `kernoid-sync`, released
with kernoid in the same version (`cargo publish` in `apps/e2e`, then `apps/client`, then `apps/sync`); the apps of
`kernoid/apps` take it from there.

`apps/sync` (MIT) is `kernoid-sync`, the file sync of kernoid's apps on the SDK: one round (`Folder::sync`) reads the
store's changes (`FileNode/changes`, the whole store when the state is too old), scans the folder (size and modification
time) and decides in `plan` – a pure function with the tests of every case – what to carry over; a change on both sides
keeps the local version as a copy beside the server's. Its state is SQLite through rusqlite (bundled) outside the folder
(`state`). A workspace of its own like the SDK, minimum versions with a lock file. `scripts/client-check.sh` runs the
SDK's and its tests against a real kernoid (this checkout's binary, a fresh database, objects in memory) – CI does in
the job `rust`.

`apps/tui` (AGPL) is the terminal app `kernoid-tui` (ratatui; `docs/tui.md`) on the SDK: what the user writes in their
editor – messages (`src/compose.rs`), events and contacts (`src/forms.rs`) – is a library with tests; the screen is
`src/app.rs` (state and keys) and `src/ui.rs` (drawing). The SDK's calls run on a runtime of the app's own
(`kernoid_tui::RUNTIME`): the screen waits for each with `block`, the push stream and transfers run on it in the
background. A **Cargo workspace of its own** like the SDK – its dependencies are its own (and stay out of the server's
image: `.dockerignore`), and CI checks it in a job of its own. The password comes from `KERNOID_PASSWORD`, a command or
a prompt, never an argument. Dependencies are exact (`=` in `Cargo.toml`) and at least two weeks old when taken –
`apps/tui/scripts/check-age.py [--fix]` lists the younger ones in `Cargo.lock` (and sets them back); run it after
changing the lock file.

`apps/e2e` (MIT) is the end-to-end library of kernoid's apps (`kernoid-e2e`, RFC 0006): an account's OpenPGP key of
one of two kinds (`pqc`: v6 with ML-DSA-65+Ed25519 and ML-KEM-768+X25519, RFC 9980; `compatible`: v4 Curve25519), its
protected copies (Argon2 with AES-256-OCB), encrypting and decrypting (`message`), PGP/MIME with header protection and
the encrypted summary (`mime`) – all through rpgp (crate `pgp`, feature `pqc`), nothing of its own. A **Cargo workspace
of its own** like the terminal app; `--features wasm` gives the web app's `Keyring` (`src/wasm.rs`), which
`scripts/build-wasm.sh` turns into `web/e2e/dist` (`@kernoid/e2e`, not checked in; CI's job `e2e` and the image's
stage `e2e` build it with wasm-bindgen-cli of the version in its `Cargo.lock`). Homebrew's Rust has no WebAssembly
target – build with rustup's (`PATH=$HOME/.cargo/bin:$PATH`). Its `deny.toml` ignores three advisories of rpgp's
dependencies, each with the reason it does not reach kernoid's keys.

`operator/` (AGPL) is the Kubernetes operator `kernoid-operator` (kube-rs; docs: Operations, Kubernetes): the resource
`Kernoid` (`crd.rs`), what it becomes – a migration Job per image, a Deployment and Service per role – as pure
functions with tests (`resources.rs`), and the loop that applies them server-side (`controller.rs`). It is a **Cargo
workspace of its own**, like the terminal app: kube's dependencies and the mail libraries need versions of the same
crates that do not go together (smallvec), and the server need not carry the Kubernetes client. The image builds it
beside `kernoid` (`/usr/local/bin/kernoid-operator`). `deploy/kubernetes/crd.json` comes from `kernoid-operator crd`,
and CI checks it is current – the Helm chart `deploy/helm/kernoid-operator` carries a copy in `crds/`, which CI
compares too, and lints the chart. Dependencies are exact and at least two weeks old
(`apps/tui/scripts/check-age.py --dir=operator`).

The documentation site lives in `docs/` (GitHub Pages, Jekyll with Just the Docs); `docs/_data/openapi.json` and
`docs/api/schema.graphql` come from `kernoid openapi` and `kernoid graphql-schema`, and CI checks they are current –
regenerate them when the API changes, and update the pages with the code.

Design decisions are written down as RFCs in `rfcs/` (CC BY 4.0); [0001](rfcs/0001-data-and-event-model.md) covers
instances, tenants, aggregates, events, consistency, keys, login and APIs, [0002](rfcs/0002-mail-data-model.md) the
mail store, [0003](rfcs/0003-accounts-logins-services.md) accounts, logins and services, [0004](rfcs/0004-calendars-and-contacts.md)
calendars and contacts, [0005](rfcs/0005-files.md) files, [0006](rfcs/0006-end-to-end-encryption.md) post-quantum
and end-to-end encryption, [0007](rfcs/0007-push-notifications.md) push notifications. Change the RFC with the code.

## Rules

- **Only PostgreSQL and S3.** No further service may become a requirement (whitepaper, Data). Object storage is
  any S3-compatible service; Compose uses Garage, and `crates/kernoid-store/tests/s3.rs` runs against it.
- **SQL only through sqlx's checked macros** (`query!`, `query_as!`, `query_scalar!`): literal statements, values
  only as bound parameters, checked against the schema at build time. The unchecked functions and `QueryBuilder` are
  forbidden in `clippy.toml`; tests that need them (tables that exist only in the test) allow it per file, with a
  reason. After changing a query, run `cargo sqlx prepare --workspace -- --all-targets` and commit `.sqlx/`.
- **Two database roles.** The owner runs migrations; the runtime role serves with only what
  `kernoid_grant_runtime` gives it. A migration that adds a table replaces that function with the complete list of
  grants – least privilege: no `UPDATE`/`DELETE` unless the runtime truly needs it. Connections carry a statement
  timeout and an idle-in-transaction timeout.
- **Mail is data, not events** (RFC 0002): mailboxes, emails and threads are tables changed in transactions that
  take the account's `mail_accounts` row first and record each change in `mail_changes` under the next `modseq`.
  What an administrator decides about mail (quotas, later permissions) is an event. An object is written only after
  `garbage::pending` named it, and the transaction that needs it calls `garbage::keep`; removing an email marks its
  object with `garbage::mark` – object storage is not transactional. **Files** (RFC 0005) are data the same way, in
  their own store (`file_accounts`, `file_changes`) – an account may have files without mail; their content goes
  through `parts` (never whole into memory), and whoever changes a store does it with their `FileAccess`.
- **Content goes through `BlobStore`** and is sealed with the tenant's key (`crypto`: XChaCha20-Poly1305 in STREAM
  chunks, bound to path and key number). Nothing else writes to object storage. Tenant keys live wrapped in
  `tenant_keys`, never in events. Do not invent cryptography: change `crypto` only with review.
- **Modules** (connections to one particular outside service, e.g. Jitsi) live in this repository, are compiled in,
  off by default and switched on per installation and per tenant; a module that is off opens no ports and runs no
  jobs. A module that must act inside a core path does so through a hook of the core crate (as `kernoid_store::scan`
  for `clamav`) that `main` sets from the module – core crates never depend on module crates. There is no way to load foreign code into the process: others integrate from outside through actions and
  hooks (planned before 1.0), which see a public, versioned set of events – never the internal ones.
- **HTTP:** every API operation exists in REST (with `#[utoipa::path]`, so it appears in `/openapi.json`) and in
  GraphQL, with the same permission checks – which live in one place: the `admin_*` functions of `kernoid-identity`
  and `kernoid-oidc` take an `Admin` and check its permissions; handlers only translate. Errors are `Problem`s –
  never internal details in a response. Read the host and client address only from `Client` (it believes forwarded
  headers only from `trusted_proxies`); never build links from the request's host. The routes of a module (below
  `/modules/<name>/`) are its own and documented in `docs/modules.md`.
- **Projections** derive state from events and move their cursor in the same transaction (`projection::Runner`);
  they write only to their own tables.
- **Credentials never go into events** (password hashes, session tokens, client secrets, codes, access and refresh
  tokens, private keys, TOTP secrets, passkey public keys and counters): they live in their own tables,
  written in the transaction of an event that only says they changed. Login failures are one indistinguishable
  `InvalidCredentials`; secrets are read from stdin, never from command-line arguments.
- **No events from unauthenticated requests.** Anything an anonymous caller can trigger (failed logins, throttling)
  is counted in tables, not written as events. Commands called from handlers must be `Send`: inline projections are
  `|c, e| Box::pin(async move { … })` with owned data (`kernoid_events::inline` for stored closures).
- **Every event has `instance_id` and `owner`** (the tenant, or the instance for instance-wide aggregates); tenant
  ids and instance ids are UUIDv7. Requests find their instance with `CurrentInstance` (by host, see RFC 0001).
- **Identity and administration are events.** State is derived from `kernoid-events`; the `events` table is
  append-only (enforced by triggers). Keep transactions short – an open transaction holds back readers of all events.
- **Migrations** live in `crates/kernoid-store/migrations`, are never edited once released, and run with
  `kernoid migrate`, not on start.
- **Secrets** are `kernoid_config::Secret` and never logged.
- **Licences:** every file carries `SPDX-License-Identifier` (own code `AGPL-3.0-or-later`); files without a header are
  covered in `REUSE.toml`. Code taken over from Stalwart keeps `AGPL-3.0-only` plus its copyright and a note of its
  origin; its header `AGPL-3.0-only OR LicenseRef-SEL` becomes `AGPL-3.0-only`. Nothing under `LicenseRef-SEL` – no
  file, no `SPDX-SnippetBegin` section – ever enters; `scripts/check-sel.sh` enforces it. Code written while reading
  Zitadel's source is marked as derived from Zitadel and is `AGPL-3.0-only`.
- **Commits** are signed off (`git commit -s`, DCO).
- **XML signatures only through bergshamra** (SAML): no own XML-DSig, canonicalisation or certificate parsing; DTDs
  are refused before parsing, and what kernoid reads comes from the tree bergshamra verified.
- **TLS prefers post-quantum key exchange** (RFC 0006, 2): every `rustls` dependency – here, in the terminal app and
  in the operator – takes the feature `prefer-post-quantum` with AWS-LC, and no TLS uses ring;
  `crates/kernoid-server/tests/tls.rs` checks it.
- **Outbound requests** to addresses tenants configure go through `kernoid_oidc::outbound` (HTTPS, public addresses
  only, checked for DNS and redirects) – never through a client of one's own. MTA-STS policies use its client
  without redirects; SMTP connections of the queue go only to public addresses (`outbound::is_public`).
- **iCalendar and vCard only through calcard** – parsing, writing, recurrences, JSCalendar and JSContact; no own
  parsers of these formats. calcard 0.3.14 reads a UTC start as local time in the default time zone when it expands recurrences:
  `ical::expansion_tz` works around it.
- **Mail authentication only through mail-auth** (SPF, DKIM, DMARC, ARC, iprev) and SMTP parsing only through
  smtp-proto, Sieve only through sieve-rs – no own parsers of these records, signatures or protocols.
- **WebAuthn only through webauthn-rs** – no own parsing of WebAuthn, CBOR or COSE. It needs OpenSSL (`pkg-config`,
  `libssl-dev` to build; the distroless runtime image has `libssl`).
- **Exact versions everywhere:** container images by full tag (`postgres:18.6-alpine3.24`) or by digest where
  there is no tag, GitHub Actions by commit with the version as a comment, Rust via `rust-toolchain.toml`, crates
  via `Cargo.lock` (CI and the image build with `--locked`). New versions are at least two weeks old – except the
  smallest version that fixes a RustSec advisory, taken at once and named with the advisory in the commit (and in
  `SECURITY_FIXES` of `apps/tui/scripts/check-age.py`). `cargo deny check` (`deny.toml`, `apps/tui/deny.toml`) fails
  on known vulnerabilities, licences that do not fit (permissive only for the MIT apps) and sources besides
  crates.io; an advisory that does not affect kernoid is ignored there with a reason.
- Facts need a source; what is not settled is marked `OPEN`.

## The falkOSS starter pack

kernoid follows [falkoss/starterpack](https://github.com/falkoss/starterpack) (`docs/practices.md`): its own
organisation with `.github`, `website`, `brand` (the brand kit – copies of its artwork here are CC BY-ND 4.0),
`whitepaper` and this repository; SPDX and REUSE everywhere, the starter pack's REUSE, DCO and Jekyll workflows
pinned by commit, CI on Linux and macOS. Where kernoid deviates, it has a reason:

- **The software's shape.** Not `core`/`store`/`app`/`api`/`tui` crates but one crate per part of the system
  (identity, mail, files, the protocols, modules) behind roles – kernoid replaces two existing servers and runs as
  separately scaled processes. GraphQL besides REST: decided for the administration API.
- **The apps.** The web app talks JMAP for mail, calendar, contacts and files – only its administration takes types
  from OpenAPI. The Rust SDK (`apps/client`, MIT) and the terminal app on it (`apps/tui`, AGPL) are workspaces of their
  own, not crates of the server: they must not reach server code, and the SDK may go into app stores with the apps.
- **Files where tools need them.** The API descriptions are in `docs/` (`_data/openapi.json`, `api/`) – Jekyll cannot
  read outside its folder – under MIT as the starter pack's `api/openapi.json` would be; Compose is in
  `deploy/compose/` beside Kubernetes and the test VM.
- **macOS CI** takes PostgreSQL from Homebrew, its major version pinned: macOS runners have no containers.

## Checks

```sh
cargo fmt --check && cargo clippy --all-targets && cargo test   # tests need DATABASE_URL, see README
(cd apps/client && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked)
(cd apps/sync && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked)
scripts/client-check.sh   # the SDK and kernoid-sync against this checkout's kernoid (DATABASE_URL, psql)
(cd apps/tui && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked)
(cd operator && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked)
(cd apps/e2e && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked && scripts/build-wasm.sh)
scripts/upgrade-check.sh v0.1.0 kernoid:local   # after `docker build -t kernoid:local .`
./scripts/check-sel.sh
cargo deny check && (cd apps/client && cargo deny check) && (cd apps/sync && cargo deny check) && (cd apps/tui && cargo deny check) && (cd operator && cargo deny check) && (cd apps/e2e && cargo deny check)    # cargo-deny 0.20.2
docker run --rm -v "$PWD":/data fsfe/reuse:6.2.0 lint
```
