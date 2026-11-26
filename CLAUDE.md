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
| `kernoid-config` | – | `Config`, `Role`, `Services` (RFC 0008, 4: what an installation runs, checked against `[smtp]`, `[imap]` and `[blob]`), `Secret` |
| `kernoid-sieve` | – | the Sieve interpreter, kernoid's own, written from the RFCs (not from Stalwart's): `lexer` and `parser` (the grammar of RFC 5228, errors with line and column), `compile` (commands and tests checked against their definitions and the required capabilities), `run` (actions, implicit keep, limits of work, actions, redirects and variables), `matching` (comparators, match types, wildcards with match variables), `message` (what tests read, through kernoid-mime), `vacation` (whom to answer, the reply built with kernoid-mime); `CAPABILITIES` lists what `require` takes; what it asks of the world goes through `Environment` |
| `kernoid-store` | config | PostgreSQL pool, `MIGRATOR` (all migrations, one history), `migrate` (owner → runtime grants), `BlobStore` (object storage through the kit's own client `kernoid_blob::objects` – in memory or S3 –, or PostgreSQL's `blob_objects` for identity alone – `[blob] kind = "database"`, `BlobStore::open`), `TenantKeys`, `crypto`, `lock` (advisory locks for work one process does at a time), `garbage` (objects to remove once nothing needs them), `parts` (content of any size streamed in sealed parts of 8 MiB), `scan` (the hook of a malware scanner: content of tenants that switched its module on is scanned as `parts` stores it, mail with `check_bytes` before it is accepted) |
| `kernoid-events` | sqlx | `EventStore`: append with expected sequence, load an aggregate, read all by cursor; `projection::{Projection, Runner}` |
| `kernoid-identity` | events, store | `Identity`: instance, tenant and account aggregates with inline read models (`instances`, `instance_domains`, `tenants`, `tenant_domains`, `tenant_modules`, `accounts`, `addresses`), `account_passwords`, `DomainName`, `Address`, DNS verification (`TxtLookup`), `authenticate`, sessions, TOTP (`mfa`, with kernoid's own QR encoder `mfa::qr`, ISO/IEC 18004), certificates and certificate requests kernoid makes – the SAML key's, ACME's, those of tests (`certificate`: x509-cert structures signed with aws-lc-rs; it builds, never checks), passkeys (`passkey`: WebAuthn verified by kernoid – `webauthn`, `cbor`; `soft`, a software passkey for tests, feature `soft-passkey`), groups (`group`), roles and permissions (`role`: built in, a tenant's own, instance roles), projects and authorizations (`project`), app passwords and mail logins (`app_password`), shared mailboxes, grants on mail and quotas (`mail_access`), files quotas, drives and grants on files (`files_quota`), logins by address, username or contact address (`login`), services and their rules (`services`), registration (`registration`), end-to-end encryption (`openpgp`, RFC 0006: accounts' OpenPGP keys and the protected copies of their secret keys – read through `kernoid-e2e` –, mail encrypted on arrival, the tenant's policy and recovery key, what WKD serves), administration with permission checks (`admin`, used by REST and GraphQL alike) |
| `kernoid-auth` | – | logging in with kernoid – or any OpenID provider – for other programs' servers (RFC 0009, 2; AGPL, on crates.io): `relying` (PKCE login, ID, access and logout tokens, `Principal` with kernoid's `urn:kernoid:tenant` and project roles), `sessions` (`Sessions`, `MemorySessions`), `web` (axum routes `/auth/*`, `Authenticated`, CSRF as kernoid's); and the client of OpenID providers kernoid itself uses: `provider` (discovery, keys, code exchange, JWS checked with aws-lc-rs) and `outbound` (HTTPS to public addresses only) – `kernoid_oidc` re-exports both as `external` and `outbound` |
| `kernoid-relay` | store; kit's base, crypt | the relay of the foundation (RFC 0010, 4): `Relay` (member records, envelopes – large ones through `BlobStore` with garbage –, requests to join, in `relay_*`; one writer per space with `FOR UPDATE`), `router` below `/relay/{scheme}/v1/spaces/{space}/…` (aktujo's protocol) and protocol 2, streams (`v2`, RFC 0012: the roster, streams by identity with the hashes of their tokens, records, originals, follow, purge – a space is of one protocol), `Founders` (who founds a space – kernoid-server's `relay::AccountFounders`), `spaces`/`remove_space` for the administration |
| `kernoid-node` | store; kit's base, crypt, log, spaces (without SQLite) | a server as one more node of spaces of streams (RFC 0010, 8): `Node`, kernoid-spaces' `StreamBackend` in PostgreSQL (`node_*`, one database for several nodes by name) – the state with the node's seed, stream keys and the events read sealed under the node's key with `crypto::seal_secret`, bound to node, space, stream and kind; the engine (`Streams<Node>`) is synchronous and runs in `spawn_blocking`, the queries wait through the runtime's handle |
| `kernoid-oidc` | auth, events, identity, store | `Oidc`: applications (aggregate, in a project), admin functions with permission checks (`admin`), external identity providers of a tenant or the whole instance (`federation`: OpenID Connect via `external` – kernoid-auth's `provider` –, SAML 2.0 via `saml` with kernoid's SAML key, encrypted assertions and single logout – its XML kernoid's own: `saml/dom.rs` (the tree on quick-xml), `c14n.rs` (Exclusive XML Canonicalization), `xmldsig.rs` (enveloped signatures, verified and made), `xmlenc.rs` (EncryptedAssertion), `keys.rs` (certificates through x509-cert, algorithms, signing)), outbound requests only to public addresses (`outbound`, kernoid-auth's), signing keys (one aggregate per instance), authorize → finish/decline → token (code, refresh with rotation) → userinfo, revoke, end_session, discovery, JWKS, `clean_up` |
| `kernoid-mail` | store | `Mail`: the mail store of each account (RFC 0002) – mailboxes with roles and IMAP UIDs, emails imported with kernoid-mime (raw message sealed in object storage, summary in PostgreSQL), threads (`thread`: a shared message id and the same base subject, never merged), keywords, quotas, the journal of changes (`changes`) for JMAP and IMAP, who may use whose mail (`access`: `Rights`, `Access` from the grants in `mail_access`), full-text search and retention (`search`), mbox (`mbox`), delivery of incoming mail (`deliver`: recipients, duplicates) and Sieve (`scripts`, kernoid-sieve), the queue of outgoing mail (`outbox`, which adds Autocrypt), encryption on arrival and of mail stored before (`e2e`, RFC 0006, 5.2, through `kernoid-e2e`), uploads, and `MailEvents` (PostgreSQL `LISTEN` on `kernoid_mail`, which every change `NOTIFY`s) |
| `kernoid-smtp` | config, identity, mail, oidc, groupware (all with the feature `server`, by default) | `client` (always): the queue's deliveries and `submit`, kernoid's own messages through `mail.notification_relay` where kernoid keeps no mail, so that identity alone – `kernoid-server` takes the crate without `server` – sends codes; `Server`: the MX (RFC 0002, 9) and submission (10.1, `submission.rs`) – the protocol, kernoid's own (`proto`: commands with their parameters – `request` –, the message after `DATA` – only CRLF.CRLF ends it – and `BDAT` – `data` –, replies and `EHLO` – `reply`, which the client reads), the session (`session.rs`, its states – commands, `DATA`, `BDAT`, `AUTH` – fed by `proto`'s receivers), the checks, kernoid's own (`auth`: `spf` with macros and the lookup limits, `dkim` verifying and signing – RSA-SHA256, Ed25519-SHA256, `rsa-sha1` is `policy` –, `dmarc` with DMARCbis's tree walk instead of a public suffix list, `arc` validating and sealing, `iprev`, `results` writing `Authentication-Results` and `Received-SPF`, on `tags` and `message` – raw header fields and their canonical forms; signatures through aws-lc-rs), `dns` (hickory's resolvers – one validating DNSSEC – with caches tests fill), headers and delivery (`message.rs`), the basic spam filter (`spam`), invitations in delivered mail handed to `kernoid-groupware` when DMARC passed or the sender is logged in; sending (10): `outbound` (the worker delivering the queue, with the client `client.rs`), `dkim` (keys and signing), `mta_sts` and `dane`, `dsn` (bounces), `dns_check`.|
| `kernoid-files` | store | `Files`: the file store of each account and drive (RFC 0005) – its own store beside the mail store (`file_accounts`: row, modseq, quota), directories and files in `file_nodes` with names unique among siblings and a depth of at most 64 (`node`), the Trash made at the first use, contents and versions in `file_contents` stored in parts (`content`, `kernoid_store::parts`; uploads taken over, copies share parts), who may do what (`access`: `Rights`, `FileAccess`, `View` from `file_access`) – every change takes the `FileAccess` of whoever acts –, WebDAV locks (`locks`), the journal (`changes`), vaults – what lies in one stays in it, names there are encrypted – and their members' wrapped keys (`vault`, RFC 0006, 6), and vaults on spaces, whose directory only names a space of the relay and holds nothing (`space_id`, RFC 0010, 5; destroyed, the worker removes the space through `relay_space_removals`); every change `NOTIFY`s `kernoid_mail` |
| `kernoid-jmap` | mail, groupware, files, identity | `Jmap`: JMAP Core and Mail (RFC 0002, 11.1) on the mail store – the session object, requests with result references (`request`), `Mailbox/*` (`mailbox`), `Email/get`/`parse` (`email`), `Email/query` (`query`, in kernoid, not SQL), `Email/set`/`import` (`email_set`, built with kernoid-mime), threads, identities, submissions, snippets (`other`), blobs (`blob`); JMAP for Contacts (`contacts`) and Calendars (`calendars`) on `kernoid-groupware`, JSContact and JSCalendar through kernoid-pim (`js`; patches through `kernoid_pim::jmap`); JMAP for files (`files`, draft-ietf-jmap-filenode-19: `FileNode/*` with rights and `shareWith`, kernoid's `FileVersion/get`, direct writes, downloads in ranges), principals (`principals`, RFC 9670), kernoid's end-to-end extension (`openpgp`: `OpenPgpKey/*`, `E2eSettings/*`, RFC 0006, 4.3; keys of outside addresses through the server's `KeyDirectory`); a `Caller` says which services the account has – mail methods need `mail`, a file store needs `files` or a grant; HTTP and the push stream are the server's (`jmap.rs`) |
| `kernoid-imap` | config, identity, mail | `Server`: IMAP4rev2/rev1 (RFC 0002, 11.2) and POP3 (11.3, `pop3`), all kernoid's own – the protocol (`proto`: commands cut from the bytes with their literals and limits in `frame`, the parser `parse` into `request`, sequence sets, modified UTF-7, the writer of responses `response`), the session (`session`), mailbox names (`folders`) and commands on them (`mailboxes`), the selected mailbox with its updates, `FETCH`, `STORE`, `COPY`/`MOVE`, `EXPUNGE` (`selected`), `ACL` (`acl`), `SEARCH` in kernoid (`search`), `SORT`, `THREAD` and quotas (`sort`), flags ↔ keywords (`flags`), what `FETCH` reads from a message – envelope, structure, sections, `BINARY` (`message.rs`) |
| `kernoid-ldap` | config, identity | `Server`: the directory over LDAPv3 (RFC 0003, 8), read only – messages in BER, kernoid's own (`proto`: both directions, `Codec` for tokio-util), the session (binds over TLS with `program_login`, StartTLS, Who am I?), the tree of a tenant with filters, scopes and attributes (`tree`, from `Identity::directory`) |
| `kernoid-groupware` | mail, store | `Groupware`: calendars and contacts of each account (RFC 0004) in its mail store (`kernoid_mail::StoreChange`: the same row, modseq and quota) – calendars and events (`calendar`, `event`), address books and contacts (`addressbook`, `contact`), iCalendar/vCard parsed and indexed with kernoid-pim (`ical`; the span of an event's instances as a `tstzrange`), content sealed with the tenant's key in PostgreSQL, the journal for JMAP and DAV sync (`changes`), levels of access from `collection_access` (`access`), calendar users (`principal`), import and export (`transfer`), encrypted collections – their entries the apps' OpenPGP messages, refused as plain iCalendar or vCard (`sealed`, RFC 0006, 7); scheduling (RFC 0004, 7): implicit scheduling and iTIP as pure functions on kernoid-pim's components (`scheduling`, kernoid's own), applied to the store (`itip`), sent as iMIP through the queue or delivered at once to local accounts (`send`), notifications (`notification`) |
| `kernoid-dav` | groupware | `Dav`: CalDAV and CardDAV (RFC 0004, 8.1) – the protocol, kernoid's own from the RFCs (`proto`: request bodies read through quick-xml into typed requests – DTDs refused, size and depth bounded –, responses with their preconditions, WebDAV's headers; the files' WebDAV of `kernoid-server` uses it too), paths (`path`), what a path names with the user's level (`node`), properties (`props`), the server (`server`), query filters, partial retrieval and free/busy (`query`, kernoid's own, on kernoid-pim; the names of components, properties and parameters in requests are `proto/names.rs`), the scheduling outbox (`schedule`) |
| `kernoid-module` | store, events | `Module` trait, `Registry` (from `[modules.<name>]`), `Context` (with `Sessions`: the core's logins for a module's routes) |
| `kernoid-jitsi` | module | the module `jitsi`: meetings (`jitsi_rooms`), HS256 tokens for Jitsi Meet, routes below `/modules/jitsi/` that know who is logged in through `kernoid_module::Sessions` (`kernoid_server::ModuleSessions`) |
| `kernoid-clamav` | module, store | the module `clamav`: `ClamAv`, a client of clamd's `INSTREAM` protocol and the `kernoid_store::scan::Scanner` the process sets on its blob store |
| `kernoid-server` | config, store, identity, oidc, web; with the features `mail`, `calendars`, `files` (default) the service crates | router with REST + OpenAPI (utoipa) – the routes of each service apart (`rest`, `rest_mail`, `rest_calendars`, `rest_files`), only those of the installation's services served (`AppState::services`, `GET /v1/services`; GraphQL's fields of a service that is off answer `SERVICE_OFF`) –, GraphQL (async-graphql; `graphql/admin.rs`), the administration routes (`admin/`, extractor `AdminSession`, header `kernoid-tenant`), SCIM 2.0 (`scim.rs`), mail administration for REST and GraphQL (`mail_admin.rs`, `admin/mail.rs`, `graphql/mail.rs`), CalDAV and CardDAV over HTTP (`dav.rs`, logging in like JMAP with `jmap::MailCaller`), registration (`registration.rs`), logins and services (`admin/logins.rs`, `graphql/logins.rs`), identity provider endpoints (`federation.rs`), `openapi()`, `graphql_schema()`, problem details, request ids, metrics (`metrics`: kernoid's own recorder of the `metrics` facade, Prometheus's text format), trusted-proxy `Client`; `serve` (plain or TLS), `serve_with` and `acme` (certificates from an ACME CA, kept in PostgreSQL, served by SNI; the client is kernoid's own, `acme::client`, RFC 8555), `certificate_files` (the mail protocols' certificates from files, `mail.tls`, read again when they change), `jobs` (identity's background work, for the role `worker` and for programs that build kernoid in), `embedded` (kernoid's identity in another program's process, RFC 0009, 3: `Embedded::start`, `router(program)`, the extractor `Session`), `mail_dns` (the DNS check of mail domains behind a trait, so that identity builds without the mail crates); everything of mail, calendars and files behind the feature `data`, which `mail`, `calendars` and `files` turn on – `cargo clippy -p kernoid-server --no-default-features` must stay clean, files administration – quotas, drives, grants (`files_admin.rs`, `admin/files.rs`, `graphql/files.rs`), WebDAV for files at `/webdav/` (`webdav.rs`, XML and headers through `kernoid_dav::proto`); the Web Key Directory, served and asked (`wkd.rs`, RFC 0006, 4.4); uploads, direct writes and WebDAV have their own body limit and timeout (transfers) |
| `kernoid-web` | – | `LOGIN_UI`, `WEB_APP`: the builds of `web/login` and `web/app` as tables of files (`build.rs`, `include_bytes!`; empty without `pnpm build`); in the repository from `web/*/dist`, in the package on crates.io from a copy in `dist/` that `scripts/web-crate.sh` makes when the release is published (without source maps) |
| `kernoid` | all | CLI (`serve`, `migrate`, `openapi`, `graphql-schema`, `keys`, `instance`, `tenant`, `account`, `project`, `app`, `signing-key`, `acme`, `mail`, `collections`, `files`), logging and OTLP traces (`otlp`: kernoid's own exporter, a `tracing` layer sending protobuf over OTLP/HTTP), passwords read without echo (`no_echo`), roles `api`, `worker` (every worker job safe in several processes), `smtp`, `imap` and `ldap`, one shutdown for all tasks; `MODULES` lists the compiled-in modules |

`web/` (pnpm workspace, AGPL – RFC 0008, 6; Node 26, TypeScript 7) holds the TypeScript SDK (`web/sdk`, `@kernoid/sdk`, no runtime
dependencies), the login UI (`web/login`) and the web app (`web/app`: mail, calendar, contacts and files over JMAP; the
account and the administration over the REST API, typed from `docs/_data/openapi.json` with openapi-typescript and
openapi-fetch – `pnpm --filter @kernoid/app run api`, checked in CI), both Vite + Svelte 5 without SvelteKit. kernoid
embeds the builds (`include_bytes!` in the crate `kernoid-web`'s `build.rs`, from `web/login/dist` and `web/app/dist`; served by kernoid-server's `login_ui.rs`) and serves them at `/login` and `/app`; `http.login_ui`/`http.web_app`
name a directory to serve instead (development). The image builds them in a Node stage before the binary. They talk to the server only through the API – never import
server code, and keep dependencies exact (`package.json` without ranges, `pnpm-lock.yaml`), at least two weeks old
(`minimumReleaseAge` in `pnpm-workspace.yaml`) – except the smallest version that fixes a security advisory, taken at
once as for crates (an `overrides` entry, named with the advisory in the commit) –, without install scripts of
dependencies (pnpm's default).

`kit/client` (MIT) is kernoid's Rust SDK `kernoid-client`, async on tokio with reqwest (rustls on AWS-LC, post-quantum
key exchange preferred): the session, method calls, uploads, downloads and push (`lib.rs`, `push.rs`); mail with
threads, files with versions, sharing and links, calendars with scheduling, contacts (`mail`, `files`, `calendars`,
`contacts`); HTML mail as text by kernoid's own converter (`html`, from the HTML standard, linear on any input); the account's everyday settings over kernoid's own API (`account`); end-to-end encrypted mail and vaults on `kernoid-e2e` (`e2e`, `e2e/vault.rs`), vaults on spaces through the foundation's streams (`e2e/spaces.rs`, `Vaults`: their store on the device, members by a recovery code sealed to the account's key, moving an OpenPGP vault onto a space); finding the server through `_jmap._tcp` (`srv`, DNS
messages by hickory-proto, over tokio's sockets); iCalendar and vCard files through kernoid-pim (`transfer`); logging in with OpenID Connect as kernoid's apps do –
PKCE, the built-in client of the apps, the scope `urn:kernoid:data`, refresh (`oidc`; `Client::connect_with_token`,
`set_access_token`). Tests run
against a recording HTTP server (`tests/`).

**The kit** (`kit/`, RFC 0008, 2) is a **Cargo workspace of its own** with one `Cargo.lock` – the SDK, `kernoid-e2e`,
`kernoid-pim`, `kernoid-mime`, `kernoid-sync`, the foundation (RFC 0010: `kernoid-base`, `-blob`, `-log`, `-crypt`, `-spaces` (a device's spaces: their store in SQLite and their synchronisation), taken
over from aktujo 0.4.1) and the Flutter packages of `kit/flutter/` (RFC 0011, `kit/flutter/README.md`; not Cargo
members – the bridge's crate `kit/flutter/kernoid_bridge/rust` is a workspace of its own on the kit by path, with its own
lock and `deny.toml`): everything apps use, all MIT. The server takes the
foundation's crates by path too (`kernoid-relay`); none of its crates may bring SQLite into the server's lock file
(rusqlite and sqlx-sqlite both link `sqlite3`) – the test of `kernoid-spaces` against a relay runs from the kit
(`kit/spaces/tests/server.rs`, through `scripts/client-check.sh`). Not part of the
server's workspace: that one sets `license = "AGPL-3.0-or-later"` for its crates, and a member could depend on a
server crate by a path without anyone noticing; apart, the kit cannot reach server code at all, and
`scripts/kit-check.sh` (CI's job `kit`) checks that every crate is MIT, that no path leads out of `kit/` and that every
file in it says MIT. Its requirements are minimum versions, as a library's; `kit/Cargo.lock` pins them (at least two
weeks old, `tui/scripts/check-age.py --dir=kit`), and `kit/deny.toml` allows only permissive licences. The server
takes `kernoid-e2e`, `kernoid-pim` and `kernoid-mime` from it by path. Streams (RFC 0012) are `kernoid_crypt::stream` (with the hybrid keys of
`kernoid_crypt::pq`), `kernoid_spaces::store::streams` and `kernoid_spaces::streams`; protocol 1 (`Replica`, member
lists and envelopes) stays beside them until every program has moved. The SDK logs in with HTTP Basic (an address and an app password) and sends the
credentials only to the origin it logged in to. The kit's crates are on crates.io, released with kernoid in the same
version (`[workspace.package] version` in `kit/Cargo.toml`) – CI's job `crates` publishes them in the order
`kit/scripts/publish-order.sh` gives on a version tag, through crates.io's trusted publishing (environment
`crates-io`); the apps of `kernoid/apps` take them from there.

`kit/vault` (MIT) is `kernoid-vault`, kernoid's vaults on spaces (RFC 0010, 5) on the foundation's streams: the model
(directories and files as streams, `entry`/`gone`/`version` events) and its operations, synchronous. The SDK runs it
off its runtime; with `--features wasm` (and `--no-default-features`: no reqwest) it is the web app's `WebVaults`, which
`scripts/build-wasm.sh` turns into `web/vault/dist` (`@kernoid/vault`, not checked in) – SQLite is compiled for the
browser by sqlite-wasm-rs, which needs a clang that knows wasm32 and llvm-ar (Apple's ar writes no WebAssembly objects;
the script takes Homebrew's LLVM on macOS). The web app runs it in a worker (`web/app/src/files/space.worker.ts`):
the relay by synchronous requests, the store kept in IndexedDB. kernoid-sync (`Folder::sync_all`) and the terminal app
take a `Vaults` too: a vault's entries become paths of the folder, a file's `version` its blob. On devices the store is
kept sealed (`kernoid_vault::sealed`, `Vaults::open_sealed`) under a key of the system's key store; the file shells'
core (`kernoid_bridge::provider`, `provider/spaces.rs`) is a device of its own, handed its store and the codes with the
login the app keeps for it.

`kit/sync` (MIT) is `kernoid-sync`, the file sync of kernoid's apps on the SDK: one round (`Folder::sync`) reads the
store's changes (`FileNode/changes`, the whole store when the state is too old), scans the folder (size and modification
time) and decides in `plan` – a pure function with the tests of every case – what to carry over; a change on both sides
keeps the local version as a copy beside the server's; moves stay moves (node ids on the server, inodes here), downloads
go on from where they broke off and large uploads go in pieces (`Blob/upload`), vaults are kept in step with the
account's key (`Folder::sync_with`), and names the file system cannot hold are left out (`Names`). Its state is SQLite
through rusqlite (bundled) outside the folder (`state`, upgraded by `PRAGMA user_version`). `scripts/client-check.sh` runs the
SDK's and its tests against a real kernoid (this checkout's binary, a fresh database, objects in memory) – CI does in
the job `rust`.

`tui` (AGPL) is the terminal app `kernoid-tui` (ratatui; `docs/tui.md`) on the SDK: what the user writes in their
editor – messages (`src/compose.rs`), events and contacts (`src/forms.rs`) – is a library with tests; the screen is
`src/app.rs` (state and keys) and `src/ui.rs` (drawing). The SDK's calls run on a runtime of the app's own
(`kernoid_tui::RUNTIME`): the screen waits for each with `block`, the push stream and transfers run on it in the
background. A **Cargo workspace of its own** like the kit – its dependencies are its own (and stay out of the server's
image: `.dockerignore`), and CI checks it in a job of its own. The password comes from `KERNOID_PASSWORD`, a command or
a prompt (read without echo, `src/system.rs`), never an argument. What it asks of the system is its own code in `src/system.rs` – the key store (the Keychain through security-framework, the Credential Manager through windows-sys, elsewhere the Secret Service through kernoid's own synchronous D-Bus client `src/dbus.rs`, tested alone against GNOME Keyring with `rustc --test src/dbus.rs`), the terminal's echo (termios through libc, the console's mode), the download directory; the app's only unsafe code is there (`unsafe_code` is denied elsewhere). Dependencies are exact (`=` in `Cargo.toml`) and at least two weeks old when taken –
`tui/scripts/check-age.py [--fix]` lists the younger ones in `Cargo.lock` (and sets them back); run it after
changing the lock file.

`kit/pim` (MIT) is `kernoid-pim`, kernoid's own library of calendars and contacts, written from the RFCs: content
lines with folding, parameters and quoted-printable (`content`), iCalendar components kept as written (`ical`), times
and durations (`time`), recurrence rules (`recur`) and the instances of an object with its overrides (`expand`), time
zones – IANA, prefixed and Windows names, `VTIMEZONE`s read as POSIX rules and written with yearly `RRULE`s (`tz`) –,
vCard 4.0/3.0/2.1 (`vcard`), JSCalendar and JSContact as JSON with the conversions both ways (`jscalendar`,
`jscontact`) and JMAP's PatchObject (`jmap`). Its only dependencies are jiff and serde_json. The server takes it by
path (`kernoid-groupware`, `-dav`, `-jmap`), the SDK through `transfer`.

`kit/mime` (MIT) is `kernoid-mime`, kernoid's own library of Internet mail, written from the RFCs: messages read
with the byte ranges of every part (`message`: RFC 5322 and MIME, multiparts without their closing delimiter, bare line
feeds, nesting cut at `MAX_DEPTH`), header fields cut and read in their forms (`header`; addresses and groups in
`address`, dates in `date`, encoded words of RFC 2047 in `words`, content types and dispositions with RFC 2231 in
`params`), transfer encodings (`transfer`), charsets (`charset`, encoding_rs's WHATWG charsets and UTF-7; text that is
valid UTF-8 is read as such whatever its label), what a reader shows – text, HTML and attachments as RFC 8621, 4.1.4
chooses them, HTML as text (`body`) –, base subjects (`subject`, RFC 5256 with the markers of other languages) and
messages written (`build`: folding, encoded words, multiparts, attachments, `Date` and `Message-ID`). Its only
dependency is encoding_rs. Part numbers are the order `MessageRef::parts` gives – the top part first, then document
order, a nested message one part – which JMAP's part blob ids (`p-<email>-<n>`) and the apps' `compose::part` depend
on: never change it. The server takes it by path (`kernoid-mail`, `-imap`, `-jmap`, `-sieve`, `-smtp`, `-groupware`,
`-server`), `kernoid-e2e` too.

`kit/e2e` (MIT) is the end-to-end library of kernoid's apps (`kernoid-e2e`, RFC 0006): an account's OpenPGP key of
one of two kinds (`pqc`: v6 with ML-DSA-65+Ed25519 and ML-KEM-768+X25519, RFC 9980; `compatible`: v4 Curve25519), its
protected copies (Argon2 with AES-256-OCB), encrypting and decrypting (`message`), PGP/MIME with header protection and
the encrypted summary (`mime`, messages read with kernoid-mime) – the OpenPGP through rpgp (crate `pgp`, feature `pqc`), nothing of its own. `--features wasm` gives the web app's `Keyring` (`src/wasm.rs`), which
`scripts/build-wasm.sh` turns into `web/e2e/dist` (`@kernoid/e2e`, not checked in; CI's job `kit` and the image's
stage `e2e` build it with wasm-bindgen-cli of the version in the kit's `Cargo.lock`). Homebrew's Rust has no WebAssembly
target – build with rustup's (`PATH=$HOME/.cargo/bin:$PATH`). The kit's `deny.toml` ignores three advisories of rpgp's
dependencies, each with the reason it does not reach kernoid's keys.

`operator/` (AGPL) is the Kubernetes operator `kernoid-operator` (kube-rs; docs: Operations, Kubernetes): the resource
`Kernoid` (`crd.rs`), what it becomes – a migration Job per image, a Deployment and Service per role – as pure
functions with tests (`resources.rs`), and the loop that applies them server-side (`controller.rs`). It is a **Cargo
workspace of its own**, like the terminal app: kube's dependencies and the mail libraries need versions of the same
crates that do not go together (smallvec), and the server need not carry the Kubernetes client. The image builds it
beside `kernoid` (`/usr/local/bin/kernoid-operator`). `deploy/kubernetes/crd.json` comes from `kernoid-operator crd`,
and CI checks it is current – the Helm chart `deploy/helm/kernoid-operator` carries a copy in `crds/`, which CI
compares too, and lints the chart. Dependencies are exact and at least two weeks old
(`tui/scripts/check-age.py --dir=operator`).

The documentation site lives in `docs/` (GitHub Pages, Jekyll with Just the Docs); `docs/_data/openapi.json` and
`docs/api/schema.graphql` come from `kernoid openapi` and `kernoid graphql-schema`, and CI checks they are current –
regenerate them when the API changes, and update the pages with the code.

Design decisions are written down as RFCs in `rfcs/` (CC BY 4.0); [0001](rfcs/0001-data-and-event-model.md) covers
instances, tenants, aggregates, events, consistency, keys, login and APIs, [0002](rfcs/0002-mail-data-model.md) the
mail store, [0003](rfcs/0003-accounts-logins-services.md) accounts, logins and services, [0004](rfcs/0004-calendars-and-contacts.md)
calendars and contacts, [0005](rfcs/0005-files.md) files, [0006](rfcs/0006-end-to-end-encryption.md) post-quantum
and end-to-end encryption, [0007](rfcs/0007-push-notifications.md) push notifications,
[0008](rfcs/0008-suite-and-building-blocks.md) the suite – building blocks, services, licences –,
[0009](rfcs/0009-kernoid-in-other-servers.md) kernoid's identity in other servers, [0010](rfcs/0010-foundation.md) the
foundation of end-to-end encrypted spaces and the relay, [0011](rfcs/0011-app-kit.md) the app kit, [0012](rfcs/0012-streams.md) streams in the foundation. Change the RFC with
the code.

## Rules

- **Only PostgreSQL and S3.** No further service may become a requirement (whitepaper, Data). Object storage is
  any S3-compatible service, reached through kernoid's own client (`kit/blob/src/objects/s3.rs`: Signature Version 4,
  MIT); Compose uses Garage, and `crates/kernoid-store/tests/s3.rs` and the kit's ignored test
  `objects::s3::tests::against_real_object_storage` run against it.
- **SQL only through sqlx's checked macros** (`query!`, `query_as!`, `query_scalar!`): literal statements, values
  only as bound parameters, checked against the schema at build time. The unchecked functions and `QueryBuilder` are
  forbidden in `clippy.toml`; tests that need them (tables that exist only in the test) allow it per file, with a
  reason. The macros read the database from `KERNOID_DATABASE_URL` (every crate's `sqlx.toml`), not `DATABASE_URL` –
  which the tests use at run time and programs building kernoid in may set for their own queries; without it they take
  the offline data. After changing a query, run `cargo sqlx prepare --workspace -- --all-targets` and commit `.sqlx/` – then `scripts/sqlx-crates.sh` (same database) and commit `crates/*/.sqlx`: every crate
  goes to crates.io and builds there outside the workspace, so each carries the queries of its library (all features)
  in its own `.sqlx`; CI runs `scripts/sqlx-crates.sh --check`.
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
  covered in `REUSE.toml`. Since 2026-11-20 no code of Stalwart is left (`CREDITS.md`). Should code be taken over
  again, it keeps its licence (Stalwart's and Zitadel's: `AGPL-3.0-only`, with the licence text back in `LICENSES/`),
  its copyright and a note of its origin; nothing under `LicenseRef-SEL` – no file, no `SPDX-SnippetBegin` section –
  ever enters (`scripts/check-sel.sh`). Code written while reading Zitadel's source is marked as derived from Zitadel
  and is `AGPL-3.0-only`.
- **Names:** a crate is `kernoid-` and one word (`kernoid-spaces`, not `kernoid-space-store`); what does not fit one
  word is a module of a crate.
- **Commits** are signed off (`git commit -s`, DCO).
- **SAML's XML is kernoid's own** (`kernoid_oidc::saml`: `dom`, `c14n`, `xmldsig`, `xmlenc`, `keys`), written from
  W3C XML Signature 1.1, Exclusive XML Canonicalization 1.0, XML Encryption 1.1 and SAML 2.0 – not from bergshamra,
  xmlsec or samael, whose sources are not to be read for it. It accepts a strict profile and refuses everything else:
  no DTD, entities or processing instructions, unique IDs, one enveloped signature per signed element referencing
  exactly that element, exc-c14n, SHA-2, RSA or ECDSA, keys only from the configured certificates, RSA-OAEP with
  AES-GCM (AES-CBC only inside a signed Response). What kernoid reads comes from the very element it verified – never
  found again by name or ID. Signatures and ciphers only through aws-lc-rs, certificates through x509-cert. It is part
  of the external audit before 1.0 – change it only with review, and with attack tests of what it refuses
  (`crates/kernoid-oidc/tests/saml_xml.rs`).
- **TLS prefers post-quantum key exchange** (RFC 0006, 2): every `rustls` dependency – here, in the terminal app and
  in the operator – takes the feature `prefer-post-quantum` with AWS-LC, and no TLS uses ring;
  `crates/kernoid-server/tests/tls.rs` checks it.
- **Outbound requests** to addresses tenants configure go through `kernoid_oidc::outbound` (HTTPS, public addresses
  only, checked for DNS and redirects) – never through a client of one's own. MTA-STS policies use its client
  without redirects; SMTP connections of the queue go only to public addresses (`outbound::is_public`).
- **iCalendar and vCard only through kernoid-pim** (`kit/pim`, MIT) – parsing, writing, recurrences, time zones,
  JSCalendar, JSContact and JMAP patches; no other parsers of these formats, in the server or the SDK. It is
  kernoid's own, written from the RFCs: nothing of calcard, jmap-tools or Stalwart's scheduling enters it (they went
  on 2026-11-20); interoperability fixes come with a test of the file that needed them.
- **Mail authentication and SMTP on the wire are kernoid's own** (`kernoid_smtp::auth`: SPF, DKIM, DMARC, ARC, iprev
  and the headers that report them; `kernoid_smtp::proto`: commands, the message after `DATA`/`BDAT`, replies),
  written from the RFCs – not from mail-auth's or smtp-proto's source – with signatures only through aws-lc-rs and DNS
  only through `kernoid_smtp::Dns`. They are security-relevant and part of the external audit before 1.0: change them
  only with tests – RFC test vectors where the RFC has them, and of what they refuse. Sieve only through kernoid-sieve, which reads
  messages and builds replies through kernoid-mime.
- **Mail messages only through kernoid-mime** (`kit/mime`, MIT) – parsing, header forms, charsets, transfer encodings
  and writing; no other mail parser or builder in the server, the kit or the apps. It is kernoid's own, written from
  the RFCs (nothing of mail-parser or mail-builder), and what kernoid stores or answers from it – IMAP's `ENVELOPE` and
  `BODYSTRUCTURE`, JMAP's properties and part blob ids, search text, base subjects – must stay as it is: a change comes
  with a test of the message that needed it.
- **WebAuthn is kernoid's own** (`kernoid_identity::passkey::webauthn`, with its CBOR decoder `passkey::cbor`), written
  from W3C WebAuthn Level 3, RFC 8949 and RFC 9052/9053; signatures only through aws-lc-rs, no attestation trusted. It
  is part of the external audit before 1.0 – change it only with review, and with tests of what it refuses. Passkeys
  stored by webauthn-rs (up to 0.5.1) must keep reading (`Credential::from_stored`). No OpenSSL anywhere:
  `cargo tree -i openssl-sys` stays empty.
- **Exact versions everywhere:** container images by full tag (`postgres:18.6-alpine3.24`) or by digest where
  there is no tag, GitHub Actions by commit with the version as a comment, Rust via `rust-toolchain.toml`, crates
  via `Cargo.lock` (CI and the image build with `--locked`). New versions are at least two weeks old – except the
  smallest version that fixes a RustSec advisory, taken at once and named with the advisory in the commit (and in
  `SECURITY_FIXES` of `tui/scripts/check-age.py`). The one other exception: Jiff 1.0 (with jiff-sqlx), taken at
  once in place of chrono (unmaintained, RUSTSEC-2026-0543). `cargo deny check` (`deny.toml`, `kit/deny.toml`,
  `tui/deny.toml`, `operator/deny.toml`) fails on known vulnerabilities, licences that do not fit (permissive only for
  the kit) and sources besides
  crates.io; an advisory that does not affect kernoid is ignored there with a reason.
- Facts need a source; what is not settled is marked `OPEN`.

## Releases

A release is a commit of main that main's CI run passed, tagged afterwards – the tag's run checks nothing again:

1. Versions everywhere (`Cargo.toml` of every workspace with its lock file, `web/*/package.json`, compose, the
   Kubernetes examples, the Helm chart, `kernoid-operator crd`), `kernoid openapi`, and the changelog's section with
   the day of the release – in one commit, pushed to main.
2. Once main's run of that commit passed (its image `sha-<commit>` is on ghcr.io), tag it `vX.Y.Z` and push the tag.
3. The tag's run: `release` gives that image the version's tags, `chart` pushes the chart, `crates` publishes after
   the approval of the environment `crates-io` – the kit's crates (`kit/scripts/publish-order.sh`), the server's
   (`scripts/publish-order.sh`; it builds the WebAssembly and `web/` first and copies the builds into kernoid-web,
   `scripts/web-crate.sh`, published with `--allow-dirty`), then `kernoid-tui` and `kernoid-operator`; a version
   already on crates.io is skipped. A crate new to crates.io the maintainer publishes by hand the first time (or
   reserves its name), then sets up trusted publishing for it. `upgrade` upgrades the release before to the new image.

Every crate of the four workspaces goes to crates.io, so path dependencies carry their version, and dependencies on
crates of the other workspaces (the server on `kernoid-e2e`, `kernoid-pim`, `kernoid-mime`; the terminal app on
`kernoid-client`) name the same version as the crates – a release changes them all together. Packages stay small
(`cargo package --list`): no test data outside `src/`, no builds but kernoid-web's. To try a release before tagging:
`cargo publish --workspace --dry-run --locked` in the kit, and in the server's workspace with the kit's crates patched
in (`--config 'patch.crates-io.kernoid-pim.path="kit/pim"'`, the same for -mime and -e2e) and `scripts/web-crate.sh`
first, `--allow-dirty` for kernoid-web.

`release` waits up to 90 minutes for main's run when the commit and the tag were pushed together, and refuses a tag
on a commit that is not on main.

## The falkOSS starter pack

kernoid follows [falkoss/starterpack](https://github.com/falkoss/starterpack) (`docs/practices.md`): its own
organisation with `.github`, `website`, `brand` (the brand kit – copies of its artwork here are CC BY-ND 4.0),
`whitepaper` and this repository; SPDX and REUSE everywhere, the starter pack's REUSE, DCO and Jekyll workflows
pinned by commit, CI on Linux and macOS. Where kernoid deviates, it has a reason:

- **The software's shape.** Not `core`/`store`/`app`/`api`/`tui` crates but one crate per part of the system
  (identity, mail, files, the protocols, modules) behind roles – kernoid replaces two existing servers and runs as
  separately scaled processes. GraphQL besides REST: decided for the administration API.
- **The apps.** The web app talks JMAP for mail, calendar, contacts and files – only its administration takes types
  from OpenAPI. The kit (`kit/`, MIT) and the terminal app on it (`tui/`, AGPL) are workspaces of their own, not
  crates of the server: they must not reach server code, and the kit goes into app stores with the apps.
- **Files where tools need them.** The API descriptions are in `docs/` (`_data/openapi.json`, `api/`) – Jekyll cannot
  read outside its folder – under MIT as the starter pack's `api/openapi.json` would be; Compose is in
  `deploy/compose/` beside Kubernetes and the test VM.
- **macOS CI** takes PostgreSQL from Homebrew, its major version pinned: macOS runners have no containers.

## Checks

```sh
cargo fmt --check && cargo clippy --all-targets && cargo test   # tests need DATABASE_URL, see README
(cd kit && ../scripts/kit-check.sh && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked && e2e/scripts/build-wasm.sh)
scripts/client-check.sh   # the SDK and kernoid-sync against this checkout's kernoid (DATABASE_URL, psql)
scripts/profile-check.sh  # identity alone (and later the relay alone) against this checkout's kernoid
(cd tui && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked)
(cd operator && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked)
scripts/upgrade-check.sh v0.1.0 kernoid:local   # after `docker build -t kernoid:local .`
./scripts/check-sel.sh
cargo deny check && (cd kit && cargo deny check) && (cd tui && cargo deny check) && (cd operator && cargo deny check)    # cargo-deny 0.20.2
docker run --rm -v "$PWD":/data fsfe/reuse:6.2.0 lint
```
