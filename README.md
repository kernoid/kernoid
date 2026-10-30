<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/kernoid-lockup-on-dark.svg">
    <img src="docs/assets/kernoid-lockup-on-light.svg" alt="kernoid" width="480">
  </picture>
</p>

<p align="center"><b>One core for email, identity and storage.</b><br>
<sub>a <a href="https://falkoss.org">falkOSS</a> project</sub></p>

**kernoid** is one self-hostable system for an organisation's core: an account is created once and is at the same
time the mailbox, the login for single sign-on and the owner of files. Free software in Rust – everything included.

> **Status:** 0.2.0, a pre-release – identity and single sign-on (OpenID Connect, SAML and OIDC federation, SCIM),
> mail (SMTP, JMAP, IMAP) with end-to-end encryption, calendars and contacts (CalDAV, CardDAV, JMAP), files (JMAP,
> WebDAV, drives, public links), LDAP for older software, a Kubernetes operator, virus scanning and Jitsi as the first
> modules, a web app with administration and a terminal app; the Rust SDK on crates.io (`kernoid-client`). For trying
> out and testing: no external security audit yet, and formats may still change ([changelog](CHANGELOG.md)). The app
> for desktop and mobile is an unsigned preview ([kernoid/apps](https://github.com/kernoid/apps)); the first stable
> release, ready for production, comes with it signed once falkOSS is incorporated and holds the app stores'
> developer accounts. The design
> is in the [whitepaper](https://github.com/kernoid/whitepaper).

**Documentation:** [kernoid.dev](https://kernoid.dev) – built from [`docs/`](docs/). **Website:** [kernoid.org](https://kernoid.org).

## What is here

| Path | Content |
|---|---|
| `crates/kernoid` | the program: `serve`, `migrate`, `check-config`, `openapi`, `graphql-schema`, `keys`, `instance`, `tenant`, `account`, `project`, `app`, `signing-key`, `acme`, `mail`, `collections`, `files` |
| `crates/kernoid-config` | configuration from a TOML file and `KERNOID__…` environment variables; roles |
| `crates/kernoid-store` | PostgreSQL (pool, migrations, owner and runtime role) and object storage, encrypted with a key per tenant |
| `crates/kernoid-events` | the event store that identity and administration are built on, and the projections that derive state from it |
| `crates/kernoid-identity` | instances, tenants and accounts: domains and DNS verification, addresses and aliases, Argon2id passwords, sessions with limits on failed attempts, TOTP, passkeys, recovery codes, requiring a second factor, groups, roles and permissions (built in, a tenant's own, instance roles), projects with their roles, administration with permission checks |
| `crates/kernoid-oidc` | the OpenID Connect provider: applications in projects, signing keys with a life cycle, authorization code flow with PKCE, ID, access and refresh tokens, project roles in tokens, userinfo, logout; logging in with other OpenID and SAML 2.0 providers (`federation`, `saml` with bergshamra) |
| `crates/kernoid-mail` | the mail store of each account: mailboxes, emails (raw messages sealed in object storage), threads, keywords, quotas, the journal of changes for JMAP and IMAP, and who may use whose mail (shared mailboxes, grants) |
| `crates/kernoid-smtp` | mail over SMTP: the MX for the tenants' domains (SPF, DKIM, DMARC, ARC, iprev, a basic spam filter, Sieve), submission with app passwords, the queue's delivery with DKIM signing, MTA-STS and DANE, bounces, DNS checks |
| `crates/kernoid-groupware` | calendars and contacts of each account: events and contacts parsed with calcard, sharing, invitations (iTIP/iMIP) |
| `crates/kernoid-dav` | CalDAV and CardDAV; the protocol parser taken over from Stalwart |
| `crates/kernoid-files` | the file store of each account and of the tenant's team folders: directories, files of any size in sealed parts, versions, sharing, WebDAV locks |
| `crates/kernoid-jmap` | JMAP Core, Mail, Calendars, Contacts and FileNode for programs and web apps, with push over EventSource |
| `crates/kernoid-imap` | IMAP4rev2/IMAP4rev1 and POP3 for mail programs; the protocol parser taken over from Stalwart |
| `crates/kernoid-module` | the interface for modules – connections to one particular outside service, off unless switched on |
| `crates/kernoid-server` | the HTTP server: REST (OpenAPI at `/openapi.json`), GraphQL (`/graphql`), sessions (`/v1/sessions`), the administration API (tenants, accounts, groups, roles, projects, applications, the instance), SCIM 2.0 at `/scim/v2`, health checks, problem details, TLS or reverse proxy |
| `web/` | the TypeScript SDK (`@kernoid/sdk`), the login UI served at `/login` and the web app at `/app` (mail, calendar, contacts, files, account, administration) – MIT, like every first-party app |
| `apps/client` | kernoid's Rust SDK `kernoid-client` – JMAP for mail, files, calendars and contacts, push, end-to-end encryption; MIT, a Cargo workspace of its own, for kernoid's apps and anyone else's |
| `apps/sync` | `kernoid-sync` – a folder kept in step with a file store (changes, transfers, conflicts, local state in SQLite); MIT, part of the Rust SDK |
| `apps/e2e` | `kernoid-e2e`, the end-to-end encryption of the apps (RFC 0006) – MIT, also built as WebAssembly for the web app |
| `apps/tui` | the terminal app `kernoid-tui` – mail, files, calendars and contacts, on the Rust SDK; AGPL, a Cargo workspace of its own |
| `docs/` | the documentation site (GitHub Pages, Jekyll); `docs/_data/openapi.json` and `docs/api/schema.graphql` are generated |
| `rfcs/` | design decisions open for discussion, starting with [the data and event model](rfcs/0001-data-and-event-model.md) and [the mail data model](rfcs/0002-mail-data-model.md) |
| `deploy/compose` | Docker Compose: kernoid, PostgreSQL, [Garage](https://garagehq.deuxfleurs.fr) as object storage |

## Trying it out

```sh
cd deploy/compose
cp env.example .env    # set every value, see the comments there
docker compose up -d   # the released image; docs/getting-started.md says how to run the checkout's code
curl localhost:8080/readyz

# an instance reached under localhost, with a tenant
docker compose exec kernoid kernoid instance add --name Example --domain login.example.localhost
docker compose exec kernoid kernoid instance list
curl -H 'Host: login.example.localhost' localhost:8080/v1/instance
docker compose exec kernoid kernoid tenant add <instance> --name Firma
docker compose exec kernoid kernoid tenant add-domain <tenant> firma.example
docker compose exec kernoid kernoid tenant verify-domain <tenant> firma.example --trust   # no public DNS here
docker compose exec kernoid kernoid account add <tenant> alice@firma.example --name Alice
docker compose exec -it kernoid kernoid account password <account>
docker compose exec kernoid kernoid tenant grant <tenant> --account <account> --role tenant_admin

# log in, look at the session, log out
curl -H 'Host: login.example.localhost' -H 'content-type: application/json' \
     -d '{"address": "alice@firma.example", "password": "…"}' localhost:8080/v1/sessions
curl -H 'Host: login.example.localhost' -H 'Authorization: Bearer ks1.…' localhost:8080/v1/sessions/current
curl -X DELETE -H 'Host: login.example.localhost' -H 'Authorization: Bearer ks1.…' localhost:8080/v1/sessions/current

# an OpenID Connect client
docker compose exec kernoid kernoid tenant grant <tenant> --account <account> --role tenant_admin
docker compose exec kernoid kernoid project add <tenant> --name Portal
docker compose exec kernoid kernoid app add <project> --name App --redirect-uri https://app.example/callback
curl -H 'Host: login.example.localhost' localhost:8080/.well-known/openid-configuration
```

## Development

Rust 1.99.1 (`rust-toolchain.toml`; the code needs at least 1.94), OpenSSL with `pkg-config` (for webauthn-rs) and
Docker. Building needs no database: SQL is
checked at build time against the query cache in `.sqlx/`. The tests need PostgreSQL and a role that may create
databases and roles; each test creates its own database:

```sh
docker run -d --name kernoid-pg -e POSTGRES_USER=kernoid -e POSTGRES_PASSWORD=kernoid -p 5432:5432 postgres:18.6-alpine3.24
export DATABASE_URL=postgres://kernoid:kernoid@localhost:5432/kernoid
cargo test
```

After adding or changing a query, update the cache against a migrated database and commit `.sqlx/`:

```sh
cargo sqlx migrate run --source crates/kernoid-store/migrations
cargo sqlx prepare --workspace -- --all-targets
```

Every change is checked by CI: `cargo fmt`, `cargo clippy`, that the query cache matches queries and schema, the tests, [REUSE](https://reuse.software) compliance
and `scripts/check-sel.sh`, which keeps code under the Stalwart Enterprise License out of the repository.

## The name

```
Kern    German      → core
kerno   Esperanto   → core
kerno + id          → kernoid
kern0id, 0 as o     → kerno.id
kern0id, without 0  → kern.id
kernoid, OIDC       → OpenID Connect
```

*Kern* is German for core, and *kerno* is Esperanto for core. Both are in the wordmark `kern0id`: read the 0 as
an o and it says **kerno.id**, leave it out and it says **kern.id** – the core, with identity; the dot in the 0 is
the dot of the domain. kernoid joins the two: *kerno* and *id*. The *oid* also winks at OpenID Connect (OIDC), the
protocol kernoid logs people in with, and, as an aside, at mathematics: the kernel of a map, and *-oid* as in monoid –
kernel and monoid make kernoid.

## Contributing

Issues and pull requests are welcome – see [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org) (`git commit -s`); there is no contributor licence
agreement. Security problems: [SECURITY.md](SECURITY.md).

## Licence

- kernoid's own code: [GNU AGPL-3.0-or-later](LICENSE).
- The SDK, the login UI and the web app in `web/`, the Rust SDK in `apps/client/` and the end-to-end library in
  `apps/e2e/`: [MIT](LICENSES/MIT.txt). The terminal app in `apps/tui/` is AGPL-3.0-or-later like the server.
- The RFCs in `rfcs/` and the documentation's text in `docs/`: [CC BY 4.0](LICENSES/CC-BY-4.0.txt); the API
  descriptions (`docs/_data/openapi.json`, `docs/api/`) [MIT](LICENSES/MIT.txt), so that clients may be generated from
  them.
- Code taken over from Stalwart and Zitadel keeps its licence, the GNU AGPL-3.0-only, and is marked in every file –
  see the whitepaper, chapter "Building on Stalwart and Zitadel", and [CREDITS.md](CREDITS.md) for what came from
  where.
- Copies of the logo and icons from [kernoid/brand](https://github.com/kernoid/brand) (`docs/assets/`, the web apps'
  `public/`): [CC BY-ND 4.0](LICENSES/CC-BY-ND-4.0.txt) – passed on unchanged.
- The name and logo "kernoid" are not covered by these licences; they belong to falkOSS – Falcon Lake Open Source
  Software gUG (haftungsbeschränkt) i. G.
