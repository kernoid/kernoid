<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0009 – kernoid in other servers

- **Status:** draft, 2026-11-19; the direction decided by the maintainer the same day (RFC 0008, 1), the mechanism a
  proposal. Implemented with 0.5.0: `kernoid-auth` (section 2), `kernoid_server::embedded` with the features of
  section 3, `database.schema` (section 4), the claim `urn:kernoid:tenant`.
- **Scope:** how a server of another program – aktujo, notenwart, spezado, or anyone's – gets accounts, logins and
  administration from kernoid instead of building its own: beside a kernoid, or with kernoid's identity built in.

Every program of falkOSS so far signs people in on its own: notenwart with passwords and links by mail, spezado with
paired devices, aktujo not at all. Passkeys, second factors, single sign-on with an organisation's provider,
provisioning and recovery are much work, and they are kernoid's already – tested, and to be audited before 1.0.

## 1. Two ways

| | **Beside** | **Built in** |
|---|---|---|
| What runs | the program, and a kernoid (identity alone will do, RFC 0008, 5) | the program, with kernoid's identity in its process |
| How it signs in | OpenID Connect against kernoid, or against any provider | kernoid's login UI and API, mounted in the program's router |
| Accounts | kernoid's; the program maps the subject to its own records | kernoid's, in the program's database (a schema of their own) |
| Crate | `kernoid-auth` | `kernoid-server` without default features |
| Fits | a suite: one kernoid, many programs, one login | a program on its own that wants accounts without a second server |

A program may offer both and let its operator choose: built in for one program alone, beside for a suite. Moving from
built in to beside keeps the accounts – they are kernoid's in both cases: the built-in identity's schema is the schema
of a kernoid ([section 4](#4-the-database)), and a kernoid can take it over (OPEN: the steps, section 7).

## 2. Beside: `kernoid-auth`

A crate for the program's server (AGPL – only servers use it, RFC 0008, 6) that is the **relying party** of OpenID
Connect, written against the standard so that it works with any provider; kernoid's claims are a bonus, not a need:

- discovery, the authorization code flow with PKCE and `state`/`nonce`, the callback, refresh;
- ID tokens and JWT access tokens checked against the provider's keys (JWKS, cached, fetched again for an unknown key);
- `Principal { subject, tenant, roles, name, email, session }` from the claims – the tenant from kernoid's
  `urn:kernoid:tenant` (in every ID token, JWT access token and userinfo answer since 0.5), the roles from
  `urn:kernoid:project:roles` (RFC 0001), roles of another provider through a claim the program names;
- the program's own **sessions** after the login: an HttpOnly cookie for its web app (with the same protection
  against cross-site requests as kernoid's, `kernoid-csrf` and the origin), bearer tokens for its apps; stored behind a
  trait (`Sessions`), in the process (`MemorySessions`), in PostgreSQL (`PgSessions`, feature `postgres`: a table
  `kernoid_auth_sessions` in the program's database with a history of migrations of its own, ids only as hashes) or
  in a program's own store;
- **back-channel logout** (an endpoint that ends the sessions of a `sid` or `sub`) and front-channel logout;
- an axum extractor that gives a handler the `Principal`, or answers `401`.

Outbound requests go only to HTTPS and public addresses, as kernoid's do (RFC 0001, 7.7) – except a provider the
operator marks as local (`allow_private`, development). It is the same code kernoid uses for the identity providers of
its tenants (`kernoid_oidc::external` and `outbound` are `kernoid-auth`'s), and it is on crates.io.

## 3. Built in: kernoid's identity as a library

`kernoid-server` gets a Cargo feature per service of RFC 0008, 4 – `mail`, `calendars`, `files`, `relay` – on by
default. Built without them, it is identity alone: instances, tenants, accounts, logins, MFA, passkeys, sessions,
groups, roles, projects, OpenID Connect and SAML (as provider and as client of other providers), SCIM, the login UI, the
account's settings and the administration – and nothing of mail, calendars, files or the relay is compiled in.

A program builds it in like this (sketch):

```rust
let kernoid = kernoid_server::embedded::Embedded::start(config, shutdown).await?;   // migrates, starts its jobs
let program = Router::new().nest("/music", music_routes()).with_state(kernoid.state().clone());
let app = kernoid.router(program);   // kernoid's routes and the program's, behind kernoid's layers
// in the program's handlers:
async fn list(session: kernoid_server::embedded::Session) { session.has_project_role(PROJECT, "librarian").await }
```

The program's routes go through kernoid's layers – the client as trusted proxies give it, which finds the instance;
request ids, tracing, limits. A program takes `kernoid-server` by git, at a release's tag (**OPEN:** the server's
crates on crates.io).

- **Configuration** is kernoid's (`kernoid_config::Config`, its tables `[http]`, `[database]`, `[blob]`, `[oidc]` …),
  as part of the program's or in a file of its own.
- **Permissions** of the program are kernoid's **project roles**: the program names a project (made once per tenant
  by the program through `Identity`), its roles are the program's roles, and a `Session` checks them. Tenant roles
  (`tenant_admin` …) keep their meaning.
- **Jobs** (clean-up of sessions, key rotation, ACME) run in the program's process, as the role `worker` would.
- **Mail kernoid sends** (codes for registration) needs a way out: with the service `mail` off, kernoid submits it
  straight to an SMTP relay the operator names (`[mail.notification_relay]`, over TLS, with or without login) through
  `kernoid-smtp-client` – the client of the queue, a crate of its own so that identity alone builds without the mail
  crates. Without a queue there is no retry: a code that cannot be sent is an error the person sees.

The program's routes and kernoid's share one origin; kernoid's paths are fixed (`/login`, `/app`, `/v1`, `/graphql`,
`/oauth/v2`, `/oidc/v1`, `/idp`, `/scim/v2`, `/.well-known/…`) and a program must not use them.

## 4. The database

kernoid's tables live in a **schema of their own** in the program's PostgreSQL database (`[database] schema =
"kernoid"`, default `public` for kernoid itself): kernoid's migrations, its two roles and its grants stay as they
are, and the program's tables stay apart. kernoid's migrations are **one history** for every service, as before
(RFC 0008, 4): a built-in identity has the empty tables of mail and files too. That costs nothing at run time, and it is
what lets a kernoid take the schema over later.

Not on SQLite: kernoid checks its SQL at build time against PostgreSQL (sqlx), and keeps one schema. **OPEN:** identity
on SQLite for very small servers (aktujo RFC 0011 asks for it) – a second backend of every query, so not before
measurements say a small server cannot run PostgreSQL.

## 5. What the identity crates give up for this

- `kernoid-identity` knows **services by name only**: an account's services (RFC 0003, 5) are a set of names, and what a
  service adds to an account – quotas, grants on mailboxes or files, OpenPGP keys – stays in the crate it is today but
  is used only when the service is on. Moving each into its service's crate: OPEN, when a program needs it.
- **Nothing in identity may require object storage**: pictures of accounts go to `[blob] kind = "database"` where
  there is none (RFC 0008, 5).
- `kernoid-server` keeps every route of a service behind its feature and behind the switch of the installation.

## 6. Licences

`kernoid-auth`, `kernoid-server` and everything below them are AGPL. A program that builds them in is AGPL-3.0 as a
whole – -only, since `kernoid-oidc` carries code derived from Zitadel under AGPL-3.0-only (RFC 0001, 1). aktujo,
notenwart and spezado are AGPL-3.0-or-later; combined with kernoid's identity they are distributed under AGPL-3.0-only.
A program under another licence uses kernoid **beside** it, over OpenID Connect – with any client library.

## 7. Open

- **OPEN:** the steps to take a built-in identity over into a kernoid of its own (dump the schema, restore it, point the
  program at the kernoid with `kernoid-auth`).
- **OPEN:** whether `kernoid-auth` becomes MIT once an app needs it – today no app does; apps log in with
  `kernoid-client` (`oidc`).
