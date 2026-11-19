---
title: Building on kernoid
nav_order: 8.7
permalink: /building-on-kernoid/
---

# Building on kernoid

kernoid is the core of a suite ([RFC 0008](https://github.com/kernoid/kernoid/blob/main/rfcs/0008-suite-and-building-blocks.md)):
other programs take accounts and logins from it instead of building their own, and an installation runs only the
parts it needs.

## Only what is needed

`[services]` switches mail, calendars and files off for an installation ([Configuration]({{ '/configuration/' | relative_url }})).
**Identity alone** – accounts, logins with passkeys and second factors, single sign-on with an organisation's
provider, OpenID Connect and SAML for applications, SCIM, the administration – needs nothing but PostgreSQL:

```toml
[services]
mail = false
calendars = false
files = false

[blob]
kind = "database"
```

`GET /v1/services` tells apps and other servers what an installation runs.

## Beside kernoid: `kernoid-auth`

A program's server logs in with a kernoid – or any OpenID provider – through the crate `kernoid-auth` (AGPL, on
crates.io). Register the program as an application of a project in kernoid (its redirect URI
`https://<program>/auth/callback`, back-channel logout `https://<program>/auth/backchannel-logout`); the project's
roles become the program's roles.

```rust
use std::sync::Arc;
use axum::{Router, routing::get};
use kernoid_auth::{relying::{RelyingParty, Settings}, sessions::MemorySessions, web::{Auth, Authenticated}};

let settings: Settings = toml::from_str(r#"
    issuer = "https://id.example.org"
    client_id = "…"
    client_secret = "…"
    redirect_uri = "https://music.example.org/auth/callback"
"#)?;
let auth = Auth::new(RelyingParty::new(settings)?, Arc::new(MemorySessions::new()));
let app: Router = Router::new()
    .route("/library", get(|Authenticated(who): Authenticated| async move {
        if who.has_role("librarian") { "all of it" } else { "your parts" }
    }))
    .merge(Auth::routes())
    .with_state(auth);
```

A web app sends the browser to `/auth/login?next=/library`; kernoid's login does the rest. Requests with the session
cookie that change something carry the header `kernoid-csrf`. The program's apps send kernoid's access tokens as
`Authorization: Bearer` (for an application with JWT access tokens). `MemorySessions` keeps sessions in the process;
`PgSessions` in the program's PostgreSQL (`PgSessions::migrate(&pool)` once at start makes its table).

This is the way for a **suite**: one kernoid, many programs, one login.

## kernoid built in

A program that runs on its own can build kernoid's identity into its process instead – `kernoid-server` without
its default features compiles nothing of mail, calendars or files:

```toml
kernoid-server = { git = "https://github.com/kernoid/kernoid", tag = "v0.5.0", default-features = false }
```

```rust
use kernoid_server::embedded::{Embedded, Session};

let kernoid = Embedded::start(config, shutdown.clone()).await?;   // migrates, starts identity's background work
let program = Router::new()
    .route("/music/me", get(|session: Session| async move { session.account.display_name }))
    .with_state(kernoid.state().clone());
let app = kernoid.router(program);                                 // kernoid's routes and the program's, one origin
```

kernoid's tables go into a schema of their own in the program's database (`database.schema = "kernoid"`; create the
schema, owned by the role of `migrate_url`, before the first start). kernoid's paths – `/login`, `/app`, `/v1`,
`/graphql`, `/oauth/v2`, `/oidc/v1`, `/idp`, `/scim/v2`, `/.well-known/…` – are kernoid's; the program's are others.
`Session::has_project_role` checks the program's roles. A program that builds kernoid in is AGPL-3.0 as a whole
([RFC 0009](https://github.com/kernoid/kernoid/blob/main/rfcs/0009-kernoid-in-other-servers.md), 6).

### From built in to a kernoid of its own

When a program's identity should serve more than the program – a suite, other programs logging in –, its schema
becomes a kernoid of its own. The accounts, their passwords, second factors and sessions move with it; an account keeps
its id, which is the subject (`sub`) the program sees through `kernoid-auth` as well. The steps (checked by
`scripts/profile-check.sh`):

1. Stop the program. Dump kernoid's schema – nothing of the program's –:
   `pg_dump --schema=kernoid --no-owner --no-privileges <program's database> > kernoid.sql`.
2. Create the new kernoid's database and its two roles ([Operations](operations.md)), restore the dump as the owner,
   and configure the kernoid with `database.schema = "kernoid"` and **the program's `encryption.main_key`** (it wraps
   the tenant keys and the signing keys). Keep `[blob] kind = "database"`: the pictures of the accounts are in
   `blob_objects` (OPEN: moving them into object storage).
3. `kernoid migrate` – it brings the schema to the new kernoid's version and grants the runtime role.
4. Give the instance its new host: `kernoid instance add-domain <INSTANCE> <HOST>`, then `kernoid instance set-primary
   <INSTANCE> <HOST>` – the issuer is built from it. Passkeys are bound to the instance's RP ID: set it with
   `kernoid instance set-passkey-rp-id` to the domain they were made for, where the new host is below it; otherwise
   accounts add their passkeys again.
5. In kernoid, register the program as an application of its project (`kernoid app add`, redirect URI
   `https://<program>/auth/callback`), and in the program, replace `Embedded` by `kernoid-auth` with that client and
   the new issuer. Sessions of the program's own end: people log in once more, at the new kernoid.
6. Once the program runs against the new kernoid, drop the schema from the program's database.

## Spaces, end to end

kernoid's foundation ([RFC 0010](https://github.com/kernoid/kernoid/blob/main/rfcs/0010-foundation.md)) keeps data that
only its members read: a **space** is a log of events and originals, encrypted on the devices, merged by union, and
synchronised through a **relay** that checks signatures and the member list but never sees content. The crates are in
kernoid's kit, under MIT, for apps of any licence: `kernoid-base`, `-blob`, `-log`, `-crypt`, `-space-store` (a
device's spaces in SQLite) and `-replica` (a device's replica, synchronising through a relay).

With `services.relay = true` a kernoid is that relay, below `/relay/<program>/v1/` – `<program>` is the scheme of the
program's signed requests, allowed by `relay.domains`. Spaces are founded by accounts of the installation
(`Replica::start_sync_for` with the account's token), or by anyone on a relay open for a tenant
(`relay.open_for_tenant`). A tenant's administrators see its spaces – who founded them, how large they are, never what
is in them – and remove them: `GET /v1/relay/spaces`, `DELETE /v1/relay/spaces/{space}`, in GraphQL `relaySpaces` and
`removeRelaySpace`, on the command line `kernoid relay spaces` and `kernoid relay remove`. A relay and nothing else is
`[services]` with only `relay = true`.
