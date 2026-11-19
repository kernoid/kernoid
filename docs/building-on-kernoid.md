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
a program with several processes implements `Sessions` on its own database.

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
