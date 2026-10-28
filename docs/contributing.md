---
title: Contributing
nav_order: 10
permalink: /contributing/
---

# Contributing

Issues and pull requests are welcome at [kernoid/kernoid](https://github.com/kernoid/kernoid). Contributions are
accepted under the [Developer Certificate of Origin](https://developercertificate.org) – sign off every commit with
`git commit -s`; there is no contributor licence agreement. The rules of the repository are in its
[CLAUDE.md](https://github.com/kernoid/kernoid/blob/main/CLAUDE.md) – written for AI assistants and for anyone new.

## Build and test

Rust 1.99.1 (`rust-toolchain.toml`), OpenSSL with `pkg-config` (for webauthn-rs) and Docker. Building needs no
database: SQL is checked at build time against the query cache in `.sqlx/`. The tests need PostgreSQL and a role that
may create databases; each test gets its own database:

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

The web part (`web/`: SDK, login UI and web app, MIT) needs Node 26 or later and pnpm (the version in `web/package.json`,
`packageManager`). pnpm installs only versions published at least two weeks ago (`minimumReleaseAge`) and runs no
install scripts of dependencies. To try them, point `http.login_ui` at `web/login/dist` and `http.web_app` at
`web/app/dist`, and open `/app/` on an instance's domain.

```sh
cd web
pnpm install
pnpm run check && pnpm test && pnpm run build    # web/login/dist and web/app/dist
```

After changing the API, regenerate the files this site serves:

```sh
cargo run -q -- openapi > docs/_data/openapi.json
cargo run -q -- graphql-schema > docs/api/schema.graphql
```

CI checks formatting, lints, that the query cache matches queries and schema, the tests, that the API files on this
site are current, [REUSE](https://reuse.software) compliance, that no code under the Stalwart Enterprise License
enters (`scripts/check-sel.sh`), and the dependencies: known vulnerabilities, licences and sources with
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) (`deny.toml`) and `pnpm audit`.

## Rules in short

- **Only PostgreSQL and S3** – no further service may become a requirement.
- **SQL only through sqlx's checked macros**; values only as bound parameters.
- **Identity and administration are events**; credentials never go into them.
- **Every API operation in REST and GraphQL**, with the same permission checks – they live in one place
  (`kernoid_identity::admin`, the admin functions of `kernoid-oidc`).
- **Exact versions everywhere** – container images, GitHub Actions (by commit), Rust, crates.
- **Licences:** own code AGPL-3.0-or-later; code taken over from Stalwart or derived from Zitadel stays
  AGPL-3.0-only and says where it comes from.
- **Facts need a source;** what is not settled is marked `OPEN`.

## Design changes

Changes to the protocol, the data model or the licence go through a public RFC in
[`rfcs/`](https://github.com/kernoid/kernoid/tree/main/rfcs) (CC BY 4.0). Change the RFC with the code.

## This site

The site is built by GitHub Pages from `docs/` with Jekyll and [Just the Docs](https://just-the-docs.com). To preview
it locally, with Ruby and Bundler:

```sh
cd docs
bundle init && bundle add github-pages --group jekyll_plugins
bundle exec jekyll serve
```
