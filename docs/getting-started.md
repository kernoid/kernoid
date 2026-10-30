---
title: Getting started
nav_order: 2
permalink: /getting-started/
---

# Getting started

This runs kernoid on one machine with Docker Compose – kernoid, PostgreSQL and [Garage](https://garagehq.deuxfleurs.fr)
as object storage – and sets up a first instance, tenant and administrator. It serves plain HTTP on `localhost:8080`,
which is fine for trying kernoid out and nothing else; see [Operations]({{ '/operations/' | relative_url }}) for TLS.

{: .note }
Compose runs the released image `ghcr.io/kernoid/kernoid:0.2.0` (`linux/amd64` and `linux/arm64`). To run the code of the checkout
instead, build it and name it in `.env`: `docker build -t kernoid:local ../..` and `KERNOID_IMAGE=kernoid:local`.
For a public machine with TLS and mail, see `deploy/test` and its README.

## Start

```sh
git clone https://github.com/kernoid/kernoid && cd kernoid/deploy/compose
cp env.example .env    # set every value; the comments in the file say how to generate them
docker compose up -d
curl localhost:8080/readyz
```

`readyz` answers `{"database":"ok","blob":"ok"}` once PostgreSQL and Garage are reachable. The `migrate` service has
then brought the database schema up to date – with the owner role, while kernoid itself serves with a role that has
only the rights it needs.

{: .warning }
`KERNOID_MAIN_KEY` encrypts all content. Without it, content cannot be read again: keep a copy apart from the server.

## A first instance and tenant

An **instance** is an identity provider with its own domains; a request finds its instance by the host it asked for.
A **tenant** is an organisation in an instance and owns mail domains. ([Concepts]({{ '/concepts/' | relative_url }})
explains both.) The operator sets them up with the CLI:

```sh
alias kernoid='docker compose exec kernoid kernoid'
kernoid instance add --name Example --domain login.example.localhost
kernoid instance list                                  # prints the instance id
kernoid tenant add <instance> --name Firma             # prints the tenant id
kernoid tenant add-domain <tenant> firma.example       # prints the DNS record that proves the domain
kernoid tenant verify-domain <tenant> firma.example --trust   # no public DNS here: the operator vouches for it
```

## The first administrator

Accounts log in with an address on a verified domain of their tenant. The password is read from standard input, never
from the command line:

```sh
kernoid account add <tenant> alice@firma.example --name Alice     # prints the account id
docker compose exec -it kernoid kernoid account password <account>
kernoid tenant grant <tenant> --account <account> --role tenant_admin
kernoid instance grant <instance> --account <account> --role instance_admin   # optional: administers all tenants
```

From here on, Alice administers through the [API]({{ '/api/' | relative_url }}); the CLI stays for operators. Her
account page is at `http://login.example.localhost:8080/login/account` – with a browser that resolves `*.localhost`
to this machine.

## Log in and administer

```sh
H='Host: login.example.localhost'
curl -H "$H" -H 'content-type: application/json' \
     -d '{"address": "alice@firma.example", "password": "…"}' localhost:8080/v1/sessions
# → {"id": …, "token": "ks1.…", …} – the token is shown once
T='Authorization: Bearer ks1.…'
curl -H "$H" -H "$T" localhost:8080/v1/tenant
curl -H "$H" -H "$T" -H 'content-type: application/json' -d '{"name": "Team"}' localhost:8080/v1/groups
```

The same in GraphQL:

```sh
curl -H "$H" -H "$T" -H 'content-type: application/json' \
     -d '{"query": "{ tenant { name domains { domain verified } } permissions { permissions } }"}' \
     localhost:8080/graphql
```

## Connect an application

Applications are OpenID Connect clients and belong to a **project** of the tenant:

```sh
curl -H "$H" -H "$T" -H 'content-type: application/json' -d '{"name": "Portal"}' localhost:8080/v1/projects
curl -H "$H" -H "$T" -H 'content-type: application/json' localhost:8080/v1/applications -d '{
  "project": "<project>", "name": "Portal", "kind": "confidential",
  "redirect_uris": ["https://portal.example/callback"]
}'
# → {"id": "<client id>", "client_secret": "kcs1.…"} – the secret is shown once
curl -H "$H" localhost:8080/.well-known/openid-configuration
```

[Login and OpenID Connect]({{ '/login/' | relative_url }}) describes the flow, scopes and claims.
