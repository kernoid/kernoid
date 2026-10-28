---
title: API
nav_order: 6
permalink: /api/
---

# API

Every operation exists twice, with the same permission checks: in **REST** (described by OpenAPI) and in
**GraphQL**. Both are served by every kernoid process with the `api` role, for the instance the request's host
belongs to.

| | Where | Description |
|---|---|---|
| REST | `/v1/…` | OpenAPI 3.1 at `/openapi.json` on every instance – also [here]({{ '/api/openapi.json' | relative_url }}) |
| GraphQL | `POST /graphql` | schema: [schema.graphql]({{ '/api/schema.graphql' | relative_url }}) |

Both files are generated from the code (`kernoid openapi`, `kernoid graphql-schema`); CI checks that this site has the
current ones.

## Requests

- **The instance** is chosen by the host: send requests to a domain of the instance (behind a reverse proxy, the
  forwarded host counts only from trusted proxies).
- **Authentication:** `Authorization: Bearer <session token>` – the token from `POST /v1/sessions`. The session's
  account acts; what it may do follows from its [roles]({{ '/administration/' | relative_url }}).
- **In a browser,** the session can live in an HttpOnly cookie instead (`"cookie": true` at login, see
  [Login]({{ '/login/' | relative_url }}#sessions)); a change made with the cookie needs the header `kernoid-csrf` and
  an `Origin` of the instance, otherwise `403` with `urn:kernoid:problem:csrf`.
- **The tenant administered** is the account's own; instance administrators name another one with the header
  `kernoid-tenant: <tenant id>`.
- **Request bodies** are JSON, at most 2 MiB; a request may take 30 seconds.
- Every response carries an `x-request-id`, which the server's log carries as well.

## Errors

REST errors are problem details (RFC 9457, `application/problem+json`): `type`, `title`, `status`, `detail`. Internal
details never appear in a response – they go to the log, findable by the request id.

| Status | Means |
|---|---|
| `400` | the request is not acceptable: a malformed value, or a rule refuses it (e.g. revoking the last `tenant_admin`) |
| `401` | no valid session, or wrong credentials; with type `urn:kernoid:problem:login-required` a fresh login is needed, with `urn:kernoid:problem:mfa-required` a second factor |
| `403` | the session is valid, but the permission named in `detail` is missing; or the account is deactivated |
| `404` | it does not exist – or it belongs to a tenant the caller cannot see |
| `409` | it exists already, or a domain or address is in use |
| `429` | too many failed attempts; see `Retry-After` |
| `503` | PostgreSQL or object storage is not reachable |

GraphQL errors carry the same as a code in `extensions.code`: `UNAUTHENTICATED`, `LOGIN_REQUIRED`, `MFA_REQUIRED`,
`FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `BAD_REQUEST`, `TOO_MANY_ATTEMPTS` (with `retryAfter`), `UNAVAILABLE`. Queries
are limited in depth (16) and complexity (1000).

## GraphQL

Queries read, mutations change; names follow the REST operations in camelCase – `GET /v1/groups` is `groups`,
`POST /v1/groups` is `addGroup`, `PATCH /v1/accounts/{id}` is `updateAccount`, `PUT /v1/roles/{role}/{kind}/{id}`
is `grantRole`. Several mutations in one request run one after the other:

```graphql
mutation {
  addGroupMember(group: "…", account: "…")
  grantRole(role: "user_manager", principalKind: "group", principalId: "…")
}
```

## REST operations

{% assign tags = "sessions,account,login,tenant,accounts,mail,groups,roles,projects,applications,identity providers,provisioning,instance,health,meta" | split: "," %}
{% assign titles = "Sessions,One's own account,Login UI,The tenant,Accounts,Mail,Groups,Roles,Projects,Applications,Identity providers,Provisioning (SCIM tokens),The instance,Health,Meta" | split: "," %}
{% for tag in tags %}
### {{ titles[forloop.index0] }}

| Method | Path | What it does |
|---|---|---|
{%- for path in site.data.openapi.paths -%}
{%- for operation in path[1] -%}
{%- if operation[1].tags[0] == tag %}
| `{{ operation[0] | upcase }}` | `{{ path[0] }}` | {{ operation[1].summary | normalize_whitespace }} |
{%- endif -%}
{%- endfor -%}
{%- endfor %}
{% endfor %}

## OpenID Connect

The protocol endpoints (`/.well-known/openid-configuration`, `/oauth/v2/…`, `/oidc/v1/…`) are standard OpenID Connect
and OAuth 2.0 and not part of the OpenAPI description – see [Login and OpenID Connect]({{ '/login/' | relative_url }}).
The same holds for SCIM 2.0 at `/scim/v2` and the identity provider endpoints `/idp/callback`, `/idp/saml/acs` and
`/idp/saml/metadata` – see [Identity providers and SCIM]({{ '/federation/' | relative_url }}).
