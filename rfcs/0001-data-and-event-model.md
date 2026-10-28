<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0001 – Data and event model

- **Status:** draft, 2026-10-23; implemented: sections 1–3 (instances, tenants, accounts), the password login and the
  OpenID Connect code flow, TOTP and passkeys of section 7 (`kernoid-identity`, `kernoid-oidc`, `kernoid-server`)
- **Scope:** the objects kernoid is built from, how they are stored as events, how requests find their instance and
  tenant, and the decisions that follow for consistency, keys, APIs and the login. It is the basis for everything
  else (identity first, then mail).

Statements about ZITADEL refer to its documentation and source as of 2026-10-23 (release v4.20.0); sources are
linked where used. kernoid takes over concepts, not code, unless marked otherwise.

## 1. Levels: installation, instance, tenant

| Level | Is | Holds | Administered by |
|---|---|---|---|
| **Installation** | one deployment: the processes, PostgreSQL, object storage | instances | the operator (configuration, `kernoid` CLI) |
| **Instance** | one identity provider with its own domains and issuer | tenants, instance-wide defaults and policies, OIDC signing keys | instance administrators |
| **Tenant** | an organisation | its mail domains, accounts, groups, shared mailboxes, resources, service accounts, roles, applications, module switches | tenant administrators |

An installation usually has one instance, created at setup. Several instances in one installation – each with its
own domains, issuer and administrators – serve a managed service or an umbrella organisation with independent
members, without separate deployments.

This mirrors ZITADEL, where an instance "normally runs on one domain and represents one issuer" and holds
organizations, which hold users, projects and applications
([instance](https://zitadel.com/docs/concepts/structure/instance)). kernoid's tenant corresponds to ZITADEL's
organization, but is more: it owns mail domains, and an account is at the same time login, mailbox and owner of
files.

### Access across tenants

An application belongs to one tenant, in one of its projects. Like ZITADEL's project grants
([granted projects](https://zitadel.com/docs/concepts/structure/granted_projects)), a tenant can grant a project with
chosen roles to another tenant of the same instance, whose administrators then assign them to their own accounts
(section 7.5). Nothing crosses instances.

## 2. Finding instance and tenant

- **Instance – by host.** Each instance has one or more domains (e.g. `login.example.org`). The host a request asked
  for selects the instance; an unknown host gets `404`, there is no fallback instance. The host is taken from the
  connection, or from `Forwarded` / `X-Forwarded-Host` **only if the connection comes from a configured trusted
  proxy** (`http.trusted_proxies`). ZITADEL resolves instances by host as well, and had several vulnerabilities from
  trusting forwarded host headers (e.g. [GHSA-pfrf-9r5f-73f5](https://osv.dev/vulnerability/GHSA-pfrf-9r5f-73f5)).
  Links kernoid sends (password reset, invitations) are built from the instance's configured domain, never from the
  request.
- **Tenant – by address.** An account's login name is its mail address, so the domain part names the tenant:
  `alice@firma.de` belongs to the tenant that owns `firma.de`. Mail follows the same rule (recipient domain for SMTP,
  login name for IMAP and JMAP). Any tenant may claim a domain; it is used only once verified by a DNS TXT record
  `_kernoid-challenge.<domain>` with the value `kernoid-verification=<token>`, and **one tenant in the whole
  installation** can have it verified – incoming mail reaches the installation, not an instance, and must find exactly
  one recipient. A verified domain stays with its tenant until that tenant removes it.
- **Hints at login.** Applications may restrict a login to a tenant with OIDC scopes, as ZITADEL does with
  `urn:zitadel:iam:org:id:{id}` ([scopes](https://zitadel.com/docs/apis/openidoauth/scopes)): kernoid uses
  `urn:kernoid:tenant:id:{id}` and `urn:kernoid:tenant:domain:{domain}`; a login outside that tenant is refused.

## 3. Objects (aggregates)

| Aggregate | Scope | Notes |
|---|---|---|
| `instance` | installation | domains, defaults, policies |
| `tenant` | instance | name, active state, mail domains (claimed, verified), module switches, policies, cross-tenant grants |
| `account` | tenant | login name = primary address, aliases, display name, active state; credentials apart (see 3.1); who may use its mail (RFC 0002, 12.2) |
| `group` | tenant | members and addresses; at the same time distribution list (RFC 0002, 9.2) and owner of shared folders and calendars |
| `shared_mailbox` | tenant | an account of the kind `shared` (`account.shared_added`): addresses and mail without a person and without any login; access through the grants of RFC 0002, 12.2 |
| `resource` | tenant | room or device with address and calendar |
| `service_account` | tenant | keys instead of a login; for machines and integrations |
| `role` | tenant | permissions for administration – built in or the tenant's own – held as tenant events, instance roles as instance events (7.4); access to mail is granted per store and mailbox with IMAP's rights instead (RFC 0002, 12.2) |
| `project` | tenant | applications and the roles they know, settings (7.5) |
| `authorization` | tenant | the project roles of one account or group in one project (7.5) |
| `application` | tenant | OIDC or SAML client, in a project |

Not in events, on purpose: **key material** (tenant keys, OIDC signing keys, secrets) lives in its own tables,
encrypted, so that it can be rotated and destroyed – an append-only log could do neither. **Mail, calendar and file
content** is data, not administration: structure in PostgreSQL, content in object storage. For mail, RFC 0002 sets
this out.

### Identifiers

Aggregates are identified by UUID version 7: unique without coordination, ordered by creation time, which keeps
indexes compact. Addresses and names are attributes, never identifiers – an account can be renamed.

### Instance and owner of events

Every event carries `instance_id` – the partition every query filters by – and an `owner`: the tenant the aggregate
belongs to, or the instance itself for instance-wide aggregates. A tenant owns its own events. An aggregate keeps its
owner; an event naming another owner is refused.

### Domain names

Domains are stored lower case without a trailing dot; internationalised names in their ASCII form (`xn--…`), so
that two spellings of one name cannot both be registered.

### Addresses

`local@domain`, lower case; the local part has letters, digits and `.`, `_`, `-`. **`+` is reserved for
subaddresses**: `alice+news@example.org` will be delivered to `alice@example.org`, so nobody can register an address
that reads like someone else's. Every address – primary or alias – is on a domain the tenant has verified and belongs
to **one account or group in the whole installation**. A domain cannot be removed from a tenant while addresses use it.

### 3.1 Accounts and passwords

- An account is its id. It logs in with its primary address or an alias, a username, its verified contact address
  or a linked provider (RFC 0003, 2); an account without an address of its tenant is external and has no mailbox
  (RFC 0003, 1). An alias can become the primary address; the former one stays as an alias.
- A login is checked **at the instance it happens at**: an account of another instance does not log in there, even
  with the right password.
- **Password hashes are credentials, not events.** They live in `account_passwords`, written in the transaction of
  the event `account.password_changed`, which carries no hash. A hash can thus be replaced and removed; the event log
  keeps only that it changed.
- Argon2id with at least the parameters OWASP recommends (19 MiB, 2 passes, 1 lane), as PHC strings; a hash made
  with other parameters is replaced at the next successful login. Passwords have at least 12 characters and at most
  1024 bytes.
- A failed login says only that **address or password are wrong** – an unknown address, a wrong password, an
  account without password and an account of another instance are the same answer and take the same time (an
  unknown address is checked against a dummy hash). That an account or its tenant is deactivated is said only after
  the right password.
- Failed attempts are limited – see section 7.


## 4. Events

- **Names** are `<aggregate>.<past tense>`: `account.added`, `account.disabled`, `group.member_added`. An event says
  what happened, not what was requested.
- **Payloads are versioned** per event type (`revision`). A changed payload gets a new revision; code reads older
  revisions by upcasting them (`DomainEvent::upcast`). Stored events are never rewritten.
- **Creator** is the account, service account or `system` that caused the event; with the event's time it is the
  audit log.
- **Internal and public events are separate.** Integrations (actions, section 8) receive a curated, versioned set of
  public events derived from the internal ones. The internal model can then change without breaking anyone.

## 5. Consistency

Commands load an aggregate, decide on new events against its state and append them with the expected sequence; a
concurrent change makes the command decide again (`EventStore::execute`).

Read models come in two kinds:

- **Inline**, in the transaction of the append (`append_with`, `execute_with`): everything that decides a login or a
  permission – login names, credentials, sessions, role assignments, domain and instance lookups – and every
  **uniqueness rule** (an address, a domain, a login name exists once), enforced by `UNIQUE` constraints on those
  tables. A read right after a write sees it.
- **Asynchronous projections** for everything else (lists, search, statistics), kept current by the projection
  runner; they may lag for a moment.

ZITADEL started with asynchronous projections everywhere and triggers projections before queries to get
read-after-write ([source](https://github.com/zitadel/zitadel/blob/main/internal/query/user.go)). It is now moving
to "write to relational tables first, then generate events" in the same transaction, naming projection latency and
uniqueness under eventual consistency as reasons
([blog, 2026-01-30](https://zitadel.com/blog/relational-core-event-driven-soul-evolving-zitadel-for-scale)). kernoid
starts where ZITADEL is heading.

**Ordering for readers.** ZITADEL orders events by the start time of the writing transaction and drains in-flight
writers with advisory locks before reading
([source](https://github.com/zitadel/zitadel/blob/main/internal/eventstore/repository/sql/postgres.go)). kernoid
orders by transaction id and position and only hands out events of transactions older than the oldest one still
running (`pg_snapshot_xmin`), which needs no locks between writers and readers.

## 6. Keys

- **Content keys** per tenant, wrapped by the main key; both rotate (`kernoid keys rotate`, `kernoid keys rewrap`).
- **OIDC signing keys** per instance with the states *initial → active → inactive → removed*: a new key is published
  before it signs, an old one stays published until the tokens it signed have expired. This follows ZITADEL's web
  keys ([web keys](https://zitadel.com/docs/guides/integrate/login/oidc/webkeys)).
- **Secrets** kernoid must read again (SMTP relay passwords, IdP client secrets, action signing keys) are encrypted
  with keys per purpose under the main key, each with one key for new data and older ones for reading – rotation by
  adding a key, as in ZITADEL's encryption key configuration.
- **Passwords** are stored only as hashes (Argon2id), apart from the events, and rehashed on login when the
  parameters change (see 3.1).

## 7. Login, sessions and the web app

- kernoid's web app is its own **TypeScript progressive web app**; with it comes a **TypeScript SDK** (MIT), so that
  anyone can build a login – or a whole client – into their own web app.
- The login runs on a **session API**, following ZITADEL's session API v2
  ([custom login](https://zitadel.com/docs/guides/integrate/login-ui/oidc-standard)): an OIDC or SAML request is
  parked as an auth request; the login UI creates a session and adds checks to it (account, passkey, password, TOTP);
  then it finalises the auth request with the session and redirects to the callback. Any UI that holds the right
  service account can do this – kernoid's own app is just the first.
- **Sessions always expire.** ZITADEL sessions without an explicit lifetime never expire
  ([session API](https://github.com/zitadel/zitadel/blob/main/proto/zitadel/session/v2/session_service.proto)); in
  kernoid every session has a lifetime, set by the tenant's policy within the instance's limits.

### 7.1 Sessions (implemented for passwords)

- A session is created **only after a successful check** (`POST /v1/sessions` with address and password; GraphQL
  `createSession`). Requests without valid credentials therefore never write events – nobody can fill the event log
  from outside. The events `session.created` and `session.terminated` are owned by the account's tenant, so a
  tenant's audit log shows its logins.
- The **token** `ks1.<session id>.<secret>` (256-bit secret) is shown once and sent as `Authorization: Bearer`. Only
  its SHA-256 is stored, in `sessions`, never in an event; the prefix lets secret scanners recognise leaked tokens.
- **Lifetime** 8 hours unless asked otherwise, at most 30 days; a session also stops working when its account or
  tenant is deactivated. Ended and expired sessions are removed by the worker a day later.
- **Failed attempts** are counted in a table, not as events: per login name as typed (5 per 15 minutes) – whether it
  exists or not, so the limit tells nothing – and per client address (50 per 15 minutes). Above a limit, attempts are
  refused with `429` and `Retry-After` before the password is even checked; a success clears the count of the name.
- Every failure that could tell whether an account exists is `401` with the same text; `403` only after the right
  password (deactivated); an invalid or expired token is `401` with `WWW-Authenticate: Bearer`.
- **Known devices** keep that limit from locking people out (OWASP Authentication Cheat Sheet, device cookies): a
  successful password login answers with a device token (`kdt1.…`, stored as SHA-256 in `known_devices`, bound to the
  login name as typed, valid a year from its last use). Sent with the next login, it makes failures count against the
  device instead of the name – so the person gets in from their own device while others throttle the name – and the
  device is throttled in turn after five failures. A token of another name, an unknown or an expired one counts as
  none. A passkey login was never limited per name.

### 7.2 OpenID Connect (implemented)

- **Applications** are OpenID Connect clients of one tenant: *confidential* (a secret, shown once, stored as
  SHA-256) or *public* (browser and mobile apps, no secret). Redirect URIs are matched exactly; accepted are `https`,
  `http` only for loopback, and private schemes with a dot (RFC 8252).
- **PKCE with S256 is required for every client** (as in OAuth 2.1); there is no implicit flow, no `plain`.
- `authorize` checks client and redirect URI first – errors about them are shown, never redirected to – then
  parks an **auth request** (10 minutes) and sends the browser to the login UI (`<issuer>/login?authRequest=…`). The
  UI finishes it with its session (`POST /v1/auth-requests/{id}`, GraphQL `finishAuthRequest`) and gets the callback
  URL with a **one-time code** (60 seconds) and `iss` (RFC 9207 against mix-up attacks).
- The **token** endpoint (client authentication by Basic header or form) checks code, client, redirect URI and PKCE
  verifier, and issues an **ID token** (RS256 JWT: `iss`, `sub` = account id, `aud`, `azp`, `exp`, `iat`, `auth_time`,
  `nonce`, `sid`, `amr`) and an opaque **access token** (1 hour, stored as SHA-256) for **userinfo**, whose claims
  follow the scopes (`profile`: `name`, `preferred_username`; `email`: `email`, `email_verified`). A code presented a
  second time revokes the tokens issued for it. Ending the session ends its access tokens.
- An application serves accounts of its own tenant; `urn:kernoid:tenant:id:<id>` restricts a login further.
- The **issuer** is `<public_scheme>://<primary domain>` of the instance – never taken from a request.
- **Signing keys** (section 6) are one aggregate per instance; the first login creates and activates one.
- Paths follow ZITADEL: `/.well-known/openid-configuration`, `/oauth/v2/authorize`, `/oauth/v2/token`,
  `/oauth/v2/keys`, `/oidc/v1/userinfo`.
- **Refresh tokens** (`krt1.…`) come with every code exchange and live as long as the session they came from.
  Each refresh hands out the next one and uses up the old (rotation); a used refresh token that comes back was
  copied, and every token of that login is revoked (RFC 9700, 4.14.2). A refresh may ask for fewer scopes, not
  more. Clients revoke tokens at `/oauth/v2/revoke` (RFC 7009): a refresh token with its whole login, an access token
  alone.
- **`prompt` and `max_age`** reach the login UI with the auth request (`GET /v1/auth-requests/{id}`). Sessions are
  held by the login UI, not as cookies on the provider's domain, so the UI decides; the server enforces what it can:
  `prompt=login` needs a session newer than the request, `max_age` one at most that old – otherwise finishing is
  refused with the problem type `urn:kernoid:problem:login-required`. The UI ends a request it cannot serve (no
  session for `prompt=none`, a declined login) with `POST /v1/auth-requests/{id}/decline` and an OpenID Connect error
  code, which goes back to the application.
- **RP-initiated logout** at `/oidc/v1/end_session` (OpenID Connect RP-Initiated Logout 1.0): the session named in
  `id_token_hint` – an ID token of this instance, its signature checked, expired is fine – ends, and with it its
  access and refresh tokens. The browser goes back only to a `post_logout_redirect_uri` registered for the client.
- **Application options** (`application.options_set`): access tokens as JWTs (RFC 9068: `typ` `at+jwt`, audience the
  application, `scope`, `client_id`, `jti`, project roles) instead of opaque – stored by hash either way, so that
  revocation, introspection and userinfo treat both alike; whether the application may ask for `offline_access`;
  whether it requires consent; its front- and back-channel logout URIs. A back-channel URI must pass the outbound
  check (HTTPS, public address) when it is set and when it is called.
- **Consent** (`account.consent_granted`, `account.consent_revoked`, read model `consents`): needed when the
  application requires it, when it asks for `offline_access`, or with `prompt=consent`. Finishing answers with the
  problem type `urn:kernoid:problem:consent-required` until the login UI finishes with the person's consent; the
  consent covers the scopes agreed to, and a request for more asks again. Withdrawing it – by the account or an
  administrator who holds every permission the account holds – also deletes the application's tokens for the account.
- **Offline access:** `offline_access` is dropped from requests of applications that may not ask for it (OpenID
  Connect Core, 11). Refresh tokens of an offline grant carry `offline`, `auth_time` and `checks` themselves, outlive
  the session (its row may go; the foreign key is set to null) and last 30 days from their last use; their access
  tokens are not bound to the session. Refreshing still checks the account, the tenant, a second factor required since,
  the project roles – and the consent and the application's option.
- **Introspection** (RFC 7662, `/oauth/v2/introspect`): a confidential client asks about access and refresh tokens of
  its own project; any other token is reported inactive, as an unknown one. A confidential application may have no
  redirect URIs at all – an API that only checks tokens.
- **Logout notifications:** `finish` records which applications a session logged in to (`session_applications`).
  Front-channel logout (Front-Channel Logout 1.0): the end-session endpoint answers with a page of hidden frames for
  their `frontchannel_logout_uri` (with `iss` and `sid`; `frame-src` limited to their origins), then a refresh to the
  redirect URI. Back-channel logout (Back-Channel Logout 1.0): the worker turns ended sessions into
  `logout_notifications` and posts a logout token (`typ` `logout+jwt`; `iss`, `aud`, `iat`, `exp`, `jti`, `sub`,
  `sid`, `events`) through the outbound client; a notification is leased for a minute while being sent, retried after
  30 seconds, doubling up to six hours, eight attempts in all, and removed after seven days. Ending a session through
  end-session keeps offline grants.
- **Rotation of signing keys** by the worker, hourly: a key active for `oidc.key_rotation_days` gets a successor,
  published (initial) for `oidc.key_publish_hours` before it is activated; an inactive key is removed after
  `oidc.retired_key_days`, never before ID tokens it signed have expired. Events name `system:key-rotation`.
- **A login UI of the instance's own** (`instance.login_ui_set`, `instances.login_ui_url`): an HTTPS URL without
  query or fragment. `authorize` sends the browser there, external identity providers hand logins back to its
  `/idp`, and its origin – only that – gets CORS answers from the `/v1` API (no credentials mode: the UI sends the
  session token as a bearer token).

### 7.3 TOTP and passkeys (implemented)

- **Further checks of a session**: TOTP (`POST /v1/sessions/current/totp`) and a passkey
  (`/v1/sessions/current/passkey/start|finish`) add `totp` or `passkey` to the session's checks
  (`session.checked`). The ID token's `amr` follows RFC 8176: `pwd`, `otp`, `pop`, and `mfa` with more than one factor
  – a passkey with user verification counts as two.
- **Logging in with a passkey alone** (`/v1/sessions/passkey/start|finish`): a discoverable passkey, no address and no
  password; the browser offers the person's passkeys, so the answer tells nothing about which accounts exist. Failed
  attempts count against the client address.
- **Setting up and removing** TOTP and passkeys (`/v1/account/totp`, `/v1/account/passkeys`) needs a session from the
  last 15 minutes – otherwise `401` with the problem type `urn:kernoid:problem:login-required`. Operators reset all
  second factors of someone who lost their devices (`kernoid account reset-second-factors`).
- **TOTP** (RFC 6238): HMAC-SHA1, six digits, 30-second steps, one step of tolerance; every code works once (the last
  accepted step is kept); failed codes limited like passwords. The secret (160 bits) is sealed with the main key;
  `account.totp_enabled` carries none of it.
- **Passkeys** are verified by webauthn-rs (Kanidm project, MPL-2.0) – kernoid parses no WebAuthn structures itself.
  User verification is required; the relying party is the instance: its **RP ID** is `passkey_rp_id`
  (`instance.passkey_rp_id_set`), which starts as the instance's first domain and does not follow the primary domain,
  and its origins are every domain of the instance and its own login UI. The RP ID may be set to a domain of the
  instance or a parent domain of one; a domain the RP ID needs cannot be removed. kernoid answers
  `/.well-known/webauthn` with these origins (WebAuthn Level 3, related origins), for browsers that support it.
  Registration asks for no attestation (`none`): kernoid accepts any authenticator with user verification and does
  not check models;
  challenges and their state stay on the server for five minutes and are used once; counters are kept, so a cloned
  key is refused. webauthn-rs brings OpenSSL as a second cryptographic library next to aws-lc-rs.
- **Requiring a second factor** per tenant (`tenant.mfa_requirement_set`) or per application
  (`application.mfa_requirement_set`). A session passes with two different checks, or a passkey (possession plus PIN
  or biometrics). It is enforced where it matters: finishing an auth request is refused with the problem type
  `urn:kernoid:problem:mfa-required` – the login UI asks for a factor, or has one set up, and finishes again – and so
  is refreshing, so a requirement switched on later reaches existing logins. Managing one's own account stays
  possible with a password session; otherwise nobody could set up the required factor.
- **Recovery codes**: ten at a time (`xxxx-xxxx-xxxx-xxxx` from 31 unambiguous characters, about 79 bits), shown once,
  stored only as SHA-256 bound to the account; each works once as a further check (`recovery`, `amr` `otp`); new
  ones replace all earlier ones and need a recent session; guesses are limited. `GET /v1/account/factors` tells the
  login UI which factors an account has and how many codes are left.
- **Grace period** (`tenant.mfa_grace_set`, 0 to 365 days): an account without a second factor may log in – to
  applications and to the administration – without one until that many days after the requirement or the account
  began (`tenants.mfa_required_since`, `accounts.created_at`). `GET /v1/account/factors` says until when
  (`setup_due`), and the login UI offers to set one up. An account that has a factor uses it; an application's own
  requirement and another tenant administered know no grace period.
- **OPEN:** an allow-list of authenticator models (AAGUIDs, with attestation) for tenants that need certified ones.

### 7.4 Groups, roles and administration (implemented)

- **Groups** (`group` aggregate, owned by the tenant): a name, members (accounts of the same tenant) and addresses.
  They hold roles and are distribution lists (RFC 0002, 9.2); owner of shared folders follows with files. A group
  that holds roles cannot be removed until they are revoked, so that no permission disappears unnoticed.
- **Permissions** say what kind of administration is allowed. Tenant permissions: `directory.read`, `tenant.manage`
  (name, modules), `domains.manage`, `policies.manage`, `accounts.manage`, `groups.manage`, `roles.manage`,
  `projects.manage`, `applications.manage`, `authorizations.manage` (project roles). Instance permissions:
  `instance.read`, `instance.manage` (name, domains, signing keys), `tenants.manage`, `instance_roles.manage`.
- **Built-in tenant roles:** `tenant_admin` (all tenant permissions), `user_manager` (directory, accounts, groups,
  authorizations), `application_manager` (directory, projects, applications), `auditor` (directory). This follows
  ZITADEL's managers with fixed roles such as `ORG_OWNER` and `ORG_USER_MANAGER`
  ([administrators](https://zitadel.com/docs/guides/manage/console/administrators)), with groups as holders added.
- **Roles of a tenant's own** (`tenant.role_defined`, `tenant.role_deleted`): a name and a set of tenant permissions,
  at least one; the names of built-in roles are taken. A role can be deleted once nobody holds it; changing its
  permissions changes its holders' at once.
- **Built-in instance roles** (`instance.role_granted`, `instance.role_revoked`): `instance_admin` (all instance
  permissions, and all tenant permissions in every tenant of the instance) and `instance_auditor` (`instance.read`,
  and `directory.read` in every tenant). They go to accounts or groups of any tenant of the instance – ZITADEL's
  `IAM_OWNER` and `IAM_OWNER_VIEWER` on the same page.
- **Instance roles of an instance's own** (`instance.role_defined`, `instance.role_deleted`, with
  `instance_roles.manage`): a name and permissions, at least one – instance permissions apply at the instance, tenant
  permissions in every tenant of it (e.g. a help desk with `instance.read`, `directory.read` and `accounts.manage`).
  Deleted once nobody holds it.
- Roles are assigned to an account or a group as events of the tenant (`tenant.role_granted`, `tenant.role_revoked`)
  or of the instance; an account holds the permissions of its own roles and of its groups' roles.
- **Administration through the API** acts on the tenant of the session's account. Instance administrators name
  another tenant of the instance with the header `kernoid-tenant` – as ZITADEL's management API does with
  `x-zitadel-orgid` ([APIs](https://zitadel.com/docs/apis/introduction)); for anyone else another tenant does not
  exist (`404`). Every operation checks its permission in one place (`kernoid_identity::admin`, `kernoid-oidc`'s admin
  functions), which REST and GraphQL both call. If the account's tenant or the tenant administered requires a second
  factor, so does administration (`urn:kernoid:problem:mfa-required`). Events name the administrator as their
  creator (`account:<id>`).
- **No escalation by the back door:** granting roles needs `roles.manage` (instance roles `instance_roles.manage`,
  project roles `authorizations.manage`); changing the members of a group needs, besides `groups.manage`, the
  permission to grant what the group holds. Setting another account's password, resetting its second factors,
  deactivating it or ending its sessions needs every permission that account holds. An application's own
  requirement of a second factor only adds to the tenant's, so `applications.manage` cannot weaken the tenant's
  policy.
- **Someone must stay in charge:** the last `tenant_admin` assignment of a tenant and the last `instance_admin`
  assignment of an instance cannot be revoked – nor anything that would leave no **active** account administering:
  only active accounts of active tenants count, directly or as members of a group, so revoking an assignment,
  deactivating an account, removing a group member or deactivating a tenant is refused if it takes the last one away.
  An instance administrator cannot deactivate their own tenant. (The check runs before the command, not inside one
  aggregate; two simultaneous changes could still slip past it – the operator's CLI remains the way back.)
  Operators assign the first ones, and any later ones, from the command line (`kernoid tenant grant`, `kernoid
  instance grant`).
- **Own account:** everyone lists and ends their own sessions, changes their display name and – with the current
  password and a recent session – their password, which ends their other sessions.
- **Mail:** access to other accounts' mail is RFC 0002, 12. **OPEN:** permissions on calendars and folders (with
  files).

### 7.5 Projects (implemented)

As in ZITADEL, a project is "the vessel that holds your Applications and Roles"
([projects](https://zitadel.com/docs/concepts/structure/projects)).

- **Projects** (`project` aggregate, owned by the tenant): a name, roles (key, display name, optional group) and two
  settings: `role_assertion` puts the account's project roles into ID tokens and userinfo; `role_check` lets only
  accounts with a role in the project log in to its applications (ZITADEL: "assert roles on authentication", "check
  role assignment on authentication"). The check applies when a login is finished and when tokens are refreshed.
- **Authorizations** (`authorization` aggregate, one per project and account or group, so that a large project does
  not grow one aggregate without end): which project roles an account or group of the tenant holds. An account holds
  the roles given to it and to its groups.
- **Applications** belong to a project (`application.added` carries it; `application.project_set` moves one).
  Applications from before projects have none and behave as before.
- **The claim** `urn:kernoid:project:roles` has the shape of ZITADEL's `urn:zitadel:iam:org:project:roles`
  ([claims](https://zitadel.com/docs/apis/openidoauth/claims)) – role key, then tenant id and tenant name. It is
  issued when the project asserts roles, or when the client asks for the scope `urn:kernoid:project:roles`.
- A project role can be removed once nobody holds it, a project once it has no applications and no role is given.
- **Grants** (`project.granted`, `project.grant_revoked`): a project's tenant grants it to another tenant of the
  instance – named by id or by a verified mail domain – with some of its roles. That tenant's administrators give
  those roles to their own accounts and groups (with `authorizations.manage`); its accounts may then log in to the
  project's applications, and the roles claim names their tenant. The project's tenant sees every tenant's
  authorizations, a granted tenant only its own. A grant, or a role in it, can be taken back once that tenant no
  longer holds it; a project with grants cannot be removed. This is ZITADEL's project grant
  ([granted projects](https://zitadel.com/docs/concepts/structure/granted_projects)).
- Roles reach resource servers in JWT access tokens and in introspection answers (section 7.2).

### 7.6 Login UI and SDK (implemented)

- **The login UI** (`web/login`) is a TypeScript PWA, served by kernoid at `/login` from `http.login_ui` and built
  into the container image. It answers auth requests (`/login?authRequest=…`): log in with address and password or a
  passkey, ask for a second factor or have one set up when it is required, honour `prompt` and `max_age`, offer
  another account, decline. `/login/account` is the account page: name, password, TOTP, passkeys, recovery codes,
  sessions.
- **The session lives in an HttpOnly cookie** (decided 2026-10-24), so that one login serves every application of the
  instance and no script – not even the login UI's own – can read the token. A login with `"cookie": true` sets
  `__Host-kernoid-session` (`kernoid-session` without HTTPS) – `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, as long
  as the session – and leaves the token out of the answer; logout removes it. Without it, a login answers with the
  token as before, for clients that send it as a bearer token (CLI, scripts, apps, login UIs on another site). A
  request uses the bearer token if it has one, else the cookie.
- **Cross-site request forgery:** a request that authenticates with the cookie and changes something (any method but
  `GET`, `HEAD`, `OPTIONS`; GraphQL counts as a change) must carry the header `kernoid-csrf` and an `Origin` of the
  instance – one of its domains (over HTTPS, if the installation uses it) or its own login UI; otherwise `403` with
  `urn:kernoid:problem:csrf`. A custom header cannot be sent from another origin without a CORS preflight, which
  kernoid answers for the instance's own login UI only; `SameSite=Lax` keeps the cookie from other sites' requests on
  top. The pages still build no markup from strings and keep their strict Content-Security-Policy.
- **The SDK** (`@kernoid/sdk`, `web/sdk`) has no runtime dependencies. `OidcClient` lets a web app log in with kernoid
  as a public client: authorization code with PKCE, the ID token verified against the instance's JWKS (signature,
  issuer, audience, expiry, nonce), refresh, userinfo, revocation, logout. `LoginClient` wraps the session API for
  login UIs and account pages, with the WebAuthn translation for passkeys.
- **Licence:** both are MIT, like every first-party app – only the protocol connects them to the server, they share
  no code with it.
- **Cross-origin calls:** discovery, keys, token, revocation and userinfo answer requests from any origin (CORS,
  without cookies), so that a web app can use them from the browser. The `/v1` API answers the same origin and the
  instance's own login UI, if it has one (section 7.2).
- **Consent screen:** on `consent-required` the UI shows what the application asks for, in words, and finishes with
  the consent; the account page lists the applications allowed and withdraws consents.
- **Languages:** English and German, from catalogs in the UI (`web/login/src/i18n.ts`, the English text is the key);
  the browser's first language of the two, `?lang=` overrides. kernoid's error texts the UI knows are shown in its
  words; others as the server wrote them (English).
- **TOTP setup** answers with a QR code drawn by the server (crate `qrcode`, SVG, error correction M) as a `data:`
  URL – the UI shows it as an image (the CSP allows `img-src data:`) and needs neither a QR library nor markup.
- **Passkeys in the autofill** (WebAuthn conditional mediation): the address field has `autocomplete="username
  webauthn"`; where the browser supports it, the page asks for a passkey with `mediation: "conditional"` as it shows,
  and aborts that request before any other – the button still opens the dialog.

### 7.7 External identity providers (implemented: OpenID Connect and SAML 2.0)

- **Providers** (`identity_provider` aggregate, owned by the tenant – or by the instance, see below): a tenant connects
  another OpenID provider –
  issuer, client id, scopes, an optional client secret (sealed with the main key, never in an event) – and routes
  some of its verified mail domains there. `auto_create` creates an account at the first login, `auto_link` links an
  existing account; both only for an email address the provider marks verified (`email_verified`) on a verified
  domain of the tenant. Administered with `identity_providers.manage`. A provider with `register` is offered to
  everyone on the login page and creates external accounts where registration is open; an account with the
  provider's verified address is proposed for linking, never linked unasked (RFC 0003, 3 and 5).
- **Links** (`account.link_added`, `account.link_removed`): the provider's `sub` logs in as the linked account. One
  external identity is linked to one account; a provider with linked accounts cannot be removed.
- **The flow:** the login UI asks where an address logs in (`GET /v1/login-options` – by domain, saying nothing about
  whether the account exists), starts the login (`POST /v1/idp-logins`: PKCE, `state`, `nonce`, `login_hint`), the
  provider sends the browser to `https://<instance>/idp/callback`, kernoid exchanges the code, verifies the ID token
  against the provider's keys (RS256/384/512, PS256, ES256/384; issuer, audience, `azp`, expiry, nonce) and sends the
  browser to `/login/idp` with a one-time code in the fragment, which the UI exchanges for a session
  (`POST /v1/idp-logins/session`). No session token ever appears in a URL.
- **Factors:** the session's checks are `idp`, and `idp_mfa` when the provider's `amr` contains `mfa`; a tenant that
  requires a second factor then accepts such logins.
- **Requests to providers** go out only as HTTPS to public addresses – checked for the URL, every address DNS gives
  and every redirect – unless the installation sets `outbound.allow_private_networks` (for an own Keycloak in the
  network). Without it, a tenant administrator could make kernoid read services inside the installation (server-side
  request forgery).
- **SAML 2.0:** a provider with SAML settings – SSO URL, signing certificates, optionally the attributes for address
  and name – gets an AuthnRequest (HTTP-Redirect binding, `RelayState` as the state) and posts its Response
  to `https://<instance>/idp/saml/acs` (HTTP-POST binding). kernoid's entity ID is `https://<instance>/idp/saml`, its
  metadata at `/idp/saml/metadata`. XML signatures are verified by **bergshamra** (pure Rust, BSD-2-Clause, AWS-LC as
  the backend, without legacy algorithms) with its SAML defaults: only the configured certificates, references only
  where the signature can cover them (against XML signature wrapping), duplicate IDs refused, every reference digest
  verified. kernoid refuses DTDs before parsing, parses once and reads from the tree it verified, takes the one
  Assertion only if a valid signature references it or the Response around it, and checks issuer, `InResponseTo`,
  destination, recipient, time windows and audience. The NameID is the subject; an `AuthnContextClassRef` for more
  than one factor counts as `idp_mfa`. An address the tenant's own SAML provider asserts on a verified domain of the
  tenant counts as verified. bergshamra has had no external audit yet; kernoid's audit before 1.0 includes this path.
- **kernoid's SAML key** of an instance (`saml_sp_keys`): RSA 2048, made at first use by rcgen, sealed with the main
  key, with a self-signed certificate (ten years) that the metadata publishes for signing and encryption – providers
  trust it because it is in the metadata. With `sign_requests`, AuthnRequests are signed (redirect binding:
  RSA-SHA256 over the URL-encoded query, SAML Bindings 3.4.4.1); the signature is made and checked through
  bergshamra's algorithm registry, no own cryptography.
- **Encrypted assertions:** an `EncryptedAssertion` (XML Encryption, e.g. AES-GCM with RSA-OAEP) is decrypted by
  bergshamra with kernoid's key; then the same checks apply. A signature over the Response counts when it verifies on
  the Response as received; otherwise the decrypted Assertion must carry a valid signature of its own. Exactly one
  assertion – plain or encrypted – is accepted. Legacy algorithms (RSA PKCS #1 v1.5 key transport) are not built in.
- **Single logout** (HTTP-Redirect binding, `/idp/saml/slo`, in the metadata): a session from a SAML login keeps its
  NameID and SessionIndex (`idp_sessions`). Logging out at kernoid (`POST /v1/sessions/current/logout`, GraphQL
  `logout`) ends the session and, if the provider has an `slo_url`, answers with the provider's address and kernoid's
  signed LogoutRequest; the provider's LogoutResponse sends the browser back to the login UI (matched by
  `InResponseTo`, kept ten minutes in `saml_logouts`). A provider's own LogoutRequest must carry a redirect signature
  by one of its certificates (RSA or ECDSA with SHA-256 or more), is checked for destination and expiry, ends the
  sessions of that NameID (and SessionIndex), and is answered with kernoid's signed LogoutResponse.
- **Providers for the whole instance** (owner the instance, `tenant_id` empty; `instance.manage`): the verified
  domains of any tenant of the instance may be routed to them – one provider per domain in the instance – and
  accounts are found, linked or created in the tenant whose domain the address is on. Tenants see them and cannot
  change them. A linked account must belong to the provider's instance (and tenant, for a tenant's provider).
- **Profile sync** (`sync_profile`): at every login of a linked account, its display name becomes the provider's.
  Addresses are not changed by logins – that is what SCIM is for.
- **OPEN:** rotating kernoid's SAML key (with a second certificate in the metadata for a while); the HTTP-POST binding
  for single logout; single logout for sessions ended by an administrator or by OpenID Connect end-session.

### 7.8 Provisioning with SCIM 2.0 (implemented)

- A tenant's directory – Entra ID, Okta, Google, any SCIM 2.0 client – creates, changes and deactivates its accounts
  and groups at `https://<instance>/scim/v2` (RFC 7643, RFC 7644): `Users`, `Groups`, `ServiceProviderConfig`,
  `ResourceTypes`, `Schemas`.
- **Tokens** (`tenant.scim_token_added`, `tenant.scim_token_removed`): the directory authenticates with a token of the
  tenant (`kscim1.…`, stored as SHA-256, shown once), created with `provisioning.manage`. Events it causes name it
  (`scim:<token id>`).
- **Users are accounts:** `userName` is the login name (an address on a verified domain of the tenant, as accounts
  provisioned by a directory are native – RFC 0003), further `emails` on such domains become aliases, `displayName` or `name` the display name, `externalId` is kept
  (`account.external_id_set`). `DELETE` deactivates the account and ends its sessions – an account is also a mailbox
  and owns files; it is not deleted on a directory's word.
- **Groups** are groups (`group.external_id_set` for `externalId`).
- **Filters** `userName`, `externalId`, `displayName` with `eq`; paging with `startIndex` and `count`; sorting with
  `sortBy` (`userName`, `displayName`, `externalId`, `meta.created`) and `sortOrder`; PATCH in the forms Entra ID and
  Okta send (capitalised ops, booleans as strings, operations without path).
- **Versions:** `meta.version` is the sequence of the resource's last event, as a weak ETag; `meta.created` and
  `lastModified` come from its events. PUT, PATCH and DELETE with `If-Match` are refused with `412` if the resource
  has changed since. The check runs before the change, not inside the same transaction.
- **Passwords** (`password`, write-only, never returned) set the account's password – only for accounts the token may
  manage – and end its sessions, as an administrator's would.
- **Bulk** (`/Bulk`, RFC 7644, 3.7): up to 100 operations, 1 MiB, run in order as the single requests they stand for;
  `bulkId:<id>` in a path or value refers to a resource made by an earlier operation (one made later is a `409`);
  `failOnErrors` stops after that many errors.
- **The same safeguards as for administrators:** a SCIM token holds `directory.read`, `accounts.manage` and
  `groups.manage`. It cannot deactivate an account holding more, nor change the members of a group that holds roles.
- **OPEN:** filters beyond `eq` on the three attributes; `If-None-Match` for reads.

## 8. Actions and hooks (before 1.0)

Third-party services integrate from outside. The shape follows ZITADEL's Actions V2
([concept](https://zitadel.com/docs/concepts/features/actions_v2),
[usage](https://zitadel.com/docs/guides/integrate/actions/usage)):

- **Targets** (where to call: URL, timeout, how to treat errors) and **executions** (when: on a public event, before
  or after an API operation, or at a decision point such as "before a login completes" or "before a message is
  accepted").
- Event deliveries are queued in the transaction that wrote the event and delivered by the worker, in order, with
  retries – the projection runner already provides this.
- Hooks are synchronous with a timeout per target and a cap for all targets of one request; on failure the policy of
  the hook decides (allow or deny). A hook can refuse with a status and a message for the user.
- Requests are signed (`t=<unix time>,v1=<HMAC-SHA256>`, with a tolerance against replays); targets are registered
  per tenant through a manifest and work with a service account limited to what the manifest declares.

## 9. Transport and APIs

- **TLS:** kernoid serves HTTPS itself (`[http.tls]`, or certificates from an ACME CA) or runs behind a reverse proxy
  such as Caddy, nginx or Traefik, whose forwarded headers it believes only from `trusted_proxies`. Mail protocols
  always use kernoid's own TLS.
- **ACME** (RFC 8555, client: instant-acme with AWS-LC): the worker orders certificates for every instance domain with
  the HTTP-01 challenge – it needs no DNS access and works for any domain pointed at the installation, whereas DNS-01
  would need credentials for every DNS provider (left to the DNS automation module of 1.0) and TLS-ALPN-01 the TLS
  port of the very process the CA reaches. The account key, the certificates and their keys (sealed with the main
  key), the challenge answers and failed attempts live in PostgreSQL (`acme_accounts`, `tls_certificates`,
  `acme_challenges`, `acme_orders`), so every `api` process serves every certificate by SNI and answers every
  challenge; a PostgreSQL advisory lock lets one worker order at a time. Rate limits: at most ten orders an hour,
  failures wait an hour, doubling up to a day; names for local use are not ordered. The operator agrees to the CA's
  terms explicitly (`terms_agreed`).
- **Several workers:** every worker job is safe to run in more than one process – projection cursors with
  `FOR UPDATE SKIP LOCKED`, logout notifications leased, clean-up idempotent, key rotation and ACME behind advisory
  locks (session-level, so no transaction stays open during the work).
- **APIs:** REST, described by OpenAPI (`/openapi.json`), and GraphQL (`/graphql`) from the start, with the same
  operations and the same permission checks. Errors are problem details (RFC 9457). GraphQL queries are limited in
  depth and complexity.
- **One version of each API at a time.** ZITADEL runs v1 and v2 APIs, two logins and two action systems side by
  side, with preview APIs that "can AND will continue breaking"
  ([upgrade guide](https://github.com/zitadel/zitadel/blob/main/apps/docs/content/self-hosting/manage/upgrade-v3-to-v4.mdx)).
  kernoid marks experimental API parts as such and removes or stabilises them within one minor version.

## 10. Open

- **Recovery** of an instance whose administrators have all lost access is the operator's CLI, by design: it talks to
  the database directly, its changes are events naming `operator`, and kernoid itself refuses changes that would
  leave nobody active in charge. Whoever can run it holds the installation anyway (database and main key).
- **OPEN:** whether SAML responses and LDAP binds go through the same session API.
- **OPEN:** wildcard certificates (need DNS-01); ACME Renewal Information (RFC 9773) to renew when the CA asks.
