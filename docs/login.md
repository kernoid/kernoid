---
title: Login and OpenID Connect
nav_order: 5
permalink: /login/
---

# Login and OpenID Connect

## The login UI

kernoid brings its own login UI, served at `https://<instance domain>/login`:

- **Coming back:** `/login/account?next=<path>` returns to a path of the same origin once logged in – the web app
  (`/app/`) sends people there.
- **Logging in to an application:** an OpenID Connect auth request sends the browser to `/login?authRequest=<id>`.
  Someone already logged in at the instance continues without logging in again (single sign-on). Otherwise the page
  asks for the address or username – and sends addresses of domains routed to an [identity provider]({{ '/federation/' | relative_url }})
  there – then for the password; or it offers "Continue with …" for the providers open to everyone; or it logs in with a passkey alone; then for a second factor if one is required – and has one set up, a
  passkey or an authenticator app with recovery codes, if the account has none yet. It honours `prompt=none`,
  `login`, `consent`, `select_account` and `max_age`, and the person can choose another account or cancel. An
  application that needs consent shows what it asks for, once (see [Consent](#consent-and-offline-access)).
- **The account page** is a section of the [web app]({{ '/app/' | relative_url }}) (`/app/#/account`): display name,
  appearance (light, dark or as the system), password, authenticator app, passkeys, recovery codes, app passwords for
  mail programs and file managers with their settings, applications allowed (consents, to withdraw), sessions on
  other devices, and the services to log in with (linking and unlinking providers, after a recent login; the last way
  to log in stays). `/login/account` logs in if needed and leads there.
- **Registering** at `/login/register`, where the instance allows it (see [Accounts and logins](#accounts-and-logins)).
- **Linking:** a login at a provider that finds an account with the same verified address proposes linking it – the
  person logs in to that account – or, where registration is open, creating a separate account.
- **A login UI of one's own:** an instance can send logins elsewhere – `PUT /v1/instance/login-ui` with an HTTPS URL
  (needs `instance.manage`). Authorization requests then go to `<that URL>?authRequest=<id>`, logins at an identity
  provider come back to `<that URL>/idp`, and that origin – no other – may call the `/v1` API from the browser (CORS,
  without cookies). Build it on the [SDK]({{ '/sdk/' | relative_url }}).

It is a small PWA in TypeScript (`web/login`, MIT) on the [SDK]({{ '/sdk/' | relative_url }}). Its pages carry a
strict Content-Security-Policy and may not be framed. It speaks English and German – the browser's first language of
the two, or `?lang=de` / `?lang=en`. The address field offers the person's passkeys in the browser's autofill where
the browser can (conditional mediation); setting up an authenticator app shows a QR code.

## Accounts and logins

An account is its id – never an address ([RFC 0003](https://github.com/kernoid/kernoid/blob/main/rfcs/0003-accounts-logins-services.md)).
What it uses are **services**: `mail` (a mailbox) and `files`. An account with an address on a verified domain of its
tenant is *native* and can have mail; an account without one exists for logins – and files, if granted – only, e.g.
someone who signs in with their Google account.

- **Logins:** the address (primary or alias), a **username** where the tenant uses them, the **verified contact
  address** (any domain; on by default), and links to identity providers. kernoid tries them in that order. Usernames
  and verified contact addresses are unique in the instance.
- **Services** are on, requested or off. A tenant decides who gets them when an account is created – `none`,
  `native` or `all` – and whether that waits for an administrator (`PUT /v1/tenant/service-policies/{service}`).
  By default native accounts get mail at once and nobody gets files. Administrators grant and revoke services by hand
  (`PUT`/`DELETE /v1/accounts/{id}/services/{service}`). Without `mail`, an account receives no mail and mail programs
  cannot log in.
- **Registering** (`PUT /v1/tenant/registration`): a tenant opens registration and names the domains on which new
  accounts may take an address. People without an address of their own register with the instance's registration
  tenant (`PUT /v1/instance/registration-tenant`). They enter a name, an email address and a password – and, where
  offered, their own address and a username; kernoid sends a code to the email address from `mail.notification_from`,
  and only the code creates the account. Taken addresses and usernames are refused before anything is sent.
- **Providers for everyone:** a provider with `register` is offered on the login page to everyone; a person it does not
  know gets an external account in its tenant (or the registration tenant) – where registration is open.
- **Separate accounts** of one person stay apart unless linked: a native account with a mailbox, and one that logs in
  with Microsoft only, are two accounts.

## Sessions

A login creates a session (`POST /v1/sessions` with address and password, or `/v1/sessions/passkey/start|finish` with
a passkey alone). Its token `ks1.…` is sent as `Authorization: Bearer <token>` and shown only once; kernoid keeps a
hash of it.

**In a browser – and in kernoid's login UI – the session lives in an HttpOnly cookie:** a login with `"cookie": true`
sets `__Host-kernoid-session` (`HttpOnly`, `Secure`, `SameSite=Lax`, for as long as the session) and answers without
the token, so no script can read it. Requests then carry the cookie; one that changes something must also carry the
header `kernoid-csrf` and come from the instance's own origin (or its own login UI) – otherwise kernoid refuses it as
a possible cross-site request forgery (`403`, `urn:kernoid:problem:csrf`). Logging out removes the cookie. A login UI
on another site uses bearer tokens instead.

- A session lasts 8 hours unless the login asks for another `lifetime_seconds`, at most 30 days. It ends at logout
  (`DELETE /v1/sessions/current`), when its account or tenant is deactivated, when an administrator ends it, or when
  the account's password is set anew.
- Failed logins are limited: 5 per login name and 50 per client address within 15 minutes; then `429` with
  `Retry-After`. Wrong address and wrong password give the same answer.
- **Known devices:** so that nobody can lock an account out by failing on purpose, a password login answers with a
  `device_token`. Sent with the next login of that address from that device, failures count against the device
  instead of the address – the person still gets in from their own device while the address is throttled. The login
  UI keeps these tokens per address; a token lasts a year from its last use.
- Everyone can list and end their own sessions (`GET /v1/sessions`, `DELETE /v1/sessions/<id>`) and change their own
  password (`PUT /v1/account/password`, with the current one and a session from the last 15 minutes) – which ends
  every other session of the account.

## Second factors

A session passes **checks**: `password`, then `totp`, `passkey` or `recovery`. A session counts as multi-factor with
two different checks, or with a passkey (possession plus PIN or biometrics).

| Factor | Set up | Check |
|---|---|---|
| TOTP (RFC 6238, six digits, 30 s) | `POST /v1/account/totp`, then `/v1/account/totp/confirm` | `POST /v1/sessions/current/totp` |
| Passkey (WebAuthn, through webauthn-rs) | `POST /v1/account/passkeys/start`, `/finish` | `POST /v1/sessions/current/passkey/start`, `/finish` |
| Recovery codes (ten, each once) | `POST /v1/account/recovery-codes` | `POST /v1/sessions/current/recovery` |

Setting up or removing a factor needs a session from the last 15 minutes – otherwise `401` with the problem type
`urn:kernoid:problem:login-required`. Administrators with `accounts.manage` reset the factors of someone who lost
their devices.

**Passkeys** belong to the instance's RP ID – its first domain unless an administrator with `instance.manage` sets
another (`PUT /v1/instance/passkey-rp-id`: a domain of the instance or a parent domain of one). Changing the primary
domain leaves it alone; changing the RP ID makes earlier passkeys stop working. Passkeys work on every domain of the
instance and on its own login UI; kernoid lists these origins at `/.well-known/webauthn` for browsers that support
related origins. Any authenticator with user verification is accepted (no attestation).

**Requiring a second factor:** a tenant (`PUT /v1/tenant/policy`) or an application (`PUT
/v1/applications/<id>/policy`) can require one. Finishing a login to an application then answers `401` with the
problem type `urn:kernoid:problem:mfa-required` until the session has a second check; refreshing tokens stops too.
If the tenant requires a second factor, its administration does as well.

**Grace period:** with `mfa_grace_days` in the tenant policy (0 to 365), an account without a second factor may still
log in without one for that many days after the requirement – or the account – began. `GET /v1/account/factors`
answers until when (`setup_due`); the login UI offers to set one up, and the person may do it later. Once the
account has a factor, it is asked for it. An application's own requirement allows no grace period.

## OpenID Connect

Every instance is an OpenID Connect provider. Its issuer is `https://<primary domain of the instance>`; the
discovery document is at `/.well-known/openid-configuration`.

| Endpoint | Path |
|---|---|
| Authorization | `/oauth/v2/authorize` |
| Token | `/oauth/v2/token` |
| Userinfo | `/oidc/v1/userinfo` |
| End session (RP-initiated logout) | `/oidc/v1/end_session` |
| Revocation (RFC 7009) | `/oauth/v2/revoke` |
| Introspection (RFC 7662) | `/oauth/v2/introspect` |
| Keys (JWKS) | `/oauth/v2/keys` |

- **Flow:** authorization code with PKCE (`S256`, required for every client). Redirect URIs match exactly.
- **Clients** are confidential (with a secret: `client_secret_basic` or `client_secret_post`) or public (`none`).
- **The login UI:** an authorization request sends the browser to `https://<primary domain>/login?authRequest=<id>`.
  The UI reads the request (`GET /v1/auth-requests/<id>`), logs the person in and finishes it with the session
  (`POST /v1/auth-requests/<id>`), or declines it (`POST /v1/auth-requests/<id>/decline`). `prompt` (`none`,
  `login`, `consent`, `select_account`) and `max_age` are honoured.
- **From the browser:** discovery, keys, token, revocation and userinfo answer requests from any origin (CORS,
  without cookies), so a web app can use them directly – see the [SDK]({{ '/sdk/' | relative_url }}).
- **Tokens:** codes live 60 seconds and work once (a second use revokes what was issued for it). Access tokens and ID
  tokens (RS256) live an hour. Refresh tokens (`krt1.…`) live as long as the session – with `offline_access`, 30 days
  from their last use – and are rotated at every use; a refresh token used twice revokes the whole login.
- **Access tokens** are opaque (`kat1.…`) unless the application asks for JWTs (`access_token_format: jwt`): then they
  follow RFC 9068 – type `at+jwt`, audience the application, with `scope`, `client_id`, `jti` and the project roles –
  so a resource server checks them itself against the JWKS. kernoid knows both kinds: userinfo, revocation and
  introspection work alike.
- **Introspection** (`POST /oauth/v2/introspect`, RFC 7662) is for resource servers: a confidential application –
  one without redirect URIs is fine, an API – learns whether an access or refresh token of its own project is active,
  for whom, with which scopes and roles. Tokens of other projects are reported inactive, like unknown ones.
- **Signing keys** are per instance and rotate in three states: *initial* (published, not signing), *active*
  (signing) and *inactive* (published, no longer signing). The worker rotates them on its own (see
  [Operations]({{ '/operations/' | relative_url }})).

### Application options

`PUT /v1/applications/<id>/options` (GraphQL `setApplicationOptions`, needs `applications.manage`):

| Option | Meaning |
|---|---|
| `access_token_format` | `opaque` (default) or `jwt` (RFC 9068) |
| `offline_access` | the application may ask for the scope `offline_access`; otherwise the scope is ignored |
| `consent_required` | the person agrees before the first login – for applications of others |
| `backchannel_logout_uri` | receives a logout token when a session it logged in to ends; HTTPS to a public address |
| `frontchannel_logout_uri` | loaded in a frame when the person logs out through kernoid's end-session endpoint |

### Consent and offline access

An application asks for **consent** if it requires it, if it asks for `offline_access`, or with `prompt=consent`.
Finishing the login then answers `403` with the problem type `urn:kernoid:problem:consent-required`; the login UI
shows what the application asks for and finishes again with `{"consent": true}`. The consent is stored for the
account (an event, `account.consent_granted`) and covers the scopes agreed to – asking for more asks again.

**Offline access** gives refresh tokens that outlive the session: logging out leaves them, they last 30 days from
their last use. They end when the account withdraws its consent (on the account page, `DELETE
/v1/account/consents/<application>`, or an administrator with `DELETE /v1/accounts/<id>/consents/<application>`), when
the application may no longer ask for offline access, or when the account or its tenant is deactivated. Withdrawing a
consent also withdraws every token the application holds for the account. A new password ends the account's sessions, not its
offline grants – withdraw those on the account page, too.

### Logout

- **RP-initiated:** `/oidc/v1/end_session` with `id_token_hint` ends the session, and the browser goes back to a
  registered `post_logout_redirect_uri`.
- **Front-channel** (OpenID Connect Front-Channel Logout 1.0): if applications the session logged in to have a
  `frontchannel_logout_uri`, the end-session endpoint answers with a page that loads each of them in a hidden frame
  (with `iss` and `sid`) and then goes on to the redirect URI.
- **Back-channel** (OpenID Connect Back-Channel Logout 1.0): whenever a session ends – logout, an administrator, a
  deactivated account – the worker posts a logout token (a JWT of type `logout+jwt` with `sub`, `sid` and the
  back-channel logout event) to every application the session logged in to that has a `backchannel_logout_uri`. A
  failed delivery is tried again with growing pauses, eight times in all.

### Scopes and claims

| Scope | Claims |
|---|---|
| `openid` (required) | `sub` (the account id), `iss`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `sid`, `amr`, `nonce` |
| `profile` | `name`, `preferred_username` (the login name) |
| `email` | `email`, `email_verified` – the contact address if the account has one, else its primary address (verified) |
| `offline_access` | none; refresh tokens that outlive the session, for applications allowed to ask, with consent |
| `urn:kernoid:project:roles` | `urn:kernoid:project:roles` – also without the scope if the project asserts roles |
| `mail` | none; the access token logs a mail program in over IMAP and SMTP (`OAUTHBEARER`, `XOAUTH2`) – for an account with mail |
| `urn:kernoid:tenant:id:<tenant id>` | none; restricts the login to accounts of that tenant |

`amr` follows RFC 8176: `pwd`, `otp` (TOTP or a recovery code), `pop` (passkey), and `mfa` for more than one factor.

The project roles claim has the shape of ZITADEL's `urn:zitadel:iam:org:project:roles` – role key, then tenant id
and tenant name:

```json
"urn:kernoid:project:roles": {
  "editor": { "0199a3c1-…": "Firma" }
}
```

### Who may log in

An account may log in to applications of its own tenant, and to those of projects granted to its tenant, while it and
its tenant are active. If the
application's project has `role_check` on, the account needs a role in the project. A second factor is needed if the
tenant or the application requires one.
