---
title: Identity providers and SCIM
nav_order: 4.5
permalink: /federation/
---

# Identity providers and SCIM

A tenant that already has a directory – Entra ID, Google Workspace, Okta, Keycloak, ADFS … – connects it to
kernoid: its people **log in there** (OpenID Connect or SAML 2.0), and the directory **provisions** their accounts and
groups in kernoid (SCIM 2.0).

## Logging in with another provider

Administrators with `identity_providers.manage` connect a provider (`POST /v1/identity-providers`, or
`addIdentityProvider` in GraphQL) and route some of the tenant's verified mail domains to it. Someone who types an
address of such a domain in the login UI is sent to the provider instead of being asked for a password.

| Setting | Meaning |
|---|---|
| `name` | shown on the login page |
| `issuer` | OpenID Connect: the provider's issuer. SAML: its entity ID |
| `client_id`, `client_secret` | OpenID Connect: kernoid's client at the provider; the secret is stored sealed and never shown again |
| `scopes` | OpenID Connect: `openid` is always included; add `email` and `profile` to create and link accounts |
| `saml` | SAML: `sso_url`, `certificates` (base64 DER or PEM), optionally `email_attribute`, `name_attribute`, `sign_requests` (sign AuthnRequests with kernoid's key), `slo_url` (the provider's single logout service) |
| `domains` | verified mail domains of the tenant whose logins go to this provider; one provider per domain |
| `auto_create` | create an account at the first login |
| `auto_link` | link an existing account with the same address at the first login |
| `sync_profile` | take the display name from the provider at every login |
| `instance_wide` | at creation: a provider for the whole instance (needs `instance.manage`) |

**A provider for the whole instance** – one company login for every tenant, say – is created with `instance_wide`
by an instance administrator. The verified domains of any tenant of the instance may be routed to it; accounts are
found, linked or created in the tenant whose domain the address is on. Tenants see such a provider in their list
(`instance_wide: true`) but cannot change it, and a domain goes to one provider only.

What to register at the provider is in the provider's view (`GET /v1/identity-providers/<id>`):

- **OpenID Connect:** the redirect URI `https://<instance domain>/idp/callback`.
- **SAML:** the Assertion Consumer Service `https://<instance domain>/idp/saml/acs`, the entity ID
  `https://<instance domain>/idp/saml` and the single logout service `https://<instance domain>/idp/saml/slo` – or
  simply the metadata at `https://<instance domain>/idp/saml/metadata`, which also carries kernoid's certificate (for
  signed requests and encrypted assertions).

`POST /v1/identity-providers/<id>/check` tells whether kernoid reaches an OpenID provider as configured (discovery and
keys) or can load a SAML provider's certificates.

### Which account

The first login of a person links their identity at the provider (its `sub`, or the SAML NameID) to an account; later
logins find it by that link alone – even if their address at the provider changes.

- With `auto_link`, an existing account with the same address is linked; with `auto_create`, a new one is created.
- Both need an address on a verified domain of the tenant that the provider vouches for: OpenID Connect with
  `email_verified`; for SAML, the tenant's own provider is trusted with the addresses of the tenant's domains.
- Otherwise, if an account of the instance has the provider's verified address (as its address or verified contact
  address), linking it is **proposed**: the person logs in to that account and confirms – kernoid never links on an
  address alone. Where registration is open they may create a separate account instead.
- A provider with `register` ("Sign in with …") creates an external account – without a mailbox – for a person it
  does not know, in its tenant or the instance's registration tenant, if that tenant allows registration.
- Otherwise the login is refused – an administrator links the account, or switches one of the options on.
- Logged-in people link further providers from their account page (`POST /v1/account/idp-links`).

A login at a provider counts as one factor; if the provider says it used more than one (`amr` contains `mfa`, or a
multi-factor SAML authentication context), it counts as two – and satisfies a tenant that requires a second factor.

### Security

- **OpenID Connect:** authorization code with PKCE, `state` and `nonce`; the ID token is verified against the
  provider's published keys (RS256/384/512, PS256, ES256/384) – issuer, audience, expiry, nonce.
- **SAML:** XML signatures are verified by [bergshamra](https://github.com/kushaldas/bergshamra) with its SAML
  defaults – only the configured certificates count, references must sit where the signature covers them (against
  XML signature wrapping), duplicate IDs are refused. kernoid accepts no DTDs, takes the one Assertion only if it is
  signed, and checks issuer, `InResponseTo`, destination, recipient, time windows and audience. An encrypted Assertion
  is decrypted with kernoid's key of the instance (made at first use, sealed with the main key), then checked the
  same way.
- **No session token in a URL:** after the provider's answer, the login UI receives a one-time code in the URL
  fragment and exchanges it for the session.
- **Outbound requests** go only to public addresses over HTTPS – checked for the URL, every address DNS gives and every
  redirect – unless the installation allows private networks (`outbound.allow_private_networks`, see
  [Configuration]({{ '/configuration/' | relative_url }})).

### Single logout (SAML)

A session that came from a SAML provider with an `slo_url` logs out there, too: logging out with
`POST /v1/sessions/current/logout` (the login UI's "Log out") answers with the provider's address and kernoid's signed
LogoutRequest; the provider sends the browser back to `/idp/saml/slo`, and from there to the account page. The other
way round, a provider's LogoutRequest at `/idp/saml/slo` – signed by one of its certificates, or refused – ends the
sessions of that person at kernoid, and kernoid answers with its signed LogoutResponse. kernoid takes messages in
the HTTP-Redirect binding (signed in the query) and the HTTP-POST binding (signed in the XML); it sends its own in
the HTTP-Redirect binding.

An application's logout through OpenID Connect (`end_session` with `id_token_hint`) logs out at the provider the
same way: the browser goes to the provider first and, once it answers, on to the application's
`post_logout_redirect_uri`. A session an administrator ends has no browser to send there; it ends at kernoid only
(**OPEN:** the SOAP binding, which needs no browser).

### kernoid's SAML key

kernoid signs requests and decrypts assertions with a key of its own per instance, made at the first SAML login.
To change it – through the API (`/v1/instance/saml-keys`), GraphQL (`samlKeys`, `addSamlKey`, `activateSamlKey`),
the administration's "Signing keys" page or the CLI:

1. `kernoid saml-key add <instance>` – the new key is in the metadata beside the old one, and decrypts what
   providers encrypt for it, but does not sign yet;
2. once every provider has taken in the new metadata (or certificate), `kernoid saml-key activate <instance> <id>`;
3. the former key leaves the metadata; it still decrypts what a provider encrypts for it.

## Provisioning with SCIM 2.0

A directory creates, changes and deactivates accounts and groups at `https://<instance domain>/scim/v2` (RFC 7643,
RFC 7644). Give it a SCIM token: `POST /v1/scim-tokens` with a name (needs `provisioning.manage`) – the answer holds
the token, shown once, and the endpoint.

| SCIM | kernoid |
|---|---|
| User `userName` | the login name – an address on a verified domain of the tenant |
| User `emails` | further addresses on the tenant's domains become aliases; others are left out |
| User `displayName`, `name` | the display name |
| User `active` | deactivates or reactivates the account; deactivating ends its sessions |
| `DELETE /Users/<id>` | deactivates – an account is also a mailbox and owns files; kernoid does not delete it on a directory's word |
| Group `displayName`, `members` | a group and its members |
| `externalId` | kept for users and groups |
| User `password` | sets the password (never returned) – not for an account with further permissions; ends its sessions |

Supported: `GET`, `POST`, `PUT`, `PATCH`, `DELETE` on `/Users` and `/Groups`; filters `userName eq "…"`,
`externalId eq "…"`, `displayName eq "…"`; paging with `startIndex` and `count`; sorting with `sortBy` (`userName`,
`displayName`, `externalId`, `meta.created`) and `sortOrder`; `excludedAttributes=members`; `/ServiceProviderConfig`,
`/ResourceTypes`, `/Schemas`. PATCH takes the forms Entra ID and Okta send.

- **Versions:** every resource has `meta.version` (a weak ETag, also in the `ETag` header), `meta.created` and
  `meta.lastModified`. PUT, PATCH and DELETE with `If-Match` are refused with `412` if the resource has changed.
- **Bulk:** `POST /Bulk` with up to 100 operations (1 MiB), run in order; `bulkId:<id>` refers to a resource made by
  an earlier operation of the same request, `failOnErrors` stops after that many errors.

A SCIM token holds `directory.read`, `accounts.manage` and `groups.manage` – no more. It cannot deactivate an account
that holds further permissions (an administrator), nor change the members of a group that holds roles. Changes it
makes name it in the audit log (`scim:<token id>`).
