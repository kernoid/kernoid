<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0003 – Accounts, logins and services

- **Status:** draft, 2026-10-24; implemented (migration 0030; the language in section 1, migration 0044, since 0.2)
- **Scope:** what an account is apart from its mail address; how people log in (addresses, usernames, verified
  email addresses, external providers) and register; how one person's logins are linked; which services
  (mail, files) an account uses and who decides. It changes RFC 0001 (3.1, 7.7, 7.8) and RFC 0002 (2, 9.2, 11).

Until now an account's login name was its primary address, on a verified domain of its tenant, and so every account
was a mailbox. That does not fit installations that offer logins without mail – a cloud whose users log in with
their Google or Microsoft account – nor people who want to log in with another provider as well as with their own
mailbox. This RFC separates **who someone is** (the account), **how they log in** (logins) and **what they use**
(services).

ZITADEL was the model again ([zitadel/zitadel](https://github.com/zitadel/zitadel), as of 2026-10-23): a user is
an immutable id, login names are derived from a username (`internal/domain/human.go`), a verified email address
may log in too (`proto/zitadel/settings/v2/login_settings.proto`), external identities are links
(`user.human.externalidp.added`) with auto-linking by username or verified email (`proto/zitadel/idp/v2/idp.proto`),
and its "v3" user schemas separate a user's data, its contact addresses and its authenticators
(`proto/zitadel/resources/user/v3alpha`, still alpha). ZITADEL has no per-user services; access to applications is
projects, roles and authorizations, as in kernoid (RFC 0001, 7.5).

## 1. The account

- An account is its **id** (UUIDv7) – never an address. Two accounts of one person (one with a mailbox
  `max.mustermann@mandant.org`, one that logs in only with Microsoft) are possible and stay apart unless linked.
- **Kinds:** `person` and `shared` (a shared mailbox, RFC 0002 12.1); service accounts come later.
- A person's account is **native** when it has a primary address: an address on a verified domain of its tenant,
  which kernoid serves (MX). Only native accounts can have a mailbox. An account without one is **external**: it
  exists for logins – and files, if granted – only.
- **Contact address:** every person's account may have one email address of any domain to reach it by
  (`account.email_set`, with whether it is verified). A verified contact address belongs to at most one account of
  an instance. A native account's primary address is its contact address unless another is set.
- **Language:** the emails kernoid writes itself – invitations sent for the account, notices to it – are in the
  account's language (`account.language_set`: `de`, `en`, or none), else its tenant's (`tenant.language_set`), else
  English. It is not the language of the apps, which follow the browser.

## 2. Logins

How one says who one is; each finds exactly one account of the instance.

| Login | Unique in | Notes |
|---|---|---|
| a native address (primary or alias) | the installation | as until now |
| a **username** (`account.username_set`) | the instance | letters, digits, `.`, `-`, `_`; 3–64 characters; no `@`; only if the tenant allows usernames |
| the **verified contact address** | the instance | only if the tenant allows logging in with it (default: yes) |
| a link to an external identity provider | the provider (`sub`) | RFC 0001 7.7 |

- The login UI asks for "address or username"; kernoid looks up a native address, then a username, then a verified
  contact address – one answer for "not found" and "wrong password", as before (RFC 0001 3.1).
- **Default:** the address is the login name; usernames are off until a tenant allows them
  (`tenant.login_policy_set`: `usernames`, `email_login`).
- Credentials (password, TOTP, passkeys, app passwords) belong to the account, whichever login found it.

## 3. Linking

- One external identity is linked to one account (as until now); an account may have links to several providers
  and a password at the same time.
- **Linking is proved by logging in to both:** a user who is logged in links another provider from the account
  page (the provider's login with the intent *link*). After a provider login that finds no linked account, kernoid
  checks whether the provider's verified email address is a native address or verified contact address of an
  account of the instance; if so, it **proposes linking** – the user logs in to that account (password, passkey)
  and the link is made – or, if the tenant allows registration, **creating a separate account** instead (without
  that address as its contact address, which stays the other account's).
- Providers that serve domains of a tenant keep `auto_link` and `auto_create` (RFC 0001 7.7): there the tenant
  vouches for the addresses.

## 4. Services

What an account uses: `mail` (a mailbox, RFC 0002) and `files` (a file store, RFC 0005); more may come.

- Each service of an account is **off**, **requested** or **on** (`account.service_requested`,
  `account.service_granted`, `account.service_revoked`). `mail` needs a native account; `files` does not.
- **Tenant rules** (`tenant.service_policy_set`, per service): who gets it on creation – `none`, `native` (native
  accounts) or `all` – and whether that needs an administrator's approval (then it is *requested* until granted).
  Defaults: `mail` for `native` accounts without approval – as kernoid behaved until now – and `files` for `none`.
- Administrators grant and revoke services by hand (`accounts.manage`). Revoking `mail` stops delivery and the
  mail protocols; the mail store stays until the account is removed (OPEN: removing it after a while).
- Shared mailboxes always have `mail`.
- Accounts created before this RFC have `mail` (`account.added` revision 1 is read as granting it).
- **Mail without the service:** the MX refuses its addresses as unknown (`550 5.1.1`), IMAP, POP3, JMAP and
  submission refuse its logins, sharing grants to its store have no effect.

## 5. Registration

- A tenant allows registration or not (`tenant.registration_set`: `allowed`, `domains` – the verified domains new
  native accounts may take an address on). An instance names the tenant where people without a native address
  register (`instance.registration_tenant_set`), e.g. the one tenant of a cloud.
- **With a provider:** a login with a provider the tenant offers for registration creates an external account with
  the provider's verified address as contact address (unless it is taken: then linking is proposed, section 3).
- **With an address and a password:** kernoid sends a code to the address; nothing is written as an event until
  the code is entered (RFC 0001: no events from unauthenticated requests) – the pending registration is a row in
  `registrations`, removed after a day. Codes go out through the queue from the installation's
  `mail.notification_from`; without it, registration works only with providers.
- **A native address:** in the same step the person picks an address on one of the tenant's registration domains;
  the account is native, and `mail` follows the tenant's rule (on, or requested until an administrator approves).
- **Duplicates:** an address, username or verified contact address that is taken is refused before anything is
  sent; a verified contact address that is taken leads to the login of that account instead.
- Attempts are limited per client address like logins (RFC 0001 7).

## 6. What changes elsewhere

- **RFC 0001 3.1:** the login name is any of section 2; the primary address is the native address, if any.
- **RFC 0001 7.7:** providers may serve logins without domains (a "Sign in with Google" button of a tenant), with
  registration and the linking proposal of section 3.
- **RFC 0001 7.8:** SCIM `userName` is a native address as until now, or a username if the tenant allows them.
- **RFC 0002 2, 9.2, 11:** a mail store exists only for accounts with `mail`.

## 7. Open

- **OPEN:** removing an account (and its mail store and files) – deactivating is what there is.
- **OPEN:** phone numbers as logins.
- **OPEN:** custom profile data per tenant (ZITADEL's user schemas) – metadata for now.

## 8. The directory over LDAP

Older software reads its users from a directory over LDAP – wikis, ticket systems, printers, network gear. kernoid
serves each tenant's people and groups as such a directory (LDAPv3, [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)),
read only: the directory is kept with kernoid's API, SCIM and the web app, never over LDAP.

- **Process role `ldap`**, listening when `[ldap]` is set: LDAP with `StartTLS` (389) and LDAPS (636), with the
  certificates of the mail protocols. Messages are parsed and written by
  [ldap3_proto](https://crates.io/crates/ldap3_proto) (MPL-2.0, from Kanidm); the server is kernoid's own.
- **The tree:** one per tenant, `o=<tenant id>` – stable whatever the tenant's names and domains –, with
  `ou=people` and `ou=groups`. A person is an active account of the kind `person` (no shared mailboxes, no drives) at
  `uid=<login>,ou=people,o=<tenant>` – the login of section 2 –, an `inetOrgPerson` with `uid`, `cn` and
  `displayName` (the display name), `sn` and `givenName` (its last word and the rest), `mail` (every address, the
  primary first), `memberOf` and the operational `entryUUID` (the account's id). A group is a `groupOfNames` at
  `cn=<name>,ou=groups,o=<tenant>` with `cn`, `mail`, `member` and `entryUUID`.
- **Binding:** simple binds only, over TLS only (`confidentialityRequired` otherwise), with the account's DN or its
  login name, and an app password – or its password if it needs no second factor, as for mail programs (section 4;
  `program_login` without a service: any account). Failures count like failed logins. Anonymous binds see the root
  DSE and nothing else; a bind with a name and no password is refused (RFC 4513, 5.1.2).
- **Searching:** a bound account reads its own tenant's tree – another tenant's does not exist for it. Scopes base,
  one level, subtree and children; filters with and, or, not, equality, presence, substrings, ordering (values
  compare without case); the attributes asked for, `*`, `+` and `1.1`; at most `ldap.max_entries` entries
  (`sizeLimitExceeded` beyond). Simple paged results (RFC 2696) are answered with every entry on the first page.
  Extended operations: StartTLS and Who am I? (RFC 4532).
- **OPEN:** which accounts may read the directory – today every account of the tenant reads all of it, as it can
  find its people with JMAP's principals; a service account for software that searches before binding as the user;
  `posixAccount` attributes; a cache of the tree for large tenants (every search reads it from PostgreSQL).
