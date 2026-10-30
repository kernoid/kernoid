---
title: Concepts
nav_order: 3
permalink: /concepts/
---

# Concepts

The full design is in [RFC 0001](https://github.com/kernoid/kernoid/blob/main/rfcs/0001-data-and-event-model.md); this
page is the short version.

## Installation, instance, tenant

| Level | Is | Holds | Administered by |
|---|---|---|---|
| **Installation** | one deployment: the kernoid processes, PostgreSQL, object storage | instances | the operator (configuration, `kernoid` CLI) |
| **Instance** | one identity provider with its own domains and issuer | tenants, signing keys, instance roles | instance administrators |
| **Tenant** | an organisation | mail domains, accounts, groups, roles, projects, applications, policies, module switches | tenant administrators |

Most installations have one instance. Several instances serve independent organisations from one deployment, each
with its own domains, issuer and administrators. This mirrors ZITADEL's instances and organizations; a kernoid tenant
corresponds to a ZITADEL organization, but also owns mail domains.

- A request finds its **instance** by the host it asked for. kernoid believes forwarded host headers only from
  trusted proxies, so a client cannot choose the instance.
- A login finds its **tenant** by the domain of the address: `alice@firma.de` belongs to the tenant that has verified
  `firma.de`. A tenant proves a domain with a TXT record `_kernoid-challenge.<domain>`; one domain belongs to at most
  one tenant of the installation.

## Accounts, groups, roles, projects

- An **account** is a login, a mailbox and – later – the owner of files at once. Its login name is its primary
  address; it can have aliases on the tenant's verified domains. Credentials (password hash, TOTP secret, passkeys,
  recovery codes) are stored apart from its events.
- A **group** holds accounts of its tenant. Today groups hold roles; with mail and files they also become mailing
  lists and owners of shared folders.
- A **role** is a named set of permissions. Every tenant has the built-in roles and may define its own; instances
  have instance roles. Roles go to accounts or groups. See [Administration]({{ '/administration/' | relative_url }}).
- A **project** holds a tenant's applications and the roles those applications understand (*project roles*, e.g.
  `editor`). Accounts and groups are given project roles; a project can put them into tokens or let only accounts
  with a role log in. Projects follow ZITADEL's projects.
- An **application** is an OpenID Connect client of a project: confidential (a server, with a secret) or public (a
  browser or mobile app, PKCE only).

## Sessions

A login creates a **session**: its token (`ks1.…`) is shown once and stored only as a hash. A session passes
*checks* – password, TOTP, passkey, recovery code – and expires after 8 hours by default, at most after 30 days. A
tenant or an application can require a second factor. See [Login and OpenID Connect]({{ '/login/' | relative_url }}).

## Events

Identity and administration are **events**: every change – an account created, a role granted, a session ended – is
appended to one log that cannot be changed afterwards (PostgreSQL triggers refuse updates and deletes). The state
kernoid works with is derived from it. Every event names its instance, its owner (the tenant, or the instance) and who
caused it – `account:<id>` for an administrator, the operator for the CLI. The log is therefore also the audit log.

Credentials never go into events: an event only says that a password or key changed; the secret itself lives in its
own table, written in the same transaction.

## Mail

Every account has a mail store: mailboxes (Inbox, Drafts, Sent, Archive, Junk and Trash to begin with), emails and
threads, modelled on JMAP Mail (RFC 8621) and keeping what IMAP needs – UIDs per mailbox and modification sequences.
Mail is data, not events: what administrators decide about it (an account's quota) is an event, the mail itself is
kept in tables, the raw messages in object storage. kernoid receives mail for its tenants' domains itself – see
[Mail]({{ '/mail/' | relative_url }}). The design is [RFC 0002](https://github.com/kernoid/kernoid/blob/main/rfcs/0002-mail-data-model.md).

## Storage and encryption

kernoid needs nothing but PostgreSQL and S3-compatible object storage. Content (mail bodies, attachments, files) goes
to object storage encrypted with a key per tenant; the tenant keys are wrapped with the installation's main key.

Every TLS connection kernoid makes or takes – HTTPS, SMTP, IMAP, POP3, LDAP, PostgreSQL – prefers the post-quantum
key exchange X25519MLKEM768 over X25519, so that recorded traffic stays unreadable once quantum computers can break
X25519; clients without it connect as before. The design, together with end-to-end encryption, is
[RFC 0006](https://github.com/kernoid/kernoid/blob/main/rfcs/0006-end-to-end-encryption.md).
