---
title: Home
nav_order: 1
permalink: /
---

<img src="{{ '/assets/kernoid-lockup-on-dark.svg' | relative_url }}" alt="kernoid" width="320">

# kernoid documentation

kernoid is one sovereign core for email, identity and storage: a single application in Rust, in which a mailbox, a
login and the owner of files are the same account. It runs as a self-hosted service on PostgreSQL and S3-compatible
object storage and is free software under the AGPL.
{: .fs-5 .fw-300 }

**Status:** 0.2, a pre-release – identity and single sign-on, mail with end-to-end encryption, calendars and
contacts, files with public links, LDAP, the Kubernetes operator, the first modules, the web app and the terminal app
are there to try out and test ([changelog](https://github.com/kernoid/kernoid/blob/main/CHANGELOG.md)), the app for
desktop and mobile as an unsigned preview. Nothing here is ready for production yet: the first stable release comes
after an external security audit, with the app signed, once falkOSS is incorporated and holds the app stores'
developer accounts.
{: .warning }

| Page | What it covers |
|---|---|
| [Getting started]({{ '/getting-started/' | relative_url }}) | run kernoid with Docker Compose, create the first instance, tenant and administrator |
| [Concepts]({{ '/concepts/' | relative_url }}) | installation, instance, tenant; accounts, groups, projects, applications; events |
| [Administration]({{ '/administration/' | relative_url }}) | permissions and roles, roles of a tenant's own, instance administrators, projects |
| [Identity providers and SCIM]({{ '/federation/' | relative_url }}) | logging in with Entra ID, Google, Okta, Keycloak, ADFS (OpenID Connect, SAML); provisioning with SCIM |
| [Directory (LDAP)]({{ '/directory/' | relative_url }}) | each tenant's people and groups for software that reads a directory |
| [Login and OpenID Connect]({{ '/login/' | relative_url }}) | sessions, second factors and policies; connecting an application |
| [TypeScript SDK]({{ '/sdk/' | relative_url }}) | logging in to a web app with kernoid; building a login UI |
| [Mail]({{ '/mail/' | relative_url }}) | receiving and sending, JMAP, IMAP and POP3, sharing, quotas |
| [Calendars and contacts]({{ '/calendars/' | relative_url }}) | CalDAV, CardDAV, JMAP, sharing, invitations |
| [Files]({{ '/files/' | relative_url }}) | the file store, JMAP for files, quotas |
| [Web app]({{ '/app/' | relative_url }}) | mail, calendar, contacts and files in the browser |
| [Modules]({{ '/modules/' | relative_url }}) | virus scanning (ClamAV) and video meetings (Jitsi), switched on per tenant |
| [API]({{ '/api/' | relative_url }}) | REST and GraphQL: authentication, errors, every operation |
| [CLI reference]({{ '/cli/' | relative_url }}) | every `kernoid` command |
| [Configuration]({{ '/configuration/' | relative_url }}) | every setting, as TOML key and environment variable |
| [Operations]({{ '/operations/' | relative_url }}) | deployment, TLS and reverse proxies, migrations, keys |
| [Contributing]({{ '/contributing/' | relative_url }}) | build, test and the rules of the repository |

The design decisions are written down as RFCs in the repository – [RFC 0001: data and event
model](https://github.com/kernoid/kernoid/blob/main/rfcs/0001-data-and-event-model.md). The reasons behind kernoid –
why one core, why free software – are in the [whitepaper](https://github.com/kernoid/whitepaper).

## The name

```
Kern    German      → core
kerno   Esperanto   → core
kerno + id          → kernoid
kern0id, 0 as o     → kerno.id
kern0id, without 0  → kern.id
kernoid, OIDC       → OpenID Connect
```

*Kern* is German for core, and *kerno* is Esperanto for core. Both are in the wordmark `kern0id`: read the 0 as
an o and it says **kerno.id**, leave it out and it says **kern.id** – the core, with identity; the dot in the 0 is
the dot of the domain. kernoid joins the two: *kerno* and *id*. The *oid* also winks at OpenID Connect (OIDC), the
protocol kernoid logs people in with, and, as an aside, at mathematics: the kernel of a map, and *-oid* as in monoid –
kernel and monoid make kernoid.

kernoid is a project of falkOSS – Falcon Lake Open Source Software gUG (haftungsbeschränkt) i. G. Source code:
[kernoid/kernoid](https://github.com/kernoid/kernoid) (AGPL-3.0-or-later).
