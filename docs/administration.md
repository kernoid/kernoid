---
title: Administration
nav_order: 4
permalink: /administration/
---

# Administration

Tenants administer themselves: their administrators are accounts of the tenant with roles. Instance administrators
look after the instance and may act in every tenant of it. Operators run the installation with the CLI and set up the
first administrators. The [API]({{ '/api/' | relative_url }}) lists every operation with the permission it needs.

## Permissions

A permission allows one kind of administration. **Tenant permissions** act within one tenant:

| Permission | Allows |
|---|---|
| `directory.read` | seeing the tenant, its accounts, groups, roles, projects and applications |
| `tenant.manage` | the tenant's name; switching modules on and off; the tenant's default mail quota |
| `domains.manage` | claiming, verifying and removing mail domains |
| `policies.manage` | the tenant's policies, e.g. requiring a second factor |
| `accounts.manage` | creating and changing accounts, aliases, passwords, resetting second factors, ending sessions, withdrawing consents; shared mailboxes and an account's mail: quota, mailboxes, Sieve scripts, importing messages, who may use it ([Mail]({{ '/mail/' | relative_url }})) |
| `groups.manage` | creating, renaming and removing groups, changing their members and their addresses (a group with an address is a distribution list) |
| `roles.manage` | defining the tenant's own roles; granting and revoking tenant roles |
| `projects.manage` | projects, their settings and their roles |
| `applications.manage` | applications: create, change, new secret, second-factor policy, options (token format, offline access, consent, logout URIs) |
| `authorizations.manage` | giving accounts and groups project roles |
| `identity_providers.manage` | connecting identity providers accounts log in with ([Identity providers]({{ '/federation/' | relative_url }})) |
| `provisioning.manage` | SCIM tokens for the tenant's directory |

**Instance permissions** act on the instance:

| Permission | Allows |
|---|---|
| `instance.read` | seeing the instance, its domains, tenants, instance roles and signing keys, and the queue of outgoing mail |
| `instance.manage` | the instance's name, domains and signing keys |
| `tenants.manage` | creating, renaming, deactivating tenants; marking their domains verified without DNS |
| `instance_roles.manage` | granting and revoking instance roles |

## Roles

A role is a named set of permissions, given to an account or a group. An account holds the roles given to it and to
every group it is a member of.

**Built-in tenant roles** exist in every tenant:

| Role | Permissions |
|---|---|
| `tenant_admin` | every tenant permission |
| `user_manager` | `directory.read`, `accounts.manage`, `groups.manage`, `authorizations.manage` |
| `application_manager` | `directory.read`, `projects.manage`, `applications.manage` |
| `auditor` | `directory.read` |

**Roles of a tenant's own:** a tenant defines further roles from tenant permissions – `PUT /v1/roles/<name>` with
the permissions, or `defineRole` in GraphQL. Names have lower-case letters, digits and `_`; the names of built-in roles
are taken. Changing a role's permissions changes what its holders may do at once; a role can be deleted once nobody
holds it.

**Built-in instance roles:**

| Role | At the instance | In every tenant of the instance |
|---|---|---|
| `instance_admin` | every instance permission | every tenant permission |
| `instance_auditor` | `instance.read` | `directory.read` |

Instance roles go to accounts or groups of any tenant of the instance.

**Instance roles of an instance's own:** `PUT /v1/instance/roles/<name>` with permissions (or `defineInstanceRole`,
needs `instance_roles.manage`) – instance permissions apply at the instance, tenant permissions in every tenant of it.
A help desk, for instance, with `instance.read`, `directory.read` and `accounts.manage`. Deleted with `DELETE` once
nobody holds it.

## Acting on another tenant

An administrator acts on the tenant of their own account. Instance administrators name another tenant of the
instance with the header **`kernoid-tenant: <tenant id>`** – in REST and in GraphQL alike, as ZITADEL's management API
does with `x-zitadel-orgid`. For anyone without an instance role, another tenant does not exist (`404`).

## Safeguards

- **No escalation through the back door.** Granting tenant roles needs `roles.manage`. Changing the members of a
  group that holds roles needs the permission to grant what it holds as well (`roles.manage`,
  `instance_roles.manage`, `authorizations.manage`).
- **Nobody takes over a stronger account.** Setting another account's password, resetting its second factors,
  deactivating it, ending its sessions or withdrawing its consents needs every permission that account holds – a user manager cannot reset
  the password of a tenant administrator.
- **Someone stays in charge.** The last `tenant_admin` assignment of a tenant and the last `instance_admin`
  assignment of an instance cannot be revoked. Only active accounts of active tenants count – directly or through a
  group –, so kernoid also refuses to deactivate an account, remove a group member or deactivate a tenant if that
  would leave nobody active in charge. An instance administrator cannot deactivate their own tenant.
- **Second factor.** If a tenant requires a second factor, administration does too – for its own administrators and
  for instance administrators acting on it.
- **Everything is recorded.** Every change is an event naming the administrator (`account:<id>`).

## Projects

A project holds applications and the roles they understand. Project roles have a key (e.g. `editor`, letters, digits,
`_ . : -`), a display name and an optional group for display. Two settings decide what they do at login:

| Setting | Effect |
|---|---|
| `role_assertion` | the account's project roles go into the ID token and userinfo, as the claim `urn:kernoid:project:roles` |
| `role_check` | only accounts with at least one role in the project may log in to its applications – also refreshing tokens stops once the last role is taken away |

Project roles are given to accounts and groups of the tenant (`PUT /v1/projects/<id>/authorizations/<role>/<kind>/<id>`);
an account holds the roles given to it and to its groups. A role can be removed once nobody holds it, a project once it
has no applications and no role is given.

## Granting a project to another tenant

A tenant can share a project with another tenant of the instance, as ZITADEL's project grants do: `PUT
/v1/projects/<id>/grants/<tenant>` with the roles it may use – the tenant named by its id or one of its verified mail
domains (needs `projects.manage`).

- The other tenant sees the project under `GET /v1/granted-projects` and gives the granted roles to its own accounts
  and groups (`authorizations.manage`) – no other roles, and it cannot change the project.
- Its accounts may then log in to the project's applications; the roles claim names their tenant.
- The project's tenant sees every tenant's authorizations, the other tenant only its own.
- A grant, or one of its roles, can be taken back once the other tenant no longer gives it to anyone.

## Bootstrapping

The first administrators are set up by the operator:

```sh
kernoid tenant grant <tenant> --account <account> --role tenant_admin
kernoid instance grant <instance> --account <account> --role instance_admin
```

Both also work with `--group <group>`. `kernoid tenant roles <tenant>` and `kernoid instance roles <instance>` list who
holds what; `revoke` takes a role back.

## Not yet

Marked `OPEN` in RFC 0001: permissions on calendars and folders (with files). Permissions on mailboxes are mail's
own (RFC 0002, 12).
