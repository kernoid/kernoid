---
title: Directory (LDAP)
nav_order: 4.6
permalink: /directory/
---

# Directory over LDAP

Software that reads its users from a directory – a wiki, a ticket system, a printer, network gear – reads them from
kernoid over LDAP. Each tenant's people and groups are a directory of their own, read only: accounts and groups are
kept in kernoid (API, SCIM, the web app), not over LDAP.

## Switching it on

```toml
[ldap]
listen = "0.0.0.0:389"       # LDAP with StartTLS
tls_listen = "0.0.0.0:636"   # LDAPS
max_entries = 5000           # the most entries one search returns
```

A process with the role `ldap` (part of `all`) listens when `[ldap]` is set and kernoid has certificates – the same as
IMAP: `mail.tls`, ACME or `http.tls`. Without TLS nobody can bind.

## The tree

| DN | What |
|---|---|
| `o=<tenant id>` | the tenant's tree – the id is shown in the administration's settings |
| `ou=people,o=<tenant id>` | its people: `uid=<login>,ou=people,o=<tenant id>` |
| `ou=groups,o=<tenant id>` | its groups: `cn=<name>,ou=groups,o=<tenant id>` |

A person is an active account that logs in (not a shared mailbox, not a team folder), an `inetOrgPerson`:

| Attribute | Value |
|---|---|
| `uid` | the login name: the primary address, else the username or contact address |
| `cn`, `displayName` | the display name |
| `sn`, `givenName` | the display name's last word, and the words before it |
| `mail` | every address, the primary first |
| `memberOf` | the DNs of its groups |
| `entryUUID` (operational) | the account's id |

A group is a `groupOfNames` with `cn` (its name), `mail` (its addresses), `member` (the DNs of its people) and
`entryUUID`.

## Binding

Bind over TLS – LDAPS, or StartTLS first – with a DN (`uid=alice@firma.example,ou=people,o=…`) or simply the login
name (`alice@firma.example`), and an **app password** (account page) – or the account's password, if it needs no
second factor. Failed binds count like failed logins. Without a bind, only the root DSE can be read.

A bound account reads its own tenant's tree. Software that first searches for a user and then binds as that user
binds for the search with an account of its own – e.g. `wiki@firma.example`, with an app password.

Typical settings in other software:

| Setting | Value |
|---|---|
| Server | `ldaps://ldap.firma.example:636` (or `ldap://…:389` with StartTLS) |
| Base DN | `o=<tenant id>` |
| Users | base `ou=people,o=<tenant id>`, filter `(objectClass=inetOrgPerson)`, login attribute `uid` or `mail` |
| Groups | base `ou=groups,o=<tenant id>`, filter `(objectClass=groupOfNames)`, member attribute `member` |

```sh
ldapsearch -H ldaps://ldap.firma.example -D alice@firma.example -W \
  -b "ou=people,o=<tenant id>" "(mail=bob@firma.example)" cn mail memberOf
```

Writing – add, modify, delete, rename, compare – is refused (`unwillingToPerform`). Simple paged results are
understood: every entry comes on the first page.
