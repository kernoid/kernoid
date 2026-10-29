---
title: CLI reference
nav_order: 7
permalink: /cli/
---

# CLI reference

`kernoid` is the server and the operator's tool at once – one binary, the same in the container image. Every command
reads the [configuration]({{ '/configuration/' | relative_url }}) (`--config <file>` or `KERNOID_CONFIG`, overridden by
`KERNOID__…` environment variables), except `openapi` and `graphql-schema`. `kernoid <command> --help` describes
each one.

Operators work below the API: the CLI checks no roles. Changes it makes are events like any other, with the operator
as their creator. Secrets – passwords, keys – are read from standard input, never from arguments.

## Running

| Command | Effect |
|---|---|
| `kernoid serve` | runs the roles of this process (`api`, `worker`) until SIGINT or SIGTERM |
| `kernoid migrate` | brings the database schema up to date with the owner role, grants the runtime role what it needs, then exits |
| `kernoid check-config` | reads the configuration and prints it, secrets hidden |
| `kernoid openapi` | prints the OpenAPI description of the REST API |
| `kernoid graphql-schema` | prints the GraphQL schema |

## Keys

| Command | Effect |
|---|---|
| `kernoid keys status` | counts the tenant keys by the main key that wraps them |
| `kernoid keys rotate <TENANT>` | adds a tenant's next key; new content is encrypted with it, older content stays readable |
| `kernoid keys rewrap` | wraps every tenant key and signing key with the current main key, after changing it; runs as the owner |

## Instances

| Command | Effect |
|---|---|
| `kernoid instance add --name <NAME> --domain <DOMAIN>` | creates an instance reached under DOMAIN |
| `kernoid instance list` | |
| `kernoid instance rename <INSTANCE> <NAME>` | |
| `kernoid instance registration-tenant <INSTANCE> <TENANT>` | where people without an address of a tenant register (`none`: nowhere) |
| `kernoid instance add-domain <INSTANCE> <DOMAIN>` | reaches the instance under another domain as well |
| `kernoid instance remove-domain <INSTANCE> <DOMAIN>` | not the primary domain |
| `kernoid instance set-primary <INSTANCE> <DOMAIN>` | the domain the issuer and links use |
| `kernoid acme status` | every instance domain with its certificate's end, or why ordering one failed |
| `kernoid instance set-login-ui <INSTANCE> [URL]` | sends logins to a login UI of the instance's own; without URL, back to kernoid's |
| `kernoid instance set-passkey-rp-id <INSTANCE> <DOMAIN>` | binds passkeys to another RP ID; earlier passkeys stop working |
| `kernoid instance define-role <INSTANCE> <ROLE> --permission <P>…` / `delete-role <INSTANCE> <ROLE>` | instance roles of the instance's own |
| `kernoid instance grant <INSTANCE> --account <ID> \| --group <ID> --role <ROLE>` | assigns `instance_admin` or `instance_auditor` |
| `kernoid instance revoke <INSTANCE> --account <ID> \| --group <ID> --role <ROLE>` | the last `instance_admin` stays |
| `kernoid instance roles <INSTANCE>` | who holds which instance role |

## Tenants

| Command | Effect |
|---|---|
| `kernoid tenant add <INSTANCE> --name <NAME>` | creates a tenant; prints its id |
| `kernoid tenant list <INSTANCE>` | |
| `kernoid tenant rename <TENANT> <NAME>` | |
| `kernoid tenant deactivate <TENANT>` / `reactivate` | nobody of a deactivated tenant can log in |
| `kernoid tenant add-domain <TENANT> <DOMAIN>` | claims a mail domain; prints the TXT record that proves it |
| `kernoid tenant verify-domain <TENANT> <DOMAIN> [--trust]` | looks the record up; `--trust` marks the domain verified without DNS |
| `kernoid tenant remove-domain <TENANT> <DOMAIN>` | unless addresses use it |
| `kernoid tenant module <TENANT> <MODULE> --enabled <true\|false>` | switches a compiled-in module on or off for the tenant |
| `kernoid tenant require-mfa <TENANT> --required <true\|false>` | requires a second factor for logins to applications |
| `kernoid tenant mfa-grace <TENANT> <DAYS>` | accounts without a second factor may log in without one for DAYS |
| `kernoid tenant login-policy <TENANT> --usernames <true\|false> --email-login <true\|false>` | how the tenant's accounts log in |
| `kernoid tenant registration <TENANT> --allowed <true\|false> [--domain <DOMAIN>]…` | opens registration; the domains new accounts may take an address on |
| `kernoid tenant service-policy <TENANT> <mail\|files> --assign <none\|native\|all> [--approval]` | who gets a service when an account is created |
| `kernoid tenant mail-quota <TENANT> <BYTES>` | the mail quota of every account without its own; `none` for no limit |
| `kernoid tenant files-quota <TENANT> <BYTES>` | the files quota of every account without its own; `none` for no limit |
| `kernoid tenant mail-retention <TENANT> --trash-days <DAYS> --junk-days <DAYS>` | empties Trash and Junk after so many days; `none` keeps them |
| `kernoid tenant mail-dns <TENANT>` | the DNS records the tenant's mail domains need (MX, SPF, DKIM, DMARC) and whether they are published |
| `kernoid tenant dkim-rotate <TENANT> --domain <DOMAIN> [--algorithm rsa\|ed25519]` | a new DKIM key for the domain; it signs once DNS shows its record |
| `kernoid tenant grant <TENANT> --account <ID> \| --group <ID> --role <ROLE>` | assigns a tenant role, e.g. the first `tenant_admin` |
| `kernoid tenant revoke <TENANT> --account <ID> \| --group <ID> --role <ROLE>` | the last `tenant_admin` stays |
| `kernoid tenant roles <TENANT>` | who holds which role |

## Accounts

| Command | Effect |
|---|---|
| `kernoid account add <TENANT> <ADDRESS> --name <NAME>` | creates an account; ADDRESS is its login name, on a verified domain |
| `kernoid account add-shared <TENANT> <ADDRESS> --name <NAME>` | creates a shared mailbox: an account nobody logs in as |
| `kernoid account add-external <TENANT> --name <NAME> [--email <ADDRESS> [--verified]] [--username <NAME>]` | creates an account without an address of the tenant: for logins only – and files, if granted |
| `kernoid account username <ACCOUNT> <USERNAME>` | a username to log in with (`none` removes it); the tenant must use usernames |
| `kernoid account contact <ACCOUNT> <ADDRESS> [--verified]` | the contact address, any domain (`none` removes it); a verified one logs in |
| `kernoid account services <ACCOUNT>` | the account's services and their states |
| `kernoid account grant-service <ACCOUNT> <mail\|files>` / `revoke-service` | grants a service – also a requested one – or takes it away |
| `kernoid account list <TENANT>` | with `person` or `shared` |
| `kernoid account rename <ACCOUNT> <NAME>` | |
| `kernoid account password <ACCOUNT>` | sets the password, read from standard input (no echo on a terminal) |
| `kernoid account add-alias <ACCOUNT> <ADDRESS>` / `remove-alias` | |
| `kernoid account set-primary <ACCOUNT> <ADDRESS>` | makes an alias the login name |
| `kernoid account deactivate <ACCOUNT>` / `reactivate` | |
| `kernoid account check-login <INSTANCE> <ADDRESS>` | checks a password read from standard input |
| `kernoid account reset-second-factors <ACCOUNT>` | removes all TOTP, passkeys, recovery codes and app passwords |
| `kernoid account mail-quota <ACCOUNT> <BYTES>` | how many bytes the account's emails may take; `none` for the tenant's default |
| `kernoid account files-quota <ACCOUNT> <BYTES>` | how many bytes the account's files may take; `none` for the tenant's default |
| `kernoid account app-password add <ACCOUNT> <NAME>` | makes an app password for a mail program and prints it, once |
| `kernoid account app-password list <ACCOUNT>` / `remove <ACCOUNT> <ID>` | |

## Calendars and contacts

| Command | Effect |
|---|---|
| `kernoid collections list <ACCOUNT>` | the account's calendars and address books with their ids |
| `kernoid collections access <ACCOUNT>` | who may use them, at which level |
| `kernoid collections share <ACCOUNT> <COLLECTION> <GRANTEE> <LEVEL>` | grants an address or `$group` of the tenant a level: `freebusy`, `read`, `rsvp`, `write`, `admin` (address books: `read`, `write`, `admin`) |
| `kernoid collections unshare <ACCOUNT> <COLLECTION> <GRANTEE>` | removes the grant |
| `kernoid collections export <ACCOUNT> <COLLECTION>` | writes a calendar as iCalendar or an address book as vCard to standard output |
| `kernoid collections import <ACCOUNT> <COLLECTION> <FILE>` | stores the events or contacts of a file (`-` for standard input); one with a UID that is there already is replaced |

## Files and drives

| Command | Effect |
|---|---|
| `kernoid files drives <TENANT>` | the tenant's drives: file stores that belong to the tenant |
| `kernoid files add-drive <TENANT> --name <NAME>` | creates a drive; prints its id |
| `kernoid files access <ACCOUNT>` | who may use an account's files or a drive, and where |
| `kernoid files grant <ACCOUNT> <GRANTEE> <RIGHTS> [--node <DIRECTORY>]` | grants an address or `$group` of the tenant rights – letters of `randws` – on a folder, or on the whole store |
| `kernoid files revoke <ACCOUNT> <GRANTEE> [--node <DIRECTORY>]` | removes the grant |

## Mail

| Command | Effect |
|---|---|
| `kernoid mail mailboxes <ACCOUNT>` | the account's mailboxes with their counts; creates the default ones on first use |
| `kernoid mail import <ACCOUNT> <FILE> [--mailbox <ID or ROLE>]` | stores a message (an `.eml` file, or `-` for standard input) in the inbox or the given mailbox |
| `kernoid mail export <ACCOUNT> <DIRECTORY>` | writes every mailbox as an mbox file, with the keywords |
| `kernoid mail import-mbox <ACCOUNT> <FILE> [--mailbox <ID or ROLE>]` | stores the messages of an mbox file (or `-`) in the inbox or the given mailbox, with their keywords |
| `kernoid mail sieve list <ACCOUNT>` | the account's Sieve scripts; `*` marks the active one |
| `kernoid mail sieve put <ACCOUNT> <NAME> <FILE> [--activate]` | saves a script (`-` for standard input) after checking it |
| `kernoid mail sieve activate <ACCOUNT> <NAME>` / `deactivate <ACCOUNT>` | which script runs, or none |
| `kernoid mail sieve remove <ACCOUNT> <NAME>` | |
| `kernoid mail access <ACCOUNT>` | who may use the account's mail, with which rights |
| `kernoid mail grant <ACCOUNT> <GRANTEE> --rights <RIGHTS> [--mailbox <ID or ROLE>] [--send-as]` | grants access; GRANTEE is an address of an account or `$` and a group's name, RIGHTS letters of `lrswipkxtea` |
| `kernoid mail revoke <ACCOUNT> <GRANTEE> [--mailbox <ID or ROLE>]` | removes a grant |
| `kernoid mail queue [--limit N]` | the recipients of outgoing mail: state, tries, next try, last error |

## Projects and applications

| Command | Effect |
|---|---|
| `kernoid project add <TENANT> --name <NAME>` | creates a project; prints its id |
| `kernoid project list <TENANT>` | projects with their roles |
| `kernoid app add <PROJECT> --name <NAME> [--redirect-uri <URI>…] [--public] [--post-logout-redirect-uri <URI>…]` | registers an application; prints its client id and, for a confidential one, its secret – once. A public one needs a redirect URI; a confidential one without is an API that only checks tokens |
| `kernoid app list <TENANT>` | |
| `kernoid app set-redirect-uris <APPLICATION> --redirect-uri <URI>…` | |
| `kernoid app set-post-logout-redirect-uris <APPLICATION> [--post-logout-redirect-uri <URI>…]` | |
| `kernoid app new-secret <APPLICATION>` | replaces the secret of a confidential application; prints it once |
| `kernoid app deactivate <APPLICATION>` / `reactivate` | |
| `kernoid app require-mfa <APPLICATION> --required <true\|false>` | |
| `kernoid app set-options <APPLICATION> [--jwt] [--offline-access] [--consent-required] [--backchannel-logout-uri URI] [--frontchannel-logout-uri URI]` | what is not given is off |

Project roles, authorizations and everything else a tenant does for itself go through the
[API]({{ '/api/' | relative_url }}).

## Signing keys

| Command | Effect |
|---|---|
| `kernoid signing-key list <INSTANCE>` | |
| `kernoid signing-key add <INSTANCE>` | creates a key: published at once, signing only once activated |
| `kernoid signing-key activate <INSTANCE> <KID>` | signs with this key from now on; the one before stays published, inactive |
| `kernoid signing-key remove <INSTANCE> <KID>` | removes an inactive key whose tokens have expired |
