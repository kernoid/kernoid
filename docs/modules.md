---
title: Modules
nav_order: 8.5
permalink: /modules/
---

# Modules

A module connects kernoid to one particular outside service. Modules are part of kernoid – compiled in, released with
it, under the same licence – and **off** unless switched on twice: for the installation in the configuration
(`[modules.<name>] enabled = true`), then by each tenant that wants it (`kernoid tenant module <TENANT> <MODULE>
--enabled true`, `PUT /v1/tenant/modules/{module}`, or the settings in the web app's administration). A module that is
off opens no ports and runs no jobs. Foreign code cannot be loaded into kernoid; other services will connect from
outside through actions and hooks (planned before 1.0).

| Module | Connects to | Since |
|---|---|---|
| `clamav` | ClamAV's daemon, clamd: content checked for malware | 0.2 |

## clamav – checking content for malware

kernoid asks [clamd](https://docs.clamav.net/manual/Usage/Scanning.html#clamd) about content of tenants that switched
the module on, before it keeps the content:

| What | When | Refused with |
|---|---|---|
| uploads (JMAP, also joined pieces with `Blob/upload`) | while they are stored | HTTP 422, or `forbidden` in `Blob/upload` |
| files written directly or over WebDAV (`PUT`) | while they are stored | HTTP 422 (direct write), 403 (WebDAV) |
| mail to an account of the tenant, at the MX | before it is accepted | `554 5.7.1` – the sender's server bounces it |
| mail from an account of the tenant (submission) | before it is accepted | `554 5.7.1` |
| messages added with IMAP `APPEND` | before they are stored | `NO [CANNOT]` |

Files made from an upload, attachments and imported emails come from uploads and were checked there. What was stored of
refused content is removed at once; the refusal is logged with the malware's name, without the content. Content
stored before the tenant switched the module on is not checked afterwards (`OPEN`: scanning what is stored).

```toml
[modules.clamav]
enabled = true
address = "clamav:3310"          # host:port, or "unix:/run/clamav/clamd.sock"
max_size = 26214400              # bytes; larger content is kept unscanned
timeout_seconds = 120            # for one scan
refuse_unchecked = true          # while clamd does not answer: refuse content (else keep it unscanned)
```

kernoid sends content to clamd with clamd's `INSTREAM` command, which takes at most its `StreamMaxLength` – 25 MiB by
default, 100 MiB in the official container image. Keep `max_size` and `StreamMaxLength` the same: content larger than `max_size` is kept **unscanned** (and
logged at level debug), and a larger `max_size` than clamd takes makes clamd refuse to scan. Raise both for larger
files; scanning a large file takes clamd time and memory.

While clamd does not answer, content of the tenants that use the module is refused – mail with `451`, so the sender
tries again later, uploads with HTTP 503 – unless `refuse_unchecked = false`. A worker asks clamd every five minutes
and says in the log when it does not answer. clamd needs a few minutes after its start to load its signatures.

With Docker Compose (`deploy/compose`): set `KERNOID_CLAMAV=true` in `.env` and start with
`docker compose --profile clamav up -d`; the service `clamav` runs the official image, which keeps its signatures
current with freshclam, and `max_size` is set to its 100 MiB.

The module needs nothing from clamd but its protocol; ClamAV itself is GPL-2.0 and runs as a service of its own.
