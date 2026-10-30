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
| `jitsi` | Jitsi Meet: video meetings in calendar events, joined with kernoid's tokens | 0.2 |

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

## jitsi – video meetings

kernoid hands out video meetings in a [Jitsi Meet](https://jitsi.github.io/handbook/) that trusts its tokens. In the web
app, a calendar event gets a meeting with **Add video meeting**: the event keeps a link to kernoid –
`https://<instance>/modules/jitsi/join/<room>` –, in JSCalendar's `virtualLocations` (iCalendar `CONFERENCE`) and in
its description, so it reaches invited people in any calendar program. The link names only the room, a random name of
24 hex characters.

Who opens the link is sent on to the room in Jitsi:

| Who | Goes to |
|---|---|
| logged in to the instance, the meeting's owner | the room, with a token as moderator |
| logged in to the instance, anyone else | the room, with a token as participant |
| not logged in | the login, then back to the link – or, with `guests = true`, the room without a token |

A meeting belongs to the tenant of the account that made it; when the tenant stops using the module, its links lead
nowhere (404).

```toml
[modules.jitsi]
enabled = true
url = "https://meet.example.org"   # where Jitsi Meet is
app_id = "kernoid"                 # Jitsi's JWT_APP_ID
app_secret = "…"                   # Jitsi's JWT_APP_SECRET, at least 32 characters
audience = "kernoid"               # the token's aud; the app id unless set
subject = "meet.example.org"       # the token's sub; the host of url unless set
token_minutes = 180                # how long a token is good for
guests = false                     # people without a session join without a token (Jitsi's ENABLE_GUESTS)
```

Keep the secret out of the file: `KERNOID__MODULES__JITSI__APP_SECRET`.

On Jitsi's side ([docker-jitsi-meet](https://jitsi.github.io/handbook/docs/devops-guide/devops-guide-docker/)):
`ENABLE_AUTH=1`, `AUTH_TYPE=jwt`, `JWT_APP_ID` and `JWT_APP_SECRET` as above; `ENABLE_GUESTS=1` with `guests = true`,
where guests wait until someone with a token has joined. The token is signed with HS256 and carries `iss` (the app
id), `aud`, `sub`, `room` (only this room), `iat`, `nbf`, `exp` and `context.user` with `id`, `name`, `email` and
`moderator` (`"true"` or `"false"`). Jitsi checks the token when someone joins and when the connection is made again –
a meeting longer than `token_minutes` may need the link opened again.

**Moderation.** Out of the box, a self-hosted Jitsi makes everyone with a valid token a moderator: Jicofo gives every
authenticated participant the owner role. For the meeting's owner alone to moderate, let Prosody take the role from the
token – its image brings the module – and Jicofo leave roles alone:

```sh
XMPP_MUC_MODULES=token_affiliation   # context.user.moderator "true": moderator; otherwise participant
JICOFO_ENABLE_AUTH=0                 # Jicofo does not make authenticated users owners; Prosody still checks tokens
ENABLE_AUTO_OWNER=false              # nor the first to join
```

Tried with docker-jitsi-meet `stable-11031` (2026-10-30): the owner joins as moderator, an invited account as
participant – also when it joins first –, a token with a changed claim is refused ("authentication failed"), and
`sub` may be the host of `url` (the default) or Jitsi's XMPP domain. Jitsi as a Service reads `context.user.moderator`
itself.

The routes, below the instance:

| Route | Does |
|---|---|
| `GET /modules/jitsi/status` | `{"enabled": …}`: whether the caller's tenant uses the module |
| `POST /modules/jitsi/meetings` | a new meeting of the caller: `{"room", "url"}` (201); 403 when the tenant does not use the module |
| `GET /modules/jitsi/join/{room}` | the redirect above |

They take the session of the web app (with the CSRF header `kernoid-csrf` for `POST`) or a bearer token.
