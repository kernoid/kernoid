---
title: Configuration
nav_order: 8
permalink: /configuration/
---

# Configuration

kernoid reads one TOML file (`--config <file>` or `KERNOID_CONFIG`). Every key can be set or overridden by an
environment variable: `KERNOID__A__B=value` sets `a.b` – two underscores separate the levels. Values are read as TOML
where they parse (`true`, `10`, `["api"]`), as strings otherwise. Unknown keys are an error, so a misspelt key does
not go unnoticed. `kernoid check-config` prints what kernoid read, with secrets hidden; secrets never appear in logs.

```toml
roles = ["all"]

[http]
listen = "0.0.0.0:8080"
trusted_proxies = ["10.0.0.0/8"]

[database]
url = "postgres://kernoid_app:…@db/kernoid?sslmode=verify-full"
migrate_url = "postgres://kernoid_owner:…@db/kernoid?sslmode=verify-full"

[blob]
kind = "s3"
endpoint = "http://garage:3900"
region = "garage"
bucket = "kernoid"
access_key_id = "…"
secret_access_key = "…"
allow_http = true

[encryption]
main_key = "…"   # 64 hex characters: openssl rand -hex 32
```

## Keys

| Key | Default | Meaning |
|---|---|---|
| `roles` | `["all"]` | what this process does: `api` (HTTP), `worker` (background work), `smtp` (the MX and submission), `imap` (IMAP and POP3), `all` |
| `http.listen` | `0.0.0.0:8080` | address and port to listen on |
| `http.tls.certificate`, `http.tls.key` | – | PEM files; with them kernoid serves HTTPS itself (TLS 1.2 and 1.3, HTTP/2) |
| `http.trusted_proxies` | `[]` | addresses or networks whose `Forwarded` / `X-Forwarded-*` headers are believed |
| `http.metrics_listen` | – | serve Prometheus metrics at `/metrics` on this address – an internal one, it is not protected |
| `http.login_ui` | `/usr/share/kernoid/login` | the built login UI, served at `/login`; the container image has it there |
| `http.web_app` | `/usr/share/kernoid/app` | the built web app (mail, calendar, contacts), served at `/app`; the container image has it there |
| `http.public_scheme` | `https` | how instances are reached from outside; `http` only for trying kernoid out. Issuer and links are built from it and the instance's primary domain |
| `http.public_port` | – | the port instances are reached on from outside, if not the scheme's own – e.g. `8080` when trying kernoid out; issuer and links (OpenID Connect, JMAP) name it |
| `database.url` | required | connection URL of the runtime role |
| `database.migrate_url` | – | connection URL of the role that owns the schema and runs `kernoid migrate`; leave out only if the runtime role owns the schema – then it could change events |
| `database.max_connections` | `10` | |
| `database.statement_timeout_ms` | `30000` | longest time one statement may run; `0` for no limit |
| `database.idle_in_transaction_timeout_ms` | `10000` | longest time a transaction may stay open without a statement; `0` for no limit |
| `blob.kind` | required | `s3`, or `memory` (lost on exit – for tests only) |
| `blob.endpoint` | – | S3 endpoint URL; leave out for AWS |
| `blob.region` | `us-east-1` | |
| `blob.bucket`, `blob.access_key_id`, `blob.secret_access_key` | required for `s3` | |
| `blob.allow_http` | `false` | allow an endpoint over plain HTTP, e.g. object storage on the same host |
| `encryption.main_key` | required | 64 hex characters (256 bit); wraps the tenant keys and the signing keys |
| `encryption.previous_main_keys` | `[]` | earlier main keys, only to read what is not rewrapped yet |
| `modules.<name>.enabled` | `false` | switches a compiled-in module on for the installation; the rest of the table is the module's own configuration |
| `outbound.allow_private_networks` | `false` | let kernoid reach identity providers and back-channel logout URIs at private, loopback and link-local addresses and over plain HTTP – for an own Keycloak in the network; only where the tenants are trusted with that |
| `http.acme.contact` | `[]` | contact URIs for the ACME CA, e.g. `mailto:ops@example.org` |
| `http.acme.terms_agreed` | `false` | must be `true` to use ACME: you agree to the CA's terms of service |
| `http.acme.directory` | Let's Encrypt | the CA's ACME directory URL |
| `http.acme.http_listen` | `0.0.0.0:80` | where the CA's HTTP-01 requests arrive; other requests there are redirected to HTTPS |
| `http.acme.renew_days` | `30` | renew a certificate this many days before it ends |
| `http.acme.ca_root` | – | a further root certificate (PEM) to trust for the CA – for a test CA |
| `oidc.key_rotation_days` | `90` | a signing key signs this long, then the worker rotates it; `0` turns rotation off |
| `oidc.key_publish_hours` | `24` | a new signing key is published this long before it signs |
| `oidc.retired_key_days` | `30` | a key that no longer signs stays published this long (at least an hour) |
| `mail.max_message_size` | `52428800` | largest message accepted, in bytes (50 MiB) |
| `mail.notification_from` | – | the sender of kernoid's own messages – registration codes – on a domain kernoid sends for; without it, people register only with identity providers |
| `mail.tls.certificate`, `mail.tls.key` | – | PEM files for SMTP, submission, IMAP and POP3, e.g. those of a reverse proxy such as Caddy; read again within a minute when they change. Without them: ACME's certificates, else `http.tls` |
| `mail.changes_kept_days` | `30` | how long the journal of mail changes is kept; a client away longer (JMAP, IMAP) loads the mailbox anew – the journals of calendars, contacts and files as well |
| `files.max_file_size` | `10737418240` | largest file accepted, in bytes (10 GiB); content streams to object storage in parts |
| `files.versions_kept` | `10` | earlier contents kept per file |
| `smtp.hostname` | – | receiving mail is on when `[smtp]` is set: the host name the tenants' MX records point to, used in the greeting and in `Received` and `Authentication-Results` |
| `smtp.listen` | `0.0.0.0:25` | where the MX listens (process role `smtp`) |
| `smtp.submission_listen` | `0.0.0.0:587` | submission with `STARTTLS`; only with certificates |
| `smtp.submissions_listen` | `0.0.0.0:465` | submission with TLS from the start; only with certificates |
| `smtp.max_recipients` | `100` | recipients per message |
| `smtp.max_connections` | `1000` | sessions at once; more connections wait |
| `smtp.max_received` | `50` | more `Received` headers than this means a loop: refused |
| `smtp.junk_score` | `5.0` | mail with at least this spam score goes to Junk |
| `smtp.timeout_seconds` | `300` | how long the server waits for a command or data |
| `smtp.queue_days` | `5` | how long outgoing mail is tried before it bounces |
| `smtp.spf` | – | the SPF record the DNS check suggests instead of `v=spf1 mx -all`, e.g. with a relay's `include:` |
| `smtp.relay.host`, `smtp.relay.port` | –, `587` | hand all mail for other servers to this relay, over TLS with a valid certificate |
| `smtp.relay.implicit_tls` | `false` | TLS from the start (port 465) instead of `STARTTLS` |
| `smtp.relay.username`, `smtp.relay.password` | – | the login at the relay |
| `imap.listen` | `0.0.0.0:143` | mail clients are served when `[imap]` is set (process role `imap`): IMAP with `STARTTLS`; only with certificates |
| `imap.tls_listen` | `0.0.0.0:993` | IMAP with TLS from the start |
| `imap.pop3_listen`, `imap.pop3_tls_listen` | – | POP3 with `STLS` and with TLS from the start, e.g. `0.0.0.0:110` and `0.0.0.0:995`; off unless set |
| `imap.max_connections` | `5000` | sessions at once per listener; more connections wait |
| `imap.timeout_seconds` | `1800` | a session that says nothing this long – `IDLE` included – is logged out |
| `log.filter` | – | e.g. `info,kernoid=debug` (syntax of `tracing_subscriber::EnvFilter`) |
| `log.format` | `text` | `text` or `json` |
| `log.otlp_endpoint` | – | send traces to an OpenTelemetry collector over OTLP/HTTP, e.g. `http://otel-collector:4318/v1/traces` |

{: .warning }
Without `encryption.main_key` the content in object storage cannot be read again. Keep a copy apart from the database
and the object storage.

The same as environment variables, e.g. for a container:

```sh
KERNOID__DATABASE__URL=postgres://…
KERNOID__ENCRYPTION__MAIN_KEY=…
KERNOID__HTTP__TRUSTED_PROXIES='["172.16.0.0/12"]'
```

There are no modules compiled in yet – the first ones are planned for 1.0 (Jitsi, WOPI, virus scanning). A table
`[modules.<name>]` for a module that does not exist is an error.
