<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# kernoid on a public test machine

kernoid with every role, PostgreSQL, Garage (object storage) and Caddy on one machine with Docker. Caddy obtains the
certificates from Let's Encrypt and serves HTTPS for the instance; kernoid serves mail itself (SMTP, submission,
IMAP) with Caddy's certificate for the mail host, which it reads again when Caddy renews it (`mail.tls`).

For testing: there are no backups, and everything runs once.

The names below are the defaults of `env.example`:

| Name | Default | What it is |
|---|---|---|
| `KERNOID_HOST` | `test.kernoid.dev` | the instance: login, account pages, API |
| `MAIL_HOST` | `mail.test.kernoid.dev` | where MX records point and mail programs connect; must differ from `KERNOID_HOST` |
| mail domain | `test.kernoid.dev` | the part after `@`, set up with the CLI below |

## The machine

- Docker with Compose, and this directory with `../compose/` (a checkout of the repository, or `git archive`). The
  image comes from `ghcr.io/kernoid/kernoid`, which CI pushes from `main` (tags `main` and `sha-<commit>`) and from
  version tags. While the repository is private, so is the image: log in once with a token that may only read
  packages (a classic token with `read:packages`): `docker login ghcr.io -u <GitHub user> --password-stdin`.
- Open ports: 80 and 443 (Caddy; 80 for the ACME challenge), 25 (incoming mail), 587 and 465 (submission), 143 and
  993 (IMAP). POP3 is off.
- **Outgoing port 25** must be open for kernoid to deliver mail; many hosters block it at first and open it on request.
  Otherwise send through a relay (`KERNOID__SMTP__RELAY__…`, see `docs/configuration.md`).
- **Reverse DNS:** the machine's addresses should resolve to `MAIL_HOST` (set at the hoster); receivers check it.
- Docker keeps the address of mail clients for IPv4. Whether it does for IPv6 depends on the Docker setup (`ip6tables`,
  `userland-proxy`): OPEN – check `Received:` headers when testing over IPv6.

## DNS

Before the first start (Caddy needs them for the certificates):

```
test.kernoid.dev.       A     <IPv4>      ; and AAAA <IPv6> if the machine has one
mail.test.kernoid.dev.  A     <IPv4>
test.kernoid.dev.       MX    10 mail.test.kernoid.dev.
```

The TXT records that prove the domain and the mail records (SPF, DKIM, DMARC) come from kernoid, below.

## Start

```sh
cd deploy/test
cp env.example .env     # set every value; the comments say how to generate them
docker compose up -d
docker compose logs -f caddy kernoid
```

kernoid waits until Caddy holds the mail host's certificate (Caddy's health check), then starts; the `migrate` step
has brought the schema up to date before. Then:

```sh
curl https://test.kernoid.dev/readyz     # {"database":"ok","blob":"ok"}
```

With Let's Encrypt's staging CA (see `env.example`) nothing counts against the real CA's limits, but clients do not
trust the certificates; switch to the real CA once it works, and remove the volume `kernoid-test_caddy-data` – or keep
it, Caddy then simply orders the real certificates.

## First setup

```sh
alias kernoid='docker compose exec kernoid kernoid'
kernoid instance add --name Test --domain test.kernoid.dev
kernoid instance list                                     # the instance id
kernoid tenant add <instance> --name Test                 # the tenant id
kernoid tenant add-domain <tenant> test.kernoid.dev       # prints a TXT record: publish it
kernoid tenant verify-domain <tenant> test.kernoid.dev
kernoid tenant mail-dns <tenant>                          # MX, SPF, DKIM, DMARC: publish them, run it again to check
```

The first administrator – the password is read from standard input:

```sh
kernoid account add <tenant> admin@test.kernoid.dev --name Admin   # the account id
docker compose exec -it kernoid kernoid account password <account>
kernoid tenant grant <tenant> --account <account> --role tenant_admin
kernoid instance grant <instance> --account <account> --role instance_admin
```

The account page is `https://test.kernoid.dev/login/account`; set up a second factor there. The web app – mail,
calendar, contacts – is `https://test.kernoid.dev/` (it leads to `/app/`).

### Registration and services (optional)

```sh
kernoid instance registration-tenant <instance> <tenant>        # where people without an address register
kernoid tenant registration <tenant> --allowed true --domain test.kernoid.dev
kernoid tenant service-policy <tenant> mail --assign native --approval   # mailboxes only after approval
kernoid tenant login-policy <tenant> --usernames true --email-login true
```

Registration codes are sent from `NOTIFICATION_FROM`, so it must be an address on the mail domain.

## Mail programs

| | Host | Port | Security |
|---|---|---|---|
| IMAP | `mail.test.kernoid.dev` | 993 | TLS (or 143 with STARTTLS) |
| SMTP | `mail.test.kernoid.dev` | 465 | TLS (or 587 with STARTTLS) |

Log in with the address and an app password (`kernoid account app-password add <account> <name>`, or
`POST /v1/account/app-passwords` with the account's own session). JMAP is at `https://test.kernoid.dev/.well-known/jmap`.

Calendars and contacts (CalDAV, CardDAV): the server is `test.kernoid.dev` – programs find `/dav/` through
`/.well-known/caldav` and `/.well-known/carddav` –, with the same address and app password.

## Checks

```sh
openssl s_client -connect mail.test.kernoid.dev:993 -servername mail.test.kernoid.dev </dev/null | head -5
openssl s_client -starttls smtp -connect mail.test.kernoid.dev:25 </dev/null | head -5
```

Tools such as `internet.nl` or `mail-tester.com` check SPF, DKIM, DMARC, DANE and reverse DNS from outside.

## Updating

```sh
docker compose pull kernoid && docker compose up -d
```

That takes the newest image from `main`; `KERNOID_IMAGE` in `.env` pins another one, e.g.
`ghcr.io/kernoid/kernoid:sha-<commit>`. Bring this directory up to date too when `compose.yaml` or the `Caddyfile`
changed. To run an image built on this machine instead (slow on small machines): `docker build -t kernoid:local ../..`
and `KERNOID_IMAGE=kernoid:local`.

`migrate` runs again before kernoid starts. The data stays in the Docker volumes `kernoid-test_*`.
