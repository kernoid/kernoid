---
title: Operations
nav_order: 9
permalink: /operations/
---

# Operations

kernoid is one container image and needs two services: PostgreSQL and S3-compatible object storage. Nothing else.

## Processes and roles

Every process runs the same binary; the configuration key `roles` decides what it does:

- `api` – the HTTP server: REST, GraphQL, OpenID Connect, health checks.
- `worker` – background work: projections, cleaning up expired sessions, tokens and failure counts (every 10 minutes),
  delivering back-channel logout notifications, rotating signing keys, ordering certificates (ACME), removing objects
  of deleted mail from object storage and old rows of the mail journal, emptying Trash and Junk after the tenants'
  retention and indexing older emails for search, emptying file trashes after the tenants' retention and indexing
  the text of files for search (every 10 minutes), making DKIM keys for new
  domains and letting new keys sign once DNS shows them, delivering the queue of outgoing mail, and the jobs of modules.

- `smtp` – the MX on port 25 and submission on ports 587 and 465, when `[smtp]` is configured (see
  [Mail]({{ '/mail/' | relative_url }})). Several `smtp` processes can run side by side; each delivers what it
  accepts itself.
- `imap` – IMAP on ports 143 and 993, and POP3 if configured, when `[imap]` is configured and kernoid has
  certificates. `IDLE` hears of changes made by any process through PostgreSQL; run as many as the clients need.
- `ldap` – the directory on ports 389 and 636, when `[ldap]` is configured and kernoid has certificates
  ([Directory]({{ '/directory/' | relative_url }})); it only reads, so run as many as needed.

`all` (the default) runs all of them in one process. For more load, run several `api` processes behind a load balancer and
one or more `worker` processes. **Several workers share the work without doing it twice:**

| Job | How several workers share it |
|---|---|
| projections | each projection's cursor is taken with `FOR UPDATE SKIP LOCKED`: one worker applies a batch, the others skip it and come back; every event is applied once, in order |
| clean-up | deletes of what has expired – running them twice changes nothing |
| back-channel logout | each notification is leased for a minute (`FOR UPDATE SKIP LOCKED`) by the worker that sends it |
| signing key rotation, ACME, mail housekeeping | a PostgreSQL advisory lock: one worker does the round, the others skip it |
| the queue of outgoing mail | each worker leases the due recipients of one domain (`FOR UPDATE SKIP LOCKED`) for ten minutes |
| DKIM keys | one active and one waiting key per domain and algorithm (unique indexes): the first key made stays (`ON CONFLICT DO NOTHING`); a key becomes active in one transaction that retires the one before |

A second worker is for availability more than for load: if one stops, the other carries on.

Deployment: Docker Compose – `deploy/compose` to try kernoid out, `deploy/test` for a public test machine behind
Caddy, with mail (its `README.md` walks through the setup) – or Kubernetes with the operator (below). The image is
built for `linux/amd64` and `linux/arm64`.

## Kubernetes

The operator (`kernoid-operator`, in the same image as kernoid) runs kernoid as a resource `Kernoid` describes. It
needs PostgreSQL and S3-compatible object storage from elsewhere, like every installation.

```sh
kubectl apply -f deploy/kubernetes/crd.json -f deploy/kubernetes/operator.yaml
# or, with Helm (from a release on, the chart is published next to the image):
#   helm install kernoid-operator oci://ghcr.io/kernoid/charts/kernoid-operator --version 0.2.1 \
#     -n kernoid-system --create-namespace
kubectl create namespace kernoid
kubectl -n kernoid create secret generic kernoid --from-literal=database-url=… --from-literal=migrate-url=… \
  --from-literal=main-key=$(openssl rand -hex 32) --from-literal=s3-access-key-id=… --from-literal=s3-secret-access-key=…
kubectl apply -f deploy/kubernetes/example.yaml   # after editing it
kubectl -n kernoid get kernoid                      # IMAGE, READY
```

A `Kernoid` names the **image**, kernoid's settings as **environment variables** for every process (`env`, the same
`KERNOID__…` as for a container; secrets with `valueFrom.secretKeyRef`), variables only for the migration
(`migrateEnv`: `KERNOID__DATABASE__MIGRATE_URL`), volumes (e.g. the certificate of the mail protocols), the
**replicas of each role** – `api` and `worker` one each unless set, `smtp`, `imap` and `ldap` none – and, if wanted,
an **ingress** for the web (`hosts`, `className`, `tlsSecret`, `annotations`). From it the operator makes:

| Object | What |
|---|---|
| Job `<name>-migrate-<hash>` | `kernoid migrate` with the image – once per image |
| Deployment `<name>-<role>` | the role's processes, only that role (`KERNOID__ROLES`), with the migrated image; `api` ready by `/readyz`, the others when they listen |
| Service `<name>-<role>` | the role's ports (not for `worker`); `serviceType: LoadBalancer` for mail from outside, which keeps the client's address (`externalTrafficPolicy: Local`) |
| Ingress `<name>-api` | with `ingress`: each host to the `api` Service, TLS from `tlsSecret`, the annotations for the controller – once the schema is migrated; removed with `ingress` or with the `api` role |

Behind an ingress, kernoid must believe the controller's forwarded headers – its addresses in
`KERNOID__HTTP__TRUSTED_PROXIES` – and the controller must let uploads of any size through (with ingress-nginx
`nginx.ingress.kubernetes.io/proxy-body-size: "0"`).

**Upgrading** is changing `image`: the operator migrates the schema with the new image first – the running
processes keep their image meanwhile – and replaces the processes only once the migration succeeded, one pod at a
time. A failed migration leaves everything as it was; the condition `Migrated` names the Job whose log says why.
Every pod runs as non-root with a read-only root filesystem and no capabilities; the mail and directory roles may
open their ports below 1024 through the namespaced sysctl `net.ipv4.ip_unprivileged_port_start`.

The operator reads `Kernoid` resources and changes only Deployments, Services, Ingresses and Jobs (`operator.yaml`'s
ClusterRole); it never reads Secrets. `--namespace` limits it to one namespace.

The **Helm chart** `deploy/helm/kernoid-operator` installs the same: the CustomResourceDefinition and the operator in
the release's namespace. Its values: `image.repository` and `image.tag` (the chart's version unless set),
`watchNamespace` (one namespace – the operator then gets a Role there instead of the ClusterRole), `logFormat`,
`resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations`, `podLabels`, `priorityClassName`,
`imagePullSecrets`. Helm installs a CustomResourceDefinition once and never upgrades it: after upgrading the chart,
apply `deploy/kubernetes/crd.json` of the new release.

Each release pushes the chart as `oci://ghcr.io/kernoid/charts/kernoid-operator` with the release's version (CI's job
`chart`, which also checks that the chart's version is the tag's); between releases it is installed from a checkout
(`deploy/helm/kernoid-operator`).

**OPEN:** a Gateway API route made by the operator, scaling by load.

## TLS and reverse proxies

- **kernoid terminates TLS itself** with `http.tls.certificate` and `http.tls.key` (PEM; TLS 1.2 and 1.3, HTTP/2) –
  or with **certificates from an ACME CA** such as Let's Encrypt (`[http.acme]`, below).
- **Behind a reverse proxy** – Caddy, nginx, Traefik or any other that terminates TLS – kernoid serves plain HTTP.
  List the proxy in `http.trusted_proxies`: only then are its `Forwarded` and `X-Forwarded-*` headers believed. A
  request's instance is chosen by its host, so a client must never be able to set it.

**Mail behind a reverse proxy.** SMTP, submission, IMAP and POP3 do not pass through an HTTP proxy: kernoid
terminates TLS for them itself. When the proxy holds the certificates, point `mail.tls.certificate` and `mail.tls.key`
at its files for the mail host; kernoid reads them again within a minute after they change, and keeps the certificate
in use if a file cannot be read. kernoid must be able to read them – `deploy/test` runs Caddy as kernoid's user.

Issuer and links are built from `http.public_scheme` and the instance's primary domain, never from a request.

### Certificates from an ACME CA

```toml
[http.acme]
contact = ["mailto:ops@example.org"]
terms_agreed = true          # you have read the CA's terms of service; kernoid does not agree for you
# directory = "https://acme-v02.api.letsencrypt.org/directory"
# http_listen = "0.0.0.0:80"
# renew_days = 30
```

- The **worker** orders a certificate for every domain of every instance that has none, or whose certificate ends
  within `renew_days`, using the **HTTP-01** challenge – at most ten per round, once an hour. A failed order waits an
  hour before the next attempt, doubling up to a day, so that the CA's rate limits are not used up. Names for local
  use (`localhost`, `.test`, `.local`, `.internal`, `.example`, `.invalid`, `.home.arpa`) are left out.
- **Every `api` process** serves the certificates by SNI (falling back to `http.tls`, if set) and answers the CA's
  requests at `http://<domain>/.well-known/acme-challenge/…` on `http_listen`; everything else there is redirected to
  HTTPS – for the instances' domains only. Port 80 from outside must reach `http_listen` of an `api` process.
- **Everything lives in PostgreSQL** – the account key and the certificates' keys sealed with the main key – so any
  `api` process answers any challenge and serves any certificate; they pick up new ones within a minute.
- `kernoid acme status` lists every instance domain with the end of its certificate, or why ordering one failed.
- Testing: point `directory` at a test CA such as [Pebble](https://github.com/letsencrypt/pebble), with its root in
  `ca_root`. Let's Encrypt's staging directory (`https://acme-staging-v02.api.letsencrypt.org/directory`) has higher
  limits than production.

## Database and migrations

kernoid uses two PostgreSQL roles:

- the **owner** of the schema runs `kernoid migrate` (`database.migrate_url`);
- the **runtime role** serves (`database.url`) with only what `kernoid migrate` grants it – it can add events but
  never change or remove them.

Migrations do not run when kernoid starts: run `kernoid migrate` before starting a new version. Connections carry a
statement timeout and an idle-in-transaction timeout (see [Configuration]({{ '/configuration/' | relative_url }})).

### Upgrading

Read the release's section in the [changelog](https://github.com/kernoid/kernoid/blob/main/CHANGELOG.md) first –
it says what to do besides migrating. Then:

1. Back up the database and the object storage (below).
2. Run `kernoid migrate` with the new version – Compose's `migrate` service does it before `kernoid` starts; the
   operator runs it as a Job.
3. Start the new version.

While the migration runs, processes of the old version keep running against the new schema; a release whose
migrations the old version cannot work with says so in the changelog, and then the old processes stop first. Every release is checked by upgrading an installation of the release
before it, with mail and files in it (`scripts/upgrade-check.sh`, CI job `upgrade`).

## Health, metrics, logs

| | |
|---|---|
| `GET /healthz` | the process runs – nothing about its dependencies, so an orchestrator does not restart every process when the database is away |
| `GET /readyz` | PostgreSQL and object storage answer; `503` otherwise |
| `/metrics` | Prometheus metrics on `http.metrics_listen` – keep that address internal |
| logs | text or JSON on stdout (`log.format`); traces to OpenTelemetry with `log.otlp_endpoint` |

## Keys

**The main key** (`encryption.main_key`) wraps the tenant keys and seals the signing keys. To change it:

1. set the new key as `main_key` and move the old one to `previous_main_keys`;
2. run `kernoid keys rewrap` (as the owner);
3. once `kernoid keys status` shows no key wrapped with an old main key, remove `previous_main_keys`.

**Tenant keys** encrypt a tenant's content in object storage. `kernoid keys rotate <tenant>` adds the next key: new
content is encrypted with it, older content stays readable.

**Signing keys** sign ID tokens, one set per instance – through the API (`/v1/instance/signing-keys`) or the CLI:

1. `kernoid signing-key add <instance>` – the new key is published in the JWKS at once but does not sign yet;
2. wait until clients have fetched the JWKS again, then `kernoid signing-key activate <instance> <kid>`;
3. the former key stays published, inactive; remove it once its ID tokens have expired (an hour).

**kernoid's SAML key** of an instance changes the same way, by hand: `kernoid saml-key add`, then – once the SAML
providers have the new metadata – `kernoid saml-key activate` (see [Federation]({{ '/federation/' | relative_url }})).

The worker also rotates signing keys on its own (`[oidc]` in the [configuration]({{ '/configuration/' | relative_url }})): a
key that has signed for `key_rotation_days` (90) gets a successor, published for `key_publish_hours` (24) before it
signs; a key that no longer signs is removed after `retired_key_days` (30). Its changes appear in the audit log as
`system:key-rotation`.

## Backups

A backup has three parts. Without any one of them, nothing can be restored.

| Part | What it holds | How |
|---|---|---|
| **PostgreSQL** | the events (all identity and administration, the audit log), the read models, sealed secrets and keys, sessions | continuous archiving with point-in-time recovery (e.g. `pg_basebackup` with WAL archiving, or the provider's backups); `pg_dump` for small installations |
| **Object storage** | the content: mail, files – encrypted with the tenants' keys | bucket versioning or replication to a second site, or a copy (`rclone`, the provider's backups) |
| **The main key** | `encryption.main_key` – without it, the tenant keys, signing keys and every sealed secret cannot be opened | kept apart from both, e.g. in the operator's password manager or a key store; never next to a database backup |

**Order and consistency.** kernoid writes content to object storage before the database records it. So:

1. take the database backup first,
2. then the object storage backup (or snapshot) – it then contains everything the database refers to.

Objects in storage that the database does not know (written after its backup) are harmless. A database newer than
the object storage would refer to content that is missing – avoid it by the order above, or with bucket versioning
(restore the bucket to the database backup's time or later).

**Restoring:**

1. Restore PostgreSQL (as the owner), then run `kernoid migrate` – a restored older schema is brought up to date.
2. Restore the object storage bucket.
3. Configure the main key (and `previous_main_keys`, if the backup is older than the last change of main key).
4. Check before serving: `kernoid keys status` must show no key wrapped with an unknown main key; `kernoid check-config`
   shows the configuration.
5. Start the processes; `GET /readyz` answers `200` once PostgreSQL and object storage are reachable.

Sessions, codes and tokens in the backup are restored with it – end them if the backup may have fallen into other
hands: `kernoid signing-key add` and `activate` for each instance (old ID tokens stop verifying once the old key is
removed), and new client secrets for confidential applications.

**Test the restore**, not only the backup: restore into a separate installation now and then and log in there.

## When nobody can administer an instance

Administration needs an account with an instance or tenant role. If none of them can log in any more – passwords
forgotten, second factors lost, accounts deactivated – the **operator's command line** is the way back. It talks to
the database directly, needs no login, and its changes are events naming `operator` in the audit log.

1. Find the account: `kernoid instance list`, `kernoid tenant list <instance>`, `kernoid account list <tenant>`.
2. Let it in again:
   - `kernoid account reactivate <account>` if it was deactivated;
   - `kernoid account password <account>` – the password is read from standard input, never from the command line;
   - `kernoid account reset-second-factors <account>` if its devices are lost; it sets up new ones at the next login
     when the tenant requires a second factor.
3. Give it the role, if it lost it: `kernoid instance grant <instance> --account <account> --role instance_admin`, or
   `kernoid tenant grant <tenant> --account <account> --role tenant_admin`.
4. Log in and look at the audit log for how it came to this.

kernoid refuses changes that would leave nobody active in charge (see [Administration]({{ '/administration/' | relative_url }})),
so this is for accidents outside kernoid's reach – lost devices, people leaving. Whoever can run the CLI can do all
of this: keep access to the database and to the main key as narrow as access to the servers.
