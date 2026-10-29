#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Upgrades a kernoid of an earlier release to a new image, with data in it, and checks that the data is still there –
# the way someone running deploy/compose upgrades: the earlier release's compose files and image, then this
# checkout's compose files and the new image, on the same volumes.
#
#   scripts/upgrade-check.sh [FROM_TAG] [NEW_IMAGE]
#
# FROM_TAG is a release tag (v0.1.0); NEW_IMAGE an image of this checkout (default kernoid:local, from
# `docker build -t kernoid:local .`). Needs Docker with Compose, curl and jq; publishes HTTP and SMTP on
# 127.0.0.1:$HTTP_PORT and :$SMTP_PORT (18180 and 12525 unless set).
set -euo pipefail

from=${1:-v0.1.0}
new_image=${2:-kernoid:local}
old_image="ghcr.io/kernoid/kernoid:${from#v}"
root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
project=kernoid-upgrade-check
host=kernoid.localhost
http_port=${HTTP_PORT:-18180}
smtp_port=${SMTP_PORT:-12525}
base="http://$host:$http_port"
password=$(openssl rand -hex 16)

compose() {
    local dir=$1
    shift
    docker compose -p "$project" --project-directory "$dir" --env-file "$dir/.env" -f "$dir/compose.yaml" \
        -f "$work/ports.yaml" "$@"
}
cleanup() {
    compose "$work/new" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

mkdir -p "$work/old" "$work/new"
# Other ports than the compose files' own, so that the check does not collide with a kernoid already running.
cat >"$work/ports.yaml" <<YAML
services:
  kernoid:
    ports: !override
      - "127.0.0.1:$http_port:8080"
      - "127.0.0.1:$smtp_port:2525"
YAML
git -C "$root" archive "$from" deploy/compose | tar -x -C "$work/old" --strip-components=2
cp -R "$root/deploy/compose/." "$work/new/"
{
    echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"
    echo "KERNOID_OWNER_PASSWORD=$(openssl rand -hex 24)"
    echo "KERNOID_APP_PASSWORD=$(openssl rand -hex 24)"
    echo "KERNOID_MAIN_KEY=$(openssl rand -hex 32)"
    echo "GARAGE_RPC_SECRET=$(openssl rand -hex 32)"
    echo "S3_ACCESS_KEY_ID=GK$(openssl rand -hex 12)"
    echo "S3_SECRET_KEY=$(openssl rand -hex 32)"
    echo "KERNOID_MAIL_HOSTNAME=mail.$host"
} >"$work/old/.env"
cp "$work/old/.env" "$work/new/.env"
echo "KERNOID_IMAGE=$old_image" >>"$work/old/.env"
echo "KERNOID_IMAGE=$new_image" >>"$work/new/.env"

# A command of the kernoid CLI in the running setup of `dir`; its last line.
cli() {
    local dir=$1
    shift
    compose "$dir" run --rm --no-deps -T kernoid "$@" | tail -n 1
}
wait_ready() {
    for _ in $(seq 1 120); do
        curl -fsS "$base/readyz" >/dev/null 2>&1 && return 0
        sleep 1
    done
    compose "$1" logs kernoid | tail -n 30
    fail "kernoid did not get ready"
}
schema() {
    compose "$1" exec -T postgres psql -U postgres -d kernoid -Atc 'SELECT max(version) FROM _sqlx_migrations'
}
jmap() {
    curl -fsS -u "alice@firma.test:$password" -H 'content-type: application/json' "$base/jmap/api" -d "$1"
}

step "$from: $old_image"
compose "$work/old" up -d
wait_ready "$work/old"
instance=$(cli "$work/old" instance add --name Check --domain "$host")
tenant=$(cli "$work/old" tenant add "$instance" --name Firma)
cli "$work/old" tenant add-domain "$tenant" firma.test >/dev/null
cli "$work/old" tenant verify-domain "$tenant" firma.test --trust >/dev/null
account=$(cli "$work/old" account add "$tenant" alice@firma.test --name Alice)
cli "$work/old" account grant-service "$account" files >/dev/null
printf '%s\n' "$password" | compose "$work/old" run --rm --no-deps -T kernoid account password "$account" >/dev/null
echo "instance $instance, tenant $tenant, account $account"

step "mail over SMTP, a file over WebDAV"
printf 'From: Bob <bob@remote.test>\r\nTo: alice@firma.test\r\nSubject: Before the upgrade\r\nMessage-ID: <upgrade@remote.test>\r\nDate: Thu, 29 Oct 2026 10:00:00 +0000\r\n\r\nWritten by %s.\r\n' "$from" >"$work/mail.eml"
curl -fsS --url "smtp://127.0.0.1:$smtp_port" --mail-from bob@remote.test --mail-rcpt alice@firma.test -T "$work/mail.eml"
head -c 300000 /dev/urandom >"$work/file.bin"
curl -fsS -u "alice@firma.test:$password" -T "$work/file.bin" "$base/webdav/alice@firma.test/file.bin"
curl -fsS -u "alice@firma.test:$password" "$base/webdav/alice@firma.test/file.bin" | cmp - "$work/file.bin" || fail "the file before the upgrade"

before=$(schema "$work/old")

step "upgrade to $new_image"
compose "$work/old" stop kernoid
compose "$work/new" up -d --remove-orphans
wait_ready "$work/new"
after=$(schema "$work/new")
latest=$(find "$root/crates/kernoid-store/migrations" -name '*.sql' -exec basename {} \; |
    sed -n 's/^0*\([0-9][0-9]*\)_.*/\1/p' | sort -n | tail -n 1)
echo "schema: migration $before before, $after after"
[ "$after" = "$latest" ] || fail "the schema is at migration $after, not $latest"

step "the data after the upgrade"
curl -fsS -u "alice@firma.test:$password" "$base/webdav/alice@firma.test/file.bin" | cmp - "$work/file.bin" || fail "the file after the upgrade"
echo "the file is as it was"
using='"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"]'
query=$(jmap "{$using,\"methodCalls\":[[\"Email/query\",{\"accountId\":\"$account\"},\"q\"],[\"Email/get\",{\"accountId\":\"$account\",\"#ids\":{\"resultOf\":\"q\",\"name\":\"Email/query\",\"path\":\"/ids\"},\"properties\":[\"subject\",\"preview\"]},\"g\"]]}")
subject=$(jq -r '.methodResponses[1][1].list[0].subject' <<<"$query")
[ "$subject" = "Before the upgrade" ] || fail "the mail after the upgrade: $query"
echo "the mail is there: $subject"
cli "$work/new" tenant list "$instance" | grep -q Firma || fail "the tenant after the upgrade"
echo
echo "upgrade from $from to $new_image: OK"
