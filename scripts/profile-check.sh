#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Runs this checkout's kernoid as the small installations of RFC 0008, 5, each against a fresh database in the
# PostgreSQL of DATABASE_URL (a role that may create databases), and checks what each serves:
#
# - identity alone: no object storage (`[blob] kind = "database"`), no JMAP, CalDAV or WebDAV – but logging in and a
#   picture of the account, kept in PostgreSQL;
# - a relay alone, open: the relay's routes, nothing of mail, calendars or files;
# - a built-in identity taken over (RFC 0009, 7): kernoid's schema in a program's database, dumped and restored into a
#   database of its own, served at another host – the accounts and their passwords are there.
#
#   scripts/profile-check.sh [BINARY]
#
# BINARY defaults to target/debug/kernoid (`cargo build --bin kernoid`). Needs curl, and psql – or PSQL, a command that
# runs psql against that server (`PSQL="docker exec -i kernoid-pg psql -U kernoid -d kernoid"`), and pg_dump – or
# PG_DUMP (`PG_DUMP="docker exec kernoid-pg pg_dump -U kernoid"`); both are given `-d <database>` where they need one.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
binary=$(cd "$root" && realpath "${1:-target/debug/kernoid}")
admin=${DATABASE_URL:?"DATABASE_URL: a PostgreSQL role that may create databases"}
port=${PORT:-18381}
host=profiles.localhost
name="kernoid_profiles_$$"
url="${admin%/*}/$name"
work=$(mktemp -d)
password=$(openssl rand -hex 16)
server=""

cleanup() {
    [ -n "$server" ] && kill "$server" 2>/dev/null && wait "$server" 2>/dev/null
    sql "DROP DATABASE IF EXISTS $name" >/dev/null 2>&1 || true
    sql "DROP DATABASE IF EXISTS ${name}_program" >/dev/null 2>&1 || true
    sql "DROP DATABASE IF EXISTS ${name}_own" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
fail() { printf 'FAILED: %s\n' "$*" >&2; [ -f "$work/server.log" ] && tail -n 30 "$work/server.log" >&2; exit 1; }
sql() {
    if [ -n "${PSQL:-}" ]; then $PSQL -qc "$1"; else psql "$admin" -qc "$1"; fi
}
# psql in database $1, reading statements from stdin.
sql_in() {
    if [ -n "${PSQL:-}" ]; then $PSQL -q -v ON_ERROR_STOP=1 -d "$1"; else psql "${admin%/*}/$1" -q -v ON_ERROR_STOP=1; fi
}
dump() {
    if [ -n "${PG_DUMP:-}" ]; then $PG_DUMP -d "$1" "${@:2}"; else pg_dump "${admin%/*}/$1" "${@:2}"; fi
}
ready() {
    for _ in $(seq 1 60); do
        curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "kernoid did not get ready"
}
# The status of a request to kernoid, by the instance's host name.
status() {
    local method=$1 path=$2
    shift 2
    curl -s -o /dev/null -w '%{http_code}' -X "$method" -H "Host: $host:$port" "$@" "http://127.0.0.1:$port$path"
}
expect() {
    local want=$1 method=$2 path=$3
    shift 3
    local got
    got=$(status "$method" "$path" "$@")
    [ "$got" = "$want" ] || fail "$method $path answered $got, not $want"
}

# Identity alone.
sql "CREATE DATABASE $name" >/dev/null
cat >"$work/config.toml" <<TOML
roles = ["api", "worker"]

[services]
mail = false
calendars = false
files = false

[http]
listen = "127.0.0.1:$port"
public_scheme = "http"
public_port = $port

[database]
url = "$url"
migrate_url = "$url"

[blob]
kind = "database"

[encryption]
main_key = "$(openssl rand -hex 32)"
TOML
cli() { "$binary" --config "$work/config.toml" "$@" | tail -n 1; }

"$binary" --config "$work/config.toml" migrate >/dev/null
instance=$(cli instance add --name Profiles --domain "$host")
tenant=$(cli tenant add "$instance" --name Firma)
cli tenant add-domain "$tenant" firma.test >/dev/null
cli tenant verify-domain "$tenant" firma.test --trust >/dev/null
account=$(cli account add "$tenant" alice@firma.test --name Alice)
cli tenant grant "$tenant" --account "$account" --role tenant_admin >/dev/null
printf '%s\n' "$password" | "$binary" --config "$work/config.toml" account password "$account" >/dev/null

"$binary" --config "$work/config.toml" serve >"$work/server.log" 2>&1 &
server=$!
for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && break
    sleep 1
done
curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null || fail "kernoid did not get ready"

services=$(curl -fsS -H "Host: $host:$port" "http://127.0.0.1:$port/v1/services")
[ "$services" = '{"mail":false,"calendars":false,"files":false,"relay":false}' ] || fail "services: $services"
expect 404 GET /jmap/session
expect 404 PROPFIND /dav/
expect 404 PROPFIND /webdav/
expect 404 GET /mail/config-v1.1.xml
expect 200 GET /.well-known/openid-configuration

token=$(curl -fsS -H "Host: $host:$port" -H 'Content-Type: application/json' \
    -d "{\"address\":\"alice@firma.test\",\"password\":\"$password\"}" "http://127.0.0.1:$port/v1/sessions" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || fail "no session"
# A picture, kept in PostgreSQL: the smallest PNG there is.
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa7\x35\x81\x84\x00\x00\x00\x00IEND\xaeB`\x82' >"$work/picture.png"
expect 204 PUT /v1/account/avatar -H "Authorization: Bearer $token" -H 'Content-Type: image/png' \
    --data-binary "@$work/picture.png"
expect 200 GET "/v1/avatars/$account" -H "Authorization: Bearer $token"
expect 409 PUT "/v1/accounts/$account/services/files" -H "Authorization: Bearer $token" -H "kernoid-tenant: $tenant"
echo "identity alone works: logins and pictures without object storage, nothing of mail, calendars or files"

# A relay alone, open for the tenant: the same database, other services.
kill "$server" && wait "$server" 2>/dev/null || true
server=""
sed -e 's/^files = false$/files = false\nrelay = true/' -e 's/^kind = "database"$/kind = "memory"/' "$work/config.toml" >"$work/relay.toml"
printf '\n[relay]\nopen_for_tenant = "%s"\n' "$tenant" >>"$work/relay.toml"
"$binary" --config "$work/relay.toml" serve >"$work/server.log" 2>&1 &
server=$!
for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && break
    sleep 1
done
services=$(curl -fsS -H "Host: $host:$port" "http://127.0.0.1:$port/v1/services")
[ "$services" = '{"mail":false,"calendars":false,"files":false,"relay":true}' ] || fail "services: $services"
expect 404 GET /jmap/session
expect 200 GET "/relay/kernoid/v1/spaces/0192f1e4-0000-7000-8000-0000000000c1/members?after=-1"
expect 404 GET "/relay/spezado/v1/spaces/0192f1e4-0000-7000-8000-0000000000c1/members?after=-1"
echo "a relay alone works: its routes, nothing of mail, calendars or files"

# A built-in identity taken over: what a program that builds kernoid in keeps in its database (`database.schema`),
# moved into a kernoid of its own at another host.
kill "$server" && wait "$server" 2>/dev/null || true
server=""
program="${name}_program"
own="${name}_own"
sql "CREATE DATABASE $program" >/dev/null
echo "CREATE SCHEMA kernoid" | sql_in "$program"
main_key=$(sed -n 's/^main_key = "\(.*\)"$/\1/p' "$work/config.toml")
built_in() {
    cat <<TOML
roles = ["api", "worker"]

[services]
mail = false
calendars = false
files = false

[http]
listen = "127.0.0.1:$port"
public_scheme = "http"
public_port = $port

[database]
url = "${admin%/*}/$1"
migrate_url = "${admin%/*}/$1"
schema = "kernoid"

[blob]
kind = "database"

[encryption]
main_key = "$main_key"
TOML
}
built_in "$program" >"$work/program.toml"
"$binary" --config "$work/program.toml" migrate >/dev/null
pcli() { "$binary" --config "$work/program.toml" "$@" | tail -n 1; }
p_instance=$(pcli instance add --name Program --domain "program.$host")
p_tenant=$(pcli tenant add "$p_instance" --name Firma)
pcli tenant add-domain "$p_tenant" program.test >/dev/null
pcli tenant verify-domain "$p_tenant" program.test --trust >/dev/null
p_account=$(pcli account add "$p_tenant" bob@program.test --name Bob)
printf '%s\n' "$password" | "$binary" --config "$work/program.toml" account password "$p_account" >/dev/null

# The steps of docs/building-on-kernoid.md: dump kernoid's schema, restore it, migrate, give the instance its new host.
sql "CREATE DATABASE $own" >/dev/null
dump "$program" --schema=kernoid --no-owner --no-privileges | sql_in "$own" >/dev/null
built_in "$own" >"$work/own.toml"
"$binary" --config "$work/own.toml" migrate >/dev/null
"$binary" --config "$work/own.toml" instance add-domain "$p_instance" "$host" >/dev/null
"$binary" --config "$work/own.toml" instance set-primary "$p_instance" "$host" >/dev/null
"$binary" --config "$work/own.toml" serve >"$work/server.log" 2>&1 &
server=$!
ready
token=$(curl -fsS -H "Host: $host:$port" -H 'Content-Type: application/json' \
    -d "{\"address\":\"bob@program.test\",\"password\":\"$password\"}" "http://127.0.0.1:$port/v1/sessions" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || fail "no session after the takeover"
issuer=$(curl -fsS -H "Host: $host:$port" "http://127.0.0.1:$port/.well-known/openid-configuration" \
    | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')
[ "$issuer" = "http://$host:$port" ] || fail "issuer after the takeover: $issuer"
echo "a built-in identity is taken over: its accounts log in at the kernoid of its own"

