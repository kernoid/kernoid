#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Runs the tests of the Rust SDK (kit/client), of kernoid-sync (kit/sync) and of the spaces (kit/spaces, through the
# relay – open, for the test's tenant) that need a real kernoid: this
# checkout's binary, serving a fresh database in the PostgreSQL of DATABASE_URL (a role that may create databases),
# objects in memory, on http://clients.localhost:$PORT (18380 unless set). An instance, a tenant and the account
# alice@firma.test with mail and files are made with the CLI; the tests log in with its password. kernoid-sync's vault
# test takes bob@firma.test, who has no end-to-end key yet (the SDK's tests make alice's and carol@firma.test's).
#
#   scripts/client-check.sh [BINARY]
#
# BINARY defaults to target/debug/kernoid (`cargo build --bin kernoid`). Needs curl, and psql – or PSQL, a command that
# runs psql against that server (`PSQL="docker exec -i kernoid-pg psql -U kernoid -d kernoid"`).
set -euo pipefail

root=$(git rev-parse --show-toplevel)
binary=$(cd "$root" && realpath "${1:-target/debug/kernoid}")
admin=${DATABASE_URL:?"DATABASE_URL: a PostgreSQL role that may create databases"}
port=${PORT:-18380}
host=clients.localhost
name="kernoid_clients_$$"
url="${admin%/*}/$name"
work=$(mktemp -d)
password=$(openssl rand -hex 16)
server=""

cleanup() {
    [ -n "$server" ] && kill "$server" 2>/dev/null && wait "$server" 2>/dev/null
    sql "DROP DATABASE IF EXISTS $name" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }
sql() {
    if [ -n "${PSQL:-}" ]; then $PSQL -qc "$1"; else psql "$admin" -qc "$1"; fi
}

sql "CREATE DATABASE $name" >/dev/null
cat >"$work/config.toml" <<TOML
roles = ["api", "worker"]

[http]
listen = "127.0.0.1:$port"
public_scheme = "http"

[database]
url = "$url"
migrate_url = "$url"

[blob]
kind = "memory"

[encryption]
main_key = "$(openssl rand -hex 32)"
TOML
cli() { "$binary" --config "$work/config.toml" "$@" | tail -n 1; }

"$binary" --config "$work/config.toml" migrate >/dev/null
instance=$(cli instance add --name Clients --domain "$host")
tenant=$(cli tenant add "$instance" --name Firma)
cli tenant add-domain "$tenant" firma.test >/dev/null
cli tenant verify-domain "$tenant" firma.test --trust >/dev/null
account=$(cli account add "$tenant" alice@firma.test --name Alice)
cli account grant-service "$account" files >/dev/null
printf '%s\n' "$password" | "$binary" --config "$work/config.toml" account password "$account" >/dev/null
erin=$(cli account add "$tenant" erin@firma.test --name Erin)
cli account grant-service "$erin" files >/dev/null
printf '%s\n' "$password" | "$binary" --config "$work/config.toml" account password "$erin" >/dev/null
dave=$(cli account add "$tenant" dave@firma.test --name Dave)
cli account grant-service "$dave" files >/dev/null
printf '%s\n' "$password" | "$binary" --config "$work/config.toml" account password "$dave" >/dev/null
# Alice manages groups: the vault test shares with one.
cli tenant grant "$tenant" --account "$account" --role user_manager >/dev/null
carol=$(cli account add "$tenant" carol@firma.test --name Carol)
cli account grant-service "$carol" files >/dev/null
printf '%s\n' "$password" | "$binary" --config "$work/config.toml" account password "$carol" >/dev/null
bob=$(cli account add "$tenant" bob@firma.test --name Bob)
cli account grant-service "$bob" files >/dev/null
printf '%s\n' "$password" | "$binary" --config "$work/config.toml" account password "$bob" >/dev/null
# The relay of the foundation, open: spaces anyone founds belong to the tenant (RFC 0010, 4).
cat >>"$work/config.toml" <<TOML

[services]
relay = true

[relay]
open_for_tenant = "$tenant"
TOML

"$binary" --config "$work/config.toml" serve >"$work/server.log" 2>&1 &
server=$!
for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && break
    sleep 1
done
curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null || { tail -n 30 "$work/server.log"; fail "kernoid did not get ready"; }

export KERNOID_TEST_SERVER="http://$host:$port" KERNOID_TEST_ADDRESS=alice@firma.test KERNOID_TEST_PASSWORD="$password"
export KERNOID_TEST_VAULT_ADDRESS=bob@firma.test KERNOID_TEST_VAULT_PASSWORD="$password"
# Vaults on spaces (RFC 0010, 5): Carol is made a member of Alice's vault.
export KERNOID_TEST_SPACE_ADDRESS=carol@firma.test KERNOID_TEST_GROUP_ADDRESS=dave@firma.test
# The system's file manager on a vault on a space: Erin's.
export KERNOID_TEST_SHELL_ADDRESS=erin@firma.test
(cd "$root/kit/client" && cargo test --locked --test server -- --test-threads 1) || { tail -n 30 "$work/server.log"; fail "the SDK"; }
(cd "$root/kit/sync" && cargo test --locked --test server -- --test-threads 1) || { tail -n 30 "$work/server.log"; fail "kernoid-sync"; }
(cd "$root/kit/flutter/kernoid_bridge/rust" && cargo test --locked --test provider -- a_vault_on_a_space) \
    || { tail -n 30 "$work/server.log"; fail "the file shells' core"; }
KERNOID_TEST_RELAY="http://127.0.0.1:$port/relay/kernoid" \
    cargo test --manifest-path "$root/kit/Cargo.toml" --locked -p kernoid-spaces --test server --test streams \
    || { tail -n 30 "$work/server.log"; fail "the spaces through the relay"; }
echo "the SDK, kernoid-sync, the file shells' core and the spaces work against kernoid"
