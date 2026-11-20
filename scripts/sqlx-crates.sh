#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Each crate with sqlx's checked macros carries the queries of its library in its own .sqlx: a package on crates.io
# builds outside the workspace, where the workspace's .sqlx is not. This writes them; with `--check` it fails if that
# changed anything committed. The workspace's .sqlx (`cargo sqlx prepare --workspace -- --all-targets`, with the
# tests' queries) stays what builds in the repository use – the macros look in the crate's .sqlx first, then there.
#
# How: one `cargo check` of every library and binary with all features, against the database in DATABASE_URL
# (migrated, as for `cargo sqlx prepare`), in a target directory of its own (target/sqlx-crates/build). sqlx's macros write
# the data of each query they check to SQLX_OFFLINE_DIR; a rustc wrapper points that at a directory per package
# (Cargo names the package of each rustc in CARGO_PKG_NAME), so each crate gets exactly the queries in its own code.
set -eu
cd "$(dirname "$0")/.."
: "${DATABASE_URL:?set DATABASE_URL to a migrated database}"
check=false
if [ "${1-}" = --check ]; then
  check=true
fi
root=$(pwd)
work="$root/target/sqlx-crates"
target="$work/build"
out="$work/queries"
mkdir -p "$work"
rm -rf "$out"
wrapper="$work/rustc-wrapper.sh"
cat > "$wrapper" <<'WRAPPER'
#!/bin/sh
# Written by scripts/sqlx-crates.sh: the query data of each package into a directory of its own.
SQLX_OFFLINE=false
SQLX_OFFLINE_DIR="$SQLX_CRATES_OUT/${CARGO_PKG_NAME:-none}"
mkdir -p "$SQLX_OFFLINE_DIR"
export SQLX_OFFLINE SQLX_OFFLINE_DIR
exec "$@"
WRAPPER
chmod +x "$wrapper"

# The workspace's crates with a normal dependency on sqlx's macros, by name and directory.
crates=$(cargo metadata --format-version 1 --no-deps --locked | python3 -c '
import json, os, sys
meta = json.load(sys.stdin)
for package in meta["packages"]:
    for dep in package["dependencies"]:
        if dep["name"] == "sqlx" and dep["kind"] is None and ("macros" in dep["features"] or dep["uses_default_features"]):
            print(package["name"] + "=" + os.path.relpath(os.path.dirname(package["manifest_path"])))
            break
')
# Those crates compile again (the rest is reused from the last run).
if [ -d "$target" ]; then
  for entry in $crates; do
    cargo clean --quiet --target-dir "$target" -p "${entry%%=*}"
  done
fi
SQLX_CRATES_OUT="$out" RUSTC_WRAPPER="$wrapper" CARGO_TARGET_DIR="$target" \
  cargo check --locked --workspace --lib --bins --all-features

for entry in $crates; do
  name=${entry%%=*}
  dir=${entry#*=}
  rm -rf "$dir/.sqlx"
  if [ -n "$(ls "$out/$name" 2>/dev/null)" ]; then
    mkdir "$dir/.sqlx"
    cp "$out/$name"/query-*.json "$dir/.sqlx/"
  fi
  echo "$name: $(ls "$dir/.sqlx" 2>/dev/null | wc -l | tr -d ' ') queries"
done

if $check; then
  changed=$(git status --porcelain -- 'crates/*/.sqlx')
  if [ -n "$changed" ]; then
    echo "$changed"
    echo "the crates' .sqlx are out of date: run scripts/sqlx-crates.sh and commit them" >&2
    exit 1
  fi
fi
