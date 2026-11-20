#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Tries what the job `crates` does on a release, without uploading: `cargo publish --dry-run` of the kit, the server's
# crates, the terminal app and the operator – each package built from its tarball. The kit's crates are patched in
# from kit/ (crates.io has only released versions of them, which the code here may have outgrown). Needs the builds
# of web/ (`pnpm build`) for kernoid-web, and the network (crates.io's index).
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
# The patches as a Cargo configuration file.
patches="$root/target/publish-dry-run.toml"
mkdir -p target
echo '[patch.crates-io]' > "$patches"
(cd kit && cargo metadata --format-version 1 --no-deps --locked) | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p.get("publish") != []:
        print("%s = { path = %s }" % (p["name"], json.dumps(p["manifest_path"].rsplit("/", 1)[0])))
' >> "$patches"
# Unused patches land in the lock files ([[patch.unused]]), so those two run without --locked, on copies kept aside.
cp Cargo.lock target/publish-dry-run.lock
cp tui/Cargo.lock target/publish-dry-run-tui.lock
scripts/web-crate.sh
trap 'scripts/web-crate.sh --remove; cp target/publish-dry-run.lock Cargo.lock; cp target/publish-dry-run-tui.lock tui/Cargo.lock' EXIT
if [ "${1-}" != --skip-kit ]; then
  echo "== kit"
  (cd kit && cargo publish --workspace --dry-run --locked)
fi
echo "== server"
# kernoid-web's builds are not in git (--allow-dirty).
cargo publish --workspace --dry-run --allow-dirty --config "$patches"
echo "== tui"
(cd tui && cargo publish --dry-run --allow-dirty --config "$patches")
echo "== operator"
(cd operator && cargo publish --dry-run --locked)
echo "all packages built from their tarballs ($root)"
