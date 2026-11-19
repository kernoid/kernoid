#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# The kit (kit/, RFC 0008, 2) stays MIT and apart from the server: every crate says `license = "MIT"`, no crate depends
# on a package outside kit/ by path, and every source file with an SPDX header says MIT. cargo-deny (kit/deny.toml)
# checks the licences of what comes from crates.io.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/kit"
cargo metadata --format-version 1 --locked | python3 -c '
import json, os, sys
kit = os.path.realpath(".")
meta = json.load(sys.stdin)
members = set(meta["workspace_members"])
bad = []
for package in meta["packages"]:
    path = os.path.realpath(os.path.dirname(package["manifest_path"]))
    local = package["source"] is None
    if package["id"] in members and package["license"] != "MIT":
        name, licence = package["name"], package["license"]
        bad.append(name + ": licence " + str(licence) + ", not MIT")
    if local and not (path == kit or path.startswith(kit + os.sep)):
        bad.append(package["name"] + ": a path outside kit/ (" + path + ")")
for line in bad:
    print(line)
sys.exit(1 if bad else 0)
'
other=$(grep -rIl --exclude-dir=target --exclude-dir=build --exclude-dir=.dart_tool "SPDX-License-Identifier:" . \
  | xargs grep -L "SPDX-License-Identifier: MIT" || true)
if [ -n "$other" ]; then
  echo "files in kit/ with a licence other than MIT:"; echo "$other"; exit 1
fi
echo "the kit is MIT and apart from the server"
