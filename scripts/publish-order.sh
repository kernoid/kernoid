#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# The server workspace's crates that go to crates.io, each after the workspace crates it depends on – the order
# `cargo publish` needs (as kit/scripts/publish-order.sh for the kit, whose crates go first).
set -eu
cd "$(dirname "$0")/.."
cargo metadata --format-version 1 --no-deps --locked | python3 -c '
import json, sys
meta = json.load(sys.stdin)
crates = {p["name"]: p for p in meta["packages"] if p.get("publish") != []}
done, order = set(), []
def visit(name):
    if name in done:
        return
    done.add(name)
    for dep in crates[name]["dependencies"]:
        # Normal and build dependencies; a dev-dependency without a version is left out of the package.
        if dep["name"] in crates and dep["kind"] != "dev":
            visit(dep["name"])
    order.append(name)
for name in sorted(crates):
    visit(name)
print("\n".join(order))
'
