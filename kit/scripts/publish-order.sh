#!/bin/sh
# SPDX-License-Identifier: MIT
# The kit's crates that go to crates.io, each after the kit crates it depends on – the order `cargo publish` needs.
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
        if dep["name"] in crates and dep["kind"] is None:
            visit(dep["name"])
    order.append(name)
for name in sorted(crates):
    visit(name)
print("\n".join(order))
'
