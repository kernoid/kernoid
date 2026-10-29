#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Lists the crates in Cargo.lock published less than two weeks ago (but for SECURITY_FIXES), from crates.io's API – once a second, as its
# crawler policy asks. Exit status 1 if there is one. With --fix, each is set back to its newest version old enough
# (`cargo update -p <crate>@<version> --precise <older>`), and the lock file is checked again. Run it after changing
# Cargo.lock; CI does not (it needs the network and minutes).
#   scripts/check-age.py [--fix] [--dir=<workspace>] [days]
# --dir checks another workspace's Cargo.lock than the terminal app's, e.g. `--dir=operator`.
import json
import subprocess
import sys
import time
import tomllib
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = next(
    (Path(a.split("=", 1)[1]).resolve() for a in sys.argv[1:] if a.startswith("--dir=")),
    Path(__file__).resolve().parent.parent,
)
# The one exception to the two weeks: the smallest version that fixes a RustSec advisory, with the advisory's id.
SECURITY_FIXES = {
    ("rustls-webpki", "0.103.16"): "RUSTSEC-2026-0382",
    ("webpki-roots", "1.0.10"): "RUSTSEC-2026-0381",
    ("webpki-root-certs", "1.0.10"): "RUSTSEC-2026-0383",
}
HEADERS = {"User-Agent": "kernoid-tui check-age (https://github.com/kernoid/kernoid)"}


def get(url):
    time.sleep(1)
    with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS)) as response:
        return json.load(response)


def date(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def young(limit):
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    out = []
    for package in lock["package"]:
        if not package.get("source", "").startswith("registry+"):
            continue
        name, version = package["name"], package["version"]
        if (name, version) in SECURITY_FIXES:
            continue
        published = date(get(f"https://crates.io/api/v1/crates/{name}/{version}")["version"]["created_at"])
        if published > limit:
            out.append((name, version, published))
    return out


def fix(name, version, limit):
    versions = get(f"https://crates.io/api/v1/crates/{name}/versions?per_page=100")["versions"]
    candidates = [v["num"] for v in versions if not v["yanked"] and date(v["created_at"]) <= limit and "-" not in v["num"]]
    for candidate in candidates:  # newest first
        update = ["cargo", "update", "-p", f"{name}@{version}", "--precise", candidate]
        if subprocess.run(update, cwd=ROOT, capture_output=True).returncode == 0:
            print(f"{name} {version} → {candidate}", flush=True)
            return True
    print(f"{name} {version}: no older version fits", file=sys.stderr)
    return False


def main():
    args = [a for a in sys.argv[1:] if a != "--fix" and not a.startswith("--dir=")]
    days = int(args[0]) if args else 14
    limit = datetime.now(timezone.utc) - timedelta(days=days)
    found = young(limit)
    # One crate may hold another back (pest_derive needs its own pest): set back what can be, then look again.
    for _ in range(8 if "--fix" in sys.argv else 0):
        if not found or not [fix(name, version, limit) for name, version, _ in found].count(True):
            break
        found = young(limit)
    for name, version, published in found:
        print(f"{name} {version} ({published.date()})")
    print(f"{len(found)} of the locked crates are younger than {days} days", file=sys.stderr)
    sys.exit(1 if found else 0)


main()
