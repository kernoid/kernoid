#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copies the builds of the login UI and the web app (web/login/dist, web/app/dist – `pnpm build` in web/) into
# crates/kernoid-web/dist, without source maps, for the package of kernoid-web on crates.io: a package has no web/.
# Run before packaging kernoid-web (the copy is ignored by git, so `cargo publish -p kernoid-web --allow-dirty`);
# `--remove` takes the copy away again. The build script prefers web/*/dist while web/ is there, so the copy never
# shadows a newer build in the repository.
set -eu
cd "$(dirname "$0")/.."
target=crates/kernoid-web/dist
rm -rf "$target"
if [ "${1-}" = --remove ]; then
  exit 0
fi
for name in login app; do
  test -f "web/$name/dist/index.html" || { echo "no build in web/$name/dist: run pnpm build in web/ first" >&2; exit 1; }
  mkdir -p "$target/$name"
  (cd "web/$name/dist" && find . -type f ! -name '*.map' ! -name '.*' -print) | while read -r file; do
    mkdir -p "$target/$name/$(dirname "$file")"
    cp "web/$name/dist/$file" "$target/$name/$file"
  done
done
du -sh "$target"
