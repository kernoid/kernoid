#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Fails if anything under the Stalwart Enterprise License has entered the repository: a file or a section marked
# LicenseRef-SEL (SPDX-SnippetBegin … SPDX-SnippetEnd), or the licence text itself. kernoid takes Stalwart code only
# under the AGPL-3.0 (whitepaper, "Building on Stalwart and Zitadel"): a file taken over whose header reads
# "AGPL-3.0-only OR LicenseRef-SEL" gets the header "AGPL-3.0-only" – the choice is made once, on taking it over.
# Checks the tracked files of the working tree.
set -eu
cd "$(git rev-parse --show-toplevel)"
pattern='LicenseRef-SEL|SPDX-SnippetBegin'
found=$(git grep -l -I -E "$pattern" -- . ':!scripts/check-sel.sh' ':!*.md' || true)
files=$(git ls-files | grep -i -E '(^|/)LicenseRef-SEL' || true)
if [ -n "$found$files" ]; then
    echo "Stalwart Enterprise License material found – remove it:" >&2
    printf '%s\n' $found $files >&2
    exit 1
fi
echo "no Stalwart Enterprise License material"
