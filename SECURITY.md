<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub:
[Report a vulnerability](https://github.com/kernoid/kernoid/security/advisories/new) (the repository's *Security*
tab). OPEN: an email address for reports.

Say what is affected (version or commit, component), how to reproduce it, and what an attacker gains. We confirm the
report within a week, keep you informed, and credit you in the advisory unless you prefer not to be named. Fixes are
released as soon as they are ready; the advisory follows once operators have had a chance to update.

## Supported versions

kernoid is before 1.0: only the latest release gets security fixes. Run the latest 0.x and follow
[the changelog](CHANGELOG.md).

## Scope

The server (`crates/`), the web app, login UI and SDK (`web/`), the terminal app (`apps/tui`), the container image and
the deployment files in `deploy/`. Code taken over from Stalwart and Zitadel is in scope here too; we report what
affects them upstream as well.

An external security audit is planned before 1.0 (see the whitepaper); its results will be published.
