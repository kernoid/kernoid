<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Contributing to kernoid

Thank you for helping. Issues and pull requests are welcome.

- **Sign off every commit** (`git commit -s`): contributions are accepted under the
  [Developer Certificate of Origin](https://developercertificate.org). There is no contributor licence agreement.
- **Licences:** kernoid's own code is AGPL-3.0-or-later, the apps in `web/` and `apps/tui` are MIT, the RFCs CC BY 4.0.
  Every file carries an `SPDX-License-Identifier`. Code under the Stalwart Enterprise License never enters
  (`scripts/check-sel.sh`).
- **Design changes** – to the protocol, the data model or the licence – go through a public RFC in [`rfcs/`](rfcs/).
- **Security problems** are reported privately: see [SECURITY.md](SECURITY.md).
- Be kind: [Code of Conduct](CODE_OF_CONDUCT.md).

How to build and test, and the rules the code follows, are on
[kernoid.dev/contributing](https://kernoid.dev/contributing/) ([`docs/contributing.md`](docs/contributing.md)) and in
[CLAUDE.md](CLAUDE.md). Before opening a pull request:

```sh
cargo fmt --check && cargo clippy --all-targets && cargo test     # tests need DATABASE_URL
(cd web && pnpm run check && pnpm test)
(cd apps/tui && cargo fmt --check && cargo clippy --locked --all-targets && cargo test --locked)
./scripts/check-sel.sh
```
