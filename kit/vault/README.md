<!-- SPDX-License-Identifier: MIT -->
# kernoid-vault

kernoid's vaults on spaces ([RFC 0010](https://github.com/kernoid/kernoid/blob/main/rfcs/0010-foundation.md), 5):
a vault is a space of the foundation's relay; its root directory is the space stream, every directory and file a
stream linked below its directory. Directories say what lies in them (`entry`, `gone`), files their versions
(`version`), contents are originals in parts. The same code runs on devices (`kernoid-client`) and, built with the
feature `wasm`, in kernoid's web app.
