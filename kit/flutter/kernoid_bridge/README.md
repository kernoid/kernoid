<!-- SPDX-License-Identifier: MIT -->
# kernoid_bridge

The Rust side of kernoid's apps (RFC 0011, 2): `rust/` is the crate `kernoid_bridge` on the kit's SDK, `lib/src/rust/`
the Dart code flutter_rust_bridge generates from `rust/src/api/` (`flutter_rust_bridge_codegen generate` here – never
edit it), and `cargokit/` builds the crate for every platform. `rust/src/provider.rs` is the core of the file shells
(File Provider, DocumentsProvider, Cloud Files) that kernoid's app links on its own.
