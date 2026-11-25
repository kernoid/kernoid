<!-- SPDX-License-Identifier: MIT -->
# kernoid_bridge

The Rust side of kernoid's apps (RFC 0011, 2): `rust/` is the crate `kernoid_bridge` on the kit's SDK, `lib/src/rust/`
the Dart code flutter_rust_bridge generates from `rust/src/api/` (`flutter_rust_bridge_codegen generate` here – never
edit it). This package has no native build: [`kernoid_native`](../kernoid_native) builds the crate into kernoid's app,
and a program's app builds its own crate on this one (`rust/src/program.rs`, RFC 0011, 4). `rust/src/provider.rs` is
the core of the file shells (File Provider, DocumentsProvider, Cloud Files) that kernoid's app links on its own.
