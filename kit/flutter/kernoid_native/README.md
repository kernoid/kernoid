<!-- SPDX-License-Identifier: MIT -->
# kernoid_native

kernoid's native library (RFC 0011, 4): an FFI plugin whose platform folders build the crate of
[`kernoid_bridge`](../kernoid_bridge/rust) with `cargokit/` – for Android, iOS, Linux, macOS and Windows – as the
library `kernoid_bridge`. It holds no Dart: the generated API is `package:kernoid_bridge`, which needs no native build of
its own, so that an app has one Rust library.

kernoid's app depends on this package. A program built on kernoid makes a package like it for its own crate on
`kernoid_bridge` – a copy of this one with its crate's path and library name – and names that library in
`runKernoidApp(library: …)`; it never depends on this one.
