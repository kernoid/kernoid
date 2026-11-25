// SPDX-License-Identifier: MIT
import 'dart:ffi';

import 'package:flutter/foundation.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import 'src/rust/frb_generated.dart';

/// What a program's library exports to register its part (`kernoid_bridge::program::register`) – called once, when
/// the library is loaded.
const programsSymbol = 'kernoid_programs';

/// Loads the Rust side (RFC 0011, 4): kernoid's own library, or – in a program's app, whose one native library is its
/// own crate on `kernoid_bridge` – the library named `library`, whose part registers itself through [programsSymbol].
Future<void> loadKernoid({String? library}) async {
  if (library == null) return RustLib.init();
  await loadKernoidFrom(
    await loadExternalLibrary(
      ExternalLibraryLoaderConfig(
        stem: library,
        ioDirectory: RustLib.kDefaultExternalLibraryLoaderConfig.ioDirectory,
        webPrefix: RustLib.kDefaultExternalLibraryLoaderConfig.webPrefix,
        wasmBindgenName: RustLib.kDefaultExternalLibraryLoaderConfig.wasmBindgenName,
      ),
    ),
  );
}

/// [loadKernoid] from a library already opened.
@visibleForTesting
Future<void> loadKernoidFrom(ExternalLibrary library) async {
  await RustLib.init(externalLibrary: library);
  final native = library.ffiDynamicLibrary;
  if (native.providesSymbol(programsSymbol)) {
    native.lookupFunction<Void Function(), void Function()>(programsSymbol)();
  }
}
