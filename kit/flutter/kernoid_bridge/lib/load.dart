// SPDX-License-Identifier: MIT
import 'dart:ffi';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import 'src/rust/frb_generated.dart';

/// What a program's library exports to register its part (`kernoid_bridge::program::register`) – called once, when
/// the library is loaded.
const programsSymbol = 'kernoid_programs';

/// Loads the Rust side (RFC 0011, 4): kernoid's own library `kernoid_bridge`, or – in a program's app, whose one native
/// library is its own crate on `kernoid_bridge` – the library named `library`, whose part registers itself through
/// [programsSymbol].
///
/// On iOS and macOS the library is linked into the app inside the framework of the plugin package that builds it
/// (`kernoid_native`, or the program's), named after that package: its symbols are found in the process. That is
/// safe because an app has one library with flutter_rust_bridge's symbols.
Future<void> loadKernoid({String? library}) async {
  if (Platform.isIOS || Platform.isMacOS) {
    return loadKernoidFrom(ExternalLibrary.process(iKnowHowToUseIt: true));
  }
  final defaults = RustLib.kDefaultExternalLibraryLoaderConfig;
  await loadKernoidFrom(
    await loadExternalLibrary(
      ExternalLibraryLoaderConfig(
        stem: library ?? defaults.stem,
        ioDirectory: defaults.ioDirectory,
        webPrefix: defaults.webPrefix,
        wasmBindgenName: defaults.wasmBindgenName,
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
