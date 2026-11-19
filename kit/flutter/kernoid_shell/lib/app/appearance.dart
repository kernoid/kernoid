// SPDX-License-Identifier: MIT
import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'package:kernoid_ui/ui.dart';

/// Light, dark or as the system is – kept on this device in the app's support directory, not at the server.
abstract final class Appearance {
  static final mode = ValueNotifier<KThemeMode>(KThemeMode.system);

  static Future<File> _file() async => File('${(await getApplicationSupportDirectory()).path}/appearance');

  static Future<void> load() async {
    try {
      final name = (await (await _file()).readAsString()).trim();
      mode.value = KThemeMode.values.firstWhere((m) => m.name == name, orElse: () => KThemeMode.system);
    } catch (_) {
      // Nothing kept yet: as the system is.
    }
  }

  static Future<void> set(KThemeMode value) async {
    mode.value = value;
    try {
      final file = await _file();
      await file.parent.create(recursive: true);
      await file.writeAsString(value.name);
    } catch (_) {
      // Not kept: the choice holds until the app ends.
    }
  }
}
