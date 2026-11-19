// SPDX-License-Identifier: MIT
import 'dart:io';

import 'package:flutter/services.dart';

/// Starting the app when the user logs in to the computer, so that folders are kept in step without opening it: a login
/// item on macOS (`SMAppService`, the channel in `macos/Runner/MainFlutterWindow.swift`), the `Run` key of the user's
/// registry on Windows, a desktop entry in `~/.config/autostart` on Linux (XDG Autostart).
abstract final class LoginItem {
  static const _channel = MethodChannel('dev.kernoid.kernoid/login-item');
  static const _name = 'kernoid';
  static const _run = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';

  static bool get available => Platform.isMacOS || Platform.isWindows || Platform.isLinux;

  static File get _desktopEntry => File(
    '${Platform.environment['XDG_CONFIG_HOME'] ?? '${Platform.environment['HOME']}/.config'}/autostart/'
    'dev.kernoid.kernoid.desktop',
  );

  static Future<bool> enabled() async {
    try {
      if (Platform.isMacOS) return await _channel.invokeMethod<bool>('enabled') ?? false;
      if (Platform.isWindows) return (await Process.run('reg', ['query', _run, '/v', _name])).exitCode == 0;
      if (Platform.isLinux) return _desktopEntry.existsSync();
    } catch (_) {
      // Not to be asked here: off.
    }
    return false;
  }

  /// Turns it on or off; whether it is on afterwards.
  static Future<bool> set(bool on) async {
    try {
      if (Platform.isMacOS) {
        await _channel.invokeMethod<void>(on ? 'enable' : 'disable');
      } else if (Platform.isWindows) {
        final exe = Platform.resolvedExecutable;
        await Process.run(
          'reg',
          on ? ['add', _run, '/v', _name, '/t', 'REG_SZ', '/d', '"$exe"', '/f'] : ['delete', _run, '/v', _name, '/f'],
        );
      } else if (Platform.isLinux) {
        if (on) {
          await _desktopEntry.parent.create(recursive: true);
          await _desktopEntry.writeAsString(
            '[Desktop Entry]\nType=Application\nName=kernoid\nExec="${Platform.resolvedExecutable}"\n'
            'X-GNOME-Autostart-enabled=true\n',
          );
        } else if (_desktopEntry.existsSync()) {
          await _desktopEntry.delete();
        }
      }
    } catch (_) {
      // Left as it was; the switch shows what is.
    }
    return enabled();
  }
}
