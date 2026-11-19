// SPDX-License-Identifier: MIT
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

/// The app's icon in the menu bar (macOS) or the notification area (Windows, Linux) while folders are kept in step:
/// closing the window hides it, the icon opens it again, syncs at once or quits.
class Tray with TrayListener, WindowListener {
  Tray({required this.labels, required this.onSync});

  /// Open, sync now, quit – in the app's language.
  final ({String open, String sync, String quit}) labels;
  final VoidCallback onSync;

  static bool get available => Platform.isMacOS || Platform.isWindows || Platform.isLinux;

  Future<void> start() async {
    if (!available) return;
    await windowManager.ensureInitialized();
    await trayManager.setIcon(Platform.isWindows ? 'assets/tray/tray.ico' : 'assets/tray/tray.png');
    await trayManager.setToolTip('kernoid');
    await trayManager.setContextMenu(
      Menu(
        items: [
          MenuItem(key: 'open', label: labels.open),
          MenuItem(key: 'sync', label: labels.sync),
          MenuItem.separator(),
          MenuItem(key: 'quit', label: labels.quit),
        ],
      ),
    );
    trayManager.addListener(this);
    windowManager.addListener(this);
    await windowManager.setPreventClose(true);
  }

  Future<void> stop() async {
    if (!available) return;
    trayManager.removeListener(this);
    windowManager.removeListener(this);
    await windowManager.setPreventClose(false);
    await trayManager.destroy();
  }

  @override
  void onTrayIconMouseDown() => trayManager.popUpContextMenu();

  @override
  void onTrayIconRightMouseDown() => trayManager.popUpContextMenu();

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    switch (menuItem.key) {
      case 'open':
        windowManager.show();
        windowManager.focus();
      case 'sync':
        onSync();
      case 'quit':
        windowManager.setPreventClose(false).then((_) => windowManager.destroy());
    }
  }

  @override
  void onWindowClose() => windowManager.hide();
}
