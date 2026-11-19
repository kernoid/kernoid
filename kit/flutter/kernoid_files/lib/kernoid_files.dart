// SPDX-License-Identifier: MIT
/// Files in an app on kernoid (RFC 0011, 2): stores, drives, sharing, links, versions, vaults, the viewer – and on
/// desktops folders kept in step, the tray and the system's file integration.
library;

import 'package:flutter/widgets.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_shell/kernoid_shell.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'account_sections.dart';
import 'documents_provider.dart';
import 'explorer_files.dart';
import 'file_provider.dart';
import 'files.dart';
import 'sync_folders.dart';
import 'tray.dart';
import 'l10n/files_text.dart';

export 'sync_folders.dart' show SyncFolders;
export 'tray.dart' show Tray;

/// Files, where the server offers them. While the account is signed in, folders of this computer are kept in step and
/// the stores are in Windows' Explorer; the system's file integration belongs to kernoid's own app (RFC 0011, 5) –
/// an app of another program passes `system: false`.
class FilesFeature extends KFeature {
  const FilesFeature({this.system = true});

  /// Whether this app integrates file stores with the system (Files app, Finder, Explorer).
  final bool system;

  @override
  String get id => 'files';

  @override
  IconData get icon => LucideIcons.folder;

  @override
  String label(AppLocalizations l) => l.filesText.files;

  @override
  bool offeredBy(Kernoid account) => account.offers(capability: KCapability.files);

  @override
  Widget page(Kernoid account) => FilesPage(account: account);

  @override
  KFeatureSession start(BuildContext context, Kernoid account) => FilesSession(context, account, system: system);

  @override
  List<Widget> accountSections(BuildContext context, Kernoid account, KFeatureSession session) {
    final files = session as FilesSession;
    return [
      if (SyncFolders.available) SyncSection(account: account, sync: files.sync),
      if (system && ExplorerFiles.available) ExplorerSection(account: account, explorer: files.explorer),
      if (system && DocumentsProvider.available) DocumentsSection(account: account),
      if (system && FileProvider.available) FileProviderSection(account: account),
    ];
  }

  @override
  Future<void> signingOut() async {
    // The stores leave the Files app with the account.
    if (system && DocumentsProvider.available) await DocumentsProvider.disable();
  }
}

/// What files keep while the account is signed in: the folders kept in step, the tray while there are any, and the
/// stores in Explorer.
class FilesSession extends KFeatureSession {
  FilesSession(this._context, Kernoid account, {required bool system})
    : sync = SyncFolders(account),
      explorer = ExplorerFiles(account) {
    _system = system;
    sync.addListener(_trayWhenNeeded);
    sync.start();
    if (_system) explorer.start();
  }

  final BuildContext _context;
  late final bool _system;

  /// Folders of this computer kept in step while the app is open, whatever page is shown.
  final SyncFolders sync;

  /// The stores in Windows' Explorer, kept in step while the app is open.
  final ExplorerFiles explorer;

  /// The icon in the menu bar while folders are kept in step – closing the window then only hides it.
  Tray? _tray;

  void _trayWhenNeeded() {
    if (!Tray.available || !_context.mounted) return;
    final want = sync.folders.isNotEmpty;
    if (want && _tray == null) {
      final l = AppLocalizations.of(_context);
      final tray = Tray(
        labels: (open: l.filesText.trayOpen, sync: l.filesText.traySync, quit: l.filesText.trayQuit),
        onSync: sync.syncAll,
      );
      _tray = tray;
      tray.start();
    } else if (!want && _tray != null) {
      _tray?.stop();
      _tray = null;
    }
  }

  @override
  void dispose() {
    sync.removeListener(_trayWhenNeeded);
    _tray?.stop();
    sync.dispose();
    explorer.dispose();
  }
}
