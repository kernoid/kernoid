// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

import 'package:kernoid_bridge/kernoid_bridge.dart';

/// A folder of this computer kept in step with a store: its path and, on macOS, the security-scoped bookmark that lets
/// the sandboxed app reach it again after a restart.
@immutable
class SyncFolder {
  const SyncFolder({required this.store, required this.path, this.bookmark});

  /// The store's id (a JMAP account id).
  final String store;
  final String path;
  final String? bookmark;

  Map<String, Object?> toJson() => {'store': store, 'path': path, 'bookmark': bookmark};

  static SyncFolder? fromJson(Object? json) => switch (json) {
    {'store': final String store, 'path': final String path} => SyncFolder(
      store: store,
      path: path,
      bookmark: json['bookmark'] as String?,
    ),
    _ => null,
  };
}

/// How a folder's rounds went.
@immutable
class SyncStatus {
  const SyncStatus({this.running = false, this.last, this.report, this.error});

  final bool running;
  final DateTime? last;
  final SyncReport? report;
  final String? error;
}

/// The folders of this computer kept in step with the account's stores (desktops only – phones show files through
/// the system's file provider, docs/plan.md, 5), by kernoid-sync on the Rust side: a round soon after kernoid pushes a
/// change of files or the folder changes here, every few minutes besides, and on demand – while the app is open. What is chosen is kept on this device in the app's support directory, per
/// account; each folder's state database lies beside it, never in the folder.
class SyncFolders extends ChangeNotifier {
  SyncFolders(this.account);

  final Kernoid account;

  static bool get available => Platform.isMacOS || Platform.isLinux || Platform.isWindows;
  static const interval = Duration(minutes: 3);
  static const _bookmarks = MethodChannel('dev.kernoid.kernoid/bookmarks');

  List<SyncFolder> _folders = const [];
  final Map<String, SyncStatus> _status = {};
  Timer? _timer;
  Timer? _soon;
  StreamSubscription<List<String>>? _pushes;
  final Map<String, StreamSubscription<FileSystemEvent>> _watches = {};

  /// On macOS: the paths of folders whose bookmark was opened – the access stays while the folder is kept in step.
  final Map<String, String> _opened = {};
  bool _round = false;
  bool _again = false;
  bool _disposed = false;

  List<SyncFolder> get folders => _folders;
  SyncFolder? folderOf(String store) => _folders.where((f) => f.store == store).firstOrNull;
  SyncStatus statusOf(String store) => _status[store] ?? const SyncStatus();

  /// Loads what was chosen and begins the rounds.
  Future<void> start() async {
    if (!available) return;
    try {
      final list = jsonDecode(await (await _config()).readAsString());
      _folders = [for (final entry in list as List<Object?>) ?SyncFolder.fromJson(entry)];
    } catch (_) {
      // Nothing chosen yet.
    }
    _changed();
    _timer = Timer.periodic(interval, (_) => syncAll());
    _pushes = account.watchChanges().listen((types) {
      if (types.contains('FileNode')) _later(const Duration(seconds: 2));
    }, onError: (Object _) {});
    await _openAll();
    _watchAll();
    unawaited(syncAll());
  }

  /// Opens the bookmark of each folder not opened yet (macOS) and closes those of folders no longer kept in step.
  Future<void> _openAll() async {
    if (!Platform.isMacOS) return;
    for (final store in [..._opened.keys]) {
      if (folderOf(store) == null) await _close(store);
    }
    for (final folder in _folders) {
      if (_opened.containsKey(folder.store) || folder.bookmark == null) continue;
      try {
        final path = await _bookmarks.invokeMethod<String>('open', folder.bookmark);
        if (path != null) _opened[folder.store] = path;
      } on PlatformException catch (error) {
        _status[folder.store] = SyncStatus(error: error.message ?? error.code);
      }
    }
  }

  Future<void> _close(String store) async {
    final path = _opened.remove(store);
    if (path != null) await _bookmarks.invokeMethod<void>('close', path);
  }

  /// Where a folder is reached: through its opened bookmark on macOS.
  String _pathOf(SyncFolder folder) => _opened[folder.store] ?? folder.path;

  /// A round shortly – changes come in bursts, one round takes them all.
  void _later(Duration wait) {
    _soon?.cancel();
    _soon = Timer(wait, syncAll);
  }

  /// Watches each folder for changes made here (recursively where the system can: macOS and Windows; on Linux only
  /// the folder's top, the timer finds the rest).
  void _watchAll() {
    for (final store in [..._watches.keys]) {
      if (folderOf(store) == null) unawaited(_watches.remove(store)?.cancel());
    }
    for (final folder in _folders) {
      final path = _pathOf(folder);
      if (_watches.containsKey(folder.store) || !Directory(path).existsSync()) continue;
      try {
        _watches[folder.store] = Directory(path)
            .watch(recursive: !Platform.isLinux)
            .where((event) => !event.path.endsWith('.kernoid-part'))
            .listen((_) => _later(const Duration(seconds: 5)), onError: (Object _) {});
      } catch (_) {
        // Not watchable here (a sandbox without access yet): the timer still runs.
      }
    }
  }

  /// Keeps `path` in step with `store` from now on, and syncs it at once.
  Future<void> add(String store, String path) async {
    String? bookmark;
    if (Platform.isMacOS) bookmark = await _bookmarks.invokeMethod<String>('create', path);
    _folders = [..._folders.where((f) => f.store != store), SyncFolder(store: store, path: path, bookmark: bookmark)];
    _status.remove(store);
    await _save();
    await _close(store);
    await _openAll();
    _changed();
    _watchAll();
    await syncAll();
  }

  /// Stops keeping a store's folder in step; the folder stays as it is, the state of its rounds is dropped.
  Future<void> remove(String store) async {
    _folders = [..._folders.where((f) => f.store != store)];
    _status.remove(store);
    await _save();
    await _close(store);
    _watchAll();
    try {
      for (final suffix in ['', '-wal', '-shm']) {
        final file = File('${(await _state(store)).path}$suffix');
        if (await file.exists()) await file.delete();
      }
    } catch (_) {
      // Left behind: a later folder of the store starts from it, which only costs a comparison.
    }
    _changed();
  }

  /// A round for every folder, one after the other; asked while one runs, another follows it (what the round itself
  /// wrote to the folders is seen again, which costs only a comparison).
  Future<void> syncAll() async {
    if (_disposed) return;
    if (_round) {
      _again = true;
      return;
    }
    _round = true;
    try {
      do {
        _again = false;
        for (final folder in [..._folders]) {
          if (_disposed) return;
          await _sync(folder);
        }
      } while (_again && !_disposed);
    } finally {
      _round = false;
    }
  }

  Future<void> _sync(SyncFolder folder) async {
    final before = statusOf(folder.store);
    _status[folder.store] = SyncStatus(running: true, last: before.last, report: before.report);
    _changed();
    try {
      await (await _directory()).create(recursive: true);
      final report = await account.syncFolder(
        accountId: folder.store,
        root: _pathOf(folder),
        state: (await _state(folder.store)).path,
      );
      _status[folder.store] = SyncStatus(last: DateTime.now(), report: report);
    } on KernoidError catch (error) {
      _status[folder.store] = SyncStatus(last: before.last, report: before.report, error: error.message);
    }
    _changed();
  }

  /// This account's directory in the app's support directory.
  Future<Directory> _directory() async {
    final key = base64Url.encode(utf8.encode('${account.server}|${account.username}')).replaceAll('=', '');
    return Directory('${(await getApplicationSupportDirectory()).path}/sync/$key');
  }

  Future<File> _config() async => File('${(await _directory()).path}/folders.json');

  Future<File> _state(String store) async => File('${(await _directory()).path}/$store.db');

  Future<void> _save() async {
    final file = await _config();
    await file.parent.create(recursive: true);
    await file.writeAsString(jsonEncode([for (final f in _folders) f.toJson()]));
  }

  void _changed() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    _soon?.cancel();
    unawaited(_pushes?.cancel());
    for (final watch in _watches.values) {
      unawaited(watch.cancel());
    }
    for (final store in [..._opened.keys]) {
      unawaited(_close(store));
    }
    super.dispose();
  }
}
