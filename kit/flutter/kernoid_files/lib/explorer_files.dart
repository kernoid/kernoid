// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import 'package:kernoid_bridge/kernoid_bridge.dart';

/// kernoid's stores in Windows' Explorer (docs/plan.md, 5): a sync root per store below `%USERPROFILE%\kernoid`, with
/// placeholders downloaded when they are opened – the Cloud Files shell on the Rust side, running while the app is
/// open. It has a login of its own, set up once with kernoid's login page and kept by the shell (DPAPI) in the app's
/// support directory per account – never the app's own login, since two holders renewing one refresh token would end
/// it.
class ExplorerFiles extends ChangeNotifier {
  ExplorerFiles(this.account);

  final Kernoid account;

  static bool get available => Platform.isWindows;

  bool _configured = false;
  bool _busy = false;
  String? _error;
  WindowsFilesStatus? _status;
  Timer? _timer;
  bool _disposed = false;

  bool get configured => _configured;
  bool get busy => _busy;
  String? get error => _error;
  WindowsFilesStatus? get status => _status;

  /// The folder the stores appear in.
  static String get folder => '${Platform.environment['USERPROFILE'] ?? ''}\\kernoid';

  /// Starts the shell with the login kept for it, if it was set up.
  Future<void> start() async {
    if (!available) return;
    _configured = windowsFilesConfigured(stateDir: await _stateDir());
    _changed();
    if (_configured) await _run(null);
    _timer = Timer.periodic(const Duration(seconds: 20), (_) => _refresh());
  }

  /// Sets the shell up with a login made for it just now and hands it over: `shell` is disposed, so that only the
  /// shell renews it from here on.
  Future<void> setUp(Kernoid shell) async {
    final kept = shell.keptLogin();
    shell.dispose();
    if (kept == null) return;
    await _run(kept);
  }

  /// Takes the stores out of Explorer: the folders stay with what was downloaded; the shell's login is dropped.
  Future<void> remove() async {
    _busy = true;
    _changed();
    try {
      await windowsFilesStop(stateDir: await _stateDir(), forget: true);
      _configured = false;
      _error = null;
    } on KernoidError catch (error) {
      _error = error.message;
    } finally {
      _busy = false;
      _refresh();
    }
  }

  Future<void> _run(String? kept) async {
    _busy = true;
    _error = null;
    _changed();
    try {
      await windowsFilesStart(kept: kept, rootDir: folder, stateDir: await _stateDir());
      _configured = true;
    } on KernoidError catch (error) {
      _error = error.message;
      if (error.unauthorized) _configured = false;
    } finally {
      _busy = false;
      _refresh();
    }
  }

  void _refresh() {
    if (!available || _disposed) return;
    _status = windowsFilesStatus();
    _changed();
  }

  /// This account's directory for the shell in the app's support directory.
  Future<String> _stateDir() async {
    final key = base64Url.encode(utf8.encode('${account.server}|${account.username}')).replaceAll('=', '');
    return '${(await getApplicationSupportDirectory()).path}${Platform.pathSeparator}explorer${Platform.pathSeparator}$key';
  }

  void _changed() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    if (available) unawaited(_stateDir().then((dir) => windowsFilesStop(stateDir: dir, forget: false)));
    super.dispose();
  }
}
