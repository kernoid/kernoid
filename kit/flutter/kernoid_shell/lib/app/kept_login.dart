// SPDX-License-Identifier: MIT
import 'dart:async';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'package:kernoid_bridge/kernoid_bridge.dart';

/// A login with OpenID Connect kept in the system's key store – Keychain, Android Keystore, Windows Credential Manager,
/// Secret Service –, so that the app stays signed in across starts: the server and the refresh token, never the access
/// token. kernoid rotates refresh tokens; every renewal is kept again, since one used before ends the login.
class KeptLogin {
  KeptLogin._();

  /// The integration test (`KERNOID_TEST_SERVER` set) keeps its logins apart, so that it never resumes or ends the
  /// login of someone using the app on the same machine.
  static const _key = String.fromEnvironment('KERNOID_TEST_SERVER') == '' ? 'kernoid.login' : 'kernoid.login.test';
  static const _storage = FlutterSecureStorage(
    // This device only, readable after the first unlock – also for the sync in the background later.
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
    // The login keychain: the data protection keychain would need a signing team's entitlement.
    mOptions: MacOsOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
      usesDataProtectionKeychain: false,
    ),
  );

  static StreamSubscription<String>? _watching;

  /// Signs in with what was kept; none if nothing was, or if the login has ended (then it is forgotten).
  static Future<Kernoid?> resume() async {
    final String? kept;
    try {
      kept = await _storage.read(key: _key);
    } catch (_) {
      return null;
    }
    if (kept == null) return null;
    try {
      final account = await Kernoid.resume(kept: kept);
      await keep(account);
      return account;
    } on KernoidError catch (error) {
      if (error.unauthorized) await forget();
      rethrow;
    }
  }

  /// Keeps an account's login – and every renewal of it – while it is signed in. A login with an app password is
  /// not kept.
  static Future<void> keep(Kernoid account) async {
    final kept = account.keptLogin();
    if (kept == null) return;
    await _storage.write(key: _key, value: kept);
    // The stream of the account before does not end on its own; nothing waits for it to be cancelled.
    unawaited(_watching?.cancel());
    _watching = account.watchLogin().listen((renewed) => _storage.write(key: _key, value: renewed));
  }

  static Future<void> forget() async {
    unawaited(_watching?.cancel());
    _watching = null;
    try {
      await _storage.delete(key: _key);
    } catch (_) {
      // Nothing kept, or no key store: nothing to forget.
    }
  }
}
