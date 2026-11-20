// SPDX-License-Identifier: MIT
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

import 'package:kernoid_bridge/kernoid_bridge.dart';

import 'space_vault.dart';

/// kernoid's stores in Android's Files app and every document picker: the DocumentsProvider of the Android part
/// (`KernoidDocumentsProvider.kt`, docs/plan.md, 5), switched on and off here through the channel
/// `dev.kernoid.kernoid/documents` of `MainActivity.kt`.
///
/// The provider has a login of its own, made by signing in once more – never the app's: kernoid rotates refresh
/// tokens, and two holders renewing one login would end it.
abstract final class DocumentsProvider {
  static const _channel = MethodChannel('dev.kernoid.kernoid/documents');

  static bool get available => Platform.isAndroid;

  /// Whether the provider has a login.
  static Future<bool> enabled() async => await _channel.invokeMethod<bool>('enabled') ?? false;

  /// Signs in once more in the system's browser – at the server and with the address of [account] – and hands that
  /// login to the provider. The browser's session at kernoid usually makes it one tap.
  static Future<void> enable(Kernoid account) async {
    final login = await Kernoid.beginLogin(
      server: account.server,
      redirectUri: 'dev.kernoid.kernoid:/oauth',
      address: account.username,
    );
    final callback = await FlutterWebAuth2.authenticate(url: login.url, callbackUrlScheme: 'dev.kernoid.kernoid');
    final shell = await Kernoid.finishLogin(login: login, callback: callback);
    await handVaultsToShell(account, shell);
    final kept = shell.keptLogin();
    // Its renewal in this process stops here: from now on the provider alone renews this login.
    shell.dispose();
    if (kept == null) throw StateError('the login gave nothing to keep');
    await _channel.invokeMethod<void>('enable', kept);
  }

  /// Takes the provider's login away and ends it at the server; offline it ends when its refresh token expires.
  static Future<void> disable() async {
    final kept = await _channel.invokeMethod<String>('disable');
    if (kept == null) return;
    try {
      final shell = await Kernoid.resume(kept: kept);
      await shell.signOut();
      shell.dispose();
    } catch (_) {
      // Ended already, or offline.
    }
  }
}
