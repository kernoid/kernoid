// SPDX-License-Identifier: MIT
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

import 'package:kernoid_bridge/kernoid_bridge.dart';

/// The stores in Finder and the Files app (docs/plan.md, 5): the File Provider extension in `native/apple/`, a domain
/// per store, through the channel `dev.kernoid.kernoid/fileprovider` (`native/apple/App/FileProviderChannel.swift`).
///
/// The extension runs in processes of its own and has a login of its own: kernoid rotates refresh tokens, and two
/// processes renewing the app's login would end it. Turning it on therefore signs in once more in the browser
/// ([login]) and hands that login to the extension – never the app's own.
class FileProvider {
  FileProvider._();

  static const _channel = MethodChannel('dev.kernoid.kernoid/fileprovider');

  static bool get available => Platform.isMacOS || Platform.isIOS;

  /// The ids of the stores shown in the system's file manager; none when it is off.
  static Future<List<String>> shown() async => (await _channel.invokeListMethod<String>('state')) ?? const [];

  /// Signs in once more at the account's server, in the browser, for the extension: what to keep for it. The account
  /// made for it is let go at once, so that this process never renews that login.
  static Future<String> login(Kernoid account) async {
    final login = await Kernoid.beginLogin(
      server: account.server,
      redirectUri: 'dev.kernoid.kernoid:/oauth',
      address: account.username,
    );
    final callback = await FlutterWebAuth2.authenticate(url: login.url, callbackUrlScheme: 'dev.kernoid.kernoid');
    final shell = await Kernoid.finishLogin(login: login, callback: callback);
    if (shell.username.toLowerCase() != account.username.toLowerCase()) {
      // Another account was signed in with in the browser: its stores are not the ones shown.
      final other = shell.username;
      await shell.signOut();
      shell.dispose();
      throw StateError('signed in as $other, not as ${account.username}');
    }
    final kept = shell.keptLogin();
    shell.dispose();
    if (kept == null) throw StateError('the login gave nothing to keep');
    return kept;
  }

  /// Shows the account's stores in the system's file manager, with the extension's own login ([login]) – or, without
  /// one, with the login handed to it before: the stores only are brought up to date.
  static Future<void> enable(Kernoid account, String? kept) => _channel.invokeMethod('enable', {
    'kept': ?kept,
    'stores': [
      for (final store in account.fileStores()) {'id': store.accountId, 'name': store.name},
    ],
  });

  /// Removes the stores from the system's file manager and revokes the extension's login at the server.
  static Future<void> disable() async {
    final kept = await _channel.invokeMethod<String>('disable');
    if (kept == null) return;
    try {
      final shell = await Kernoid.resume(kept: kept);
      await shell.signOut();
      shell.dispose();
    } catch (_) {
      // Ended already, or the server out of reach: the login expires on its own.
    }
  }

  /// Asks the system to look for changes in every store shown – after the app changed files or heard of changes.
  static Future<void> signal() async {
    if (!available) return;
    try {
      await _channel.invokeMethod('signal');
    } on PlatformException {
      // No domains, or the system has no File Provider for the app: nothing to tell.
    } on MissingPluginException {
      // A test, without the runner's channel.
    }
  }
}
