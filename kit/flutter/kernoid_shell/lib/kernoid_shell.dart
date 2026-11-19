// SPDX-License-Identifier: MIT
/// The frame of an app on kernoid (RFC 0011): logging in, the home with the features the server offers, the account.
/// An app hands [runKernoidApp] its features; mail, calendars, contacts and files are kernoid's own packages, a
/// program built on kernoid brings its own.
library;

import 'package:flutter_localizations/flutter_localizations.dart' show GlobalWidgetsLocalizations;
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_ui/ui.dart';

import 'app/appearance.dart';
import 'app/kept_login.dart';
import 'feature.dart';
import 'pages/home.dart';
import 'pages/login.dart';

export 'feature.dart';

/// Starts the app: the Rust side, the look kept on this device, then [KernoidApp] with `features`.
Future<void> runKernoidApp({required List<KFeature> features}) async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  await Appearance.load();
  runApp(KernoidApp(features: features));
}

/// The app: the login until an account is signed in, then its home. A login kept from before is resumed at start.
class KernoidApp extends StatefulWidget {
  const KernoidApp({super.key, required this.features});

  /// The app's features, in the order of the side bar.
  final List<KFeature> features;

  /// Wraps the whole app, so that tests can take a picture of it.
  static const screen = ValueKey('kernoid-screen');

  @override
  State<KernoidApp> createState() => _KernoidAppState();
}

class _KernoidAppState extends State<KernoidApp> {
  Kernoid? _account;

  /// Resuming a kept login; the login page waits until it is done.
  bool _resuming = true;

  /// Why a kept login could not be resumed – shown on the login page.
  String? _resumeError;

  @override
  void initState() {
    super.initState();
    _resume();
  }

  Future<void> _resume() async {
    try {
      final account = await KeptLogin.resume();
      if (mounted) setState(() => _account = account);
    } on KernoidError catch (error) {
      // Ended at the server: sign in again. Anything else (offline): the kept login stays for the next start.
      if (mounted && !error.unauthorized) setState(() => _resumeError = error.message);
    } finally {
      if (mounted) setState(() => _resuming = false);
    }
  }

  Future<void> _signedIn(Kernoid account) async {
    setState(() {
      _account = account;
      _resumeError = null;
    });
    await KeptLogin.keep(account);
  }

  Future<void> _signOut() async {
    final account = _account;
    setState(() => _account = null);
    await KeptLogin.forget();
    // What the features registered with the system goes with the account.
    for (final feature in widget.features) {
      try {
        await feature.signingOut();
      } catch (_) {}
    }
    try {
      await account?.signOut();
    } catch (_) {
      // Offline: the login ends at the server when its refresh token expires.
    }
  }

  @override
  Widget build(BuildContext context) {
    final account = _account;
    return RepaintBoundary(
      key: KernoidApp.screen,
      child: ValueListenableBuilder<KThemeMode>(
        valueListenable: Appearance.mode,
        builder: (context, mode, _) => KApp(
          onGenerateTitle: (context) => AppLocalizations.of(context).appTitle,
          mode: mode,
          localizationsDelegates: const [AppLocalizations.delegate, GlobalWidgetsLocalizations.delegate],
          supportedLocales: AppLocalizations.supportedLocales,
          home: _resuming
              ? const KScaffold(body: KLoading())
              : account == null
              ? LoginPage(onSignedIn: _signedIn, notice: _resumeError)
              : HomePage(account: account, features: widget.features, onSignOut: _signOut),
        ),
      ),
    );
  }
}
