// SPDX-License-Identifier: MIT
import 'package:flutter/widgets.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_shell/kernoid_shell.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

/// A feature that works on the device alone, as a program's personal archive does.
class _Notes extends KFeature {
  const _Notes();

  @override
  String get id => 'notes';

  @override
  IconData get icon => LucideIcons.notebook;

  @override
  String label(AppLocalizations l) => 'Notes';

  @override
  bool get onDevice => true;

  @override
  bool offeredBy(Kernoid account) => true;

  @override
  Widget page(Kernoid account) => const Text('notes of the account');

  @override
  Widget pageOnDevice() => const Text('notes on the device');
}

/// A feature that needs an account's server.
class _Mail extends KFeature {
  const _Mail();

  @override
  String get id => 'mail';

  @override
  IconData get icon => LucideIcons.mail;

  @override
  String label(AppLocalizations l) => 'Mail';

  @override
  bool offeredBy(Kernoid account) => true;

  @override
  Widget page(Kernoid account) => const Text('mail');
}

Future<void> _start(WidgetTester tester, List<KFeature> features, Size size) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  // An empty key store: no login kept from before.
  FlutterSecureStorage.setMockInitialValues({});
  await tester.pumpWidget(KernoidApp(features: features));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('an app with a feature on the device starts at its home, and offers the login in the side bar', (
    tester,
  ) async {
    await _start(tester, const [_Mail(), _Notes()], const Size(1200, 800));
    expect(find.text('notes on the device'), findsOneWidget);
    expect(find.byKey(const ValueKey('nav-notes')), findsOneWidget);
    // Mail needs a server: not shown before anyone signs in.
    expect(find.byKey(const ValueKey('nav-mail')), findsNothing);
    expect(find.text('Sign in'), findsOneWidget);
    expect(find.text('On this device only'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('nav-account')));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('sign-in-browser')), findsOneWidget);
    expect(find.text('notes on the device'), findsNothing);
  });

  testWidgets('narrow, the login is the last item of the bottom bar', (tester) async {
    await _start(tester, const [_Notes()], const Size(400, 800));
    expect(find.text('notes on the device'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('nav-account')));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('sign-in-browser')), findsOneWidget);
  });

  testWidgets('an app whose features all need an account starts at the login', (tester) async {
    await _start(tester, const [_Mail()], const Size(1200, 800));
    expect(find.byKey(const ValueKey('sign-in-browser')), findsOneWidget);
    expect(find.byKey(const ValueKey('nav-account')), findsNothing);
  });
}
