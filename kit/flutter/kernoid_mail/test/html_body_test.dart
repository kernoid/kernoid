// SPDX-License-Identifier: MIT
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart' show GlobalWidgetsLocalizations;
import 'package:flutter_test/flutter_test.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_ui/ui.dart' show KApp, KThemeMode, KScaffold;
import 'package:kernoid_mail/html_body.dart';

Widget _app(Widget child) => KApp(
  mode: KThemeMode.dark,
  onGenerateTitle: (_) => 'kernoid',
  localizationsDelegates: const [AppLocalizations.delegate, GlobalWidgetsLocalizations.delegate],
  supportedLocales: AppLocalizations.supportedLocales,
  home: KScaffold(body: SingleChildScrollView(child: child)),
);

/// The image widgets drawn and what they would load.
Iterable<ImageProvider> _images(WidgetTester tester) =>
    tester.widgetList<Image>(find.byType(Image)).map((i) => i.image);

void main() {
  const pixel =
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
  const html =
      '<p>Hello <b>you</b></p><script>alert(1)</script>'
      '<img src="https://tracker.example/pixel.gif"><img src="file:///etc/passwd"><img src="$pixel">'
      '<a href="https://example.org/real">https://bank.example</a>';

  testWidgets('nothing is loaded from the internet or the device until the user asks', (tester) async {
    await tester.pumpWidget(_app(const HtmlBody(html: html)));
    await tester.pumpAndSettle();
    expect(find.textContaining('Hello', findRichText: true), findsOneWidget);
    expect(find.textContaining('alert', findRichText: true), findsNothing);
    // Only the image inside the message itself.
    expect(_images(tester).whereType<NetworkImage>(), isEmpty);
    expect(_images(tester).whereType<FileImage>(), isEmpty);
    expect(_images(tester).whereType<MemoryImage>(), hasLength(1));

    await tester.tap(find.byKey(const ValueKey('load-images')));
    await tester.pump();
    expect(_images(tester).whereType<NetworkImage>().map((i) => i.url), ['https://tracker.example/pixel.gif']);
    expect(_images(tester).whereType<FileImage>(), isEmpty);
    expect(find.byKey(const ValueKey('load-images')), findsNothing);
  });

  testWidgets('a link shows where it really goes before it opens', (tester) async {
    await tester.pumpWidget(_app(const HtmlBody(html: html)));
    await tester.pumpAndSettle();
    await tester.tap(find.textContaining('bank.example', findRichText: true));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('open-link')), findsOneWidget);
    expect(find.text('https://example.org/real'), findsOneWidget);
    await tester.tap(find.text(AppLocalizations.of(tester.element(find.byType(HtmlBody))).cancel));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('open-link')), findsNothing);
  });
}
