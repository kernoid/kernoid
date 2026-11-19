// SPDX-License-Identifier: MIT
import 'package:flutter/widgets.dart';

/// kernoid's look, as the web app has it (kernoid/kernoid, web/app/src/style.css): dark by default, light when the
/// system is light. Every colour, size and space of the app comes from here, through `context.k`.
@immutable
class KTokens {
  const KTokens({
    required this.bg,
    required this.panel,
    required this.surface,
    required this.raised,
    required this.hover,
    required this.line,
    required this.lineStrong,
    required this.text,
    required this.muted,
    required this.faint,
    required this.accent,
    required this.accentSoft,
    required this.accentText,
    required this.violet,
    required this.error,
    required this.errorSoft,
    required this.dark,
  });

  final Color bg;
  final Color panel;
  final Color surface;
  final Color raised;
  final Color hover;
  final Color line;
  final Color lineStrong;
  final Color text;
  final Color muted;
  final Color faint;
  final Color accent;
  final Color accentSoft;
  final Color accentText;
  final Color violet;
  final Color error;
  final Color errorSoft;
  final bool dark;

  static const darkTokens = KTokens(
    bg: Color(0xFF0B0D10),
    panel: Color(0xFF0F1317),
    surface: Color(0xFF12171C),
    raised: Color(0xFF1A2027),
    hover: Color(0xFF1E252D),
    line: Color(0xFF232B34),
    lineStrong: Color(0xFF2F3943),
    text: Color(0xFFE6FBFB),
    muted: Color(0xFF8B9EA4),
    faint: Color(0xFF5F7076),
    accent: Color(0xFF3DDC97),
    accentSoft: Color(0x1F3DDC97),
    accentText: Color(0xFF06120C),
    violet: Color(0xFF9B8CFF),
    error: Color(0xFFFF7A7A),
    errorSoft: Color(0x1FFF7A7A),
    dark: true,
  );

  static const lightTokens = KTokens(
    bg: Color(0xFFF3F6F7),
    panel: Color(0xFFF8FAFB),
    surface: Color(0xFFFFFFFF),
    raised: Color(0xFFEEF2F4),
    hover: Color(0xFFE8EEF1),
    line: Color(0xFFDFE6EA),
    lineStrong: Color(0xFFC9D3D9),
    text: Color(0xFF0B2340),
    muted: Color(0xFF4F6472),
    faint: Color(0xFF8496A1),
    accent: Color(0xFF0F7F52),
    accentSoft: Color(0x1A0F7F52),
    accentText: Color(0xFFFFFFFF),
    violet: Color(0xFF5B47D6),
    error: Color(0xFFB42318),
    errorSoft: Color(0x14B42318),
    dark: false,
  );

  /// For the brightness of a theme.
  static KTokens of(Brightness brightness) => brightness == Brightness.dark ? darkTokens : lightTokens;
}

/// Colours that do not depend on the theme.
abstract final class KColor {
  static const transparent = Color(0x00000000);
  static const white = Color(0xFFFFFFFF);
  static const black = Color(0xFF000000);
}

/// The tokens of the app below it – what Material's `Theme` was. [KApp] puts it above every page.
class KTheme extends InheritedWidget {
  const KTheme({super.key, required this.tokens, required super.child});

  final KTokens tokens;

  static KTokens of(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<KTheme>()?.tokens ?? KTokens.darkTokens;

  @override
  bool updateShouldNotify(KTheme oldWidget) => tokens != oldWidget.tokens;
}

/// Sizes of the comfortable density (the web app's default).
abstract final class KSize {
  static const space = 12.0;
  static const control = 36.0;
  static const rowY = 12.0;
  static const radius = 10.0;
  static const radiusSmall = 7.0;
  static const sideWidth = 236.0;
  static const listWidth = 380.0;
  static const bar = 56.0;
  static const icon = 18.0;
}

abstract final class KFont {
  // The fonts are this package's (pubspec.yaml): Flutter names a package's fonts `packages/<package>/<family>`.
  static const sans = 'packages/kernoid_ui/Plex Sans';
  static const mono = 'packages/kernoid_ui/Plex Mono';
}

/// Text of the interface: body 15 px, headings a little heavier and tighter.
abstract final class KText {
  static TextStyle body(KTokens k) => TextStyle(fontFamily: KFont.sans, fontSize: 15, height: 1.5, color: k.text);
  static TextStyle small(KTokens k) => TextStyle(fontFamily: KFont.sans, fontSize: 13, height: 1.4, color: k.muted);
  static TextStyle label(KTokens k) =>
      TextStyle(fontFamily: KFont.sans, fontSize: 14, fontWeight: FontWeight.w500, height: 1.3, color: k.text);
  static TextStyle title(KTokens k) => TextStyle(
    fontFamily: KFont.sans,
    fontSize: 19,
    fontWeight: FontWeight.w600,
    letterSpacing: -0.2,
    height: 1.3,
    color: k.text,
  );
  static TextStyle heading(KTokens k) =>
      TextStyle(fontFamily: KFont.sans, fontSize: 16, fontWeight: FontWeight.w600, height: 1.35, color: k.text);
  static TextStyle overline(KTokens k) =>
      TextStyle(fontFamily: KFont.mono, fontSize: 11, letterSpacing: 0.9, fontWeight: FontWeight.w500, color: k.faint);
  static TextStyle mono(KTokens k) => TextStyle(fontFamily: KFont.mono, fontSize: 13, color: k.muted);
}

extension KContext on BuildContext {
  /// The tokens of the current theme.
  KTokens get k => KTheme.of(this);
}
