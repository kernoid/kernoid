// SPDX-License-Identifier: MIT
import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:intl/date_symbol_data_local.dart';

import 'tokens.dart';

/// Which look the app takes: the system's, light or dark – the user's choice in the account.
enum KThemeMode { system, light, dark }

/// The app's frame on Flutter's widgets alone – no Material, no Cupertino: kernoid's tokens ([KTheme]), text, icons,
/// selection colours, scroll bars on desktops, the pages' route ([KPageRoute]) and the host of short notes
/// ([KToast]).
class KApp extends StatelessWidget {
  const KApp({
    super.key,
    required this.home,
    required this.mode,
    required this.onGenerateTitle,
    required this.localizationsDelegates,
    required this.supportedLocales,
  });

  final Widget home;
  final KThemeMode mode;
  final GenerateAppTitle onGenerateTitle;
  final Iterable<LocalizationsDelegate<dynamic>> localizationsDelegates;
  final Iterable<Locale> supportedLocales;

  @override
  Widget build(BuildContext context) {
    final brightness = switch (mode) {
      KThemeMode.light => Brightness.light,
      KThemeMode.dark => Brightness.dark,
      KThemeMode.system => MediaQuery.platformBrightnessOf(context),
    };
    final k = KTokens.of(brightness);
    return WidgetsApp(
      color: k.accent,
      onGenerateTitle: onGenerateTitle,
      localizationsDelegates: [_DateFormats.delegate, ...localizationsDelegates],
      supportedLocales: supportedLocales,
      textStyle: KText.body(k),
      pageRouteBuilder: <T>(RouteSettings settings, WidgetBuilder builder) =>
          KPageRoute<T>(settings: settings, builder: builder),
      home: home,
      builder: (context, child) => KTheme(
        tokens: k,
        child: DefaultTextStyle(
          style: KText.body(k),
          child: IconTheme(
            data: IconThemeData(color: k.muted, size: KSize.icon),
            child: DefaultSelectionStyle(
              cursorColor: k.accent,
              selectionColor: k.accent.withValues(alpha: 0.28),
              child: ScrollConfiguration(
                behavior: const KScrollBehavior(),
                child: KToastHost(
                  child: ColoredBox(color: k.surface, child: child ?? const SizedBox.shrink()),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Sets up intl's dates and times for the app's language as it loads – what Material's localizations did, wherever
/// the app is built (also in tests that start it without `main`).
abstract final class _DateFormats {
  static const delegate = _DateFormatsDelegate();
}

class _DateFormatsDelegate extends LocalizationsDelegate<void> {
  const _DateFormatsDelegate();

  @override
  bool isSupported(Locale locale) => true;

  @override
  Future<void> load(Locale locale) => initializeDateFormatting(locale.toLanguageTag());

  @override
  bool shouldReload(_DateFormatsDelegate old) => false;
}

/// Scrolling as the platform has it, with a thin scroll bar in kernoid's colours on desktops.
class KScrollBehavior extends ScrollBehavior {
  const KScrollBehavior();

  static bool get _desktop => switch (defaultTargetPlatform) {
    TargetPlatform.macOS || TargetPlatform.linux || TargetPlatform.windows => true,
    _ => false,
  };

  @override
  Widget buildScrollbar(BuildContext context, Widget child, ScrollableDetails details) {
    if (!_desktop || details.direction != AxisDirection.down && details.direction != AxisDirection.up) {
      return child;
    }
    return RawScrollbar(
      controller: details.controller,
      thumbColor: context.k.lineStrong,
      radius: const Radius.circular(4),
      thickness: 6,
      child: child,
    );
  }
}

/// A page: it fades in and rises a little; a full-screen dialog rises from below. What Material's route did, drawn
/// without it.
class KPageRoute<T> extends PageRoute<T> {
  KPageRoute({required this.builder, super.settings, this.fullscreenDialog = false})
    : super(fullscreenDialog: fullscreenDialog);

  final WidgetBuilder builder;

  @override
  // ignore: overridden_fields
  final bool fullscreenDialog;

  @override
  Color? get barrierColor => null;

  @override
  String? get barrierLabel => null;

  @override
  bool get maintainState => true;

  @override
  Duration get transitionDuration => const Duration(milliseconds: 220);

  @override
  Widget buildPage(BuildContext context, Animation<double> animation, Animation<double> secondaryAnimation) =>
      Semantics(scopesRoute: true, explicitChildNodes: true, child: builder(context));

  @override
  Widget buildTransitions(
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    final curved = CurvedAnimation(parent: animation, curve: Curves.easeOutCubic, reverseCurve: Curves.easeInCubic);
    final offset = Tween<Offset>(
      begin: fullscreenDialog ? const Offset(0, 0.08) : const Offset(0, 0.025),
      end: Offset.zero,
    ).animate(curved);
    return FadeTransition(
      opacity: curved,
      child: SlideTransition(position: offset, child: child),
    );
  }
}

/// A page's frame – what Material's scaffold was: the bar on top, the content below it (above the keyboard), a button
/// floating at the bottom end, a bar at the bottom.
class KScaffold extends StatelessWidget {
  const KScaffold({
    super.key,
    this.topBar,
    required this.body,
    this.floating,
    this.bottom,
    this.background,
    this.avoidKeyboard = true,
  });

  final Widget? topBar;
  final Widget body;
  final Widget? floating;
  final Widget? bottom;
  final Color? background;

  /// The content ends above the on-screen keyboard.
  final bool avoidKeyboard;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final insets = MediaQuery.viewInsetsOf(context);
    Widget content = topBar == null ? body : MediaQuery.removePadding(context: context, removeTop: true, child: body);
    if (floating != null) {
      content = Stack(
        children: [
          Positioned.fill(child: content),
          PositionedDirectional(
            end: 16,
            bottom: 16 + (bottom == null ? MediaQuery.paddingOf(context).bottom : 0),
            child: floating!,
          ),
        ],
      );
    }
    return ColoredBox(
      color: background ?? k.surface,
      child: Padding(
        padding: EdgeInsets.only(bottom: avoidKeyboard ? insets.bottom : 0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ?topBar,
            Expanded(child: content),
            ?bottom,
          ],
        ),
      ),
    );
  }
}

/// Short notes at the bottom of the window – “Saved”, “Sent” –, one at a time, gone after a few seconds: what
/// Material's snack bars were. [KApp] holds the host; [KToast.show] finds it from any page or dialog.
abstract final class KToast {
  static void show(BuildContext context, String text, {Duration duration = const Duration(seconds: 4)}) =>
      of(context).show(text, duration: duration);

  /// The host of `context`, taken before an `await` so that a note can follow after the page is gone.
  static KMessenger of(BuildContext context) => KMessenger._(context.findAncestorStateOfType<_KToastHostState>());
}

/// Shows short notes; see [KToast.of].
class KMessenger {
  KMessenger._(this._host);

  final _KToastHostState? _host;

  void show(String text, {Duration duration = const Duration(seconds: 4)}) {
    final host = _host;
    if (host != null && host.mounted) host._show(text, duration);
  }
}

class KToastHost extends StatefulWidget {
  const KToastHost({super.key, required this.child});

  final Widget child;

  @override
  State<KToastHost> createState() => _KToastHostState();
}

class _KToastHostState extends State<KToastHost> {
  String? _text;
  int _serial = 0;
  Timer? _timer;

  void _show(String text, Duration duration) {
    _timer?.cancel();
    setState(() {
      _text = text;
      _serial++;
    });
    _timer = Timer(duration, () {
      if (mounted) setState(() => _text = null);
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final text = _text;
    return Stack(
      textDirection: TextDirection.ltr,
      children: [
        Positioned.fill(child: widget.child),
        Positioned(
          left: 16,
          right: 16,
          bottom: 16 + MediaQuery.paddingOf(context).bottom + MediaQuery.viewInsetsOf(context).bottom,
          child: IgnorePointer(
            child: Center(
              child: AnimatedSwitcher(
                duration: const Duration(milliseconds: 180),
                child: text == null
                    ? const SizedBox.shrink()
                    : Container(
                        key: ValueKey(_serial),
                        constraints: const BoxConstraints(maxWidth: 420),
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                        decoration: BoxDecoration(
                          color: k.text,
                          borderRadius: BorderRadius.circular(KSize.radiusSmall),
                          boxShadow: const [BoxShadow(color: Color(0x33000000), blurRadius: 16, offset: Offset(0, 4))],
                        ),
                        child: Semantics(
                          liveRegion: true,
                          child: Text(
                            text,
                            key: const ValueKey('toast'),
                            style: KText.body(k).copyWith(color: k.bg, fontWeight: FontWeight.w500, fontSize: 14),
                          ),
                        ),
                      ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// Days without Material's `DateUtils`.
abstract final class KDates {
  static DateTime dateOnly(DateTime at) => DateTime(at.year, at.month, at.day);

  static DateTime addDays(DateTime at, int days) => DateTime(at.year, at.month, at.day + days);

  static bool sameDay(DateTime? a, DateTime? b) =>
      a != null && b != null && a.year == b.year && a.month == b.month && a.day == b.day;

  static int daysInMonth(int year, int month) => DateTime(year, month + 1, 0).day;
}
