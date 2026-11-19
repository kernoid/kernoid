// SPDX-License-Identifier: MIT
import 'package:flutter/widgets.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'fields.dart';
import 'tokens.dart';
import 'widgets.dart';

export 'menus.dart' show showPointMenu;

/// Opens a dialog above the page – the page dimmed behind it, closed by a tap beside it or Escape – and returns what
/// it pops with. What Material's `showDialog` was.
Future<T?> showKDialog<T>(BuildContext context, {required WidgetBuilder builder, bool dismissible = true}) {
  final tokens = context.k;
  return showGeneralDialog<T>(
    context: context,
    barrierDismissible: dismissible,
    barrierLabel: AppLocalizations.of(context).close,
    barrierColor: const Color(0x8C000000),
    transitionDuration: const Duration(milliseconds: 160),
    pageBuilder: (context, animation, secondaryAnimation) => KTheme(
      tokens: tokens,
      child: SafeArea(child: Builder(builder: builder)),
    ),
    transitionBuilder: (context, animation, secondaryAnimation, child) {
      final curved = CurvedAnimation(parent: animation, curve: Curves.easeOutCubic);
      return FadeTransition(
        opacity: curved,
        child: ScaleTransition(scale: Tween(begin: 0.97, end: 1.0).animate(curved), child: child),
      );
    },
  );
}

/// The frame of a dialog: a title, its content (scrolling when long), its buttons at the bottom end. What Material's
/// alert dialog was.
class KDialog extends StatelessWidget {
  const KDialog({
    super.key,
    this.title,
    required this.content,
    this.actions = const [],
    this.width = 420,
    this.scrollable = false,
  });

  final String? title;
  final Widget content;
  final List<Widget> actions;
  final double width;

  /// The content scrolls when it is too long – for text; content with a list of its own sizes itself (as Material's
  /// alert dialog did).
  final bool scrollable;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final insets = MediaQuery.viewInsetsOf(context);
    final padding = EdgeInsets.fromLTRB(22, title != null ? 14 : 22, 22, actions.isEmpty ? 22 : 8);
    return AnimatedPadding(
      duration: const Duration(milliseconds: 100),
      padding: EdgeInsets.only(bottom: insets.bottom) + const EdgeInsets.all(20),
      child: Center(
        child: ConstrainedBox(
          constraints: BoxConstraints(maxWidth: width),
          child: Container(
            decoration: BoxDecoration(
              color: k.surface,
              border: Border.all(color: k.line),
              borderRadius: BorderRadius.circular(KSize.radius),
              boxShadow: const [BoxShadow(color: Color(0x40000000), blurRadius: 30, offset: Offset(0, 10))],
            ),
            child: Semantics(
              scopesRoute: true,
              namesRoute: true,
              explicitChildNodes: true,
              label: title,
              child: DefaultTextStyle(
                style: KText.body(k),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    if (title != null)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(22, 20, 22, 0),
                        child: Text(title!, style: KText.heading(k).copyWith(fontSize: 17)),
                      ),
                    Flexible(
                      child: scrollable
                          ? SingleChildScrollView(padding: padding, child: content)
                          : Padding(padding: padding, child: content),
                    ),
                    if (actions.isNotEmpty)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
                        child: Wrap(alignment: WrapAlignment.end, spacing: 8, runSpacing: 8, children: actions),
                      ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Asks for a line of text – a name – and returns it, or `null` when cancelled or left empty.
Future<String?> askText(
  BuildContext context, {
  required String title,
  required String confirm,
  String initial = '',
  String? label,
}) async {
  final result = await showKDialog<String>(
    context,
    builder: (_) => _AskText(title: title, confirm: confirm, initial: initial, label: label),
  );
  return result == null || result.isEmpty ? null : result;
}

/// The dialog of [askText]: it owns its field, which lives as long as the dialog – also while it fades out.
class _AskText extends StatefulWidget {
  const _AskText({required this.title, required this.confirm, required this.initial, this.label});

  final String title;
  final String confirm;
  final String initial;
  final String? label;

  @override
  State<_AskText> createState() => _AskTextState();
}

class _AskTextState extends State<_AskText> {
  late final _controller = TextEditingController(text: widget.initial)
    ..selection = TextSelection(baseOffset: 0, extentOffset: widget.initial.length);

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _done() => Navigator.of(context).pop(_controller.text.trim());

  @override
  Widget build(BuildContext context) {
    return KDialog(
      title: widget.title,
      width: 400,
      content: KTextField(
        key: const ValueKey('ask-text'),
        controller: _controller,
        autofocus: true,
        label: widget.label,
        onSubmitted: (_) => _done(),
      ),
      actions: [
        KButton(
          label: AppLocalizations.of(context).cancel,
          tone: KTone.quiet,
          onPressed: () => Navigator.of(context).pop(),
        ),
        KButton(key: const ValueKey('ask-confirm'), label: widget.confirm, tone: KTone.primary, onPressed: _done),
      ],
    );
  }
}

/// Asks whether to go on – the confirming button in red when `danger` – and returns the answer.
Future<bool> confirmAction(
  BuildContext context, {
  required String text,
  required String confirm,
  bool danger = false,
}) async {
  final sure = await showKDialog<bool>(
    context,
    builder: (context) => KDialog(
      width: 400,
      scrollable: true,
      content: Text(text, style: KText.body(context.k)),
      actions: [
        KButton(
          label: AppLocalizations.of(context).cancel,
          tone: KTone.quiet,
          onPressed: () => Navigator.of(context).pop(false),
        ),
        KButton(
          key: const ValueKey('confirm-action'),
          label: confirm,
          tone: danger ? KTone.danger : KTone.primary,
          onPressed: () => Navigator.of(context).pop(true),
        ),
      ],
    ),
  );
  return sure ?? false;
}

/// A note to read, with one button to close it.
Future<void> showNote(BuildContext context, {required String text, required String close}) => showKDialog<void>(
  context,
  builder: (context) => KDialog(
    width: 400,
    scrollable: true,
    content: Text(text, style: KText.body(context.k)),
    actions: [
      KButton(
        key: const ValueKey('note-close'),
        label: close,
        tone: KTone.primary,
        onPressed: () => Navigator.of(context).pop(),
      ),
    ],
  ),
);
