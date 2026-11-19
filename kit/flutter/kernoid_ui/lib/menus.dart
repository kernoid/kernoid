// SPDX-License-Identifier: MIT
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'controls.dart';
import 'tokens.dart';
import 'widgets.dart';

/// The key of an open menu's panel, for tests.
const kMenuKey = ValueKey('k-menu');

/// An entry of a menu: what it stands for, its text, an icon before it, red when it destroys, a tick when it is the
/// current choice.
class KMenuItem<T> {
  const KMenuItem({
    required this.value,
    required this.label,
    this.icon,
    this.danger = false,
    this.enabled = true,
    this.checked,
    this.key,
    this.indent = 0,
    this.trailing,
  }) : header = false;

  /// A heading above a group of entries, not chosen itself.
  const KMenuItem.header(this.label, {this.key})
    : value = null,
      icon = null,
      danger = false,
      enabled = false,
      checked = null,
      indent = 0,
      trailing = null,
      header = true;

  final T? value;
  final String label;
  final IconData? icon;
  final bool danger;
  final bool enabled;

  /// A choice among several: ticked or not; `null` for an action.
  final bool? checked;

  /// The entry's key, for tests; `menu-<value>` without one.
  final Key? key;

  /// Space before it, for a tree of folders.
  final double indent;

  /// A short text at its end – a count.
  final String? trailing;
  final bool header;
}

/// Opens a menu next to `anchor` (a rectangle in global coordinates: below it when there is room, else above) and
/// returns the chosen entry's value, or `null` when it was closed.
Future<T?> showKMenu<T>(BuildContext context, {required Rect anchor, required List<KMenuItem<T>> items}) {
  return Navigator.of(context).push(
    _MenuRoute<T>(anchor: anchor, items: items, tokens: context.k, barrierLabel: AppLocalizations.of(context).close),
  );
}

/// A menu at a point – of a right click or a long press – with an icon before every entry.
Future<T?> showPointMenu<T>(
  BuildContext context, {
  required Offset position,
  required List<(T value, IconData icon, String label, bool danger)> items,
}) => showKMenu<T>(
  context,
  anchor: position & Size.zero,
  items: [
    for (final (value, icon, label, danger) in items) KMenuItem(value: value, label: label, icon: icon, danger: danger),
  ],
);

/// The rectangle of what `context` draws, in global coordinates.
Rect rectOf(BuildContext context) {
  final box = context.findRenderObject()! as RenderBox;
  return box.localToGlobal(Offset.zero) & box.size;
}

class _MenuRoute<T> extends PopupRoute<T> {
  _MenuRoute({required this.anchor, required this.items, required this.tokens, required this.barrierLabel});

  final Rect anchor;
  final List<KMenuItem<T>> items;
  final KTokens tokens;

  @override
  final String barrierLabel;

  @override
  Color? get barrierColor => null;

  @override
  bool get barrierDismissible => true;

  @override
  Duration get transitionDuration => const Duration(milliseconds: 120);

  @override
  Widget buildPage(BuildContext context, Animation<double> animation, Animation<double> secondaryAnimation) {
    final padding = MediaQuery.paddingOf(context) + const EdgeInsets.all(8);
    return KTheme(
      tokens: tokens,
      child: FadeTransition(
        opacity: CurvedAnimation(parent: animation, curve: Curves.easeOut),
        child: CustomSingleChildLayout(
          delegate: _MenuLayout(anchor, padding, Directionality.of(context)),
          child: _MenuPanel<T>(items: items),
        ),
      ),
    );
  }
}

class _MenuLayout extends SingleChildLayoutDelegate {
  _MenuLayout(this.anchor, this.padding, this.direction);

  final Rect anchor;
  final EdgeInsets padding;
  final TextDirection direction;

  @override
  BoxConstraints getConstraintsForChild(BoxConstraints constraints) => BoxConstraints.loose(
    Size(constraints.maxWidth - padding.horizontal, constraints.maxHeight - padding.vertical),
  ).copyWith(minWidth: anchor.width > 0 ? anchor.width.clamp(0, constraints.maxWidth - padding.horizontal) : 180);

  @override
  Offset getPositionForChild(Size size, Size child) {
    var x = direction == TextDirection.rtl ? anchor.right - child.width : anchor.left;
    x = x.clamp(padding.left, size.width - padding.right - child.width);
    var y = anchor.bottom + 4;
    if (y + child.height > size.height - padding.bottom) y = anchor.top - 4 - child.height;
    y = y.clamp(padding.top, size.height - padding.bottom - child.height);
    return Offset(x, y);
  }

  @override
  bool shouldRelayout(_MenuLayout old) => old.anchor != anchor || old.padding != padding;
}

class _MenuPanel<T> extends StatelessWidget {
  const _MenuPanel({required this.items});

  final List<KMenuItem<T>> items;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Container(
      key: kMenuKey,
      constraints: const BoxConstraints(maxWidth: 320),
      padding: const EdgeInsets.symmetric(vertical: 5),
      decoration: BoxDecoration(
        color: k.surface,
        border: Border.all(color: k.line),
        borderRadius: BorderRadius.circular(KSize.radius),
        boxShadow: const [BoxShadow(color: Color(0x40000000), blurRadius: 20, offset: Offset(0, 6))],
      ),
      child: IntrinsicWidth(
        child: SingleChildScrollView(
          child: FocusTraversalGroup(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final (i, item) in items.indexed)
                  _MenuItemView<T>(item: item, first: i == items.indexWhere((e) => !e.header && e.enabled)),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _MenuItemView<T> extends StatefulWidget {
  const _MenuItemView({required this.item, required this.first});

  final KMenuItem<T> item;
  final bool first;

  @override
  State<_MenuItemView<T>> createState() => _MenuItemViewState<T>();
}

class _MenuItemViewState<T> extends State<_MenuItemView<T>> {
  bool _hover = false;
  bool _focused = false;

  void _choose() {
    if (widget.item.enabled && !widget.item.header) Navigator.of(context).pop(widget.item.value);
  }

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final item = widget.item;
    if (item.header) {
      return Padding(
        padding: const EdgeInsets.fromLTRB(15, 8, 15, 4),
        child: Text(item.label.toUpperCase(), style: KText.overline(k)),
      );
    }
    final color = item.danger ? k.error : k.text;
    return FocusableActionDetector(
      autofocus: widget.first,
      enabled: item.enabled,
      mouseCursor: item.enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
      onShowHoverHighlight: (on) => setState(() => _hover = on),
      onShowFocusHighlight: (on) => setState(() => _focused = on),
      shortcuts: const {
        SingleActivator(LogicalKeyboardKey.enter): ActivateIntent(),
        SingleActivator(LogicalKeyboardKey.space): ActivateIntent(),
      },
      actions: {ActivateIntent: CallbackAction<ActivateIntent>(onInvoke: (_) => _choose())},
      child: Semantics(
        button: true,
        enabled: item.enabled,
        selected: item.checked,
        child: GestureDetector(
          key: item.key ?? ValueKey('menu-${item.value}'),
          behavior: HitTestBehavior.opaque,
          onTap: _choose,
          child: Opacity(
            opacity: item.enabled ? 1 : 0.45,
            child: Container(
              height: KSize.control,
              margin: const EdgeInsets.symmetric(horizontal: 5),
              padding: EdgeInsets.only(left: 10 + item.indent, right: 10),
              decoration: BoxDecoration(
                color: (_hover || _focused) && item.enabled ? k.hover : KColor.transparent,
                borderRadius: BorderRadius.circular(KSize.radiusSmall),
              ),
              child: Row(
                children: [
                  if (item.checked != null) ...[
                    SizedBox(
                      width: 16,
                      child: item.checked! ? Icon(LucideIcons.check, size: 15, color: k.accent) : null,
                    ),
                    const SizedBox(width: 10),
                  ],
                  if (item.icon != null) ...[
                    Icon(item.icon, size: 16, color: item.danger ? k.error : k.muted),
                    const SizedBox(width: 10),
                  ],
                  Flexible(
                    child: Text(
                      item.label,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: KText.label(k).copyWith(color: color),
                    ),
                  ),
                  if (item.trailing != null) ...[
                    const SizedBox(width: 16),
                    const Spacer(),
                    Text(
                      item.trailing!,
                      style: KText.small(k).copyWith(color: k.accent, fontWeight: FontWeight.w600),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// A button that opens a menu below itself – what Material's popup menu button was. By default an icon button with
/// three dots.
class KMenuButton<T> extends StatelessWidget {
  const KMenuButton({
    super.key,
    required this.items,
    required this.onSelected,
    required this.tooltip,
    this.icon = LucideIcons.ellipsisVertical,
    this.child,
    this.enabled = true,
  });

  /// Built when the menu opens, so that it shows the current state.
  final List<KMenuItem<T>> Function() items;
  final ValueChanged<T> onSelected;
  final String tooltip;
  final IconData icon;

  /// What to show instead of the icon button – it opens the menu when tapped.
  final Widget? child;
  final bool enabled;

  Future<void> _open(BuildContext context) async {
    final chosen = await showKMenu<T>(context, anchor: rectOf(context), items: items());
    if (chosen != null) onSelected(chosen);
  }

  @override
  Widget build(BuildContext context) => Builder(
    builder: (context) => child == null
        ? KIconButton(icon: icon, tooltip: tooltip, onPressed: enabled ? () => _open(context) : null)
        : KTooltip(
            message: tooltip,
            child: MouseRegion(
              cursor: SystemMouseCursors.click,
              child: GestureDetector(
                behavior: HitTestBehavior.opaque,
                onTap: enabled ? () => _open(context) : null,
                child: child,
              ),
            ),
          ),
  );
}

/// A choice of one from a list, shown as a box with the current choice – what Material's dropdown was; a label above
/// it like a text field's.
class KSelect<T> extends StatefulWidget {
  const KSelect({
    super.key,
    required this.value,
    required this.options,
    required this.onChanged,
    this.label,
    this.hint,
    this.expand = true,
  });

  final T? value;
  final List<(T value, String label)> options;
  final ValueChanged<T>? onChanged;
  final String? label;
  final String? hint;

  /// As wide as its parent; else as wide as its choice.
  final bool expand;

  @override
  State<KSelect<T>> createState() => _KSelectState<T>();
}

class _KSelectState<T> extends State<KSelect<T>> {
  bool _hover = false;
  bool _open = false;

  Future<void> _choose(BuildContext context) async {
    setState(() => _open = true);
    final chosen = await showKMenu<T>(
      context,
      anchor: rectOf(context),
      items: [
        for (final (value, label) in widget.options)
          KMenuItem(value: value, label: label, checked: value == widget.value, key: ValueKey('option-$value')),
      ],
    );
    if (mounted) setState(() => _open = false);
    if (chosen != null && chosen != widget.value) widget.onChanged?.call(chosen);
  }

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final enabled = widget.onChanged != null;
    final current = widget.options.where((o) => o.$1 == widget.value).map((o) => o.$2).firstOrNull;
    final box = Builder(
      builder: (context) => MouseRegion(
        cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
        onEnter: (_) => setState(() => _hover = true),
        onExit: (_) => setState(() => _hover = false),
        child: GestureDetector(
          onTap: enabled ? () => _choose(context) : null,
          child: Container(
            height: KSize.control + 2,
            padding: const EdgeInsets.only(left: 12, right: 8),
            decoration: BoxDecoration(
              color: k.surface,
              borderRadius: BorderRadius.circular(KSize.radiusSmall),
              border: Border.all(
                color: _open
                    ? k.accent
                    : _hover
                    ? k.faint
                    : k.lineStrong,
                width: _open ? 1.5 : 1,
              ),
            ),
            child: Row(
              mainAxisSize: widget.expand ? MainAxisSize.max : MainAxisSize.min,
              children: [
                Flexible(
                  fit: widget.expand ? FlexFit.tight : FlexFit.loose,
                  child: Text(
                    current ?? widget.hint ?? '',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: KText.body(k).copyWith(color: current == null ? k.faint : k.text),
                  ),
                ),
                const SizedBox(width: 6),
                Icon(LucideIcons.chevronDown, size: 16, color: k.muted),
              ],
            ),
          ),
        ),
      ),
    );
    return Semantics(
      button: true,
      label: widget.label,
      value: current,
      enabled: enabled,
      child: Opacity(
        opacity: enabled ? 1 : 0.55,
        child: Column(
          // Stretched only when it takes its parent's width: in a row the width has no bound.
          crossAxisAlignment: widget.expand ? CrossAxisAlignment.stretch : CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            if (widget.label != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Text(widget.label!, style: KText.small(k).copyWith(fontWeight: FontWeight.w500)),
              ),
            box,
          ],
        ),
      ),
    );
  }
}

/// The spinner a button shows while its work runs, in the button's colour.
class KBusy extends StatelessWidget {
  const KBusy({super.key, this.size = 16});

  final double size;

  @override
  Widget build(BuildContext context) => KSpinner(size: size, stroke: 2);
}
