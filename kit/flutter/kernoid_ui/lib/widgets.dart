// SPDX-License-Identifier: MIT
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'controls.dart';
import 'fields.dart';
import 'tokens.dart';

/// What a button is for: the one thing to do (primary), anything else, a quiet one in toolbars, one that destroys.
enum KTone { primary, normal, quiet, danger }

/// A button as the web app draws it: a label with an icon before it, hover and press without ripples.
class KButton extends StatefulWidget {
  const KButton({
    super.key,
    required this.label,
    this.icon,
    required this.onPressed,
    this.tone = KTone.normal,
    this.expand = false,
    this.busy = false,
  });

  final String label;
  final IconData? icon;
  final VoidCallback? onPressed;
  final KTone tone;

  /// Its work runs: a spinner instead of the icon, and it does not react.
  final bool busy;

  /// As wide as its parent.
  final bool expand;

  @override
  State<KButton> createState() => _KButtonState();
}

class _KButtonState extends State<KButton> {
  bool _hover = false;
  bool _down = false;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final enabled = widget.onPressed != null && !widget.busy;
    final (background, foreground, border) = switch (widget.tone) {
      KTone.primary => (k.accent, k.accentText, k.accent),
      KTone.normal => (_hover ? k.hover : k.raised, k.text, _hover ? k.lineStrong : k.line),
      KTone.quiet => (_hover ? k.hover : KColor.transparent, k.text, KColor.transparent),
      KTone.danger => (_hover ? k.errorSoft : k.raised, k.error, k.line),
    };
    final content = Row(
      mainAxisSize: widget.expand ? MainAxisSize.max : MainAxisSize.min,
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        if (widget.busy) ...[
          KSpinner(size: 15, stroke: 2, color: foreground),
          const SizedBox(width: 8),
        ] else if (widget.icon != null) ...[
          Icon(widget.icon, size: 16, color: foreground),
          const SizedBox(width: 7),
        ],
        Flexible(
          child: Text(
            widget.label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: KText.label(
              k,
            ).copyWith(color: foreground, fontWeight: widget.tone == KTone.primary ? FontWeight.w600 : FontWeight.w500),
          ),
        ),
      ],
    );
    return Semantics(
      button: true,
      enabled: enabled,
      child: MouseRegion(
        cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
        onEnter: (_) => setState(() => _hover = true),
        onExit: (_) => setState(() => _hover = false),
        child: GestureDetector(
          onTapDown: enabled ? (_) => setState(() => _down = true) : null,
          onTapUp: enabled ? (_) => setState(() => _down = false) : null,
          onTapCancel: () => setState(() => _down = false),
          onTap: enabled ? widget.onPressed : null,
          child: Focus(
            child: Opacity(
              opacity: enabled || widget.busy ? 1 : 0.5,
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 120),
                transform: Matrix4.translationValues(0, _down ? 0.5 : 0, 0),
                constraints: const BoxConstraints(minHeight: KSize.control),
                padding: const EdgeInsets.symmetric(horizontal: 14),
                alignment: widget.expand ? Alignment.center : null,
                decoration: BoxDecoration(
                  color: widget.tone == KTone.primary && _hover
                      ? Color.lerp(background, KColor.white, 0.08)
                      : background,
                  borderRadius: BorderRadius.circular(KSize.radiusSmall),
                  border: Border.all(color: border),
                ),
                child: content,
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// A button that is only an icon: square, its name in the tooltip – active ones in the accent's soft colour.
class KIconButton extends StatefulWidget {
  const KIconButton({
    super.key,
    required this.icon,
    required this.tooltip,
    required this.onPressed,
    this.active = false,
    this.color,
    this.size = KSize.control,
  });

  final IconData icon;
  final String tooltip;
  final VoidCallback? onPressed;
  final bool active;
  final Color? color;
  final double size;

  @override
  State<KIconButton> createState() => _KIconButtonState();
}

class _KIconButtonState extends State<KIconButton> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final enabled = widget.onPressed != null;
    return KTooltip(
      message: widget.tooltip,
      child: Semantics(
        button: true,
        label: widget.tooltip,
        child: MouseRegion(
          cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
          onEnter: (_) => setState(() => _hover = true),
          onExit: (_) => setState(() => _hover = false),
          child: GestureDetector(
            onTap: widget.onPressed,
            child: Opacity(
              opacity: enabled ? 1 : 0.4,
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 120),
                width: widget.size,
                height: widget.size,
                decoration: BoxDecoration(
                  color: widget.active
                      ? k.accentSoft
                      : _hover && enabled
                      ? k.hover
                      : KColor.transparent,
                  borderRadius: BorderRadius.circular(KSize.radiusSmall),
                ),
                child: Icon(
                  widget.icon,
                  size: KSize.icon,
                  color: widget.color ?? (widget.active ? k.accent : (_hover ? k.text : k.muted)),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// The bar on top of a page: a way back, the title, its actions – the web app's bar, not Material's app bar.
class KTopBar extends StatelessWidget implements PreferredSizeWidget {
  const KTopBar({super.key, this.title, this.titleWidget, this.actions = const [], this.leading, this.back});

  final String? title;
  final Widget? titleWidget;
  final List<Widget> actions;
  final Widget? leading;

  /// Shows a way back; `null` uses the navigator's when there is a page to go back to.
  final VoidCallback? back;

  @override
  Size get preferredSize => const Size.fromHeight(KSize.bar);

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final route = ModalRoute.of(context);
    final canPop = back != null || (route?.canPop ?? false);
    final closes = route is PageRoute && route.fullscreenDialog;
    final t = AppLocalizations.of(context);
    return Container(
      height: KSize.bar,
      padding: const EdgeInsets.symmetric(horizontal: 10),
      decoration: BoxDecoration(
        color: k.panel,
        border: Border(bottom: BorderSide(color: k.line)),
      ),
      child: SafeArea(
        bottom: false,
        child: Row(
          children: [
            if (leading != null)
              leading!
            else if (canPop)
              KIconButton(
                key: const ValueKey('back'),
                icon: closes ? LucideIcons.x : LucideIcons.arrowLeft,
                tooltip: closes ? t.close : t.back,
                onPressed: back ?? () => Navigator.of(context).maybePop(),
              ),
            SizedBox(width: canPop || leading != null ? 6 : 6),
            Expanded(
              child:
                  titleWidget ??
                  Text(
                    title ?? '',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: KText.heading(k).copyWith(fontSize: 17),
                  ),
            ),
            ...actions.expand((a) => [const SizedBox(width: 4), a]),
          ],
        ),
      ),
    );
  }
}

/// A row of a list – a mailbox, an email, a contact: something before, a title, a line under it, something after.
/// Chosen rows are tinted with the accent; rows react to hover.
class KListRow extends StatefulWidget {
  const KListRow({
    super.key,
    this.leading,
    required this.title,
    this.subtitle,
    this.trailing,
    this.selected = false,
    this.onTap,
    this.divider = false,
    this.dense = false,
    this.indent = 0,
  });

  final Widget? leading;
  final Widget title;
  final Widget? subtitle;
  final Widget? trailing;
  final bool selected;
  final VoidCallback? onTap;

  /// A line under the row, as between emails.
  final bool divider;
  final bool dense;

  /// Space before the row, for nested folders.
  final double indent;

  @override
  State<KListRow> createState() => _KListRowState();
}

class _KListRowState extends State<KListRow> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final y = widget.dense ? 7.0 : KSize.rowY;
    return MouseRegion(
      cursor: widget.onTap != null ? SystemMouseCursors.click : SystemMouseCursors.basic,
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTap: widget.onTap,
        child: Container(
          padding: EdgeInsets.fromLTRB(KSize.space + 4 + widget.indent, y, KSize.space + 4, y),
          decoration: BoxDecoration(
            color: widget.selected
                ? k.accentSoft
                : _hover && widget.onTap != null
                ? k.hover
                : KColor.transparent,
            border: widget.divider ? Border(bottom: BorderSide(color: k.line)) : null,
          ),
          child: Row(
            children: [
              if (widget.leading != null) ...[widget.leading!, const SizedBox(width: 12)],
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    DefaultTextStyle(
                      style: KText.body(k).copyWith(fontWeight: FontWeight.w500),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      child: widget.title,
                    ),
                    if (widget.subtitle != null)
                      DefaultTextStyle(
                        style: KText.small(k),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        child: widget.subtitle!,
                      ),
                  ],
                ),
              ),
              if (widget.trailing != null) ...[const SizedBox(width: 10), widget.trailing!],
            ],
          ),
        ),
      ),
    );
  }
}

/// An entry of a side list – a mailbox, a store: an icon, a name, a count; the chosen one tinted.
class KSideItem extends StatefulWidget {
  const KSideItem({
    super.key,
    required this.icon,
    required this.label,
    this.count,
    this.selected = false,
    required this.onTap,
    this.indent = 0,
    this.onMenu,
  });

  final IconData icon;
  final String label;
  final int? count;
  final bool selected;
  final VoidCallback onTap;
  final double indent;

  /// A menu of what can be done with the item, opened with a right click or a long press – at that point.
  final void Function(Offset position)? onMenu;

  @override
  State<KSideItem> createState() => _KSideItemState();
}

class _KSideItemState extends State<KSideItem> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return MouseRegion(
      cursor: SystemMouseCursors.click,
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTap: widget.onTap,
        // Opened once the gesture is over: a menu opened while it lasts leaves its recognizer waiting for the next.
        onSecondaryTapUp: widget.onMenu == null ? null : (d) => widget.onMenu!(d.globalPosition),
        onLongPressEnd: widget.onMenu == null ? null : (d) => widget.onMenu!(d.globalPosition),
        child: Container(
          height: KSize.control,
          margin: const EdgeInsets.symmetric(vertical: 1),
          padding: EdgeInsets.only(left: 10 + widget.indent, right: 10),
          decoration: BoxDecoration(
            color: widget.selected
                ? k.accentSoft
                : _hover
                ? k.hover
                : KColor.transparent,
            borderRadius: BorderRadius.circular(KSize.radiusSmall),
          ),
          child: Row(
            children: [
              Icon(widget.icon, size: 17, color: widget.selected ? k.accent : k.muted),
              const SizedBox(width: 10),
              Expanded(
                child: Text(widget.label, maxLines: 1, overflow: TextOverflow.ellipsis, style: KText.label(k)),
              ),
              if ((widget.count ?? 0) > 0)
                Text(
                  '${widget.count}',
                  style: KText.small(k).copyWith(
                    color: k.accent,
                    fontWeight: FontWeight.w600,
                    fontFeatures: const [FontFeature.tabularFigures()],
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

/// A small label: `preview`, `encrypted`, a count.
class KBadge extends StatelessWidget {
  const KBadge(this.text, {super.key, this.icon, this.color});

  final String text;
  final IconData? icon;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final c = color ?? k.accent;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
      decoration: BoxDecoration(color: c.withValues(alpha: 0.12), borderRadius: BorderRadius.circular(5)),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[Icon(icon, size: 12, color: c), const SizedBox(width: 4)],
          Text(
            text,
            style: KText.small(k).copyWith(color: c, fontSize: 12, fontWeight: FontWeight.w500),
          ),
        ],
      ),
    );
  }
}

/// Initials in a colour of the person's own, as in the web app (ui/Avatar.svelte).
class KAvatar extends StatelessWidget {
  const KAvatar({super.key, required this.name, this.size = 32, this.image});

  final String name;
  final double size;

  /// The person's picture; without one, their initials.
  final Uint8List? image;

  static int hue(String name) {
    var h = 0;
    for (final unit in name.toLowerCase().codeUnits) {
      h = (h * 31 + unit) & 0x7fffffff;
    }
    return h % 360;
  }

  static String initials(String name) {
    final words = name.trim().split(RegExp(r'[\s@._-]+')).where((w) => w.isNotEmpty).toList();
    if (words.isEmpty) return '?';
    final first = words.first.characters.first;
    return (words.length > 1 ? '$first${words.last.characters.first}' : first).toUpperCase();
  }

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final h = hue(name).toDouble();
    final background = k.dark
        ? HSLColor.fromAHSL(1, h, 0.42, 0.36).toColor()
        : HSLColor.fromAHSL(1, h, 0.70, 0.88).toColor();
    final foreground = k.dark
        ? HSLColor.fromAHSL(1, h, 0.70, 0.92).toColor()
        : HSLColor.fromAHSL(1, h, 0.55, 0.26).toColor();
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: background,
        shape: BoxShape.circle,
        image: image == null ? null : DecorationImage(image: MemoryImage(image!), fit: BoxFit.cover),
      ),
      child: image != null
          ? null
          : Text(
              initials(name),
              style: TextStyle(
                fontFamily: KFont.sans,
                fontSize: size * 0.38,
                fontWeight: FontWeight.w600,
                letterSpacing: 0.3,
                color: foreground,
                height: 1,
              ),
            ),
    );
  }
}

/// A choice of a few: one box, the chosen part filled.
class KSegmented<T> extends StatelessWidget {
  const KSegmented({super.key, required this.options, required this.value, required this.onChanged});

  final List<(T, String)> options;
  final T value;
  final ValueChanged<T> onChanged;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Container(
      decoration: BoxDecoration(
        color: k.surface,
        border: Border.all(color: k.line),
        borderRadius: BorderRadius.circular(KSize.radiusSmall),
      ),
      clipBehavior: Clip.antiAlias,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          for (final (i, (option, label)) in options.indexed)
            GestureDetector(
              key: ValueKey('segment-$option'),
              onTap: () => onChanged(option),
              child: MouseRegion(
                cursor: SystemMouseCursors.click,
                child: Container(
                  height: KSize.control - 4,
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: option == value ? k.accent : KColor.transparent,
                    border: i == 0 ? null : Border(left: BorderSide(color: k.line)),
                  ),
                  child: Text(
                    label,
                    style: KText.label(k).copyWith(color: option == value ? k.accentText : k.text, fontSize: 13),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

/// A part of a settings page: a heading, what it is about, its content – in a bordered card.
class KSection extends StatelessWidget {
  const KSection({super.key, required this.title, this.icon, this.description, required this.child, this.trailing});

  final String title;
  final IconData? icon;
  final String? description;
  final Widget child;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: k.surface,
        border: Border.all(color: k.line),
        borderRadius: BorderRadius.circular(KSize.radius),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              if (icon != null) ...[Icon(icon, size: 18, color: k.accent), const SizedBox(width: 10)],
              Expanded(child: Text(title, style: KText.heading(k))),
              ?trailing,
            ],
          ),
          if (description != null) ...[const SizedBox(height: 4), Text(description!, style: KText.small(k))],
          const SizedBox(height: 14),
          child,
        ],
      ),
    );
  }
}

/// kernoid's word mark in text, as the web app's bar has it: `kern` and `0` in the text's colour, `id` in mint.
class KWordmark extends StatelessWidget {
  const KWordmark({super.key, this.size = 18});

  final double size;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final style = TextStyle(fontFamily: KFont.mono, fontWeight: FontWeight.w700, fontSize: size, color: k.text);
    return Text.rich(
      TextSpan(
        style: style,
        children: [
          const TextSpan(text: 'kern'),
          TextSpan(
            text: '0',
            style: TextStyle(color: k.violet),
          ),
          TextSpan(
            text: 'id',
            style: TextStyle(color: k.accent),
          ),
        ],
      ),
    );
  }
}

/// A heading above a group in a list: small capitals in mono.
class KOverline extends StatelessWidget {
  const KOverline(this.text, {super.key, this.padding = const EdgeInsets.fromLTRB(10, 14, 10, 6)});

  final String text;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) => Padding(
    padding: padding,
    child: Text(text.toUpperCase(), style: KText.overline(context.k)),
  );
}

/// A search bar over a list: the field on a raised ground, a button to clear it; an empty field searches nothing.
class KSearchField extends StatefulWidget {
  const KSearchField({
    super.key,
    required this.controller,
    required this.onSubmitted,
    required this.hint,
    this.fieldKey,
  });

  final TextEditingController controller;
  final ValueChanged<String> onSubmitted;
  final String hint;

  /// The key of the text field itself, for tests.
  final Key? fieldKey;

  @override
  State<KSearchField> createState() => _KSearchFieldState();
}

class _KSearchFieldState extends State<KSearchField> {
  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Container(
      height: KSize.bar,
      padding: const EdgeInsets.symmetric(horizontal: 12),
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: k.surface,
        border: Border(bottom: BorderSide(color: k.line)),
      ),
      child: KTextField(
        key: widget.fieldKey,
        controller: widget.controller,
        textInputAction: TextInputAction.search,
        onSubmitted: widget.onSubmitted,
        onChanged: (text) {
          setState(() {});
          if (text.isEmpty) widget.onSubmitted('');
        },
        style: KText.body(k).copyWith(fontSize: 14),
        hint: widget.hint,
        fill: k.raised,
        borderless: true,
        icon: LucideIcons.search,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        suffix: widget.controller.text.isEmpty
            ? null
            : KIconButton(
                icon: LucideIcons.x,
                tooltip: AppLocalizations.of(context).clear,
                size: 28,
                onPressed: () {
                  widget.controller.clear();
                  widget.onSubmitted('');
                  setState(() {});
                },
              ),
      ),
    );
  }
}
