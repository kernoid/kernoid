// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'tokens.dart';

/// On or off: a track that fills with the accent, a round thumb.
class KSwitch extends StatelessWidget {
  const KSwitch({super.key, required this.value, required this.onChanged});

  final bool value;
  final ValueChanged<bool>? onChanged;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final enabled = onChanged != null;
    return Semantics(
      toggled: value,
      enabled: enabled,
      child: MouseRegion(
        cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
        child: GestureDetector(
          onTap: enabled ? () => onChanged!(!value) : null,
          child: Opacity(
            opacity: enabled ? 1 : 0.5,
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              width: 38,
              height: 22,
              padding: const EdgeInsets.all(2),
              decoration: BoxDecoration(
                color: value ? k.accent : k.raised,
                borderRadius: BorderRadius.circular(11),
                border: Border.all(color: value ? k.accent : k.lineStrong),
              ),
              child: AnimatedAlign(
                duration: const Duration(milliseconds: 150),
                curve: Curves.easeOut,
                alignment: value ? Alignment.centerRight : Alignment.centerLeft,
                child: Container(
                  width: 16,
                  height: 16,
                  decoration: BoxDecoration(color: value ? k.accentText : k.muted, shape: BoxShape.circle),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// A box to tick.
class KCheckbox extends StatelessWidget {
  const KCheckbox({super.key, required this.value, required this.onChanged});

  final bool value;
  final ValueChanged<bool>? onChanged;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final enabled = onChanged != null;
    return Semantics(
      checked: value,
      enabled: enabled,
      child: MouseRegion(
        cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
        child: GestureDetector(
          onTap: enabled ? () => onChanged!(!value) : null,
          child: Opacity(
            opacity: enabled ? 1 : 0.5,
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 120),
              width: 18,
              height: 18,
              decoration: BoxDecoration(
                color: value ? k.accent : k.surface,
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: value ? k.accent : k.lineStrong, width: 1.5),
              ),
              child: value ? Icon(LucideIcons.check, size: 13, color: k.accentText) : null,
            ),
          ),
        ),
      ),
    );
  }
}

/// A row with a title, an explanation under it and a switch or a box to tick at its end – the whole row toggles.
class KToggleRow extends StatelessWidget {
  const KToggleRow({
    super.key,
    required this.title,
    this.subtitle,
    required this.value,
    required this.onChanged,
    this.checkbox = false,
    this.leading,
  });

  final Widget title;
  final Widget? subtitle;
  final bool value;
  final ValueChanged<bool>? onChanged;

  /// A box to tick before the title instead of a switch after it.
  final bool checkbox;
  final Widget? leading;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final control = checkbox
        ? KCheckbox(value: value, onChanged: onChanged)
        : KSwitch(value: value, onChanged: onChanged);
    return MergeSemantics(
      child: MouseRegion(
        cursor: onChanged != null ? SystemMouseCursors.click : SystemMouseCursors.basic,
        child: GestureDetector(
          behavior: HitTestBehavior.opaque,
          onTap: onChanged == null ? null : () => onChanged!(!value),
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Row(
              children: [
                if (checkbox) ...[control, const SizedBox(width: 12)],
                if (leading != null) ...[leading!, const SizedBox(width: 12)],
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      DefaultTextStyle.merge(
                        style: KText.body(k).copyWith(fontWeight: FontWeight.w500),
                        child: title,
                      ),
                      if (subtitle != null) DefaultTextStyle.merge(style: KText.small(k), child: subtitle!),
                    ],
                  ),
                ),
                if (!checkbox) ...[const SizedBox(width: 12), control],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// A small rounded label: an address in a list of recipients (with a cross to remove it), or a choice among several
/// (filled when chosen).
class KChip extends StatefulWidget {
  const KChip({super.key, required this.label, this.icon, this.onDeleted, this.selected, this.onTap, this.tooltip});

  final String label;
  final IconData? icon;
  final VoidCallback? onDeleted;

  /// A choice: chosen or not; `null` for a chip that is no choice.
  final bool? selected;
  final VoidCallback? onTap;
  final String? tooltip;

  @override
  State<KChip> createState() => _KChipState();
}

class _KChipState extends State<KChip> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final chosen = widget.selected ?? false;
    final chip = MouseRegion(
      cursor: widget.onTap != null ? SystemMouseCursors.click : SystemMouseCursors.basic,
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: GestureDetector(
        onTap: widget.onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 120),
          height: 30,
          padding: EdgeInsets.only(left: 10, right: widget.onDeleted != null ? 4 : 10),
          decoration: BoxDecoration(
            color: chosen
                ? k.accentSoft
                : _hover && widget.onTap != null
                ? k.hover
                : k.raised,
            borderRadius: BorderRadius.circular(KSize.radiusSmall),
            border: Border.all(color: chosen ? k.accent : k.line),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (chosen) ...[Icon(LucideIcons.check, size: 13, color: k.accent), const SizedBox(width: 5)],
              if (widget.icon != null && !chosen) ...[
                Icon(widget.icon, size: 13, color: k.muted),
                const SizedBox(width: 5),
              ],
              Flexible(
                child: Text(
                  widget.label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: KText.label(k).copyWith(fontSize: 13),
                ),
              ),
              if (widget.onDeleted != null) ...[
                const SizedBox(width: 2),
                Semantics(
                  button: true,
                  label: widget.tooltip,
                  child: GestureDetector(
                    onTap: widget.onDeleted,
                    child: MouseRegion(
                      cursor: SystemMouseCursors.click,
                      child: Padding(
                        padding: const EdgeInsets.all(4),
                        child: Icon(LucideIcons.x, size: 13, color: k.muted),
                      ),
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
    return Semantics(button: widget.onTap != null, selected: widget.selected, child: chip);
  }
}

/// Something is being done: a turning arc in the accent.
class KSpinner extends StatefulWidget {
  const KSpinner({super.key, this.size = 22, this.stroke = 2.5, this.color});

  final double size;
  final double stroke;
  final Color? color;

  @override
  State<KSpinner> createState() => _KSpinnerState();
}

class _KSpinnerState extends State<KSpinner> with SingleTickerProviderStateMixin {
  late final _turns = AnimationController(vsync: this, duration: const Duration(milliseconds: 900))..repeat();

  @override
  void dispose() {
    _turns.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final color = widget.color ?? context.k.accent;
    return Semantics(
      label: '…',
      // Its own size wherever it is put – a list stretches what it holds.
      child: Center(
        widthFactor: 1,
        heightFactor: 1,
        child: SizedBox.square(
          dimension: widget.size,
          child: AnimatedBuilder(
            animation: _turns,
            builder: (context, _) =>
                CustomPaint(painter: _ArcPainter(color, color.withValues(alpha: 0.2), widget.stroke, _turns.value)),
          ),
        ),
      ),
    );
  }
}

class _ArcPainter extends CustomPainter {
  _ArcPainter(this.color, this.track, this.stroke, this.turn);

  final Color color;
  final Color track;
  final double stroke;
  final double turn;

  @override
  void paint(Canvas canvas, Size size) {
    final rect = (Offset.zero & size).deflate(stroke / 2);
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = stroke
      ..strokeCap = StrokeCap.round;
    canvas.drawArc(rect, 0, math.pi * 2, false, paint..color = track);
    canvas.drawArc(rect, turn * math.pi * 2, math.pi * 0.6, false, paint..color = color);
  }

  @override
  bool shouldRepaint(_ArcPainter old) => old.turn != turn || old.color != color;
}

/// A spinner in the middle of what is still loading.
class KLoading extends StatelessWidget {
  const KLoading({super.key});

  @override
  Widget build(BuildContext context) => const Center(child: KSpinner());
}

/// How far something is: a thin bar that fills with the accent; without a value, a part runs along it.
class KProgressBar extends StatefulWidget {
  const KProgressBar({super.key, this.value, this.height = 3});

  /// From 0 to 1; `null` while it is not known.
  final double? value;
  final double height;

  @override
  State<KProgressBar> createState() => _KProgressBarState();
}

class _KProgressBarState extends State<KProgressBar> with SingleTickerProviderStateMixin {
  late final _run = AnimationController(vsync: this, duration: const Duration(milliseconds: 1300));

  @override
  void initState() {
    super.initState();
    if (widget.value == null) _run.repeat();
  }

  @override
  void didUpdateWidget(KProgressBar old) {
    super.didUpdateWidget(old);
    if (widget.value == null && !_run.isAnimating) _run.repeat();
    if (widget.value != null && _run.isAnimating) _run.stop();
  }

  @override
  void dispose() {
    _run.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final value = widget.value;
    return Semantics(
      value: value == null ? null : '${(value * 100).round()} %',
      child: ClipRRect(
        borderRadius: BorderRadius.circular(widget.height),
        child: SizedBox(
          height: widget.height,
          child: ColoredBox(
            color: k.line,
            child: value != null
                ? FractionallySizedBox(
                    alignment: AlignmentDirectional.centerStart,
                    widthFactor: value.clamp(0, 1),
                    child: ColoredBox(color: k.accent),
                  )
                : AnimatedBuilder(
                    animation: _run,
                    builder: (context, _) => FractionallySizedBox(
                      alignment: Alignment(-1.6 + _run.value * 3.2, 0),
                      widthFactor: 0.35,
                      child: ColoredBox(color: k.accent),
                    ),
                  ),
          ),
        ),
      ),
    );
  }
}

/// A line between parts.
class KDivider extends StatelessWidget {
  const KDivider({super.key, this.vertical = false, this.indent = 0});

  final bool vertical;
  final double indent;

  @override
  Widget build(BuildContext context) => vertical
      ? Container(
          width: 1,
          margin: EdgeInsets.symmetric(vertical: indent),
          color: context.k.line,
        )
      : Container(
          height: 1,
          margin: EdgeInsets.symmetric(horizontal: indent),
          color: context.k.line,
        );
}

/// A bordered card on the surface.
class KCard extends StatelessWidget {
  const KCard({super.key, required this.child, this.padding = const EdgeInsets.all(16), this.margin});

  final Widget child;
  final EdgeInsets padding;
  final EdgeInsets? margin;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Container(
      margin: margin,
      padding: padding,
      decoration: BoxDecoration(
        color: k.surface,
        border: Border.all(color: k.line),
        borderRadius: BorderRadius.circular(KSize.radius),
      ),
      child: child,
    );
  }
}

/// The one thing to do on a page, floating at its bottom end: an icon, a label on wide screens.
class KFloatingButton extends StatefulWidget {
  const KFloatingButton({super.key, required this.icon, required this.tooltip, required this.onPressed, this.label});

  final IconData icon;
  final String tooltip;
  final VoidCallback? onPressed;
  final String? label;

  @override
  State<KFloatingButton> createState() => _KFloatingButtonState();
}

class _KFloatingButtonState extends State<KFloatingButton> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return KTooltip(
      message: widget.tooltip,
      child: Semantics(
        button: true,
        label: widget.tooltip,
        child: MouseRegion(
          cursor: SystemMouseCursors.click,
          onEnter: (_) => setState(() => _hover = true),
          onExit: (_) => setState(() => _hover = false),
          child: GestureDetector(
            onTap: widget.onPressed,
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 120),
              height: 52,
              constraints: const BoxConstraints(minWidth: 52),
              padding: EdgeInsets.symmetric(horizontal: widget.label == null ? 0 : 18),
              decoration: BoxDecoration(
                color: _hover ? Color.lerp(k.accent, KColor.white, 0.08) : k.accent,
                borderRadius: BorderRadius.circular(KSize.radius),
                boxShadow: const [BoxShadow(color: Color(0x33000000), blurRadius: 10, offset: Offset(0, 3))],
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(widget.icon, size: 20, color: k.accentText),
                  if (widget.label != null) ...[
                    const SizedBox(width: 8),
                    Text(
                      widget.label!,
                      style: KText.label(k).copyWith(color: k.accentText, fontWeight: FontWeight.w600),
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

/// A short name shown when the pointer rests on something (or after a long press on touch screens) – what
/// Material's tooltip was.
class KTooltip extends StatefulWidget {
  const KTooltip({super.key, required this.message, required this.child});

  final String message;
  final Widget child;

  @override
  State<KTooltip> createState() => _KTooltipState();
}

class _KTooltipState extends State<KTooltip> {
  final _portal = OverlayPortalController();
  final _link = LayerLink();
  Timer? _wait;
  Timer? _hide;

  void _show() {
    _wait?.cancel();
    _hide?.cancel();
    _wait = Timer(const Duration(milliseconds: 450), () {
      if (mounted && !_portal.isShowing) _portal.show();
    });
  }

  void _away() {
    _wait?.cancel();
    if (_portal.isShowing) _portal.hide();
  }

  void _pressed() {
    _portal.show();
    _hide?.cancel();
    _hide = Timer(const Duration(milliseconds: 1500), _away);
  }

  @override
  void dispose() {
    _wait?.cancel();
    _hide?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (widget.message.isEmpty) return widget.child;
    final k = context.k;
    final touch = switch (defaultTargetPlatform) {
      TargetPlatform.android || TargetPlatform.iOS || TargetPlatform.fuchsia => true,
      _ => false,
    };
    return CompositedTransformTarget(
      link: _link,
      child: OverlayPortal(
        controller: _portal,
        overlayChildBuilder: (context) => Positioned(
          left: 0,
          top: 0,
          child: CompositedTransformFollower(
            link: _link,
            targetAnchor: Alignment.bottomCenter,
            followerAnchor: Alignment.topCenter,
            offset: const Offset(0, 6),
            child: IgnorePointer(
              child: Container(
                constraints: const BoxConstraints(maxWidth: 280),
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
                decoration: BoxDecoration(color: k.text, borderRadius: BorderRadius.circular(6)),
                child: Text(
                  widget.message,
                  style: KText.small(k).copyWith(color: k.bg, fontWeight: FontWeight.w500, fontSize: 12),
                ),
              ),
            ),
          ),
        ),
        child: MouseRegion(
          onEnter: (_) => _show(),
          onExit: (_) => _away(),
          child: GestureDetector(
            behavior: HitTestBehavior.translucent,
            onLongPress: touch ? _pressed : null,
            onTapDown: (_) => _away(),
            child: widget.child,
          ),
        ),
      ),
    );
  }
}

/// Pulling a list down past its top refreshes it – what Material's refresh indicator was: a spinner shows at the top
/// while `onRefresh` runs. The list scrolls with a bounce, so that it can be pulled.
class KRefresh extends StatefulWidget {
  const KRefresh({super.key, required this.onRefresh, required this.child});

  final Future<void> Function() onRefresh;

  /// A scroll view; its physics are replaced by ones that can always be pulled.
  final Widget child;

  @override
  State<KRefresh> createState() => _KRefreshState();
}

class _KRefreshState extends State<KRefresh> {
  static const _trigger = 70.0;
  double _pull = 0;
  bool _busy = false;

  bool _onScroll(ScrollNotification n) {
    if (n.depth != 0 || _busy) return false;
    final over = n.metrics.minScrollExtent - n.metrics.pixels;
    if (n is ScrollUpdateNotification || n is OverscrollNotification) {
      setState(() => _pull = math.max(0, over));
    }
    if (n is ScrollEndNotification || (n is ScrollUpdateNotification && n.dragDetails == null && over > 0)) {
      if (_pull >= _trigger) _refresh();
    }
    return false;
  }

  Future<void> _refresh() async {
    setState(() => _busy = true);
    try {
      await widget.onRefresh();
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
          _pull = 0;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final shown = _busy || _pull > 8;
    return Stack(
      children: [
        NotificationListener<ScrollNotification>(
          onNotification: _onScroll,
          child: ScrollConfiguration(
            behavior: ScrollConfiguration.of(context)
                .copyWith(physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics())),
            child: widget.child,
          ),
        ),
        if (shown)
          Positioned(
            top: 12,
            left: 0,
            right: 0,
            child: Center(
              child: Opacity(opacity: _busy ? 1 : (_pull / _trigger).clamp(0.2, 1), child: const KSpinner(size: 22)),
            ),
          ),
      ],
    );
  }
}

/// Anything that reacts to a tap – what Material's ink well was, without the ripple: the hover colour under it, the
/// pointer as a hand.
class KTappable extends StatefulWidget {
  const KTappable({
    super.key,
    required this.child,
    this.onTap,
    this.onLongPress,
    this.onDoubleTap,
    this.onSecondaryTapUp,
    this.borderRadius,
    this.hover = true,
  });

  final Widget child;
  final VoidCallback? onTap;
  final VoidCallback? onLongPress;
  final VoidCallback? onDoubleTap;
  final GestureTapUpCallback? onSecondaryTapUp;
  final BorderRadius? borderRadius;

  /// Tints what it holds while the pointer is over it.
  final bool hover;

  @override
  State<KTappable> createState() => _KTappableState();
}

class _KTappableState extends State<KTappable> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final active = widget.onTap != null || widget.onLongPress != null || widget.onDoubleTap != null;
    return MouseRegion(
      cursor: active ? SystemMouseCursors.click : MouseCursor.defer,
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTap: widget.onTap,
        onLongPress: widget.onLongPress,
        onDoubleTap: widget.onDoubleTap,
        onSecondaryTapUp: widget.onSecondaryTapUp,
        child: DecoratedBox(
          position: DecorationPosition.foreground,
          decoration: BoxDecoration(
            color: widget.hover && _hover && active ? context.k.text.withValues(alpha: 0.05) : KColor.transparent,
            borderRadius: widget.borderRadius,
          ),
          child: widget.child,
        ),
      ),
    );
  }
}

/// One of several choices: a round mark before what it stands for; the whole row chooses it.
class KRadioRow<T> extends StatelessWidget {
  const KRadioRow({
    super.key,
    required this.value,
    required this.groupValue,
    required this.onChanged,
    required this.child,
  });

  final T value;
  final T? groupValue;
  final ValueChanged<T>? onChanged;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final chosen = value == groupValue;
    final enabled = onChanged != null;
    return MergeSemantics(
      child: Semantics(
        checked: chosen,
        inMutuallyExclusiveGroup: true,
        enabled: enabled,
        child: MouseRegion(
          cursor: enabled ? SystemMouseCursors.click : SystemMouseCursors.basic,
          child: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: enabled ? () => onChanged!(value) : null,
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  AnimatedContainer(
                    duration: const Duration(milliseconds: 120),
                    width: 18,
                    height: 18,
                    alignment: Alignment.center,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(color: chosen ? k.accent : k.lineStrong, width: 1.5),
                    ),
                    child: chosen
                        ? Container(
                            width: 8,
                            height: 8,
                            decoration: BoxDecoration(color: k.accent, shape: BoxShape.circle),
                          )
                        : null,
                  ),
                  const SizedBox(width: 10),
                  Flexible(child: child),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
