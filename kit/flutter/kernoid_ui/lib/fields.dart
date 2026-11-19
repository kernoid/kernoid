// SPDX-License-Identifier: MIT
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'tokens.dart';

/// The handles of a selection on touch screens: a drop in the accent, pointing at the selection's ends. On desktops
/// the platform shows none.
class KSelectionControls extends TextSelectionControls with TextSelectionHandleControls {
  static const _size = 22.0;

  @override
  Size getHandleSize(double textLineHeight) => const Size(_size, _size);

  @override
  Offset getHandleAnchor(TextSelectionHandleType type, double textLineHeight) => switch (type) {
    TextSelectionHandleType.left => const Offset(_size, 0),
    TextSelectionHandleType.right => Offset.zero,
    TextSelectionHandleType.collapsed => const Offset(_size / 2, -4),
  };

  @override
  Widget buildHandle(BuildContext context, TextSelectionHandleType type, double textLineHeight, [VoidCallback? onTap]) {
    final handle = CustomPaint(size: const Size(_size, _size), painter: _HandlePainter(context.k.accent, type));
    return onTap == null ? handle : GestureDetector(onTap: onTap, behavior: HitTestBehavior.opaque, child: handle);
  }
}

class _HandlePainter extends CustomPainter {
  _HandlePainter(this.color, this.type);

  final Color color;
  final TextSelectionHandleType type;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..color = color;
    final r = size.width / 2;
    canvas.drawCircle(Offset(r, r), r, paint);
    // The corner that points at the text.
    switch (type) {
      case TextSelectionHandleType.left:
        canvas.drawRect(Rect.fromLTWH(r, 0, r, r), paint);
      case TextSelectionHandleType.right:
        canvas.drawRect(Rect.fromLTWH(0, 0, r, r), paint);
      case TextSelectionHandleType.collapsed:
        canvas.drawPath(
          Path()
            ..moveTo(r, -4)
            ..lineTo(r - r * 0.7, r * 0.3)
            ..lineTo(r + r * 0.7, r * 0.3)
            ..close(),
          paint,
        );
    }
  }

  @override
  bool shouldRepaint(_HandlePainter old) => old.color != color || old.type != type;
}

/// The menu of a selection – cut, copy, paste, select all – in kernoid's look, placed above the selection (or below
/// it, where there is no room).
class KContextMenu extends StatelessWidget {
  const KContextMenu({super.key, required this.anchors, required this.items});

  final TextSelectionToolbarAnchors anchors;
  final List<ContextMenuButtonItem> items;

  static String? label(BuildContext context, ContextMenuButtonItem item) {
    final t = AppLocalizations.of(context);
    return item.label ??
        switch (item.type) {
          ContextMenuButtonType.cut => t.cut,
          ContextMenuButtonType.copy => t.copy,
          ContextMenuButtonType.paste => t.paste,
          ContextMenuButtonType.selectAll => t.selectAll,
          ContextMenuButtonType.delete => t.delete,
          _ => null,
        };
  }

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final shown = [
      for (final item in items)
        if (label(context, item) case final text?) (item, text),
    ];
    if (shown.isEmpty) return const SizedBox.shrink();
    final padding = MediaQuery.paddingOf(context);
    return Padding(
      padding: EdgeInsets.fromLTRB(8, padding.top + 8, 8, 8),
      child: CustomSingleChildLayout(
        delegate: TextSelectionToolbarLayoutDelegate(
          anchorAbove: anchors.primaryAnchor - Offset(8, padding.top + 8 + 8),
          anchorBelow: (anchors.secondaryAnchor ?? anchors.primaryAnchor) - Offset(8, padding.top + 8 - 8),
        ),
        child: Container(
          decoration: BoxDecoration(
            color: k.raised,
            border: Border.all(color: k.lineStrong),
            borderRadius: BorderRadius.circular(KSize.radiusSmall),
            boxShadow: const [BoxShadow(color: Color(0x33000000), blurRadius: 12, offset: Offset(0, 3))],
          ),
          clipBehavior: Clip.antiAlias,
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              for (final (i, (item, text)) in shown.indexed)
                _MenuEntry(text: text, onPressed: item.onPressed, divider: i > 0),
            ],
          ),
        ),
      ),
    );
  }
}

class _MenuEntry extends StatefulWidget {
  const _MenuEntry({required this.text, required this.onPressed, required this.divider});

  final String text;
  final VoidCallback? onPressed;
  final bool divider;

  @override
  State<_MenuEntry> createState() => _MenuEntryState();
}

class _MenuEntryState extends State<_MenuEntry> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return MouseRegion(
      cursor: SystemMouseCursors.click,
      onEnter: (_) => setState(() => _hover = true),
      onExit: (_) => setState(() => _hover = false),
      child: GestureDetector(
        onTap: widget.onPressed,
        child: Container(
          height: 34,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          alignment: Alignment.center,
          decoration: BoxDecoration(
            color: _hover ? k.hover : KColor.transparent,
            border: widget.divider ? Border(left: BorderSide(color: k.line)) : null,
          ),
          child: Text(widget.text, style: KText.label(k).copyWith(fontSize: 13)),
        ),
      ),
    );
  }
}

/// A text field in the web app's look: its label above it, a bordered box that turns to the accent when focused, a
/// hint inside, help or an error below. Built on Flutter's [EditableText] with the platform's own gestures (tap,
/// double tap, long press, drag, right click) – no Material.
class KTextField extends StatefulWidget {
  const KTextField({
    super.key,
    this.controller,
    this.focusNode,
    this.label,
    this.hint,
    this.helper,
    this.error,
    this.icon,
    this.suffix,
    this.obscureText = false,
    this.maxLines = 1,
    this.minLines,
    this.keyboardType,
    this.textInputAction,
    this.textCapitalization = TextCapitalization.none,
    this.autofillHints,
    this.inputFormatters,
    this.autocorrect = true,
    this.autofocus = false,
    this.enabled = true,
    this.readOnly = false,
    this.onChanged,
    this.onSubmitted,
    this.onEditingComplete,
    this.onTap,
    this.style,
    this.fill,
    this.borderless = false,
    this.padding = const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
  });

  final TextEditingController? controller;
  final FocusNode? focusNode;
  final String? label;
  final String? hint;
  final String? helper;
  final String? error;

  /// An icon at the start of the box.
  final IconData? icon;

  /// Something at the end of the box – a button to clear it, to show a password.
  final Widget? suffix;

  final bool obscureText;

  /// `null`: as many lines as the text needs.
  final int? maxLines;
  final int? minLines;
  final TextInputType? keyboardType;
  final TextInputAction? textInputAction;
  final TextCapitalization textCapitalization;
  final Iterable<String>? autofillHints;
  final List<TextInputFormatter>? inputFormatters;
  final bool autocorrect;
  final bool autofocus;
  final bool enabled;
  final bool readOnly;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onSubmitted;
  final VoidCallback? onEditingComplete;
  final VoidCallback? onTap;
  final TextStyle? style;

  /// The box's ground; the surface by default.
  final Color? fill;

  /// No border – for a field inside another frame (a search bar, the body of an email).
  final bool borderless;
  final EdgeInsets padding;

  @override
  State<KTextField> createState() => _KTextFieldState();
}

class _KTextFieldState extends State<KTextField> implements TextSelectionGestureDetectorBuilderDelegate {
  TextEditingController? _ownController;
  FocusNode? _ownFocus;
  late final _gestures = _Gestures(this);
  bool _hover = false;
  bool _showHandles = false;

  TextEditingController get _controller => widget.controller ?? (_ownController ??= TextEditingController());
  FocusNode get _focus => widget.focusNode ?? (_ownFocus ??= FocusNode());

  @override
  final GlobalKey<EditableTextState> editableTextKey = GlobalKey<EditableTextState>();

  @override
  bool get forcePressEnabled => defaultTargetPlatform == TargetPlatform.iOS;

  @override
  bool get selectionEnabled => widget.enabled;

  @override
  void initState() {
    super.initState();
    _focus.addListener(_focusChanged);
  }

  @override
  void didUpdateWidget(KTextField old) {
    super.didUpdateWidget(old);
    final before = old.focusNode ?? _ownFocus;
    if (before != _focus) {
      before?.removeListener(_focusChanged);
      _focus.addListener(_focusChanged);
    }
  }

  @override
  void dispose() {
    _focus.removeListener(_focusChanged);
    _ownController?.dispose();
    _ownFocus?.dispose();
    super.dispose();
  }

  void _focusChanged() => setState(() {});

  void _selectionChanged(TextSelection selection, SelectionChangedCause? cause) {
    final show = _shouldShowHandles(cause);
    if (show != _showHandles) setState(() => _showHandles = show);
    if (cause == SelectionChangedCause.longPress) editableTextKey.currentState?.bringIntoView(selection.extent);
    if (cause == SelectionChangedCause.drag && _desktop) editableTextKey.currentState?.hideToolbar();
  }

  bool _shouldShowHandles(SelectionChangedCause? cause) {
    if (!_gestures.shouldShowSelectionToolbar || !_gestures.shouldShowSelectionHandles) return false;
    if (cause == SelectionChangedCause.keyboard || !widget.enabled) return false;
    if (widget.readOnly && _controller.selection.isCollapsed) return false;
    if (cause == SelectionChangedCause.longPress || cause == SelectionChangedCause.stylusHandwriting) return true;
    return _controller.text.isNotEmpty;
  }

  static bool get _desktop => switch (defaultTargetPlatform) {
    TargetPlatform.macOS || TargetPlatform.linux || TargetPlatform.windows => true,
    _ => false,
  };

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final focused = _focus.hasFocus;
    final error = widget.error;
    final style = widget.style ?? KText.body(k).copyWith(fontSize: 15);
    final apple = defaultTargetPlatform == TargetPlatform.iOS || defaultTargetPlatform == TargetPlatform.macOS;
    final editable = EditableText(
      key: editableTextKey,
      controller: _controller,
      focusNode: _focus,
      style: style,
      strutStyle: StrutStyle.fromTextStyle(style),
      cursorColor: error != null ? k.error : k.accent,
      backgroundCursorColor: k.faint,
      selectionColor: k.accent.withValues(alpha: 0.28),
      selectionControls: KSelectionControls(),
      contextMenuBuilder: (context, state) =>
          KContextMenu(anchors: state.contextMenuAnchors, items: state.contextMenuButtonItems),
      showSelectionHandles: _showHandles,
      onSelectionChanged: _selectionChanged,
      rendererIgnoresPointer: true,
      enableInteractiveSelection: widget.enabled,
      obscureText: widget.obscureText,
      obscuringCharacter: '•',
      autocorrect: widget.autocorrect && !widget.obscureText,
      enableSuggestions: !widget.obscureText,
      maxLines: widget.obscureText ? 1 : widget.maxLines,
      minLines: widget.minLines,
      keyboardType: widget.keyboardType ?? (widget.maxLines == 1 ? TextInputType.text : TextInputType.multiline),
      textInputAction: widget.textInputAction,
      textCapitalization: widget.textCapitalization,
      autofillHints: widget.autofillHints,
      inputFormatters: widget.inputFormatters,
      autofocus: widget.autofocus,
      readOnly: widget.readOnly || !widget.enabled,
      onChanged: widget.onChanged,
      onSubmitted: widget.onSubmitted,
      onEditingComplete: widget.onEditingComplete,
      cursorWidth: 1.5,
      cursorRadius: const Radius.circular(1),
      cursorOpacityAnimates: apple,
      paintCursorAboveText: apple,
      scrollPadding: const EdgeInsets.all(20),
    );
    final hint = widget.hint;
    final box = AnimatedContainer(
      duration: const Duration(milliseconds: 120),
      padding: widget.padding,
      decoration: BoxDecoration(
        color: widget.fill ?? k.surface,
        borderRadius: BorderRadius.circular(KSize.radiusSmall),
        border: widget.borderless
            ? null
            : Border.all(
                color: error != null
                    ? k.error
                    : focused
                    ? k.accent
                    : _hover
                    ? k.faint
                    : k.lineStrong,
                width: focused ? 1.5 : 1,
              ),
      ),
      child: Row(
        crossAxisAlignment: widget.maxLines == 1 ? CrossAxisAlignment.center : CrossAxisAlignment.start,
        children: [
          if (widget.icon != null) ...[
            Icon(widget.icon, size: 16, color: focused ? k.accent : k.faint),
            const SizedBox(width: 8),
          ],
          Expanded(
            child: Stack(
              children: [
                if (hint != null)
                  ValueListenableBuilder<TextEditingValue>(
                    valueListenable: _controller,
                    builder: (context, value, _) => value.text.isEmpty
                        ? IgnorePointer(
                            child: Text(
                              hint,
                              maxLines: widget.maxLines ?? 1,
                              overflow: TextOverflow.ellipsis,
                              style: style.copyWith(color: k.faint),
                            ),
                          )
                        : const SizedBox.shrink(),
                  ),
                _gestures.buildGestureDetector(behavior: HitTestBehavior.translucent, child: editable),
              ],
            ),
          ),
          if (widget.suffix != null) ...[const SizedBox(width: 6), widget.suffix!],
        ],
      ),
    );
    final note = error ?? widget.helper;
    return Opacity(
      opacity: widget.enabled ? 1 : 0.55,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        mainAxisSize: MainAxisSize.min,
        children: [
          if (widget.label != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: Text(
                widget.label!,
                style: KText.small(k).copyWith(color: focused ? k.accent : k.muted, fontWeight: FontWeight.w500),
              ),
            ),
          Semantics(
            label: widget.label ?? hint,
            child: MouseRegion(
              cursor: widget.enabled ? SystemMouseCursors.text : SystemMouseCursors.basic,
              onEnter: (_) => setState(() => _hover = true),
              onExit: (_) => setState(() => _hover = false),
              child: GestureDetector(
                behavior: HitTestBehavior.translucent,
                onTap: () {
                  if (!_focus.hasFocus) _focus.requestFocus();
                  widget.onTap?.call();
                },
                child: box,
              ),
            ),
          ),
          if (note != null)
            Padding(
              padding: const EdgeInsets.only(top: 5),
              child: Text(note, style: KText.small(k).copyWith(color: error != null ? k.error : k.faint)),
            ),
        ],
      ),
    );
  }
}

class _Gestures extends TextSelectionGestureDetectorBuilder {
  _Gestures(_KTextFieldState state) : super(delegate: state);
}

/// [KTextField] in a [Form]: checked with `validator`, its error below it.
class KTextFormField extends FormField<String> {
  KTextFormField({
    super.key,
    this.controller,
    String? label,
    String? hint,
    String? helper,
    IconData? icon,
    Widget? suffix,
    bool obscureText = false,
    int? maxLines = 1,
    int? minLines,
    TextInputType? keyboardType,
    TextInputAction? textInputAction,
    TextCapitalization textCapitalization = TextCapitalization.none,
    Iterable<String>? autofillHints,
    List<TextInputFormatter>? inputFormatters,
    bool autocorrect = true,
    bool autofocus = false,
    super.enabled,
    bool readOnly = false,
    ValueChanged<String>? onChanged,
    ValueChanged<String>? onSubmitted,
    FocusNode? focusNode,
    super.validator,
    super.onSaved,
    String? initialValue,
    AutovalidateMode? autovalidateMode,
  }) : super(
         initialValue: controller?.text ?? initialValue ?? '',
         autovalidateMode: autovalidateMode ?? AutovalidateMode.disabled,
         builder: (field) => KTextField(
           controller: (field as _KTextFormFieldState)._controller,
           focusNode: focusNode,
           label: label,
           hint: hint,
           helper: helper,
           error: field.errorText,
           icon: icon,
           suffix: suffix,
           obscureText: obscureText,
           maxLines: maxLines,
           minLines: minLines,
           keyboardType: keyboardType,
           textInputAction: textInputAction,
           textCapitalization: textCapitalization,
           autofillHints: autofillHints,
           inputFormatters: inputFormatters,
           autocorrect: autocorrect,
           autofocus: autofocus,
           enabled: enabled,
           readOnly: readOnly,
           onSubmitted: onSubmitted,
           onChanged: onChanged,
         ),
       );

  /// The field's text; without one, the field keeps its own.
  final TextEditingController? controller;

  @override
  FormFieldState<String> createState() => _KTextFormFieldState();
}

class _KTextFormFieldState extends FormFieldState<String> {
  TextEditingController? _own;

  KTextFormField get _field => widget as KTextFormField;
  TextEditingController get _controller =>
      _field.controller ?? (_own ??= TextEditingController(text: widget.initialValue));

  @override
  void initState() {
    super.initState();
    _controller.addListener(_changed);
  }

  @override
  void didUpdateWidget(KTextFormField old) {
    super.didUpdateWidget(old);
    if (old.controller != _field.controller) {
      (old.controller ?? _own)?.removeListener(_changed);
      _controller.addListener(_changed);
      setValue(_controller.text);
    }
  }

  // The value follows the text, however it changes – typed, pasted or set by the page.
  void _changed() {
    if (_controller.text != value) didChange(_controller.text);
  }

  @override
  void reset() {
    super.reset();
    _controller.text = widget.initialValue ?? '';
  }

  @override
  void dispose() {
    _controller.removeListener(_changed);
    _own?.dispose();
    super.dispose();
  }
}

/// Text the user can select and copy – what Material's `SelectableText` and `SelectionArea` were: any widget below it
/// becomes selectable, with kernoid's handles and menu.
class KSelectable extends StatefulWidget {
  const KSelectable({super.key, required this.child});

  /// A selectable piece of text.
  KSelectable.text(String text, {Key? key, TextStyle? style, int? maxLines})
    : this(
        key: key,
        child: Text(text, style: style, maxLines: maxLines),
      );

  final Widget child;

  @override
  State<KSelectable> createState() => _KSelectableState();
}

class _KSelectableState extends State<KSelectable> {
  final _focus = FocusNode();

  @override
  void dispose() {
    _focus.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => SelectableRegion(
    focusNode: _focus,
    selectionControls: KSelectionControls(),
    contextMenuBuilder: (context, state) =>
        KContextMenu(anchors: state.contextMenuAnchors, items: state.contextMenuButtonItems),
    child: widget.child,
  );
}
