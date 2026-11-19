// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:pdfrx_engine/pdfrx_engine.dart';

import 'package:kernoid_ui/ui.dart';

/// A PDF's pages one below the other, on the width of the view, zoomed with two fingers, a pinch or a trackpad – drawn
/// by PDFium through pdfrx_engine, without pdfrx's own viewer (which brings Material).
class PdfView extends StatefulWidget {
  const PdfView({super.key, required this.path, required this.error});

  final String path;

  /// Shown when the file cannot be opened.
  final Widget error;

  @override
  State<PdfView> createState() => _PdfViewState();
}

class _PdfViewState extends State<PdfView> {
  static Future<void>? _ready;

  PdfDocument? _document;
  bool _failed = false;
  final _transform = TransformationController();

  static Future<void> _initialize() => _ready ??= () async {
    Pdfrx.cacheDirectoryPath ??= (await getTemporaryDirectory()).path;
    await PdfrxEntryFunctions.instance.init();
  }();

  @override
  void initState() {
    super.initState();
    _open();
  }

  Future<void> _open() async {
    try {
      await _initialize();
      final document = await PdfDocument.openFile(widget.path);
      if (!mounted) {
        await document.dispose();
        return;
      }
      setState(() => _document = document);
    } catch (_) {
      if (mounted) setState(() => _failed = true);
    }
  }

  @override
  void dispose() {
    _document?.dispose();
    _transform.dispose();
    super.dispose();
  }

  /// The mouse wheel turns the pages, as in any document; with Ctrl or ⌘ held it zooms, as InteractiveViewer does.
  void _wheel(PointerSignalEvent event, Size view, double contentHeight) {
    if (event is! PointerScrollEvent) return;
    final keys = HardwareKeyboard.instance;
    if (keys.isControlPressed || keys.isMetaPressed) return;
    GestureBinding.instance.pointerSignalResolver.register(event, (event) {
      final delta = (event as PointerScrollEvent).scrollDelta;
      final m = _transform.value.clone();
      final scale = m.getMaxScaleOnAxis();
      final x = m.getTranslation().x - delta.dx;
      final y = m.getTranslation().y - delta.dy;
      final minX = view.width - view.width * scale;
      final minY = view.height - contentHeight * scale;
      m.setTranslationRaw(x.clamp(minX < 0 ? minX : 0, 0), y.clamp(minY < 0 ? minY : 0, 0), 0);
      _transform.value = m;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_failed) return widget.error;
    final document = _document;
    if (document == null) return const KLoading();
    final k = context.k;
    return ColoredBox(
      color: k.bg,
      child: LayoutBuilder(
        builder: (context, constraints) {
          final width = (constraints.maxWidth - 32).clamp(100.0, 1000.0);
          final contentHeight =
              16 + document.pages.fold<double>(0, (sum, page) => sum + width * page.height / page.width + 16);
          return InteractiveViewer(
            transformationController: _transform,
            minScale: 1,
            maxScale: 6,
            constrained: false,
            child: Listener(
              onPointerSignal: (event) => _wheel(event, constraints.biggest, contentHeight),
              child: SizedBox(
                width: constraints.maxWidth,
                child: Column(
                  children: [
                    const SizedBox(height: 16),
                    for (final (i, page) in document.pages.indexed)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 16),
                        child: _PageView(key: ValueKey(i), page: page, width: width),
                      ),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}

/// One page, rendered once at the pixels its width needs.
class _PageView extends StatefulWidget {
  const _PageView({super.key, required this.page, required this.width});

  final PdfPage page;
  final double width;

  @override
  State<_PageView> createState() => _PageViewState();
}

class _PageViewState extends State<_PageView> {
  ui.Image? _image;
  double _renderedFor = 0;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _render();
  }

  @override
  void didUpdateWidget(_PageView old) {
    super.didUpdateWidget(old);
    if (old.width != widget.width) _render();
  }

  Future<void> _render() async {
    // Sharp when zoomed in a little: twice the pixels of the screen.
    final scale = MediaQuery.devicePixelRatioOf(context) * 2;
    final pixels = widget.width * scale;
    if ((pixels - _renderedFor).abs() < 1) return;
    _renderedFor = pixels;
    final page = widget.page;
    final height = pixels * page.height / page.width;
    final rendered = await page.render(fullWidth: pixels, fullHeight: height, backgroundColor: 0xFFFFFFFF);
    if (rendered == null) return;
    try {
      final image = await _toImage(rendered);
      if (!mounted || pixels != _renderedFor) {
        image.dispose();
        return;
      }
      setState(() {
        _image?.dispose();
        _image = image;
      });
    } finally {
      rendered.dispose();
    }
  }

  /// PDFium's BGRA pixels as an image of the engine.
  static Future<ui.Image> _toImage(PdfImage rendered) async {
    final buffer = await ui.ImmutableBuffer.fromUint8List(rendered.pixels);
    final descriptor = ui.ImageDescriptor.raw(
      buffer,
      width: rendered.width,
      height: rendered.height,
      pixelFormat: ui.PixelFormat.bgra8888,
    );
    try {
      final codec = await descriptor.instantiateCodec();
      try {
        return (await codec.getNextFrame()).image;
      } finally {
        codec.dispose();
      }
    } finally {
      descriptor.dispose();
      buffer.dispose();
    }
  }

  @override
  void dispose() {
    _image?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final page = widget.page;
    final height = widget.width * page.height / page.width;
    final image = _image;
    return Container(
      width: widget.width,
      height: height,
      decoration: const BoxDecoration(
        color: KColor.white,
        boxShadow: [BoxShadow(color: Color(0x33000000), blurRadius: 8, offset: Offset(0, 2))],
      ),
      child: image == null ? const KLoading() : RawImage(image: image, fit: BoxFit.fill),
    );
  }
}
