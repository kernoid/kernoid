// SPDX-License-Identifier: MIT
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';

import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_ui/ui.dart';

import 'pdf_view.dart';

import 'package:kernoid_shell/widgets/states.dart';

/// How the viewer shows a file: in the app – text, images, PDF –, or handed to another app of the system (audio,
/// video and the rest; the apps bring no player of their own, docs/plan.md, 7).
enum ViewKind { text, image, pdf, other }

/// What the viewer makes of a media type and a name.
ViewKind viewKindOf(String? mediaType, String name) {
  final type = (mediaType ?? '').toLowerCase().split(';').first.trim();
  final extension = name.contains('.') ? name.split('.').last.toLowerCase() : '';
  if (type == 'application/pdf' || extension == 'pdf') return ViewKind.pdf;
  const images = {'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/bmp'};
  if (images.contains(type) || const {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}.contains(extension)) {
    return ViewKind.image;
  }
  const texts = {'application/json', 'application/xml', 'application/javascript', 'application/x-sh'};
  if ((type.startsWith('text/') && type != 'text/html') || texts.contains(type)) return ViewKind.text;
  const textExtensions = {'txt', 'md', 'csv', 'json', 'xml', 'yaml', 'yml', 'toml', 'log', 'ini', 'conf', 'sh'};
  if ((type.isEmpty || type == 'application/octet-stream') && textExtensions.contains(extension)) {
    return ViewKind.text;
  }
  return ViewKind.other;
}

/// How much of a text file the viewer shows.
const textLimit = 1024 * 1024;

/// Fetches the file into `directory` and returns its path.
typedef FetchFile = Future<String> Function(String directory);

/// Opens a file: in the viewer when the app can show it, else in another app of the system.
Future<void> viewFile(
  BuildContext context, {
  required String name,
  required String? mediaType,
  required FetchFile fetch,
  VoidCallback? onSave,
}) async {
  final kind = viewKindOf(mediaType, name);
  if (kind == ViewKind.other) {
    await openElsewhere(context, name: name, mediaType: mediaType, fetch: fetch);
    return;
  }
  await Navigator.of(context).push<void>(
    KPageRoute(
      fullscreenDialog: true,
      builder: (_) => ViewerPage(name: name, mediaType: mediaType, kind: kind, fetch: fetch, onSave: onSave),
    ),
  );
}

/// A new, empty directory for one file to be viewed, below the app's temporary files – the system clears them.
Future<Directory> _scratch() async {
  final base = await getTemporaryDirectory();
  final directory = Directory('${base.path}/kernoid-view/${DateTime.now().microsecondsSinceEpoch}');
  return directory.create(recursive: true);
}

/// Hands a file to another app of the system: the one meant for its type on desktops, the share sheet on phones.
Future<void> openElsewhere(
  BuildContext context, {
  required String name,
  required String? mediaType,
  required FetchFile fetch,
}) async {
  final messenger = KToast.of(context);
  final l = AppLocalizations.of(context);
  final box = context.findRenderObject() as RenderBox?;
  final origin = box == null || !box.hasSize ? null : box.localToGlobal(Offset.zero) & box.size;
  try {
    final directory = await _scratch();
    final path = await fetch(directory.path);
    final phone = defaultTargetPlatform == TargetPlatform.iOS || defaultTargetPlatform == TargetPlatform.android;
    if (phone) {
      await SharePlus.instance.share(
        ShareParams(
          files: [XFile(path, mimeType: mediaType)],
          sharePositionOrigin: origin,
        ),
      );
    } else if (!await launchUrl(Uri.file(path))) {
      messenger.show(l.noAppFor(name));
    }
  } catch (error) {
    messenger.show(l.error(errorText(error)));
  }
}

/// A file shown in the app: text, an image to zoom, or a PDF.
class ViewerPage extends StatefulWidget {
  const ViewerPage({
    super.key,
    required this.name,
    required this.mediaType,
    required this.kind,
    required this.fetch,
    this.onSave,
  });

  final String name;
  final String? mediaType;
  final ViewKind kind;
  final FetchFile fetch;
  final VoidCallback? onSave;

  @override
  State<ViewerPage> createState() => _ViewerPageState();
}

class _ViewerPageState extends State<ViewerPage> {
  Directory? _directory;
  String? _path;
  String? _text;
  bool _cut = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    // What was fetched to be shown goes with the viewer.
    _directory?.delete(recursive: true).ignore();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() => _error = null);
    try {
      final directory = _directory ??= await _scratch();
      final path = _path ?? await widget.fetch(directory.path);
      String? text;
      var cut = false;
      if (widget.kind == ViewKind.text) {
        final file = await File(path).open();
        try {
          final bytes = await file.read(textLimit + 1);
          cut = bytes.length > textLimit;
          text = utf8.decode(cut ? bytes.sublist(0, textLimit) : bytes, allowMalformed: true);
        } finally {
          await file.close();
        }
      }
      if (mounted) {
        setState(() {
          _path = path;
          _text = text;
          _cut = cut;
        });
      }
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    return KScaffold(
      key: const ValueKey('viewer'),
      background: k.surface,
      topBar: KTopBar(
        title: widget.name,
        actions: [
          if (widget.onSave != null) KIconButton(icon: LucideIcons.download, tooltip: l.save, onPressed: widget.onSave),
          Builder(
            builder: (button) => KIconButton(
              key: const ValueKey('open-elsewhere'),
              icon: LucideIcons.externalLink,
              tooltip: l.openElsewhere,
              onPressed: () => openElsewhere(button, name: widget.name, mediaType: widget.mediaType, fetch: _copy),
            ),
          ),
        ],
      ),
      body: _body(l, k),
    );
  }

  /// The file already here, handed on without fetching it again.
  Future<String> _copy(String directory) async {
    final path = _path;
    if (path == null) return widget.fetch(directory);
    return (await File(path).copy('$directory/${widget.name}')).path;
  }

  Widget _body(AppLocalizations l, KTokens k) {
    if (_error != null) return ErrorView(error: _error!, onRetry: _load);
    final path = _path;
    if (path == null) return const Center(child: KSpinner());
    switch (widget.kind) {
      case ViewKind.text:
        return Column(
          children: [
            if (_cut)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                color: k.raised,
                child: Text(l.textCut, style: KText.small(k)),
              ),
            Expanded(
              child: SingleChildScrollView(
                key: const ValueKey('viewer-text'),
                padding: const EdgeInsets.all(16),
                child: KSelectable.text(_text ?? '', style: KText.mono(k).copyWith(color: k.text)),
              ),
            ),
          ],
        );
      case ViewKind.image:
        return InteractiveViewer(
          key: const ValueKey('viewer-image'),
          maxScale: 8,
          child: Center(
            child: Image.file(
              File(path),
              errorBuilder: (_, error, _) => EmptyView(l.cannotShow, icon: LucideIcons.imageOff),
            ),
          ),
        );
      case ViewKind.pdf:
        return PdfView(
          key: const ValueKey('viewer-pdf'),
          path: path,
          error: EmptyView(l.cannotShow, icon: LucideIcons.fileX),
        );
      case ViewKind.other:
        return EmptyView(l.cannotShow, icon: LucideIcons.fileQuestion);
    }
  }
}
