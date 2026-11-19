// SPDX-License-Identifier: MIT

import 'package:flutter_widget_from_html_core/flutter_widget_from_html_core.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_ui/ui.dart';

import 'l10n/mail_text.dart';

/// The HTML of an email, drawn as Flutter widgets: nothing in it runs, and nothing is loaded from the internet until
/// the user asks for its images. Files and assets of the device are never shown; a link opens only after the user saw
/// where it goes.
class HtmlBody extends StatefulWidget {
  const HtmlBody({super.key, required this.html, this.onMailto});

  final String html;

  /// A `mailto:` link was followed: write to its address.
  final void Function(String address)? onMailto;

  @override
  State<HtmlBody> createState() => _HtmlBodyState();
}

class _HtmlBodyState extends State<HtmlBody> {
  bool _remote = false;

  /// Whether the HTML has images from the internet – asked once, to offer loading them.
  late final bool _hasRemote = RegExp(
    r'''<img[^>]+src\s*=\s*["']?\s*(https?:)?//''',
    caseSensitive: false,
  ).hasMatch(widget.html);

  Future<bool> _tap(String url) async {
    final uri = Uri.tryParse(url.trim());
    if (uri == null) return true;
    if (uri.scheme == 'mailto') {
      widget.onMailto?.call(Uri.decodeComponent(uri.path));
      return true;
    }
    if (uri.scheme != 'https' && uri.scheme != 'http') return true;
    final l = AppLocalizations.of(context);
    final open = await showKDialog<bool>(
      context,
      builder: (context) => KDialog(
        title: l.mailText.openLink,
        // The address itself: the text of a link may say anything.
        content: KSelectable.text(uri.toString()),
        actions: [
          KButton(tone: KTone.quiet, onPressed: () => Navigator.of(context).pop(false), label: l.cancel),
          KButton(
            tone: KTone.primary,
            key: const ValueKey('open-link'),
            onPressed: () => Navigator.of(context).pop(true),
            label: l.open,
          ),
        ],
      ),
    );
    if (open ?? false) await launchUrl(uri, mode: LaunchMode.externalApplication);
    return true;
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (_hasRemote && !_remote)
          KCard(
            margin: const EdgeInsets.only(bottom: 12),
            child: KListRow(
              leading: const Icon(LucideIcons.imageOff),
              title: Text(l.mailText.imagesBlocked),
              trailing: KButton(
                tone: KTone.quiet,
                key: const ValueKey('load-images'),
                onPressed: () => setState(() => _remote = true),
                label: l.mailText.loadImages,
              ),
            ),
          ),
        HtmlWidget(
          widget.html,
          key: ValueKey(_remote),
          factoryBuilder: () => _MailWidgetFactory(remote: _remote),
          onTapUrl: _tap,
          renderMode: RenderMode.column,
          onLoadingBuilder: (context, element, progress) => const Padding(
            padding: EdgeInsets.all(8),
            child: Center(child: KSpinner(size: 18)),
          ),
          // Links in kernoid's accent (the package would take Material's theme for them).
          customStylesBuilder: (element) => element.localName == 'a' && element.attributes['style'] == null
              ? {'color': _css(context.k.accent)}
              : null,
        ),
      ],
    );
  }
}

/// Images only from the message itself (`data:`), and from the internet once allowed.
String _css(Color c) => '#${(c.toARGB32() & 0xFFFFFF).toRadixString(16).padLeft(6, '0')}';

class _MailWidgetFactory extends WidgetFactory {
  _MailWidgetFactory({required this.remote});

  final bool remote;

  /// A `title` as kernoid's tooltip, not Material's.
  @override
  Widget? buildTooltip(BuildTree tree, Widget child, String message) => KTooltip(message: message, child: child);

  @override
  ImageProvider? imageProviderFromAsset(String url) => null;

  @override
  ImageProvider? imageProviderFromFileUri(String url) => null;

  @override
  ImageProvider? imageProviderFromNetwork(String url) {
    final uri = Uri.tryParse(url);
    if (!remote || uri == null || (uri.scheme != 'https' && uri.scheme != 'http')) return null;
    return super.imageProviderFromNetwork(url);
  }
}
