// SPDX-License-Identifier: MIT

import 'package:flutter/foundation.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_ui/ui.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import '../feature.dart';
import 'account.dart';

/// Where the wide layout begins: a side bar and panes side by side instead of a bar and pages on top of each other.
const wideLayout = 840.0;

/// The signed-in app: the features the server offers and the account – the same functions on every screen size, laid
/// out for it. Wide: a side bar with the word mark, the sections and the account at its foot; narrow: a bar of the
/// sections at the bottom (RFC 0011, 3).
class HomePage extends StatefulWidget {
  const HomePage({super.key, required this.account, required this.features, required this.onSignOut});

  final Kernoid account;

  /// The app's features, in their order; those the server does not offer are left out.
  final List<KFeature> features;
  final VoidCallback onSignOut;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  int _section = 0;

  /// The features the server offers, with what each keeps while the account is signed in.
  late final List<(KFeature, KFeatureSession)> _features;

  /// The account's own picture, at the foot of the side bar and atop the account page – only a login of OpenID Connect
  /// may read it (an app password may not).
  final _picture = ValueNotifier<Uint8List?>(null);

  @override
  void initState() {
    super.initState();
    _features = [
      for (final feature in widget.features)
        if (feature.offeredBy(widget.account)) (feature, feature.start(context, widget.account)),
    ];
    _loadPicture();
  }

  Future<void> _loadPicture() async {
    if (!widget.account.settingsAvailable()) return;
    try {
      final picture = await widget.account.ownAvatar();
      if (mounted) _picture.value = picture;
    } catch (_) {
      // Without the picture the initials stand in for it.
    }
  }

  @override
  void dispose() {
    for (final (_, session) in _features) {
      session.dispose();
    }
    _picture.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final sections = [for (final (feature, _) in _features) (feature.id, feature.icon, feature.label(l))];
    final page = _section < _features.length
        ? KeyedSubtree(key: ValueKey(_features[_section].$1.id), child: _features[_section].$1.page(widget.account))
        : AccountPage(account: widget.account, onSignOut: widget.onSignOut, features: _features, picture: _picture);
    final name = widget.account.username;
    if (MediaQuery.sizeOf(context).width >= wideLayout) {
      return KScaffold(
        background: k.bg,
        body: Row(
          children: [
            Container(
              width: 212,
              decoration: BoxDecoration(
                color: k.panel,
                border: Border(right: BorderSide(color: k.line)),
              ),
              child: SafeArea(
                right: false,
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(10, 14, 10, 10),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const Padding(padding: EdgeInsets.fromLTRB(10, 2, 10, 18), child: KWordmark(size: 19)),
                      for (final (i, (id, icon, label)) in sections.indexed)
                        KSideItem(
                          key: ValueKey('nav-$id'),
                          icon: icon,
                          label: label,
                          selected: _section == i,
                          onTap: () => setState(() => _section = i),
                        ),
                      const Spacer(),
                      const Padding(padding: EdgeInsets.symmetric(vertical: 8), child: KDivider()),
                      _AccountItem(
                        key: const ValueKey('nav-account'),
                        name: name,
                        picture: _picture,
                        label: l.account,
                        selected: _section == sections.length,
                        onTap: () => setState(() => _section = sections.length),
                      ),
                    ],
                  ),
                ),
              ),
            ),
            Expanded(child: page),
          ],
        ),
      );
    }
    return KScaffold(
      body: page,
      bottom: Container(
        decoration: BoxDecoration(
          color: k.panel,
          border: Border(top: BorderSide(color: k.line)),
        ),
        child: SafeArea(
          top: false,
          child: SizedBox(
            height: 60,
            child: Row(
              children: [
                for (final (i, (id, icon, label)) in [...sections, ('account', LucideIcons.user, l.account)].indexed)
                  Expanded(
                    child: _BottomItem(
                      key: ValueKey('nav-$id'),
                      icon: icon,
                      label: label,
                      selected: _section == i,
                      onTap: () => setState(() => _section = i),
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// The account at the foot of the side bar: its avatar and address.
class _AccountItem extends StatefulWidget {
  const _AccountItem({
    super.key,
    required this.name,
    required this.picture,
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final String name;
  final ValueListenable<Uint8List?> picture;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  State<_AccountItem> createState() => _AccountItemState();
}

class _AccountItemState extends State<_AccountItem> {
  bool _hover = false;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Semantics(
      button: true,
      label: widget.label,
      child: MouseRegion(
        cursor: SystemMouseCursors.click,
        onEnter: (_) => setState(() => _hover = true),
        onExit: (_) => setState(() => _hover = false),
        child: GestureDetector(
          onTap: widget.onTap,
          child: Container(
            padding: const EdgeInsets.all(8),
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
                ValueListenableBuilder(
                  valueListenable: widget.picture,
                  builder: (context, picture, _) => KAvatar(name: widget.name, size: 30, image: picture),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(widget.label, style: KText.label(k)),
                      Text(
                        widget.name,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: KText.small(k).copyWith(fontSize: 12),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// A section in the bottom bar: its icon over its name, the chosen one in the accent with a mark above.
class _BottomItem extends StatelessWidget {
  const _BottomItem({super.key, required this.icon, required this.label, required this.selected, required this.onTap});

  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final color = selected ? k.accent : k.muted;
    return Semantics(
      button: true,
      selected: selected,
      label: label,
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTap: onTap,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              width: 32,
              height: 3,
              margin: const EdgeInsets.only(bottom: 7),
              decoration: BoxDecoration(
                color: selected ? k.accent : KColor.transparent,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            Icon(icon, size: 20, color: color),
            const SizedBox(height: 3),
            Text(
              label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: KText.small(k)
                  .copyWith(fontSize: 11, color: selected ? k.text : k.muted, fontWeight: FontWeight.w500),
            ),
          ],
        ),
      ),
    );
  }
}
