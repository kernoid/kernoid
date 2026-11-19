// SPDX-License-Identifier: MIT
import 'package:file_selector/file_selector.dart';
import 'package:flutter/services.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';
import 'package:url_launcher/url_launcher.dart';

import '../app/appearance.dart';
import '../app/format.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

import '../widgets/e2e.dart';
import '../feature.dart';

/// The user's own account – never administration, which stays in the web app and the terminal app (docs/plan.md, 2):
/// who is signed in, the look on this device, the vacation response, the end-to-end key – and, with a login of
/// OpenID Connect, name, picture, language and mail settings (an app password reaches none of them). What needs a login
/// with the password – the password itself, second factors, passkeys, app passwords, sessions – is the web app's, a
/// click away.
class AccountPage extends StatelessWidget {
  const AccountPage({
    super.key,
    required this.account,
    required this.onSignOut,
    this.features = const [],
    this.picture,
  });

  final Kernoid account;
  final VoidCallback onSignOut;

  /// The features the account's server offers, with what each keeps while signed in – they add sections of their own.
  final List<(KFeature, KFeatureSession)> features;

  /// The account's own picture, shared with the side bar; changed here, it changes there.
  final ValueNotifier<Uint8List?>? picture;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final web = Uri.tryParse(account.server)?.resolve('/app/#/account');
    return KScaffold(
      background: k.bg,
      topBar: KTopBar(title: l.account, leading: const SizedBox(width: 6)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 720),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  KSection(
                    title: account.username,
                    description: account.server,
                    trailing: picture == null
                        ? KAvatar(name: account.username, size: 40)
                        : ValueListenableBuilder(
                            valueListenable: picture!,
                            builder: (context, image, _) => KAvatar(name: account.username, size: 40, image: image),
                          ),
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: KButton(
                        key: const ValueKey('sign-out'),
                        label: l.signOut,
                        icon: LucideIcons.logOut,
                        onPressed: onSignOut,
                      ),
                    ),
                  ),
                  KSection(
                    title: l.appearance,
                    icon: LucideIcons.sunMoon,
                    description: l.appearanceHint,
                    child: ValueListenableBuilder<KThemeMode>(
                      valueListenable: Appearance.mode,
                      builder: (context, mode, _) => Align(
                        alignment: Alignment.centerLeft,
                        child: KSegmented<KThemeMode>(
                          options: [
                            (KThemeMode.system, l.themeSystem),
                            (KThemeMode.light, l.themeLight),
                            (KThemeMode.dark, l.themeDark),
                          ],
                          value: mode,
                          onChanged: Appearance.set,
                        ),
                      ),
                    ),
                  ),
                  if (account.settingsAvailable()) ...[
                    _ProfileSection(account: account, picture: picture),
                    _LanguageSection(account: account),
                  ],
                  for (final (feature, session) in features) ...feature.accountSections(context, account, session),
                  _KeyCard(account: account),
                  KSection(
                    title: l.security,
                    icon: LucideIcons.shieldCheck,
                    description: account.settingsAvailable() ? l.securityHintApp : l.securityHint,
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: KButton(
                        key: const ValueKey('open-web-app'),
                        label: l.openWebApp,
                        icon: LucideIcons.externalLink,
                        onPressed: web == null ? null : () => launchUrl(web, mode: LaunchMode.externalApplication),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// A section that loads something, shows it, and saves changes – with a line saying how it went.
abstract class KSettingsState<T extends StatefulWidget> extends State<T> {
  bool loaded = false;
  bool busy = false;
  String? note;
  bool failed = false;

  Future<void> load();

  @override
  void initState() {
    super.initState();
    // After the first frame: loading changes the state, which a widget cannot while it is first built.
    WidgetsBinding.instance.addPostFrameCallback((_) => _guard(load, after: () => loaded = true, say: false));
  }

  Future<void> save(Future<void> Function() work) => _guard(work, say: true);

  Future<void> _guard(Future<void> Function() work, {void Function()? after, required bool say}) async {
    final l = AppLocalizations.of(context);
    setState(() {
      busy = true;
      note = null;
    });
    try {
      await work();
      if (mounted && say) {
        setState(() {
          note = l.saved;
          failed = false;
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() {
          note = errorText(error);
          failed = true;
        });
      }
    } finally {
      if (mounted) {
        setState(() {
          busy = false;
          after?.call();
        });
      }
    }
  }

  Widget noteLine(String key) => note == null
      ? const SizedBox.shrink()
      : Padding(
          padding: const EdgeInsets.only(top: 10),
          child: Text(
            note!,
            key: ValueKey(key),
            style: KText.small(context.k).copyWith(color: failed ? context.k.error : context.k.accent),
          ),
        );
}

/// The name others see and the picture beside it.
class _ProfileSection extends StatefulWidget {
  const _ProfileSection({required this.account, this.picture});

  final Kernoid account;

  /// Told of a new picture, for the side bar and the head of the page.
  final ValueNotifier<Uint8List?>? picture;

  @override
  State<_ProfileSection> createState() => _ProfileSectionState();
}

class _ProfileSectionState extends KSettingsState<_ProfileSection> {
  final _name = TextEditingController();
  Uint8List? _picture;

  @override
  Future<void> load() async {
    final (name, picture) = (await widget.account.ownName(), await widget.account.ownAvatar());
    _name.text = name;
    _picture = picture;
    widget.picture?.value = picture;
  }

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  Future<void> _choose() async {
    final file = await openFile(
      acceptedTypeGroups: const [
        XTypeGroup(
          label: 'images',
          extensions: ['png', 'jpg', 'jpeg', 'webp'],
          mimeTypes: ['image/png', 'image/jpeg', 'image/webp'],
          uniformTypeIdentifiers: ['public.png', 'public.jpeg', 'org.webmproject.webp'],
        ),
      ],
    );
    if (file == null) return;
    await save(() async {
      final bytes = await file.readAsBytes();
      final name = file.name.toLowerCase();
      final type = name.endsWith('.png')
          ? 'image/png'
          : name.endsWith('.webp')
          ? 'image/webp'
          : 'image/jpeg';
      await widget.account.setOwnAvatar(image: bytes, mediaType: type);
      _picture = bytes;
      widget.picture?.value = bytes;
    });
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return KSection(
      title: l.profile,
      icon: LucideIcons.circleUser,
      description: l.pictureHint,
      child: !loaded
          ? const KProgressBar()
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    KAvatar(
                      key: const ValueKey('own-avatar'),
                      name: _name.text.isEmpty ? widget.account.username : _name.text,
                      size: 56,
                      image: _picture,
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          KButton(
                            key: const ValueKey('change-picture'),
                            label: l.changePicture,
                            icon: LucideIcons.imageUp,
                            onPressed: busy ? null : _choose,
                          ),
                          if (_picture != null)
                            KButton(
                              key: const ValueKey('remove-picture'),
                              label: l.removePicture,
                              icon: LucideIcons.trash2,
                              tone: KTone.quiet,
                              onPressed: busy
                                  ? null
                                  : () => save(() async {
                                      await widget.account.removeOwnAvatar();
                                      _picture = null;
                                      widget.picture?.value = null;
                                    }),
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Expanded(
                      child: KTextField(key: const ValueKey('display-name'), controller: _name, label: l.displayName),
                    ),
                    const SizedBox(width: 12),
                    KButton(
                      key: const ValueKey('name-save'),
                      label: l.save,
                      tone: KTone.primary,
                      onPressed: busy ? null : () => save(() => widget.account.setOwnName(name: _name.text)),
                    ),
                  ],
                ),
                noteLine('profile-note'),
              ],
            ),
    );
  }
}

String _languageName(AppLocalizations l, String code) => switch (code) {
  'de' => l.languageNamede,
  'en' => l.languageNameen,
  _ => code,
};

/// The language kernoid writes its emails to the account in.
class _LanguageSection extends StatefulWidget {
  const _LanguageSection({required this.account});

  final Kernoid account;

  @override
  State<_LanguageSection> createState() => _LanguageSectionState();
}

class _LanguageSectionState extends KSettingsState<_LanguageSection> {
  AccountLanguage? _language;

  @override
  Future<void> load() async => _language = await widget.account.accountLanguage();

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final language = _language;
    return KSection(
      title: l.emailLanguage,
      icon: LucideIcons.languages,
      description: l.emailLanguageHint,
      child: !loaded || language == null
          ? (loaded ? noteLine('language-note') : const KProgressBar())
          : Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                KSelect<String>(
                  key: const ValueKey('email-language'),
                  value: language.language ?? '',
                  expand: false,
                  options: [
                    // What the tenant chose is known only while it is the one used.
                    ('', language.language == null ? l.asTenantLanguage(_languageName(l, language.used)) : l.asTenant),
                    for (final code in language.available) (code, _languageName(l, code)),
                  ],
                  onChanged: busy
                      ? null
                      : (code) => save(() async {
                          await widget.account.setAccountLanguage(language: code == '' ? null : code);
                          _language = await widget.account.accountLanguage();
                        }),
                ),
                noteLine('language-note'),
              ],
            ),
    );
  }
}

/// End-to-end encryption of the account: make the key, unlock it, lock it (RFC 0006, 4).
class _KeyCard extends StatefulWidget {
  const _KeyCard({required this.account});

  final Kernoid account;

  @override
  State<_KeyCard> createState() => _KeyCardState();
}

class _KeyCardState extends State<_KeyCard> {
  E2eStatus? _status;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    widget.account.keyStatus().then((s) {
      if (mounted) setState(() => _status = s);
    });
  }

  Future<void> _act(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
      final status = await widget.account.keyStatus();
      if (mounted) setState(() => _status = status);
    } catch (error) {
      if (mounted) setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _make() => _act(() async {
    final code = await widget.account.makeKey();
    if (mounted) await showRecoveryCode(context, code);
  });

  Future<void> _unlock() => _act(() async {
    await unlockKey(context, widget.account);
  });

  Future<void> _lock() => _act(() async {
    await widget.account.lockKey();
  });

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final s = _status;
    final children = <Widget>[];
    if (s == null) {
      children.add(const KProgressBar());
    } else if (!s.available) {
      children.add(Text(l.e2eUnavailable, style: KText.body(context.k)));
    } else if (!s.hasKey) {
      children.addAll([
        Text(l.e2eNoKey, style: KText.body(context.k)),
        const SizedBox(height: 12),
        KButton(
          key: const ValueKey('make-key'),
          onPressed: _busy ? null : _make,
          icon: LucideIcons.keyRound,
          label: l.e2eMakeKey,
          tone: KTone.primary,
        ),
      ]);
    } else {
      children.addAll([
        Text(s.unlocked ? l.e2eUnlocked : l.e2eLocked, style: KText.body(context.k)),
        const SizedBox(height: 12),
        if (s.fingerprint != null) _Line(label: l.fingerprint, value: groupedFingerprint(s.fingerprint!), mono: true),
        if (s.kind != null) _Line(label: '', value: s.kind == 'pqc' ? l.postQuantum : l.compatibleKind),
        if (s.tenantRecovers) _Line(label: '', value: l.tenantRecovers),
        const SizedBox(height: 12),
        s.unlocked
            ? KButton(
                key: const ValueKey('lock-key'),
                onPressed: _busy ? null : _lock,
                icon: LucideIcons.lock,
                label: l.lock,
              )
            : KButton(
                key: const ValueKey('unlock-key'),
                onPressed: _busy ? null : _unlock,
                icon: LucideIcons.lockOpen,
                label: l.unlock,
                tone: KTone.primary,
              ),
      ]);
    }
    if (_error != null) {
      children.addAll([
        const SizedBox(height: 8),
        Text(_error!, style: KText.small(context.k).copyWith(color: context.k.error)),
      ]);
    }
    return KSection(
      title: l.e2eTitle,
      icon: s?.unlocked ?? false ? LucideIcons.lockOpen : LucideIcons.lock,
      trailing: _busy ? const SizedBox.square(dimension: 18, child: KSpinner(stroke: 2)) : null,
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: children),
    );
  }
}

class _Line extends StatelessWidget {
  const _Line({required this.label, required this.value, this.mono = false});

  final String label;
  final String value;
  final bool mono;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (label.isNotEmpty) KOverline(label, padding: const EdgeInsets.only(bottom: 2)),
          KSelectable.text(value, style: mono ? KText.mono(k) : KText.small(k)),
        ],
      ),
    );
  }
}
