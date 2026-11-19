// SPDX-License-Identifier: MIT

import 'package:flutter/services.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_shell/app/save.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

import 'l10n/files_text.dart';

/// A dialog of the files page: a title, its content scrolling, buttons at its foot.
class _FileDialog extends StatelessWidget {
  const _FileDialog({required this.title, required this.child, required this.actions});

  final String title;
  final Widget child;
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    return KDialog(title: title, width: 480, content: child, actions: actions);
  }
}

String levelName(AppLocalizations l, String level) => switch (level) {
  'full' => l.filesText.levelFull,
  'edit' => l.filesText.levelEdit,
  _ => l.filesText.levelRead,
};

/// With whom a directory is shared and how far: people and groups found by name, each with a level; saved at once
/// for all of them.
Future<bool> shareDialog(BuildContext context, Kernoid account, String accountId, FileNode directory) async {
  final done = await showKDialog<bool>(
    context,
    builder: (_) => _ShareDialog(account: account, accountId: accountId, directory: directory),
  );
  return done ?? false;
}

class _ShareDialog extends StatefulWidget {
  const _ShareDialog({required this.account, required this.accountId, required this.directory});

  final Kernoid account;
  final String accountId;
  final FileNode directory;

  @override
  State<_ShareDialog> createState() => _ShareDialogState();
}

class _ShareDialogState extends State<_ShareDialog> {
  late final List<FileShare> _shares = [...widget.directory.shares];
  final Map<String, Principal> _known = {};
  final _search = TextEditingController();
  List<Principal> _found = [];
  bool _busy = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    final ids = _shares.map((s) => s.principalId).toList();
    if (ids.isNotEmpty) {
      widget.account.principals(ids: ids).then((found) {
        if (mounted) setState(() => _known.addAll({for (final p in found) p.id: p}));
      }, onError: (Object _) {});
    }
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _find(String text) async {
    if (text.trim().isEmpty) {
      setState(() => _found = []);
      return;
    }
    try {
      final found = await widget.account.findPrincipals(text: text);
      if (!mounted || _search.text != text) return;
      setState(() {
        _known.addAll({for (final p in found) p.id: p});
        _found = found.where((p) => !_shares.any((s) => s.principalId == p.id)).toList();
      });
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _save() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.account.shareDirectory(accountId: widget.accountId, id: widget.directory.id, shares: _shares);
      // A vault's key goes to everyone it is shared with, wrapped for their own key (RFC 0006, 6).
      // A vault on a space makes them members, each with a code sealed to their key (RFC 0010, 5).
      if (widget.directory.isVault && _shares.isNotEmpty) {
        final ids = [for (final s in _shares) s.principalId];
        final space = widget.directory.space;
        final waiting = space != null
            ? await widget.account.shareSpaceVault(
                accountId: widget.accountId,
                vaultId: widget.directory.id,
                space: space,
                principalIds: ids,
              )
            : await widget.account.giveVaultKeys(
                accountId: widget.accountId,
                vaultId: widget.directory.id,
                principalIds: ids,
              );
        if (waiting.isNotEmpty && mounted) {
          final l = AppLocalizations.of(context);
          await showNote(
            context,
            text: l.filesText.vaultKeysWaiting(
              waiting.map((p) => p.name.isEmpty ? (p.email ?? p.id) : p.name).join(', '),
            ),
            close: l.done,
          );
        }
      }
      if (mounted) Navigator.of(context).pop(true);
    } catch (error) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = error;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    return _FileDialog(
      title: l.filesText.shareTitle(widget.directory.name),
      actions: [
        KButton(label: l.cancel, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop(false)),
        KButton(key: const ValueKey('share-save'), label: l.save, tone: KTone.primary, onPressed: _busy ? null : _save),
      ],
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          KTextField(
            key: const ValueKey('share-find'),
            controller: _search,
            onChanged: _find,
            hint: l.filesText.findPeople,
            icon: LucideIcons.search,
          ),
          for (final p in _found.take(6))
            KListRow(
              key: ValueKey('principal-${p.email ?? p.id}'),
              dense: true,
              leading: KAvatar(name: p.name, size: 26),
              title: Text(p.name, style: KText.label(k)),
              subtitle: p.email == null ? null : Text(p.email!, style: KText.small(k)),
              trailing: Icon(LucideIcons.plus, size: 16, color: k.accent),
              onTap: () => setState(() {
                _shares.add(FileShare(principalId: p.id, level: 'read'));
                _found = [];
                _search.clear();
              }),
            ),
          const SizedBox(height: 12),
          if (_shares.isEmpty) Text(l.filesText.notShared, style: KText.small(k)),
          for (final (i, s) in _shares.indexed)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                children: [
                  KAvatar(name: _known[s.principalId]?.name ?? '?', size: 26),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      _known[s.principalId]?.name ?? s.principalId,
                      overflow: TextOverflow.ellipsis,
                      style: KText.label(k),
                    ),
                  ),
                  KMenuButton<String>(
                    key: ValueKey('level-$i'),
                    tooltip: l.filesText.share,
                    onSelected: (level) =>
                        setState(() => _shares[i] = FileShare(principalId: s.principalId, level: level)),
                    items: () => [
                      for (final level in ['read', 'edit', 'full'])
                        KMenuItem(
                          key: ValueKey('level-option-$level'),
                          value: level,
                          label: levelName(l, level),
                          checked: level == s.level,
                        ),
                    ],
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(levelName(l, s.level), style: KText.small(k).copyWith(color: k.text)),
                        Icon(LucideIcons.chevronDown, size: 14, color: k.muted),
                      ],
                    ),
                  ),
                  KIconButton(
                    icon: LucideIcons.x,
                    tooltip: l.remove,
                    size: 30,
                    onPressed: () => setState(() => _shares.removeAt(i)),
                  ),
                ],
              ),
            ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(top: 10),
              child: Text(errorText(_error!), style: KText.small(k).copyWith(color: k.error)),
            ),
        ],
      ),
    );
  }
}

String linkModeName(AppLocalizations l, String mode) => switch (mode) {
  'add' => l.filesText.linkAdd,
  'drop' => l.filesText.linkDrop,
  _ => l.filesText.linkView,
};

/// The links to a file or folder for people without an account: those there are, and making one – its address shown
/// only then.
Future<void> linkDialog(BuildContext context, Kernoid account, String accountId, FileNode node) => showKDialog<void>(
  context,
  builder: (_) => _LinkDialog(account: account, accountId: accountId, node: node),
);

class _LinkDialog extends StatefulWidget {
  const _LinkDialog({required this.account, required this.accountId, required this.node});

  final Kernoid account;
  final String accountId;
  final FileNode node;

  @override
  State<_LinkDialog> createState() => _LinkDialogState();
}

class _LinkDialogState extends State<_LinkDialog> {
  List<FileLink>? _links;
  String _mode = 'view';
  int _days = 0;
  final _password = TextEditingController();
  String? _made;
  bool _busy = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _password.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final links = await widget.account.fileLinks(accountId: widget.accountId, id: widget.node.id);
      if (mounted) setState(() => _links = links);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _work(Future<void> Function() work) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await work();
      await _load();
    } catch (error) {
      if (mounted) setState(() => _error = error);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _create() => _work(() async {
    final expires = _days == 0
        ? null
        : '${DateTime.now().toUtc().add(Duration(days: _days)).toIso8601String().split('.').first}Z';
    final address = await widget.account.createFileLink(
      accountId: widget.accountId,
      id: widget.node.id,
      mode: _mode,
      expires: expires,
      password: _password.text.isEmpty ? null : _password.text,
    );
    _password.clear();
    if (mounted) setState(() => _made = address);
  });

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final links = _links;
    return _FileDialog(
      title: l.filesText.linksTitle(widget.node.name),
      actions: [KButton(label: l.done, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop())],
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (_made != null) ...[
              Text(l.filesText.linkMade, style: KText.small(k)),
              const SizedBox(height: 6),
              Container(
                padding: const EdgeInsets.fromLTRB(10, 4, 4, 4),
                decoration: BoxDecoration(color: k.raised, borderRadius: BorderRadius.circular(KSize.radiusSmall)),
                child: Row(
                  children: [
                    Expanded(
                      child: KSelectable.text(_made!, key: const ValueKey('link-made'), style: KText.mono(k)),
                    ),
                    KIconButton(
                      icon: LucideIcons.copy,
                      tooltip: l.copy,
                      onPressed: () async {
                        await Clipboard.setData(ClipboardData(text: _made!));
                        if (context.mounted) {
                          KToast.of(context).show(l.copied);
                        }
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
            ],
            if (links == null && _error == null) const KProgressBar(),
            if (links != null && links.isEmpty) Text(l.filesText.noLinks, style: KText.small(k)),
            for (final link in links ?? const <FileLink>[])
              KListRow(
                key: ValueKey('link-${link.id}'),
                dense: true,
                leading: Icon(LucideIcons.link, size: 16, color: k.muted),
                title: Text(linkModeName(l, link.mode), style: KText.label(k)),
                subtitle: switch ([
                  if (link.expires != null) l.filesText.expiresOn(shortDate(context, link.expires!)),
                  if (link.hasPassword) l.filesText.withPassword,
                ].join(' · ')) {
                  '' => null,
                  final text => Text(text, style: KText.small(k)),
                },
                trailing: KIconButton(
                  icon: LucideIcons.trash2,
                  tooltip: l.remove,
                  onPressed: _busy
                      ? null
                      : () => _work(() => widget.account.removeFileLink(accountId: widget.accountId, id: link.id)),
                ),
              ),
            const SizedBox(height: 16),
            if (widget.node.isDirectory) ...[
              KSegmented<String>(
                options: [('view', l.filesText.linkView), ('add', l.filesText.linkAdd), ('drop', l.filesText.linkDrop)],
                value: _mode,
                onChanged: (mode) => setState(() => _mode = mode),
              ),
              const SizedBox(height: 12),
            ],
            Row(
              children: [
                Text(l.filesText.expires, style: KText.small(k)),
                const SizedBox(width: 12),
                KSelect<int>(
                  value: _days,
                  options: [
                    (0, l.filesText.never),
                    for (final days in [1, 7, 30]) (days, l.filesText.inDays(days)),
                  ],
                  onChanged: (days) => setState(() => _days = days),
                  expand: false,
                ),
              ],
            ),
            KTextField(controller: _password, obscureText: true, label: l.filesText.passwordOptional),
            const SizedBox(height: 12),
            KButton(
              key: const ValueKey('link-create'),
              label: l.filesText.createLink,
              icon: LucideIcons.link,
              tone: KTone.primary,
              onPressed: _busy ? null : _create,
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 10),
                child: Text(errorText(_error!), style: KText.small(k).copyWith(color: k.error)),
              ),
          ],
        ),
      ),
    );
  }
}

/// The current content and the earlier versions of a file: each saved, an earlier one made current again.
Future<bool> versionsDialog(BuildContext context, Kernoid account, String accountId, FileNode file) async {
  final changed = await showKDialog<bool>(
    context,
    builder: (_) => _VersionsDialog(account: account, accountId: accountId, file: file),
  );
  return changed ?? false;
}

class _VersionsDialog extends StatefulWidget {
  const _VersionsDialog({required this.account, required this.accountId, required this.file});

  final Kernoid account;
  final String accountId;
  final FileNode file;

  @override
  State<_VersionsDialog> createState() => _VersionsDialogState();
}

class _VersionsDialogState extends State<_VersionsDialog> {
  List<FileVersion>? _versions;
  bool _changed = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final versions = await widget.account.fileVersions(accountId: widget.accountId, id: widget.file.id);
      if (mounted) setState(() => _versions = versions);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _restore(FileVersion version) async {
    final l = AppLocalizations.of(context);
    if (!await confirmAction(context, text: l.filesText.restoreConfirm, confirm: l.filesText.restore)) return;
    try {
      await widget.account.restoreVersion(accountId: widget.accountId, id: widget.file.id, versionId: version.id);
      _changed = true;
      await _load();
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final versions = _versions;
    return _FileDialog(
      title: '${l.filesText.versions} · ${widget.file.name}',
      actions: [KButton(label: l.done, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop(_changed))],
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (versions == null && _error == null) const KProgressBar(),
            for (final (i, v) in (versions ?? const <FileVersion>[]).indexed)
              KListRow(
                key: ValueKey('version-$i'),
                dense: true,
                divider: true,
                leading: Icon(LucideIcons.history, size: 16, color: k.muted),
                title: Text(switch (v.modified ?? v.created) {
                  final at? => longDate(context, at),
                  null => '',
                }, style: KText.label(k)),
                subtitle: Text(bytes(v.size), style: KText.small(k)),
                trailing: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    if (v.isCurrent) KBadge(l.filesText.currentVersion),
                    KIconButton(
                      icon: LucideIcons.download,
                      tooltip: l.save,
                      onPressed: () => saveBlob(
                        context,
                        widget.account,
                        accountId: widget.accountId,
                        blobId: v.blobId,
                        name: widget.file.name,
                        mediaType: v.mediaType ?? 'application/octet-stream',
                      ),
                    ),
                    if (!v.isCurrent)
                      KIconButton(
                        key: ValueKey('restore-$i'),
                        icon: LucideIcons.rotateCcw,
                        tooltip: l.filesText.restore,
                        onPressed: () => _restore(v),
                      ),
                  ],
                ),
              ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 10),
                child: Text(errorText(_error!), style: KText.small(k).copyWith(color: k.error)),
              ),
          ],
        ),
      ),
    );
  }
}

/// Where a node goes: a directory of any store the user may add to, and whether it is copied there or moved.
typedef FileTarget = ({FileStore store, String? directory, bool move});

Future<FileTarget?> chooseTarget(
  BuildContext context,
  Kernoid account,
  List<FileStore> stores,
  FileStore from,
  FileNode node,
) => showKDialog<FileTarget>(
  context,
  builder: (_) => _TargetDialog(account: account, stores: stores, from: from, node: node),
);

class _TargetDialog extends StatefulWidget {
  const _TargetDialog({required this.account, required this.stores, required this.from, required this.node});

  final Kernoid account;
  final List<FileStore> stores;
  final FileStore from;
  final FileNode node;

  @override
  State<_TargetDialog> createState() => _TargetDialogState();
}

class _TargetDialogState extends State<_TargetDialog> {
  late FileStore _store = widget.from;
  final List<FileNode> _path = [];
  List<FileNode>? _directories;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _directories = null;
      _error = null;
    });
    try {
      final nodes = await widget.account.files(accountId: _store.accountId, parentId: _path.lastOrNull?.id);
      if (!mounted) return;
      // Not into itself, nor into the trash.
      setState(
        () => _directories = nodes.where((n) => n.isDirectory && n.role == null && n.id != widget.node.id).toList(),
      );
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  bool get _mayAddHere => _path.isEmpty ? _store.mayCreateTopLevel : !_path.last.hasRights || _path.last.mayAddChildren;

  void _done(bool move) =>
      Navigator.of(context).pop<FileTarget>((store: _store, directory: _path.lastOrNull?.id, move: move));

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final mayMove = !widget.node.hasRights || widget.node.mayDelete;
    return _FileDialog(
      title: '${l.filesText.copyOrMove} · ${widget.node.name}',
      actions: [
        KButton(label: l.cancel, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop()),
        // Within a store a node moves; copies go to other stores (FileNode/copy).
        KButton(
          key: const ValueKey('copy-here'),
          label: l.filesText.copyHere,
          onPressed: _mayAddHere && _store.accountId != widget.from.accountId ? () => _done(false) : null,
        ),
        KButton(
          key: const ValueKey('move-here'),
          label: l.filesText.moveHere,
          tone: KTone.primary,
          onPressed: _mayAddHere && mayMove ? () => _done(true) : null,
        ),
      ],
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (widget.stores.length > 1)
            KSelect<String>(
              key: const ValueKey('target-store'),
              value: _store.accountId,
              expand: true,
              options: [for (final s in widget.stores) (s.accountId, storeName(l, s))],
              onChanged: (id) {
                _store = widget.stores.firstWhere((s) => s.accountId == id);
                _path.clear();
                _load();
              },
            ),
          Wrap(
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              KButton(
                tone: KTone.quiet,
                onPressed: () {
                  _path.clear();
                  _load();
                },
                label: storeName(l, _store),
              ),
              for (final (i, d) in _path.indexed) ...[
                Icon(LucideIcons.chevronRight, size: 14, color: k.faint),
                KButton(
                  tone: KTone.quiet,
                  onPressed: () {
                    _path.removeRange(i + 1, _path.length);
                    _load();
                  },
                  label: d.name,
                ),
              ],
            ],
          ),
          SizedBox(
            height: 260,
            child: _error != null
                ? Text(errorText(_error!), style: KText.small(k).copyWith(color: k.error))
                : _directories == null
                ? const Center(child: KSpinner())
                : ListView(
                    children: [
                      for (final d in _directories!)
                        KListRow(
                          key: ValueKey('target-${d.name}'),
                          dense: true,
                          leading: Icon(LucideIcons.folder, size: 17, color: k.muted),
                          title: Text(d.name, style: KText.label(k)),
                          trailing: Icon(LucideIcons.chevronRight, size: 15, color: k.faint),
                          onTap: () {
                            _path.add(d);
                            _load();
                          },
                        ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}

String storeName(AppLocalizations l, FileStore s) => s.isPersonal ? l.filesText.myFiles : s.name;
