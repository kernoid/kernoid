// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';
import 'package:path_provider/path_provider.dart';

import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_shell/app/save.dart';
import 'package:kernoid_shell/widgets/states.dart';
import 'package:kernoid_ui/ui.dart';

import 'files.dart' show fileIcon;
import 'l10n/files_text.dart';
import 'viewer.dart';

/// Opens the store of vaults on spaces of `account` on this device once (RFC 0010, 5): a file in the app's support
/// directory, one per account, and this device's name in the vaults made from its host name.
Future<void> openVaults(Kernoid account) async {
  if (_opened[account] ?? false) return;
  final key = base64Url.encode(utf8.encode('${account.server}|${account.username}')).replaceAll('=', '');
  final directory = Directory('${(await getApplicationSupportDirectory()).path}/vaults');
  await directory.create(recursive: true);
  await account.openVaults(path: '${directory.path}/$key.db', device: Platform.localHostname);
  _opened[account] = true;
}

/// The accounts whose store of vaults is open in this run of the app.
final _opened = Expando<bool>('vaults opened');

/// A vault on a space (RFC 0010, 5): what lies in it lives in the space – directories, files, names and versions end
/// to end encrypted – and is shown here, not by the file store, which only knows the vault's directory. Directories
/// open below each other; files open in the viewer or are saved; uploading takes files and whole directories; rename,
/// move to another directory of the vault, the vault's own trash and removing for good.
class SpaceVaultView extends StatefulWidget {
  const SpaceVaultView({super.key, required this.account, required this.accountId, required this.vault, this.onClose});

  final Kernoid account;

  /// The store the vault's directory lies in.
  final String accountId;
  final FileNode vault;

  /// Back to the store.
  final VoidCallback? onClose;

  @override
  State<SpaceVaultView> createState() => _SpaceVaultViewState();
}

class _SpaceVaultViewState extends State<SpaceVaultView> {
  /// The directories from the vault's top down to the one shown: ids and names.
  final List<({String id, String name})> _path = [];
  List<VaultEntry>? _entries;
  String? _name;

  /// False while no member gave the account access; null while that is not known yet.
  bool? _entered;
  bool _trash = false;
  bool _busy = false;
  Object? _error;
  List<({String name, int sent, int total})> _uploads = [];

  String get _space => widget.vault.space!;
  String? get _here => _path.lastOrNull?.id;

  @override
  void initState() {
    super.initState();
    _enter();
  }

  Future<void> _enter() async {
    setState(() => _error = null);
    try {
      await openVaults(widget.account);
      final entered = await widget.account.enterVault(
        accountId: widget.accountId,
        vaultId: widget.vault.id,
        space: _space,
      );
      final name = entered ? await widget.account.vaultName(vaultId: widget.vault.id, space: _space) : null;
      if (!mounted) return;
      setState(() {
        _entered = entered;
        _name = name;
      });
      if (entered) await _load();
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _load() async {
    try {
      final entries = await widget.account.vaultEntries(vaultId: widget.vault.id, space: _space, directory: _here);
      if (mounted) setState(() => _entries = entries);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  /// Reads what is new in the vault, then shows it.
  Future<void> _refresh() async {
    try {
      await widget.account.enterVault(accountId: widget.accountId, vaultId: widget.vault.id, space: _space);
    } catch (error) {
      if (mounted) setState(() => _error = error);
      return;
    }
    await _load();
  }

  Future<void> _run(Future<void> Function() work) async {
    final messenger = KToast.of(context);
    final l = AppLocalizations.of(context);
    setState(() => _busy = true);
    try {
      await work();
    } catch (error) {
      messenger.show(l.error(errorText(error)));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
    await _load();
  }

  void _openDirectory(VaultEntry entry) {
    setState(() {
      _path.add((id: entry.id, name: entry.name));
      _entries = null;
    });
    _load();
  }

  void _up([int to = -1]) {
    setState(() {
      if (to < 0) {
        _path.removeLast();
      } else {
        _path.removeRange(to, _path.length);
      }
      _entries = null;
    });
    _load();
  }

  Future<void> _newFolder() async {
    final l = AppLocalizations.of(context);
    final name = await askText(context, title: l.newFolder, confirm: l.create, label: l.filesText.newFolderName);
    if (name == null) return;
    await _run(
      () => widget.account.vaultMakeDirectory(vaultId: widget.vault.id, space: _space, parent: _here, name: name),
    );
  }

  Future<void> _upload({bool folder = false}) async {
    final paths = folder ? [?await getDirectoryPath()] : [for (final f in await openFiles()) f.path];
    if (paths.isEmpty || !mounted) return;
    setState(() => _uploads = []);
    final done = Completer<void>();
    widget.account
        .vaultUpload(vaultId: widget.vault.id, space: _space, parent: _here, paths: paths)
        .listen(
          (p) {
            if (!mounted || p.index > _uploads.length) return;
            final entry = (name: p.name, sent: p.sent, total: p.total);
            setState(() => p.index == _uploads.length ? _uploads.add(entry) : _uploads[p.index] = entry);
          },
          onError: (Object error) {
            if (!done.isCompleted) done.completeError(error);
          },
          onDone: () {
            if (!done.isCompleted) done.complete();
          },
        );
    await _run(() => done.future);
    if (mounted) setState(() => _uploads = []);
  }

  Future<String> _fetch(VaultEntry entry, String directory) => widget.account.vaultSave(
    vaultId: widget.vault.id,
    space: _space,
    entry: entry.id,
    name: entry.name,
    directory: directory,
  );

  void _view(VaultEntry entry) => viewFile(
    context,
    name: entry.name,
    mediaType: entry.mediaType,
    fetch: (directory) => _fetch(entry, directory),
    onSave: () => _save(entry),
  );

  Future<void> _save(VaultEntry entry) async {
    final messenger = KToast.of(context);
    final l = AppLocalizations.of(context);
    try {
      final path = await _fetch(entry, await saveDirectory());
      messenger.show(l.savedTo(path));
    } catch (error) {
      messenger.show(l.error(errorText(error)));
    }
  }

  Future<void> _rename(VaultEntry entry) async {
    final l = AppLocalizations.of(context);
    final name = await askText(
      context,
      title: l.rename,
      confirm: l.rename,
      initial: entry.name,
      label: l.filesText.newName,
    );
    if (name == null || name == entry.name) return;
    await _run(
      () => widget.account.vaultRename(
        vaultId: widget.vault.id,
        space: _space,
        parent: _here,
        entry: entry.id,
        name: name,
      ),
    );
  }

  /// Every directory of the vault but `entry` and what lies below it, with its path – where it may move.
  Future<List<({String? id, String path})>> _targets(VaultEntry entry) async {
    final l = AppLocalizations.of(context);
    final found = <({String? id, String path})>[(id: null, path: l.filesText.vaultTop)];
    final pending = <({String? id, String path})>[(id: null, path: '')];
    while (pending.isNotEmpty) {
      final at = pending.removeLast();
      final inside = await widget.account.vaultEntries(vaultId: widget.vault.id, space: _space, directory: at.id);
      for (final e in inside.where((e) => e.isDirectory && !e.trashed && e.id != entry.id)) {
        final path = at.path.isEmpty ? e.name : '${at.path} / ${e.name}';
        found.add((id: e.id, path: path));
        pending.add((id: e.id, path: path));
      }
    }
    return found.where((t) => t.id != _here).toList();
  }

  Future<void> _moveTo(VaultEntry entry) async {
    final l = AppLocalizations.of(context);
    final targets = await _targets(entry);
    if (!mounted) return;
    final chosen = await showKDialog<({String? id, String path})>(
      context,
      builder: (context) => KDialog(
        title: l.filesText.vaultMoveTo,
        width: 440,
        scrollable: true,
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            for (final t in targets)
              KListRow(
                key: ValueKey('vault-target-${t.path}'),
                leading: Icon(LucideIcons.folder, size: 18, color: context.k.accent),
                title: Text(t.path, style: KText.label(context.k)),
                onTap: () => Navigator.of(context).pop(t),
              ),
          ],
        ),
        actions: [KButton(label: l.cancel, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop())],
      ),
    );
    if (chosen == null) return;
    await _run(
      () => widget.account.vaultMove(
        vaultId: widget.vault.id,
        space: _space,
        from: _here,
        entry: entry.id,
        to: chosen.id,
      ),
    );
  }

  Future<void> _trashIt(VaultEntry entry, bool trashed) => _run(
    () => widget.account.vaultSetTrashed(
      vaultId: widget.vault.id,
      space: _space,
      parent: _here,
      entry: entry.id,
      trashed: trashed,
    ),
  );

  Future<void> _remove(VaultEntry entry) async {
    final l = AppLocalizations.of(context);
    final sure = await confirmAction(
      context,
      text: l.filesText.deleteFileConfirm(entry.name),
      confirm: l.filesText.deleteFileForGood,
      danger: true,
    );
    if (!sure) return;
    await _run(
      () => widget.account.vaultRemove(vaultId: widget.vault.id, space: _space, parent: _here, entry: entry.id),
    );
  }

  Future<void> _menu(VaultEntry entry, Offset position) async {
    final l = AppLocalizations.of(context);
    final choice = await showPointMenu<String>(
      context,
      position: position,
      items: [
        if (!entry.isDirectory && !entry.trashed) ('open', LucideIcons.eye, l.open, false),
        if (!entry.isDirectory) ('save', LucideIcons.download, l.save, false),
        if (!entry.trashed) ('rename', LucideIcons.pencil, l.rename, false),
        if (!entry.trashed) ('move', LucideIcons.folderInput, l.filesText.vaultMoveTo, false),
        if (entry.trashed) ('restore', LucideIcons.undo2, l.filesText.vaultRestore, false),
        if (!entry.trashed) ('trash', LucideIcons.trash2, l.delete, true),
        if (entry.trashed) ('remove', LucideIcons.trash2, l.filesText.deleteFileForGood, true),
      ],
    );
    if (!mounted) return;
    switch (choice) {
      case 'open':
        _view(entry);
      case 'save':
        await _save(entry);
      case 'rename':
        await _rename(entry);
      case 'move':
        await _moveTo(entry);
      case 'restore':
        await _trashIt(entry, false);
      case 'trash':
        await _trashIt(entry, true);
      case 'remove':
        await _remove(entry);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final open = _entered ?? false;
    final actions = [
      if (open && !_trash) ...[
        KIconButton(
          key: const ValueKey('vault-new-folder'),
          icon: LucideIcons.folderPlus,
          tooltip: l.newFolder,
          onPressed: _busy ? null : _newFolder,
        ),
        KIconButton(
          key: const ValueKey('vault-upload'),
          icon: LucideIcons.upload,
          tooltip: l.filesText.upload,
          onPressed: _busy ? null : _upload,
        ),
        if (!Platform.isIOS && !Platform.isAndroid)
          KIconButton(
            key: const ValueKey('vault-upload-folder'),
            icon: LucideIcons.folderUp,
            tooltip: l.filesText.uploadFolder,
            onPressed: _busy ? null : () => _upload(folder: true),
          ),
      ],
      if (open)
        KIconButton(
          key: const ValueKey('vault-trash'),
          icon: _trash ? LucideIcons.folderLock : LucideIcons.trash2,
          tooltip: _trash ? l.filesText.vaultTrashHide : l.filesText.vaultTrash,
          onPressed: () => setState(() => _trash = !_trash),
        ),
      KIconButton(icon: LucideIcons.refreshCw, tooltip: l.filesText.refresh, onPressed: _busy ? null : _refresh),
    ];
    return Column(
      children: [
        _VaultTrail(
          name: _name ?? l.filesText.lockedVault,
          path: [for (final p in _path) p.name],
          onClose: widget.onClose,
          onOpen: (depth) => depth < _path.length ? _up(depth) : null,
          actions: actions,
        ),
        if (_uploads.isNotEmpty)
          for (final u in _uploads)
            KListRow(
              leading: Icon(LucideIcons.upload, size: 16, color: k.muted),
              title: Text(u.name, style: KText.small(k), maxLines: 1, overflow: TextOverflow.ellipsis),
              trailing: Text(u.total == 0 ? '' : '${(u.sent * 100 / u.total).round()} %', style: KText.small(k)),
            ),
        Expanded(child: _body(l, k)),
      ],
    );
  }

  Widget _body(AppLocalizations l, KTokens k) {
    if (_error != null) return ErrorView(error: _error!, onRetry: _enter);
    if (_entered == null) return Center(child: Text(l.filesText.vaultOpening, style: KText.small(k)));
    if (_entered == false) return EmptyView(l.filesText.vaultWaiting, icon: LucideIcons.folderLock);
    final entries = _entries?.where((e) => e.trashed == _trash).toList();
    if (entries == null) return const Center(child: KSpinner());
    if (entries.isEmpty) {
      return EmptyView(_trash ? l.filesText.trashEmptyNote : l.filesText.folderEmpty, icon: LucideIcons.folderOpen);
    }
    return KRefresh(
      onRefresh: _refresh,
      child: ListView(
        children: [
          for (final e in entries)
            GestureDetector(
              onSecondaryTapUp: (d) => _menu(e, d.globalPosition),
              onLongPressEnd: (d) => _menu(e, d.globalPosition),
              child: KListRow(
                key: ValueKey('vault-entry-${e.name}'),
                divider: true,
                leading: Icon(
                  e.isDirectory ? LucideIcons.folder : fileIcon(e.mediaType),
                  size: 19,
                  color: e.isDirectory ? k.accent : k.muted,
                ),
                title: Text(e.name, maxLines: 1, overflow: TextOverflow.ellipsis, style: KText.label(k)),
                subtitle: e.isDirectory
                    ? null
                    : Text(
                        [bytes(e.size), if (e.modified != null) shortDate(context, e.modified!)].join(' · '),
                        style: KText.small(k),
                      ),
                trailing: Builder(
                  builder: (button) => KIconButton(
                    key: ValueKey('vault-more-${e.name}'),
                    icon: LucideIcons.ellipsis,
                    tooltip: l.filesText.more,
                    onPressed: _busy
                        ? null
                        : () {
                            final box = button.findRenderObject()! as RenderBox;
                            _menu(e, box.localToGlobal(box.size.bottomLeft(Offset.zero)));
                          },
                  ),
                ),
                onTap: e.trashed ? null : (e.isDirectory ? () => _openDirectory(e) : () => _view(e)),
              ),
            ),
        ],
      ),
    );
  }
}

/// The vault's name and the directories down to the one shown, each a way back; the actions at the end.
class _VaultTrail extends StatelessWidget {
  const _VaultTrail({
    required this.name,
    required this.path,
    required this.onClose,
    required this.onOpen,
    required this.actions,
  });

  final String name;
  final List<String> path;
  final VoidCallback? onClose;

  /// Opens the directory at that depth – 0 being the vault's top.
  final void Function(int depth) onOpen;
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final steps = [name, ...path];
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: k.line)),
      ),
      child: Row(
        children: [
          if (onClose != null)
            KIconButton(
              key: const ValueKey('vault-close'),
              icon: LucideIcons.arrowLeft,
              tooltip: AppLocalizations.of(context).back,
              onPressed: onClose,
            ),
          Icon(LucideIcons.folderLock, size: 17, color: k.accent),
          const SizedBox(width: 6),
          Expanded(
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              reverse: true,
              child: Row(
                children: [
                  for (var i = 0; i < steps.length; i++) ...[
                    if (i > 0) Icon(LucideIcons.chevronRight, size: 14, color: k.muted),
                    GestureDetector(
                      onTap: () => onOpen(i),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 4),
                        child: Text(steps[i], style: i == steps.length - 1 ? KText.label(k) : KText.small(k)),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
          ...actions,
        ],
      ),
    );
  }
}
