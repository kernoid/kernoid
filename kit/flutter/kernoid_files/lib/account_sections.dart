// SPDX-License-Identifier: MIT
import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/services.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_shell/pages/account.dart';
import 'package:kernoid_shell/pages/login.dart';
import 'package:kernoid_ui/ui.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'documents_provider.dart';
import 'explorer_files.dart';
import 'file_provider.dart';
import 'login_item.dart';
import 'sync_folders.dart';

/// Folders of this computer kept in step with the account's stores: one per store, chosen here.
class SyncSection extends StatelessWidget {
  const SyncSection({super.key, required this.account, required this.sync});

  final Kernoid account;
  final SyncFolders sync;

  Future<void> _choose(FileStore store) async {
    final path = await getDirectoryPath();
    if (path != null) await sync.add(store.accountId, path);
  }

  String _status(BuildContext context, AppLocalizations l, SyncStatus status) {
    if (status.running) return l.syncRunning;
    final lines = <String>[
      if (status.error != null) l.syncFailed(status.error!),
      if (status.last case final last?)
        l.syncDone(
          KTime.fromDateTime(last).format(context),
          status.report?.downloaded ?? 0,
          status.report?.uploaded ?? 0,
        )
      else if (status.error == null)
        l.syncNever,
      if (status.report case final r? when r.conflicts.isNotEmpty || r.failed.isNotEmpty)
        l.syncIssues(r.conflicts.length, r.failed.length),
      if (status.report case final r? when r.locked > 0) l.syncLocked(r.locked),
    ];
    return lines.join('\n');
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final stores = account.fileStores();
    return KSection(
      title: l.syncTitle,
      icon: LucideIcons.folderSync,
      description: l.syncHint,
      child: ListenableBuilder(
        listenable: sync,
        builder: (context, _) => Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (LoginItem.available && sync.folders.isNotEmpty) const _AtLogin(),
            for (final store in stores)
              Padding(
                key: ValueKey('sync-${store.accountId}'),
                padding: const EdgeInsets.symmetric(vertical: 6),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            store.name,
                            style: TextStyle(color: k.text, fontWeight: FontWeight.w600),
                          ),
                          if (sync.folderOf(store.accountId) case final folder?) ...[
                            Text(folder.path, style: TextStyle(color: k.muted, fontSize: 13)),
                            Text(
                              _status(context, l, sync.statusOf(store.accountId)),
                              key: ValueKey('sync-status-${store.accountId}'),
                              style: TextStyle(color: k.muted, fontSize: 13),
                            ),
                          ],
                        ],
                      ),
                    ),
                    if (sync.folderOf(store.accountId) == null)
                      KButton(
                        key: ValueKey('sync-choose-${store.accountId}'),
                        label: l.syncChoose,
                        icon: LucideIcons.folderPlus,
                        onPressed: () => _choose(store),
                      )
                    else ...[
                      KIconButton(
                        key: ValueKey('sync-now-${store.accountId}'),
                        icon: LucideIcons.refreshCw,
                        tooltip: l.syncNow,
                        onPressed: sync.statusOf(store.accountId).running ? null : sync.syncAll,
                      ),
                      KIconButton(
                        key: ValueKey('sync-stop-${store.accountId}'),
                        icon: LucideIcons.folderX,
                        tooltip: l.syncStop,
                        onPressed: () => sync.remove(store.accountId),
                      ),
                    ],
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// Whether the app starts with the computer (its own state, read from the system).
class _AtLogin extends StatefulWidget {
  const _AtLogin();

  @override
  State<_AtLogin> createState() => _AtLoginState();
}

class _AtLoginState extends State<_AtLogin> {
  bool? _on;

  @override
  void initState() {
    super.initState();
    LoginItem.enabled().then((on) => mounted ? setState(() => _on = on) : null);
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Row(
      children: [
        Expanded(
          child: Text(l.syncAtLogin, style: TextStyle(color: context.k.muted, fontSize: 13)),
        ),
        KSwitch(
          key: const ValueKey('sync-at-login'),
          value: _on ?? false,
          onChanged: _on == null
              ? null
              : (value) async {
                  final now = await LoginItem.set(value);
                  if (mounted) setState(() => _on = now);
                },
        ),
      ],
    );
  }
}

/// kernoid's stores in Android's Files app and every document picker (`app/documents_provider.dart`): switched on with
/// a login of its own – the browser opens once more for it.
class DocumentsSection extends StatefulWidget {
  const DocumentsSection({super.key, required this.account});

  final Kernoid account;

  @override
  State<DocumentsSection> createState() => _DocumentsSectionState();
}

class _DocumentsSectionState extends State<DocumentsSection> {
  bool? _enabled;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final on = await DocumentsProvider.enabled();
      if (mounted) setState(() => _enabled = on);
    } catch (error) {
      if (mounted) setState(() => _error = errorText(error));
    }
  }

  Future<void> _switch(bool on) async {
    final l = AppLocalizations.of(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (on) {
        await DocumentsProvider.enable(widget.account);
      } else {
        await DocumentsProvider.disable();
      }
      if (mounted) setState(() => _enabled = on);
    } on PlatformException catch (error) {
      if (mounted) setState(() => _error = error.code == 'CANCELED' ? l.signInCancelled : error.message ?? error.code);
    } catch (error) {
      if (mounted) setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final enabled = _enabled;
    return KSection(
      title: l.documentsTitle,
      icon: LucideIcons.folderOpen,
      description: l.documentsHint,
      trailing: _busy ? const SizedBox.square(dimension: 18, child: KSpinner(stroke: 2)) : null,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (enabled != null) ...[
            Text(
              enabled ? l.documentsOn : l.documentsOff,
              key: const ValueKey('documents-status'),
              style: KText.small(k),
            ),
            const SizedBox(height: 8),
            KButton(
              key: const ValueKey('documents-switch'),
              label: enabled ? l.documentsDisable : l.documentsEnable,
              icon: enabled ? LucideIcons.folderX : LucideIcons.folderPlus,
              tone: enabled ? KTone.normal : KTone.primary,
              onPressed: _busy ? null : () => _switch(!enabled),
            ),
          ],
          if (_error != null) ...[
            const SizedBox(height: 8),
            Text(_error!, style: KText.small(k).copyWith(color: k.error)),
          ],
        ],
      ),
    );
  }
}

/// kernoid's stores in Windows' Explorer: set up with a login of its own (kernoid's login page once more), shown with
/// its folders and how the last round went, and taken out again.
class ExplorerSection extends StatefulWidget {
  const ExplorerSection({super.key, required this.account, required this.explorer});

  final Kernoid account;
  final ExplorerFiles explorer;

  @override
  State<ExplorerSection> createState() => _ExplorerSectionState();
}

class _ExplorerSectionState extends State<ExplorerSection> {
  bool _signingIn = false;
  String? _error;

  Future<void> _setUp() async {
    final l = AppLocalizations.of(context);
    setState(() {
      _signingIn = true;
      _error = null;
    });
    try {
      // A login of its own for the shell – never the app's: two holders would end it at the next renewal.
      final shell = await signInWithBrowser(widget.account.server, widget.account.username);
      await widget.explorer.setUp(shell);
    } on PlatformException catch (error) {
      if (mounted) setState(() => _error = error.code == 'CANCELED' ? l.signInCancelled : error.message ?? error.code);
    } catch (error) {
      if (mounted) setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _signingIn = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    return KSection(
      title: l.explorerTitle,
      icon: LucideIcons.hardDrive,
      description: l.explorerHint,
      child: ListenableBuilder(
        listenable: widget.explorer,
        builder: (context, _) {
          final explorer = widget.explorer;
          final status = explorer.status;
          final signedOut = status?.signedOut ?? false;
          final error = _error ?? explorer.error;
          final lines = <String>[
            if (explorer.busy || _signingIn) l.explorerStarting,
            if (signedOut) l.explorerSignedOut,
            if (error != null) l.explorerFailed(error),
            if (DateTime.tryParse(status?.lastRound ?? '') case final last?)
              l.explorerLast(KTime.fromDateTime(last.toLocal()).format(context)),
            ...?status?.problems.take(5),
          ];
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (final folder in status?.folders ?? const <String>[])
                Text(folder, style: TextStyle(color: k.text, fontSize: 13)),
              for (final line in lines)
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Text(line, style: TextStyle(color: k.muted, fontSize: 13)),
                ),
              const SizedBox(height: 8),
              if (explorer.configured && !signedOut)
                KButton(
                  key: const ValueKey('explorer-remove'),
                  label: l.explorerRemove,
                  icon: LucideIcons.folderX,
                  onPressed: explorer.busy ? null : explorer.remove,
                )
              else
                KButton(
                  key: const ValueKey('explorer-set-up'),
                  label: l.explorerSetUp,
                  icon: LucideIcons.folderSymlink,
                  onPressed: explorer.busy || _signingIn ? null : _setUp,
                ),
            ],
          );
        },
      ),
    );
  }
}

/// The stores in Finder and the Files app (macOS, iOS): the File Provider extension, with a login of its own – signing
/// in once more in the browser when it is turned on (`app/file_provider.dart`).
class FileProviderSection extends StatefulWidget {
  const FileProviderSection({super.key, required this.account});

  final Kernoid account;

  @override
  State<FileProviderSection> createState() => _FileProviderSectionState();
}

class _FileProviderSectionState extends KSettingsState<FileProviderSection> {
  List<String> _shown = const [];

  @override
  Future<void> load() async => _shown = await FileProvider.shown();

  Future<void> _turnOn() => save(() async {
    final kept = await FileProvider.login(widget.account);
    await FileProvider.enable(widget.account, kept);
    _shown = await FileProvider.shown();
  });

  Future<void> _update() => save(() async {
    await FileProvider.enable(widget.account, null);
    _shown = await FileProvider.shown();
  });

  Future<void> _turnOff() => save(() async {
    await FileProvider.disable();
    _shown = await FileProvider.shown();
  });

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final names = [
      for (final store in widget.account.fileStores())
        if (_shown.contains(store.accountId)) store.name,
    ];
    return KSection(
      title: Platform.isIOS ? l.fileProviderTitleIos : l.fileProviderTitle,
      icon: LucideIcons.hardDrive,
      description: l.fileProviderHint,
      child: !loaded
          ? const KProgressBar()
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (_shown.isNotEmpty) ...[
                  Text(
                    l.fileProviderShown(names.join(', ')),
                    key: const ValueKey('file-provider-shown'),
                    style: TextStyle(color: k.muted, fontSize: 13),
                  ),
                  const SizedBox(height: 10),
                ],
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    if (_shown.isEmpty)
                      KButton(
                        key: const ValueKey('file-provider-on'),
                        label: l.fileProviderOn,
                        icon: LucideIcons.logIn,
                        tone: KTone.primary,
                        onPressed: busy ? null : _turnOn,
                      )
                    else ...[
                      KButton(
                        key: const ValueKey('file-provider-update'),
                        label: l.fileProviderUpdate,
                        icon: LucideIcons.refreshCw,
                        onPressed: busy ? null : _update,
                      ),
                      KButton(
                        key: const ValueKey('file-provider-off'),
                        label: l.fileProviderOff,
                        icon: LucideIcons.power,
                        tone: KTone.quiet,
                        onPressed: busy ? null : _turnOff,
                      ),
                    ],
                  ],
                ),
                noteLine('file-provider-note'),
              ],
            ),
    );
  }
}
