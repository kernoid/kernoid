// SPDX-License-Identifier: MIT

import 'package:flutter/services.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_shell/app/save.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';
import 'package:kernoid_shell/widgets/e2e.dart';

import 'html_body.dart';

import 'package:kernoid_shell/widgets/states.dart';

import 'compose.dart';

import 'package:kernoid_shell/pages/home.dart';

const _pageSize = 50;

/// Mail: the user's mailbox and the shared ones granted to them, each a tree of folders; a folder's messages – or,
/// searched, the whole mailbox's –, chosen one by one or several at once to mark, move or delete; one message read.
/// Side by side on wide screens, one after another on narrow ones.
class MailPage extends StatefulWidget {
  const MailPage({super.key, required this.account});

  final Kernoid account;

  @override
  State<MailPage> createState() => _MailPageState();
}

class _MailPageState extends State<MailPage> {
  late final List<MailAccount> _accounts = widget.account.mailAccounts();

  /// The folders of each mail account, once loaded.
  final Map<String, List<Mailbox>> _boxes = {};

  /// The account and folder shown.
  late String _accountId = _accounts.first.id;
  Mailbox? _mailbox;

  final List<EmailSummary> _emails = [];
  int _total = 0;
  String? _open;
  Object? _error;
  bool _loading = false;

  /// The search, over the whole account; empty: the folder.
  final _search = TextEditingController();
  String _query = '';

  /// The emails chosen for an action, and where a range chosen with Shift begins.
  final Set<String> _chosen = {};
  int? _anchor;

  MailAccount get _current => _accounts.firstWhere((a) => a.id == _accountId);

  @override
  void initState() {
    super.initState();
    _loadMailboxes();
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  /// The folders of every account; the one shown keeps its folder, or opens its inbox.
  Future<void> _loadMailboxes() async {
    setState(() => _error = null);
    try {
      for (final a in _accounts) {
        final boxes = await widget.account.mailboxes(accountId: a.id);
        if (!mounted) return;
        setState(() => _boxes[a.id] = boxes);
      }
      final boxes = _boxes[_accountId] ?? const <Mailbox>[];
      final keep = boxes.where((b) => b.id == _mailbox?.id).firstOrNull;
      setState(() => _mailbox = keep ?? boxes.where((b) => b.role == 'inbox').firstOrNull ?? boxes.firstOrNull);
      await _loadEmails(reset: true);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _loadEmails({required bool reset}) async {
    final mailbox = _mailbox;
    final query = _query;
    if (mailbox == null && query.isEmpty) return;
    final account = _accountId;
    setState(() => _loading = true);
    try {
      final page = await widget.account.emails(
        accountId: account,
        mailboxId: query.isEmpty ? mailbox?.id : null,
        search: query,
        position: reset ? 0 : _emails.length,
        limit: _pageSize,
      );
      if (!mounted || _accountId != account || _mailbox?.id != mailbox?.id || _query != query) return;
      setState(() {
        if (reset) {
          _emails.clear();
          _chosen.clear();
        }
        _emails.addAll(page.emails);
        _total = page.total;
        _error = null;
      });
    } catch (error) {
      if (mounted) setState(() => _error = error);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _select(String accountId, Mailbox mailbox) {
    setState(() {
      _accountId = accountId;
      _mailbox = mailbox;
      _open = null;
      _emails.clear();
      _chosen.clear();
      _search.clear();
      _query = '';
    });
    _loadEmails(reset: true);
  }

  void _runSearch(String text) {
    setState(() {
      _query = text.trim();
      _open = null;
      _emails.clear();
    });
    _loadEmails(reset: true);
  }

  Future<void> _write() async {
    if (await writeMessage(context, widget.account) && mounted) _loadMailboxes();
  }

  /// A click: opens the email – or, with Ctrl or ⌘, adds it to the chosen ones, with Shift the range up to it.
  void _tap(int index, bool wide) {
    final keys = HardwareKeyboard.instance;
    final email = _emails[index];
    if (keys.isShiftPressed && _anchor != null) {
      final (from, to) = _anchor! < index ? (_anchor!, index) : (index, _anchor!);
      setState(() => _chosen.addAll([for (var i = from; i <= to; i++) _emails[i].id]));
      return;
    }
    if (keys.isControlPressed || keys.isMetaPressed || _chosen.isNotEmpty) {
      _toggle(index);
      return;
    }
    _anchor = index;
    _openEmail(email, wide);
  }

  void _toggle(int index) {
    final id = _emails[index].id;
    setState(() {
      if (!_chosen.remove(id)) _chosen.add(id);
      _anchor = index;
    });
  }

  void _openEmail(EmailSummary email, bool wide) {
    if (wide) {
      setState(() => _open = email.id);
    } else {
      Navigator.of(context).push(
        KPageRoute(
          builder: (_) => KScaffold(
            topBar: const KTopBar(),
            body: EmailView(
              account: widget.account,
              accountId: _accountId,
              id: email.id,
              onUnlocked: () => _loadEmails(reset: true),
              onSent: _loadMailboxes,
            ),
          ),
        ),
      );
    }
    // It is seen now; the server marks it while it fetches it.
    final i = _emails.indexWhere((e) => e.id == email.id);
    if (i >= 0 && !email.seen) {
      setState(() => _emails[i] = _with(email, seen: true));
    }
  }

  List<EmailSummary> get _chosenEmails => _emails.where((e) => _chosen.contains(e.id)).toList();

  /// Marks the chosen emails: read or flagged, on when any of them is not yet.
  Future<void> _mark(String keyword) async {
    final chosen = _chosenEmails;
    final on = keyword == r'$seen' ? chosen.any((e) => !e.seen) : chosen.any((e) => !e.flagged);
    await _act(
      () => widget.account.markEmails(
        accountId: _accountId,
        ids: [for (final e in chosen) e.id],
        keyword: keyword,
        on_: on,
      ),
      keep: true,
      update: (e) => keyword == r'$seen' ? _with(e, seen: on) : _with(e, flagged: on),
    );
  }

  Future<void> _moveTo(Mailbox target) async {
    final ids = [for (final e in _chosenEmails) e.id];
    await _act(() => widget.account.moveEmails(accountId: _accountId, ids: ids, mailboxId: target.id));
  }

  /// Deletes the chosen emails: into the Trash – out of the Trash or Junk for good, once confirmed.
  Future<void> _delete() async {
    final l = AppLocalizations.of(context);
    final ids = [for (final e in _chosenEmails) e.id];
    final trash = (_boxes[_accountId] ?? const <Mailbox>[]).where((b) => b.role == 'trash').firstOrNull;
    final forGood = trash == null || _mailbox?.role == 'trash' || _mailbox?.role == 'junk';
    if (forGood) {
      final sure = await showKDialog<bool>(
        context,
        builder: (context) => KDialog(
          content: Text(l.deleteForGood(ids.length)),
          actions: [
            KButton(label: l.cancel, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop(false)),
            KButton(
              key: const ValueKey('confirm-delete'),
              label: l.delete,
              tone: KTone.danger,
              onPressed: () => Navigator.of(context).pop(true),
            ),
          ],
        ),
      );
      if (!(sure ?? false)) return;
      await _act(() => widget.account.destroyEmails(accountId: _accountId, ids: ids));
    } else {
      await _act(() => widget.account.moveEmails(accountId: _accountId, ids: ids, mailboxId: trash.id));
    }
  }

  /// Runs an action on the chosen emails; they leave the list unless `keep`, then `update` shows the change.
  Future<void> _act(
    Future<void> Function() action, {
    bool keep = false,
    EmailSummary Function(EmailSummary)? update,
  }) async {
    final messenger = KToast.of(context);
    final l = AppLocalizations.of(context);
    try {
      await action();
      if (!mounted) return;
      setState(() {
        if (keep) {
          for (final (i, e) in _emails.indexed.toList()) {
            if (_chosen.contains(e.id) && update != null) _emails[i] = update(e);
          }
        } else {
          _emails.removeWhere((e) => _chosen.contains(e.id));
          _total -= _chosen.length;
          if (_chosen.contains(_open)) _open = null;
          _chosen.clear();
        }
      });
      _refreshCounts();
    } catch (error) {
      messenger.show(l.error(errorText(error)));
    }
  }

  /// What can be done with a folder: a folder in it, and – unless it has a role (Inbox, Sent …) – renaming, moving
  /// and deleting it; the Trash and Junk are emptied.
  Future<void> _folderMenu(String accountId, Mailbox box, Offset position) async {
    final l = AppLocalizations.of(context);
    final own = box.role == null;
    final choice = await showPointMenu<String>(
      context,
      position: position,
      items: [
        ('new', LucideIcons.folderPlus, l.newSubfolder, false),
        if (own) ('rename', LucideIcons.pencil, l.rename, false),
        if (own) ('move', LucideIcons.folderInput, l.moveFolder, false),
        if (box.role == 'trash' || box.role == 'junk') ('empty', LucideIcons.trash, l.emptyFolder, true),
        if (own) ('delete', LucideIcons.trash2, l.deleteFolder, true),
      ],
    );
    if (choice == null || !mounted) return;
    await switch (choice) {
      'new' => _newFolder(accountId, box.id),
      'rename' => _renameFolder(accountId, box),
      'move' => _moveFolder(accountId, box),
      'empty' => _emptyFolder(accountId, box),
      _ => _deleteFolder(accountId, box),
    };
  }

  Future<void> _newFolder(String accountId, String? parent) async {
    final l = AppLocalizations.of(context);
    final name = await askText(context, title: l.newFolder, confirm: l.create, label: l.name);
    if (name == null) return;
    await _folderAction(
      accountId,
      () => widget.account.createMailbox(accountId: accountId, name: name, parentId: parent),
    );
  }

  Future<void> _renameFolder(String accountId, Mailbox box) async {
    final l = AppLocalizations.of(context);
    final name = await askText(context, title: l.rename, confirm: l.save, initial: box.name, label: l.name);
    if (name == null || name == box.name) return;
    await _folderAction(accountId, () => widget.account.renameMailbox(accountId: accountId, id: box.id, name: name));
  }

  Future<void> _moveFolder(String accountId, Mailbox box) async {
    final l = AppLocalizations.of(context);
    final boxes = _boxes[accountId] ?? const <Mailbox>[];
    // Not into itself or a folder of its own.
    final below = <String>{box.id};
    for (final (b, _) in mailboxTree(boxes)) {
      if (b.parentId != null && below.contains(b.parentId)) below.add(b.id);
    }
    final target = await showKDialog<(bool, String?)>(
      context,
      builder: (context) => KDialog(
        title: l.moveFolderTo(box.name),
        content: SizedBox(
          width: 360,
          height: 360,
          child: ListView(
            children: [
              KSideItem(
                key: const ValueKey('folder-top'),
                icon: LucideIcons.arrowUpToLine,
                label: l.topLevel,
                onTap: () => Navigator.of(context).pop((true, null)),
              ),
              for (final (b, depth) in mailboxTree(boxes))
                if (!below.contains(b.id))
                  KSideItem(
                    key: ValueKey('folder-to-${b.id}'),
                    icon: mailboxIcon(b),
                    label: mailboxName(l, b),
                    indent: depth * 16.0,
                    onTap: () => Navigator.of(context).pop((true, b.id)),
                  ),
            ],
          ),
        ),
        actions: [KButton(label: l.cancel, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop())],
      ),
    );
    if (target == null || target.$2 == box.parentId) return;
    await _folderAction(
      accountId,
      () => widget.account.moveMailbox(accountId: accountId, id: box.id, parentId: target.$2),
    );
  }

  Future<void> _emptyFolder(String accountId, Mailbox box) async {
    final l = AppLocalizations.of(context);
    if (!await confirmAction(
      context,
      text: l.emptyFolderConfirm(mailboxName(l, box)),
      confirm: l.emptyFolder,
      danger: true,
    )) {
      return;
    }
    await _folderAction(accountId, () => widget.account.emptyMailbox(accountId: accountId, id: box.id));
    if (_mailbox?.id == box.id) _loadEmails(reset: true);
  }

  Future<void> _deleteFolder(String accountId, Mailbox box) async {
    final l = AppLocalizations.of(context);
    final text = box.total > 0 ? l.deleteFolderWithEmails(box.name, box.total) : l.deleteFolderConfirm(box.name);
    if (!await confirmAction(context, text: text, confirm: l.deleteFolder, danger: true)) return;
    await _folderAction(
      accountId,
      () => widget.account.destroyMailbox(accountId: accountId, id: box.id, withEmails: box.total > 0),
    );
  }

  /// Runs a change of folders and shows the account's folders as they are now; the folder shown, if it went, gives way
  /// to the inbox.
  Future<void> _folderAction(String accountId, Future<Object?> Function() action) async {
    final messenger = KToast.of(context);
    final l = AppLocalizations.of(context);
    try {
      await action();
      final boxes = await widget.account.mailboxes(accountId: accountId);
      if (!mounted) return;
      setState(() => _boxes[accountId] = boxes);
      if (accountId == _accountId && !boxes.any((b) => b.id == _mailbox?.id)) {
        final inbox = boxes.where((b) => b.role == 'inbox').firstOrNull ?? boxes.firstOrNull;
        if (inbox != null) _select(accountId, inbox);
      }
    } catch (error) {
      messenger.show(l.error(errorText(error)));
    }
  }

  /// On phones: the folders of every account on a page of their own, chosen with a tap, managed with a long press.
  Future<void> _folderPage() async {
    final l = AppLocalizations.of(context);
    await Navigator.of(context).push(
      KPageRoute(
        builder: (page) => StatefulBuilder(
          builder: (page, rebuild) => KScaffold(
            topBar: KTopBar(title: l.folders),
            body: _Mailboxes(
              accounts: _accounts,
              boxes: _boxes,
              account: _accountId,
              selected: _mailbox?.id,
              onSelect: (accountId, box) {
                Navigator.of(page).pop();
                _select(accountId, box);
              },
              onMenu: (accountId, box, position) async {
                await _folderMenu(accountId, box, position);
                rebuild(() {});
              },
              onNew: (accountId) async {
                await _newFolder(accountId, null);
                rebuild(() {});
              },
            ),
          ),
        ),
      ),
    );
  }

  /// The folders again, for their counts.
  Future<void> _refreshCounts() async {
    try {
      final boxes = await widget.account.mailboxes(accountId: _accountId);
      if (mounted) setState(() => _boxes[_accountId] = boxes);
    } catch (_) {
      // The counts stay as they were.
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final wide = MediaQuery.sizeOf(context).width >= wideLayout;
    if (_boxes.isEmpty) {
      return _error != null ? ErrorView(error: _error!, onRetry: _loadMailboxes) : const Center(child: KSpinner());
    }
    final list = Column(
      children: [
        _chosen.isEmpty
            ? KSearchField(
                fieldKey: const ValueKey('mail-search'),
                controller: _search,
                onSubmitted: _runSearch,
                hint: l.searchMail,
              )
            : _ChosenBar(
                count: _chosen.length,
                boxes: _boxes[_accountId] ?? const [],
                current: _mailbox?.id,
                readOnly: _current.readOnly,
                onClear: () => setState(_chosen.clear),
                onAll: () => setState(() => _chosen.addAll(_emails.map((e) => e.id))),
                onRead: () => _mark(r'$seen'),
                onFlag: () => _mark(r'$flagged'),
                onMove: _moveTo,
                onDelete: _delete,
              ),
        Expanded(
          child: _EmailList(
            emails: _emails,
            total: _total,
            loading: _loading,
            selected: _open,
            chosen: _chosen,
            searching: _query.isNotEmpty,
            error: _error,
            onTap: (i) => _tap(i, wide),
            onChoose: _toggle,
            onMore: () => _loadEmails(reset: false),
            onRefresh: _loadMailboxes,
          ),
        ),
      ],
    );
    final title = _query.isNotEmpty
        ? l.searchResults
        : _mailbox == null
        ? ''
        : mailboxName(l, _mailbox!);
    if (!wide) {
      final k = context.k;
      return KScaffold(
        topBar: KTopBar(
          leading: const SizedBox(width: 6),
          actions: [
            KIconButton(
              key: const ValueKey('manage-folders'),
              icon: LucideIcons.folderTree,
              tooltip: l.folders,
              onPressed: _folderPage,
            ),
          ],
          titleWidget: Align(
            alignment: Alignment.centerLeft,
            child: KMenuButton<(String, Mailbox)>(
              key: const ValueKey('mailbox-menu'),
              tooltip: l.mailboxes,
              onSelected: (choice) => _select(choice.$1, choice.$2),
              items: () => [
                for (final a in _accounts) ...[
                  if (_accounts.length > 1) KMenuItem.header(_accountName(l, a)),
                  for (final (b, depth) in mailboxTree(_boxes[a.id] ?? const []))
                    KMenuItem(
                      value: (a.id, b),
                      label: mailboxName(l, b),
                      icon: mailboxIcon(b),
                      indent: depth * 16.0,
                      trailing: b.unread > 0 ? '${b.unread}' : null,
                    ),
                ],
              ],
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Flexible(
                    child: Text(title, overflow: TextOverflow.ellipsis, style: KText.heading(k).copyWith(fontSize: 17)),
                  ),
                  const SizedBox(width: 6),
                  Icon(LucideIcons.chevronDown, size: 16, color: k.muted),
                ],
              ),
            ),
          ),
        ),
        body: list,
        floating: _chosen.isNotEmpty
            ? null
            : KFloatingButton(
                key: const ValueKey('write'),
                tooltip: l.write,
                onPressed: _write,
                icon: LucideIcons.pencil,
              ),
      );
    }
    return KScaffold(
      body: Row(
        children: [
          SizedBox(
            width: KSize.sideWidth,
            child: _Mailboxes(
              accounts: _accounts,
              boxes: _boxes,
              account: _accountId,
              selected: _query.isEmpty ? _mailbox?.id : null,
              onSelect: _select,
              onMenu: _folderMenu,
              onNew: (accountId) => _newFolder(accountId, null),
              write: KButton(
                key: const ValueKey('write'),
                label: l.write,
                icon: LucideIcons.pencil,
                tone: KTone.primary,
                expand: true,
                onPressed: _write,
              ),
            ),
          ),
          SizedBox(width: KSize.listWidth, child: list),
          Expanded(
            child: DecoratedBox(
              decoration: BoxDecoration(
                color: context.k.surface,
                border: Border(left: BorderSide(color: context.k.line)),
              ),
              child: _open == null
                  ? EmptyView(l.selectMessage, icon: LucideIcons.mail)
                  : EmailView(
                      key: ValueKey(_open),
                      account: widget.account,
                      accountId: _accountId,
                      id: _open!,
                      onUnlocked: () => _loadEmails(reset: true),
                      onSent: _loadMailboxes,
                    ),
            ),
          ),
        ],
      ),
    );
  }
}

String _accountName(AppLocalizations l, MailAccount a) => a.isPersonal ? l.myMailbox : a.name;

EmailSummary _with(EmailSummary e, {bool? seen, bool? flagged}) => EmailSummary(
  id: e.id,
  from: e.from,
  subject: e.subject,
  preview: e.preview,
  receivedAt: e.receivedAt,
  seen: seen ?? e.seen,
  flagged: flagged ?? e.flagged,
  hasAttachment: e.hasAttachment,
  encrypted: e.encrypted,
  locked: e.locked,
);

/// The mailboxes in their tree: the ones with a role first (inbox, drafts, sent …), then the others by name, each
/// followed by its children.
List<(Mailbox, int)> mailboxTree(List<Mailbox> boxes) {
  const order = ['inbox', 'drafts', 'sent', 'archive', 'junk', 'trash'];
  int rank(Mailbox b) {
    final i = b.role == null ? -1 : order.indexOf(b.role!);
    return i < 0 ? order.length : i;
  }

  final ids = {for (final b in boxes) b.id};
  final children = <String?, List<Mailbox>>{};
  for (final b in boxes) {
    // A parent the account cannot see makes its child a top-level one.
    final parent = b.parentId != null && ids.contains(b.parentId) ? b.parentId : null;
    children.putIfAbsent(parent, () => []).add(b);
  }
  for (final list in children.values) {
    list.sort((a, b) {
      final r = rank(a).compareTo(rank(b));
      return r != 0 ? r : a.name.toLowerCase().compareTo(b.name.toLowerCase());
    });
  }
  final out = <(Mailbox, int)>[];
  void walk(String? parent, int depth) {
    for (final b in children[parent] ?? const <Mailbox>[]) {
      out.add((b, depth));
      walk(b.id, depth + 1);
    }
  }

  walk(null, 0);
  return out;
}

/// The mail accounts in the side bar: the user's own folders, then each shared mailbox's under its name.
class _Mailboxes extends StatelessWidget {
  const _Mailboxes({
    required this.accounts,
    required this.boxes,
    required this.account,
    required this.selected,
    required this.onSelect,
    required this.onMenu,
    required this.onNew,
    this.write,
  });

  final List<MailAccount> accounts;
  final Map<String, List<Mailbox>> boxes;
  final String account;
  final String? selected;
  final void Function(String account, Mailbox mailbox) onSelect;
  final void Function(String account, Mailbox mailbox, Offset position) onMenu;
  final ValueChanged<String> onNew;

  /// The button that writes a message, above the folders on wide screens.
  final Widget? write;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    return DecoratedBox(
      decoration: BoxDecoration(color: k.panel),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (write != null) Padding(padding: const EdgeInsets.fromLTRB(12, 14, 12, 10), child: write),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.fromLTRB(8, 0, 8, 12),
              children: [
                for (final a in accounts) ...[
                  Row(
                    children: [
                      Expanded(
                        child: KOverline(
                          accounts.length > 1 ? _accountName(l, a) : l.folders,
                          padding: const EdgeInsets.fromLTRB(10, 12, 10, 4),
                        ),
                      ),
                      if (!a.readOnly)
                        Padding(
                          padding: const EdgeInsets.only(top: 6),
                          child: KIconButton(
                            key: ValueKey('new-folder-${a.id}'),
                            icon: LucideIcons.folderPlus,
                            tooltip: l.newFolder,
                            size: 28,
                            onPressed: () => onNew(a.id),
                          ),
                        ),
                    ],
                  ),
                  for (final (b, depth) in mailboxTree(boxes[a.id] ?? const []))
                    KSideItem(
                      key: ValueKey('mailbox-${b.id}'),
                      icon: mailboxIcon(b),
                      label: mailboxName(l, b),
                      count: b.unread,
                      indent: depth * 16.0,
                      selected: a.id == account && b.id == selected,
                      onTap: () => onSelect(a.id, b),
                      onMenu: a.readOnly ? null : (position) => onMenu(a.id, b, position),
                    ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// What can be done with the chosen emails: read or unread, flag, move, delete – and how many they are.
class _ChosenBar extends StatelessWidget {
  const _ChosenBar({
    required this.count,
    required this.boxes,
    required this.current,
    required this.readOnly,
    required this.onClear,
    required this.onAll,
    required this.onRead,
    required this.onFlag,
    required this.onMove,
    required this.onDelete,
  });

  final int count;
  final List<Mailbox> boxes;
  final String? current;
  final bool readOnly;
  final VoidCallback onClear;
  final VoidCallback onAll;
  final VoidCallback onRead;
  final VoidCallback onFlag;
  final ValueChanged<Mailbox> onMove;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    return Container(
      key: const ValueKey('chosen-bar'),
      height: KSize.bar,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      decoration: BoxDecoration(
        color: k.accentSoft,
        border: Border(bottom: BorderSide(color: k.line)),
      ),
      child: Row(
        children: [
          KIconButton(icon: LucideIcons.x, tooltip: l.cancel, onPressed: onClear),
          const SizedBox(width: 4),
          Expanded(child: Text(l.chosen(count), style: KText.label(k))),
          KIconButton(
            key: const ValueKey('choose-all'),
            icon: LucideIcons.listChecks,
            tooltip: l.chooseAll,
            onPressed: onAll,
          ),
          if (!readOnly) ...[
            KIconButton(
              key: const ValueKey('mark-read'),
              icon: LucideIcons.mailOpen,
              tooltip: l.markRead,
              onPressed: onRead,
            ),
            KIconButton(key: const ValueKey('mark-flag'), icon: LucideIcons.flag, tooltip: l.flag, onPressed: onFlag),
            KMenuButton<Mailbox>(
              key: const ValueKey('move-to'),
              tooltip: l.moveTo,
              onSelected: onMove,
              icon: LucideIcons.folderInput,
              items: () => [
                for (final (b, depth) in mailboxTree(boxes))
                  if (b.id != current)
                    KMenuItem(
                      key: ValueKey('move-to-${b.id}'),
                      value: b,
                      label: mailboxName(l, b),
                      icon: mailboxIcon(b),
                      indent: depth * 16.0,
                    ),
              ],
            ),
            KIconButton(
              key: const ValueKey('delete-emails'),
              icon: LucideIcons.trash2,
              tooltip: l.delete,
              color: k.error,
              onPressed: onDelete,
            ),
          ],
        ],
      ),
    );
  }
}

class _EmailList extends StatelessWidget {
  const _EmailList({
    required this.emails,
    required this.total,
    required this.loading,
    required this.selected,
    required this.chosen,
    required this.searching,
    required this.error,
    required this.onTap,
    required this.onChoose,
    required this.onMore,
    required this.onRefresh,
  });

  final List<EmailSummary> emails;
  final int total;
  final bool loading;
  final String? selected;
  final Set<String> chosen;
  final bool searching;
  final Object? error;
  final ValueChanged<int> onTap;
  final ValueChanged<int> onChoose;
  final VoidCallback onMore;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    if (error != null && emails.isEmpty) return ErrorView(error: error!, onRetry: onRefresh);
    if (emails.isEmpty) {
      return loading
          ? const Center(child: KSpinner())
          : EmptyView(
              searching ? l.nothingFound : l.noMessages,
              icon: searching ? LucideIcons.searchX : LucideIcons.inbox,
            );
    }
    final more = emails.length < total;
    return ColoredBox(
      color: k.surface,
      child: KRefresh(
        onRefresh: onRefresh,
        child: ListView.builder(
          itemCount: emails.length + (more ? 1 : 0),
          itemBuilder: (context, i) {
            if (i == emails.length) {
              return Padding(
                padding: const EdgeInsets.all(12),
                child: Center(
                  child: KButton(label: l.loadMore, tone: KTone.quiet, onPressed: loading ? null : onMore),
                ),
              );
            }
            final e = emails[i];
            final unread = !e.seen;
            final isChosen = chosen.contains(e.id);
            final who = people(e.from);
            return GestureDetector(
              onLongPress: () => onChoose(i),
              child: KListRow(
                key: ValueKey('email-${e.id}'),
                divider: true,
                selected: e.id == selected || isChosen,
                onTap: () => onTap(i),
                leading: isChosen
                    ? Container(
                        width: 34,
                        height: 34,
                        decoration: BoxDecoration(color: k.accent, shape: BoxShape.circle),
                        child: Icon(LucideIcons.check, size: 18, color: k.accentText),
                      )
                    : Stack(
                        clipBehavior: Clip.none,
                        children: [
                          GestureDetector(
                            onTap: () => onChoose(i),
                            child: KAvatar(name: e.from.firstOrNull?.email ?? who, size: 34),
                          ),
                          if (unread)
                            Positioned(
                              left: -9,
                              top: 13,
                              child: Container(
                                width: 7,
                                height: 7,
                                decoration: BoxDecoration(color: k.accent, shape: BoxShape.circle),
                              ),
                            ),
                        ],
                      ),
                title: Row(
                  children: [
                    Expanded(
                      child: Text(
                        who,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(fontWeight: unread ? FontWeight.w600 : FontWeight.w500),
                      ),
                    ),
                    if (e.flagged) ...[Icon(LucideIcons.flag, size: 13, color: k.violet), const SizedBox(width: 6)],
                    if (e.encrypted) ...[Icon(LucideIcons.lock, size: 13, color: k.accent), const SizedBox(width: 6)],
                    if (e.hasAttachment) ...[
                      Icon(LucideIcons.paperclip, size: 13, color: k.muted),
                      const SizedBox(width: 6),
                    ],
                    Text(
                      shortDate(context, e.receivedAt),
                      style: KText.small(k).copyWith(fontSize: 12, color: unread ? k.accent : k.faint),
                    ),
                  ],
                ),
                subtitle: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      e.locked
                          ? l.encryptedMessage
                          : e.subject.isEmpty
                          ? l.noSubject
                          : e.subject,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: KText.body(k)
                          .copyWith(fontSize: 14, fontWeight: unread ? FontWeight.w600 : FontWeight.w400),
                    ),
                    Text(
                      e.locked ? l.unlockToRead : e.preview,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: KText.small(k),
                    ),
                  ],
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}

/// One message, as text – an end-to-end encrypted one decrypted on this device, with how it was signed.
class EmailView extends StatefulWidget {
  const EmailView({super.key, required this.account, this.accountId, required this.id, this.onUnlocked, this.onSent});

  final Kernoid account;

  /// The account the email lies in – a shared mailbox –, or none for the user's own.
  final String? accountId;
  final String id;

  /// The key was unlocked here: lists can show what they could not.
  final VoidCallback? onUnlocked;

  /// A reply or forward was sent from here.
  final VoidCallback? onSent;

  @override
  State<EmailView> createState() => _EmailViewState();
}

class _EmailViewState extends State<EmailView> {
  late Future<Email> _email = widget.account.email(accountId: widget.accountId, id: widget.id);

  /// The email's text instead of its HTML.
  bool _asText = false;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return FutureBuilder<Email>(
      future: _email,
      builder: (context, snapshot) {
        if (snapshot.hasError) {
          return ErrorView(
            error: snapshot.error!,
            onRetry: () => setState(() {
              _email = widget.account.email(accountId: widget.accountId, id: widget.id);
            }),
          );
        }
        final e = snapshot.data;
        if (e == null) return const Center(child: KSpinner());
        if (e.locked) {
          return Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(LucideIcons.lock, size: 40, color: context.k.accent),
                  const SizedBox(height: 12),
                  Text(l.lockedEmail, textAlign: TextAlign.center),
                  const SizedBox(height: 16),
                  KButton(
                    key: const ValueKey('unlock-to-read'),
                    tone: KTone.primary,
                    icon: LucideIcons.lockOpen,
                    label: l.unlock,
                    onPressed: () async {
                      if (await unlockKey(context, widget.account) && mounted) {
                        setState(() {
                          _email = widget.account.email(accountId: widget.accountId, id: widget.id);
                        });
                        widget.onUnlocked?.call();
                      }
                    },
                  ),
                ],
              ),
            ),
          );
        }
        final k = context.k;
        final sender = e.from.firstOrNull;
        return KSelectable(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(28, 22, 28, 28),
            children: [
              Text(e.subject.isEmpty ? l.noSubject : e.subject, style: KText.title(k).copyWith(fontSize: 21)),
              const SizedBox(height: 16),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  KAvatar(name: sender?.email ?? people(e.from), size: 40),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(people(e.from), style: KText.body(k).copyWith(fontWeight: FontWeight.w600)),
                        if (sender != null && sender.name != null) Text(sender.email, style: KText.small(k)),
                        const SizedBox(height: 4),
                        _Line(l.to, people(e.to)),
                        if (e.cc.isNotEmpty) _Line(l.cc, people(e.cc)),
                      ],
                    ),
                  ),
                  Text(longDate(context, e.receivedAt), style: KText.small(k).copyWith(fontSize: 12)),
                ],
              ),
              if (e.encrypted) ...[const SizedBox(height: 12), SealBadge(email: e)],
              const SizedBox(height: 14),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (final (kind, label, icon) in [
                    (Reply.reply, l.reply, LucideIcons.reply),
                    (Reply.replyAll, l.replyAll, LucideIcons.replyAll),
                    (Reply.forward, l.forward, LucideIcons.forward),
                  ])
                    KButton(
                      key: ValueKey(kind.name),
                      label: label,
                      icon: icon,
                      onPressed: () async {
                        if (await writeMessage(
                          context,
                          widget.account,
                          replyTo: e.id,
                          replyAccount: widget.accountId,
                          kind: kind,
                        )) {
                          widget.onSent?.call();
                        }
                      },
                    ),
                  if (e.html != null)
                    KButton(
                      key: const ValueKey('html-or-text'),
                      tone: KTone.quiet,
                      icon: _asText ? LucideIcons.globe : LucideIcons.alignLeft,
                      label: _asText ? l.asHtml : l.asText,
                      onPressed: () => setState(() => _asText = !_asText),
                    ),
                ],
              ),
              Padding(padding: const EdgeInsets.symmetric(vertical: 20), child: const KDivider()),
              if (e.html != null && !_asText)
                HtmlBody(
                  html: e.html!,
                  onMailto: (address) => writeMessage(context, widget.account, to: address),
                )
              else
                Text(e.text, style: KText.body(k).copyWith(height: 1.6)),
              if (e.attachments.isNotEmpty) ...[
                Padding(padding: const EdgeInsets.symmetric(vertical: 20), child: const KDivider()),
                KOverline(l.attachments, padding: const EdgeInsets.only(bottom: 10)),
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  children: [
                    for (final a in e.attachments)
                      _AttachmentCard(
                        name: a.name,
                        size: bytes(a.size),
                        save: l.save,
                        onSave: () => a.partIndex != null
                            ? savePart(context, widget.account, emailId: e.id, part: a.partIndex!, name: a.name)
                            : saveBlob(
                                context,
                                widget.account,
                                accountId: widget.accountId,
                                blobId: a.blobId!,
                                name: a.name,
                                mediaType: a.mediaType,
                              ),
                      ),
                  ],
                ),
              ],
            ],
          ),
        );
      },
    );
  }
}

/// An attachment: a box with its name and size, saved with the button in it.
class _AttachmentCard extends StatelessWidget {
  const _AttachmentCard({required this.name, required this.size, required this.save, required this.onSave});

  final String name;
  final String size;
  final String save;
  final VoidCallback onSave;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Container(
      width: 260,
      padding: const EdgeInsets.fromLTRB(12, 8, 6, 8),
      decoration: BoxDecoration(
        color: k.raised,
        border: Border.all(color: k.line),
        borderRadius: BorderRadius.circular(KSize.radiusSmall),
      ),
      child: Row(
        children: [
          Icon(LucideIcons.paperclip, size: 16, color: k.muted),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(name, maxLines: 1, overflow: TextOverflow.ellipsis, style: KText.label(k)),
                Text(size, style: KText.small(k).copyWith(fontSize: 12)),
              ],
            ),
          ),
          KIconButton(icon: LucideIcons.download, tooltip: save, onPressed: onSave, size: 32),
        ],
      ),
    );
  }
}

class _Line extends StatelessWidget {
  const _Line(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    return Padding(
      padding: const EdgeInsets.only(bottom: 2),
      child: Text.rich(
        TextSpan(
          style: KText.small(k).copyWith(color: k.text),
          children: [
            TextSpan(
              text: '$label  ',
              style: TextStyle(color: k.faint),
            ),
            TextSpan(text: value),
          ],
        ),
      ),
    );
  }
}
