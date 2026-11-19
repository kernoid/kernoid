// SPDX-License-Identifier: MIT
import 'dart:async';

import 'package:file_selector/file_selector.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

/// How a message went out.
enum Sent { encrypted, plain }

/// How a message refers to another – the kinds of [Kernoid.replyDraft].
enum Reply { reply, replyAll, forward }

/// Writes a message – a new one, or a reply to or a forward of the email [replyTo] – and says how it went out. Returns
/// whether it was sent.
Future<bool> writeMessage(
  BuildContext context,
  Kernoid account, {
  String to = '',
  String? replyTo,
  String? replyAccount,
  Reply kind = Reply.reply,
}) async {
  final sent = await Navigator.of(context).push<Sent>(
    KPageRoute(
      fullscreenDialog: true,
      builder: (_) => ComposePage(account: account, to: to, replyTo: replyTo, replyAccount: replyAccount, kind: kind),
    ),
  );
  if (sent == null || !context.mounted) return false;
  final l = AppLocalizations.of(context);
  KToast.of(context).show(sent == Sent.encrypted ? l.sentEncrypted : l.messageSent);
  return true;
}

/// A message in plain text, new or a reply or forward, with files attached. End-to-end encrypted and signed whenever
/// every recipient has a key and the user's key is unlocked – without a setting; the view says beforehand which it
/// will be (RFC 0006, 5.3). Pops how it was sent.
class ComposePage extends StatefulWidget {
  const ComposePage({
    super.key,
    required this.account,
    this.to = '',
    this.replyTo,
    this.replyAccount,
    this.kind = Reply.reply,
  });

  final Kernoid account;

  /// Recipients to begin with, e.g. a contact's address.
  final String to;

  /// The email answered or forwarded, as [kind] says.
  final String? replyTo;

  /// The account [replyTo] lies in – a shared mailbox –, or none for the user's own.
  final String? replyAccount;
  final Reply kind;

  @override
  State<ComposePage> createState() => _ComposePageState();
}

class _ComposePageState extends State<ComposePage> {
  final _form = GlobalKey<FormState>();
  late final _to = TextEditingController(text: widget.to);
  final _cc = TextEditingController();
  final _bcc = TextEditingController();
  final _subject = TextEditingController();
  final _text = TextEditingController();
  bool _copies = false;

  /// The thread a reply belongs to, and the attachments of a message forwarded.
  List<String> _inReplyTo = const [];
  List<String> _references = const [];
  final List<DraftAttachment> _forwarded = [];

  /// The attachments of an end-to-end encrypted message forwarded – read from it again, decrypted, when sending.
  final List<DraftPart> _forwardedParts = [];

  /// Files of the device, by path.
  final List<XFile> _files = [];
  late bool _loading = widget.replyTo != null;
  bool _busy = false;
  String? _error;
  SendPlan? _plan;
  Timer? _debounce;
  int _asked = 0;

  @override
  void initState() {
    super.initState();
    for (final field in [_to, _cc, _bcc]) {
      field.addListener(_toChanged);
    }
    if (widget.to.isNotEmpty) _toChanged();
    // The words around the quote come from the localizations, which initState may not read yet.
    if (widget.replyTo case final id?) WidgetsBinding.instance.addPostFrameCallback((_) => _begin(id));
  }

  /// Fills the view from the email answered or forwarded – the words around the quote in the user's language.
  Future<void> _begin(String id) async {
    if (!mounted) return;
    try {
      final l = AppLocalizations.of(context);
      final draft = await widget.account.replyDraft(
        accountId: widget.replyAccount,
        emailId: id,
        kind: widget.kind.name,
        phrases: ReplyPhrases(
          wrote: l.quoteWrote('{date}', '{who}'),
          forwarded: l.quoteForwarded,
          from: l.from,
          date: l.date,
          subject: l.subject,
          to: l.to,
          dateFormat: l.quoteDateFormat,
        ),
      );
      if (!mounted) return;
      setState(() {
        _to.text = draft.to;
        _cc.text = draft.cc;
        _copies = draft.cc.isNotEmpty;
        _subject.text = draft.subject;
        _text.text = draft.text;
        _inReplyTo = draft.inReplyTo;
        _references = draft.references;
        _forwarded.addAll(draft.attachments);
        _forwardedParts.addAll(draft.parts);
      });
    } catch (error) {
      if (mounted) setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _attach() async {
    final files = await openFiles();
    if (files.isNotEmpty && mounted) setState(() => _files.addAll(files));
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _to.dispose();
    _cc.dispose();
    _bcc.dispose();
    _subject.dispose();
    _text.dispose();
    super.dispose();
  }

  /// Every address in To, Cc and Bcc, without names.
  List<String> get _recipients => [
    for (final field in [_to, _cc, _bcc]) ...addresses(field.text),
  ];

  /// Asks how it would go out, once typing pauses; only the latest answer counts.
  void _toChanged() {
    _debounce?.cancel();
    _debounce = Timer(const Duration(milliseconds: 400), () async {
      final ask = ++_asked;
      final recipients = _recipients;
      if (recipients.isEmpty) {
        if (mounted) setState(() => _plan = null);
        return;
      }
      try {
        final plan = await widget.account.sendPlan(to: recipients);
        if (mounted && ask == _asked) setState(() => _plan = plan);
      } catch (_) {
        if (mounted && ask == _asked) setState(() => _plan = null);
      }
    });
  }

  Future<void> _send() async {
    if (!_form.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final encrypted = await widget.account.sendDraft(
        draft: EmailDraft(
          to: _to.text,
          cc: _cc.text,
          bcc: _bcc.text,
          subject: _subject.text,
          text: _text.text,
          inReplyTo: _inReplyTo,
          references: _references,
          attachments: _forwarded,
          parts: _forwardedParts,
          files: [for (final file in _files) file.path],
        ),
      );
      if (mounted) Navigator.of(context).pop(encrypted ? Sent.encrypted : Sent.plain);
    } catch (error) {
      setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final plan = _plan;
    return KScaffold(
      topBar: KTopBar(
        title: l.write,
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: KButton(
              tone: KTone.primary,
              key: const ValueKey('send'),
              onPressed: _busy || _loading ? null : _send,
              icon: plan?.encrypted ?? false ? LucideIcons.lock : LucideIcons.send,
              label: l.send,
            ),
          ),
        ],
      ),
      body: _loading
          ? const Center(child: KSpinner())
          : Form(
              key: _form,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  KTextFormField(
                    key: const ValueKey('to'),
                    controller: _to,
                    label: l.to,
                    suffix: _copies
                        ? null
                        : KButton(
                            tone: KTone.quiet,
                            key: const ValueKey('show-cc'),
                            onPressed: () => setState(() => _copies = true),
                            label: '${l.cc} ${l.bcc}',
                          ),
                    keyboardType: TextInputType.emailAddress,
                    autocorrect: false,
                    validator: (_) => _recipients.isEmpty ? l.required : null,
                  ),
                  if (_copies) ...[
                    KTextFormField(
                      key: const ValueKey('cc'),
                      controller: _cc,
                      label: l.cc,
                      keyboardType: TextInputType.emailAddress,
                      autocorrect: false,
                    ),
                    KTextFormField(
                      key: const ValueKey('bcc'),
                      controller: _bcc,
                      label: l.bcc,
                      keyboardType: TextInputType.emailAddress,
                      autocorrect: false,
                    ),
                  ],
                  if (plan != null)
                    Padding(
                      key: const ValueKey('send-plan'),
                      padding: const EdgeInsets.only(top: 8),
                      child: Row(
                        children: [
                          Icon(
                            plan.encrypted ? LucideIcons.lock : LucideIcons.lockOpen,
                            size: 16,
                            color: plan.encrypted ? context.k.accent : context.k.muted,
                          ),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              plan.encrypted ? l.willEncrypt : l.wontEncrypt(plan.reason ?? ''),
                              style: KText.small(context.k)
                                  .copyWith(color: plan.encrypted ? context.k.accent : context.k.muted),
                            ),
                          ),
                        ],
                      ),
                    ),
                  KTextFormField(key: const ValueKey('subject'), controller: _subject, label: l.subject),
                  const SizedBox(height: 12),
                  KTextFormField(
                    key: const ValueKey('text'),
                    controller: _text,
                    label: l.message,
                    minLines: 10,
                    maxLines: null,
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      for (final a in _forwarded)
                        KChip(
                          key: ValueKey('attachment-${a.name}'),
                          icon: LucideIcons.paperclip,
                          label: '${a.name} · ${bytes(a.size)}',
                          tooltip: l.remove,
                          onDeleted: () => setState(() => _forwarded.remove(a)),
                        ),
                      for (final p in _forwardedParts)
                        KChip(
                          key: ValueKey('attachment-${p.name}'),
                          icon: LucideIcons.lock,
                          label: '${p.name} · ${bytes(p.size)}',
                          tooltip: l.remove,
                          onDeleted: () => setState(() => _forwardedParts.remove(p)),
                        ),
                      for (final file in _files)
                        KChip(
                          key: ValueKey('attachment-${file.name}'),
                          icon: LucideIcons.paperclip,
                          label: file.name,
                          tooltip: l.remove,
                          onDeleted: () => setState(() => _files.remove(file)),
                        ),
                      KButton(
                        tone: KTone.quiet,
                        key: const ValueKey('attach'),
                        onPressed: _busy ? null : _attach,
                        icon: LucideIcons.paperclip,
                        label: l.attachFile,
                      ),
                    ],
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Text(_error!, style: TextStyle(color: context.k.error)),
                  ],
                ],
              ),
            ),
    );
  }
}

/// The addresses in what someone typed into an address field: `Name <a@b>, c@d` gives `a@b` and `c@d`.
List<String> addresses(String field) => [
  for (final part in field.split(RegExp(r'[,;]')))
    if (RegExp(r'<([^>]*@[^>]*)>').firstMatch(part) case final bracketed?)
      bracketed.group(1)!.trim()
    else if (part.trim().contains('@'))
      part.trim(),
];
