// SPDX-License-Identifier: MIT
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_shell/pages/account.dart';
import 'package:kernoid_ui/ui.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

/// Which address new emails come from, how long one can take them back, how long the Trash keeps them.
class MailSettingsSection extends StatefulWidget {
  const MailSettingsSection({super.key, required this.account});

  final Kernoid account;

  @override
  State<MailSettingsSection> createState() => _MailSettingsSectionState();
}

class _MailSettingsSectionState extends KSettingsState<MailSettingsSection> {
  MailSettings? _settings;
  String _from = '';
  int _undo = 0;
  bool _own = false;
  final _days = TextEditingController();

  @override
  Future<void> load() async {
    final s = await widget.account.mailSettings();
    _settings = s;
    _from = s.defaultFrom ?? '';
    _undo = s.undoSendSeconds;
    _own = s.trashRetentionDays != null;
    _days.text = '${s.trashRetentionDays ?? s.tenantTrashRetentionDays ?? 30}';
  }

  @override
  void dispose() {
    _days.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    final s = _settings;
    if (loaded && s == null) return const SizedBox.shrink();
    final undoChoices = {0, 5, 10, 20, 30, _undo}.toList()..sort();
    Widget row(String label, Widget field) => Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          SizedBox(width: 150, child: Text(label, style: KText.small(k))),
          Expanded(
            child: Align(alignment: Alignment.centerLeft, child: field),
          ),
        ],
      ),
    );
    return KSection(
      title: l.mailSettings,
      icon: LucideIcons.mailCheck,
      child: s == null
          ? const KProgressBar()
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                row(
                  l.sendFrom,
                  KSelect<String>(
                    key: const ValueKey('send-from'),
                    value: _from,
                    expand: true,
                    options: [
                      ('', l.myAddress),
                      for (final address in {...s.senders, if (_from.isNotEmpty) _from}) (address, address),
                    ],
                    onChanged: (v) => setState(() => _from = v),
                  ),
                ),
                row(
                  l.undoSend,
                  KSelect<int>(
                    key: const ValueKey('undo-send'),
                    value: _undo,
                    options: [for (final n in undoChoices) (n, n == 0 ? l.off : l.seconds(n))],
                    onChanged: (v) => setState(() => _undo = v),
                    expand: false,
                  ),
                ),
                KOverline(l.keepTrash, padding: const EdgeInsets.only(top: 6, bottom: 4)),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    KRadioRow<bool>(
                      key: const ValueKey('trash-tenant'),
                      value: false,
                      groupValue: _own,
                      onChanged: (v) => setState(() => _own = v),
                      child: Text(
                        s.tenantTrashRetentionDays == null
                            ? l.asTenantForever
                            : l.asTenantDays(s.tenantTrashRetentionDays!),
                        style: KText.body(k),
                      ),
                    ),
                    KRadioRow<bool>(
                      key: const ValueKey('trash-own'),
                      value: true,
                      groupValue: _own,
                      onChanged: (v) => setState(() => _own = v),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(l.ownDays, style: KText.body(k)),
                          const SizedBox(width: 12),
                          SizedBox(
                            width: 80,
                            child: KTextField(
                              key: const ValueKey('trash-days'),
                              controller: _days,
                              enabled: _own,
                              keyboardType: TextInputType.number,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Align(
                  alignment: Alignment.centerLeft,
                  child: KButton(
                    key: const ValueKey('mail-settings-save'),
                    label: l.save,
                    tone: KTone.primary,
                    onPressed: busy
                        ? null
                        : () => save(
                            () => widget.account.setMailSettings(
                              settings: MailSettings(
                                trashRetentionDays: _own ? int.tryParse(_days.text.trim()) : null,
                                tenantTrashRetentionDays: s.tenantTrashRetentionDays,
                                defaultFrom: _from.isEmpty ? null : _from,
                                undoSendSeconds: _undo,
                                senders: s.senders,
                              ),
                            ),
                          ),
                  ),
                ),
                noteLine('mail-settings-note'),
              ],
            ),
    );
  }
}

/// The vacation response: on or off, from and until when, its subject and text – shown only when the server has one.
class VacationSection extends StatefulWidget {
  const VacationSection({super.key, required this.account});

  final Kernoid account;

  @override
  State<VacationSection> createState() => _VacationSectionState();
}

class _VacationSectionState extends State<VacationSection> {
  VacationResponse? _vacation;
  bool _loaded = false;
  bool _on = false;
  DateTime? _from;
  DateTime? _until;
  final _subject = TextEditingController();
  final _text = TextEditingController();
  bool _busy = false;
  String? _note;
  bool _failed = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _subject.dispose();
    _text.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final v = await widget.account.vacation();
      if (!mounted) return;
      setState(() {
        _loaded = true;
        _vacation = v;
        if (v != null) {
          _on = v.on_;
          _from = v.from == null ? null : DateTime.tryParse(v.from!);
          _until = v.until == null ? null : DateTime.tryParse(v.until!);
          _subject.text = v.subject;
          _text.text = v.text;
        }
      });
    } catch (error) {
      if (mounted) {
        setState(() {
          _loaded = true;
          _note = errorText(error);
          _failed = true;
        });
      }
    }
  }

  static String? _local(DateTime? t) => t == null
      ? null
      : '${t.year.toString().padLeft(4, '0')}-${_two(t.month)}-${_two(t.day)}T${_two(t.hour)}:${_two(t.minute)}';

  static String _two(int n) => n.toString().padLeft(2, '0');

  Future<void> _save() async {
    final l = AppLocalizations.of(context);
    setState(() {
      _busy = true;
      _note = null;
    });
    try {
      await widget.account.setVacation(
        vacation: VacationResponse(
          on_: _on,
          from: _local(_from),
          until: _local(_until),
          subject: _subject.text,
          text: _text.text,
        ),
      );
      if (mounted) {
        setState(() {
          _note = l.saved;
          _failed = false;
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() {
          _note = errorText(error);
          _failed = true;
        });
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<DateTime?> _pick(DateTime? current, {required bool end}) async {
    final now = DateTime.now();
    final day = await showKDatePicker(
      context,
      initial: current ?? now,
      first: DateTime(now.year - 1),
      last: DateTime(now.year + 5),
    );
    if (day == null || !mounted) return null;
    final time = await showKTimePicker(
      context,
      initial: current == null
          ? (end ? const KTime(hour: 23, minute: 59) : const KTime(hour: 0, minute: 0))
          : KTime.fromDateTime(current),
    );
    if (time == null) return null;
    return DateTime(day.year, day.month, day.day, time.hour, time.minute);
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final k = context.k;
    if (_loaded && _vacation == null && !_failed) return const SizedBox.shrink();
    Widget when(String label, DateTime? value, ValueChanged<DateTime?> set, {required bool end, required Key key}) =>
        Row(
          children: [
            SizedBox(width: 120, child: Text(label, style: KText.small(k))),
            Expanded(
              child: Align(
                alignment: Alignment.centerLeft,
                child: KButton(
                  key: key,
                  label: value == null ? l.notSet : longDate(context, value.toUtc().toIso8601String()),
                  icon: LucideIcons.calendar,
                  tone: KTone.quiet,
                  onPressed: () async {
                    final picked = await _pick(value, end: end);
                    if (picked != null) setState(() => set(picked));
                  },
                ),
              ),
            ),
            if (value != null)
              KIconButton(icon: LucideIcons.x, tooltip: l.remove, size: 30, onPressed: () => setState(() => set(null))),
          ],
        );
    return KSection(
      title: l.vacation,
      icon: LucideIcons.plane,
      description: l.vacationHint,
      trailing: KSwitch(
        key: const ValueKey('vacation-on'),
        value: _on,
        onChanged: _loaded && !_failed ? (on) => setState(() => _on = on) : null,
      ),
      child: !_loaded
          ? const KProgressBar()
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (_vacation != null) ...[
                  when(l.fromOptional, _from, (t) => _from = t, end: false, key: const ValueKey('vacation-from')),
                  when(l.untilOptional, _until, (t) => _until = t, end: true, key: const ValueKey('vacation-until')),
                  const SizedBox(height: 8),
                  KTextField(
                    key: const ValueKey('vacation-subject'),
                    controller: _subject,
                    label: l.subject,
                    hint: l.vacationSubjectHint,
                  ),
                  const SizedBox(height: 10),
                  KTextField(
                    key: const ValueKey('vacation-text'),
                    controller: _text,
                    minLines: 3,
                    maxLines: 8,
                    label: l.text,
                  ),
                  const SizedBox(height: 12),
                ],
                Row(
                  children: [
                    if (_vacation != null)
                      KButton(
                        key: const ValueKey('vacation-save'),
                        label: l.save,
                        tone: KTone.primary,
                        onPressed: _busy ? null : _save,
                      ),
                    const SizedBox(width: 12),
                    if (_note != null)
                      Expanded(
                        child: Text(
                          _note!,
                          key: const ValueKey('vacation-note'),
                          style: KText.small(k).copyWith(color: _failed ? k.error : k.accent),
                        ),
                      ),
                  ],
                ),
              ],
            ),
    );
  }
}
