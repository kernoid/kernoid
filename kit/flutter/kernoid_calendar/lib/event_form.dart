// SPDX-License-Identifier: MIT

import 'package:intl/intl.dart';

import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

import 'l10n/calendar_text.dart';

/// Making or changing an event: title, calendar, when (or all day), where, who is invited, how it repeats, a
/// description. A recurring event is changed as a whole, or – with `recurrenceId` – one of its instances alone, in what
/// an instance may differ in. Pops `true` once saved.
class EventFormPage extends StatefulWidget {
  const EventFormPage({
    super.key,
    required this.account,
    required this.calendars,
    required this.draft,
    this.eventId,
    this.recurrenceId,
  });

  final Kernoid account;

  /// The calendars events can be made in.
  final List<Calendar> calendars;
  final EventDraft draft;

  /// The event changed; none for a new one.
  final String? eventId;

  /// The instance of the recurring event `eventId` changed alone.
  final String? recurrenceId;

  /// A new event: the next full hour, an hour long, in the first calendar.
  static EventDraft fresh(Calendar calendar, DateTime day) {
    final now = DateTime.now();
    final hour = DateTime(day.year, day.month, day.day, now.hour + 1);
    return EventDraft(
      calendarId: calendar.id,
      accountId: calendar.accountId,
      title: '',
      allDay: false,
      start: localTime(hour),
      end: localTime(hour.add(const Duration(hours: 1))),
      location: '',
      description: '',
      participants: const [],
    );
  }

  @override
  State<EventFormPage> createState() => _EventFormPageState();
}

/// `YYYY-MM-DDTHH:MM:SS` – a time without a zone, as the Rust side takes it.
String localTime(DateTime t) => DateFormat("yyyy-MM-dd'T'HH:mm:ss").format(t);

class _EventFormPageState extends State<EventFormPage> {
  final _form = GlobalKey<FormState>();
  late final _title = TextEditingController(text: widget.draft.title);
  late final _location = TextEditingController(text: widget.draft.location);
  late final _description = TextEditingController(text: widget.draft.description);
  late final _invite = TextEditingController(text: widget.draft.participants.join(', '));
  late String _calendar = '${widget.draft.accountId}/${widget.draft.calendarId}';
  late bool _allDay = widget.draft.allDay;
  late DateTime _start = DateTime.parse(widget.draft.start);
  late DateTime _end = DateTime.parse(widget.draft.end);
  late String? _repeat = widget.draft.repeat;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _title.dispose();
    _location.dispose();
    _description.dispose();
    _invite.dispose();
    super.dispose();
  }

  Future<void> _pickDay(bool start) async {
    final current = start ? _start : _end;
    final day = await showKDatePicker(context, initial: current, first: DateTime(2000), last: DateTime(2100));
    if (day == null) return;
    setState(() {
      final picked = DateTime(day.year, day.month, day.day, current.hour, current.minute);
      if (start) {
        // The end moves with the start, keeping the length.
        _end = picked.add(_end.difference(_start));
        _start = picked;
      } else {
        _end = picked;
      }
    });
  }

  Future<void> _pickTime(bool start) async {
    final current = start ? _start : _end;
    final time = await showKTimePicker(context, initial: KTime.fromDateTime(current));
    if (time == null) return;
    setState(() {
      final picked = DateTime(current.year, current.month, current.day, time.hour, time.minute);
      if (start) {
        _end = picked.add(_end.difference(_start));
        _start = picked;
      } else {
        _end = picked;
      }
    });
  }

  Future<void> _save() async {
    final l = AppLocalizations.of(context);
    if (!_form.currentState!.validate()) return;
    final start = _allDay ? DateTime(_start.year, _start.month, _start.day) : _start;
    final end = _allDay ? DateTime(_end.year, _end.month, _end.day) : _end;
    if (end.isBefore(start)) {
      setState(() => _error = l.calendarText.endBeforeStart);
      return;
    }
    final [account, calendar] = _calendar.split('/');
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final draft = EventDraft(
        calendarId: calendar,
        accountId: account,
        title: _title.text,
        allDay: _allDay,
        start: localTime(start),
        end: localTime(end),
        location: _location.text,
        description: _description.text,
        participants: _invite.text.split(RegExp(r'[,;\s]+')).where((a) => a.contains('@')).toList(),
        repeat: _repeat,
      );
      final instance = widget.recurrenceId;
      if (instance != null) {
        await widget.account.saveInstance(
          accountId: account,
          eventId: widget.eventId!,
          recurrenceId: instance,
          draft: draft,
        );
      } else {
        await widget.account.saveEvent(eventId: widget.eventId, draft: draft);
      }
      if (mounted) Navigator.of(context).pop(true);
    } catch (error) {
      if (mounted) setState(() => _error = errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final locale = Localizations.localeOf(context).toLanguageTag();
    final one = widget.recurrenceId != null;
    final day = DateFormat.yMMMEd(locale);
    final hm = DateFormat.Hm(locale);
    Widget when(String label, bool start) {
      final t = start ? _start : _end;
      return Row(
        children: [
          SizedBox(width: 80, child: Text(label)),
          KButton(
            tone: KTone.quiet,
            key: ValueKey(start ? 'start-day' : 'end-day'),
            onPressed: () => _pickDay(start),
            label: day.format(t),
          ),
          if (!_allDay)
            KButton(
              tone: KTone.quiet,
              key: ValueKey(start ? 'start-time' : 'end-time'),
              onPressed: () => _pickTime(start),
              label: hm.format(t),
            ),
        ],
      );
    }

    return KScaffold(
      topBar: KTopBar(
        title: widget.eventId == null
            ? l.calendarText.newEvent
            : one
            ? l.calendarText.editThisEvent
            : l.calendarText.editEvent,
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 8),
            child: KButton(
              tone: KTone.primary,
              key: const ValueKey('save-event'),
              onPressed: _busy ? null : _save,
              label: l.save,
            ),
          ),
        ],
      ),
      body: Form(
        key: _form,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            KTextFormField(
              key: const ValueKey('event-title'),
              controller: _title,
              autofocus: widget.eventId == null,
              label: l.calendarText.title,
              validator: (v) => (v ?? '').trim().isEmpty ? l.required : null,
            ),
            const SizedBox(height: 8),
            if (widget.calendars.length > 1)
              KSelect<String>(
                value: _calendar,
                label: l.calendarText.calendarField,
                options: [
                  for (final c in widget.calendars)
                    (
                      '${c.accountId}/${c.id}',
                      c.sharedBy == null ? c.name : '${c.name} (${l.calendarText.sharedBy(c.sharedBy!)})',
                    ),
                ],
                onChanged: widget.eventId == null ? (v) => setState(() => _calendar = v) : null,
              ),
            KToggleRow(
              key: const ValueKey('all-day'),
              title: Text(l.calendarText.allDay),
              value: _allDay,
              onChanged: (v) => setState(() => _allDay = v),
            ),
            when(l.calendarText.starts, true),
            when(l.calendarText.ends, false),
            if (!one)
              KSelect<String?>(
                key: const ValueKey('event-repeat'),
                value: _repeat,
                label: l.calendarText.repeat,
                options: [
                  for (final (value, label) in [
                    (null, l.calendarText.repeatNone),
                    ('daily', l.calendarText.repeatDaily),
                    ('weekly', l.calendarText.repeatWeekly),
                    ('monthly', l.calendarText.repeatMonthly),
                    ('yearly', l.calendarText.repeatYearly),
                  ])
                    (value, label),
                ],
                onChanged: (v) => setState(() => _repeat = v),
              ),
            const SizedBox(height: 8),
            KTextFormField(
              key: const ValueKey('event-location'),
              controller: _location,
              label: l.calendarText.location,
            ),
            if (!one) ...[
              const SizedBox(height: 8),
              KTextFormField(
                key: const ValueKey('event-invite'),
                controller: _invite,
                keyboardType: TextInputType.emailAddress,
                label: l.calendarText.invite,
                helper: l.calendarText.inviteHint,
              ),
            ],
            const SizedBox(height: 8),
            KTextFormField(
              key: const ValueKey('event-description'),
              controller: _description,
              minLines: 3,
              maxLines: 8,
              label: l.calendarText.description,
            ),
            if (one) ...[
              const SizedBox(height: 8),
              Text(l.calendarText.instanceEditsOne, style: KText.small(context.k)),
            ] else if (widget.eventId != null && widget.draft.repeat != null) ...[
              const SizedBox(height: 8),
              Text(l.calendarText.recurringEditsAll, style: KText.small(context.k)),
            ],
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
