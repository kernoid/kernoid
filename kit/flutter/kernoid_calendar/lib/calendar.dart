// SPDX-License-Identifier: MIT

import 'package:intl/intl.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_shell/app/format.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';
import 'package:kernoid_shell/widgets/states.dart';

import 'event_form.dart';
import 'l10n/calendar_text.dart';

/// The calendars the account reaches, two weeks at a time as a list of days or a month at a time as a grid; events are
/// made, changed and deleted – one instance of a recurring event alone or the whole series –, and an invitation is
/// answered from the event.
class CalendarPage extends StatefulWidget {
  const CalendarPage({super.key, required this.account});

  final Kernoid account;

  @override
  State<CalendarPage> createState() => _CalendarPageState();
}

/// Days shown at once.
const _span = 14;

DateTime _day(DateTime t) => DateTime(t.year, t.month, t.day);

/// The first day of the grid of the month `month` is in: the start of its first week.
DateTime _gridStart(DateTime month, int firstWeekday) {
  final first = DateTime(month.year, month.month);
  // DateTime.weekday is 1 (Monday) to 7 (Sunday); MaterialLocalizations counts from 0 (Sunday).
  final back = (first.weekday % 7 - firstWeekday) % 7;
  return first.subtract(Duration(days: back));
}

/// Six weeks: every month fits.
const _gridDays = 42;

class _CalendarPageState extends State<CalendarPage> {
  DateTime _from = _day(DateTime.now());

  /// The month shown as a grid, or none for the list of days.
  DateTime? _month;

  /// The day of the month chosen in the grid; its events are listed below it.
  DateTime _chosen = _day(DateTime.now());
  List<Calendar> _calendars = const [];
  List<Event>? _events;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _events = null;
      _error = null;
    });
    final month = _month;
    final from = month == null ? _from : _gridStart(month, _firstWeekday);
    final to = from.add(Duration(days: month == null ? _span : _gridDays));
    try {
      final calendars = await widget.account.calendars();
      final events = await widget.account.events(
        from: from.toUtc().toIso8601String(),
        to: to.toUtc().toIso8601String(),
      );
      if (mounted) {
        setState(() {
          _calendars = calendars;
          _events = events;
        });
      }
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  int get _firstWeekday => firstDayOfWeekIndex(context);

  /// Earlier (-1), later (1) or to today (0): by two weeks in the list, by a month in the grid.
  void _move(int step) {
    final today = _day(DateTime.now());
    final month = _month;
    if (month == null) {
      _from = step == 0 ? today : _from.add(Duration(days: step * _span));
    } else {
      _month = step == 0 ? DateTime(today.year, today.month) : DateTime(month.year, month.month + step);
      _chosen = step == 0 ? today : _month!;
    }
    _load();
  }

  void _toggleMonth() {
    final today = _day(DateTime.now());
    setState(() {
      if (_month == null) {
        final around = today.isBefore(_from) || !today.isBefore(_from.add(const Duration(days: _span))) ? _from : today;
        _month = DateTime(around.year, around.month);
        _chosen = around;
      } else {
        _from = _chosen;
        _month = null;
      }
    });
    _load();
  }

  Color? _color(Event e) {
    final calendar = _calendars.where((c) => e.calendarIds.contains(c.id) && c.accountId == e.accountId).firstOrNull;
    return _parseColor(calendar?.color);
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final locale = Localizations.localeOf(context).toLanguageTag();
    final last = _from.add(const Duration(days: _span - 1));
    final month = _month;
    return KScaffold(
      topBar: KTopBar(
        title: month == null
            ? '${DateFormat.MMMd(locale).format(_from)} – ${DateFormat.MMMd(locale).format(last)}'
            : DateFormat.yMMMM(locale).format(month),
        actions: [
          KIconButton(
            key: const ValueKey('calendar-view'),
            tooltip: month == null ? l.calendarText.monthView : l.calendarText.listView,
            onPressed: _toggleMonth,
            icon: month == null ? LucideIcons.calendarDays : LucideIcons.list,
          ),
          KIconButton(tooltip: l.calendarText.earlier, onPressed: () => _move(-1), icon: LucideIcons.chevronLeft),
          KButton(tone: KTone.quiet, onPressed: () => _move(0), label: l.today),
          KIconButton(tooltip: l.calendarText.later, onPressed: () => _move(1), icon: LucideIcons.chevronRight),
        ],
      ),
      body: _body(l, locale),
      floating: _writable.isEmpty
          ? null
          : KFloatingButton(
              key: const ValueKey('new-event'),
              tooltip: l.calendarText.newEvent,
              onPressed: _new,
              icon: LucideIcons.plus,
            ),
    );
  }

  List<Calendar> get _writable => _calendars.where((c) => c.writable).toList();

  Future<void> _new() async {
    final today = _day(DateTime.now());
    final day = _month != null
        ? _chosen
        : today.isBefore(_from) || !today.isBefore(_from.add(const Duration(days: _span)))
        ? _from
        : today;
    final saved = await Navigator.of(context).push<bool>(
      KPageRoute(
        fullscreenDialog: true,
        builder: (_) => EventFormPage(
          account: widget.account,
          calendars: _writable,
          draft: EventFormPage.fresh(_writable.first, day),
        ),
      ),
    );
    if (saved ?? false) _load();
  }

  Widget _body(AppLocalizations l, String locale) {
    if (_error != null) return ErrorView(error: _error!, onRetry: _load);
    final events = _events;
    if (events == null) return const Center(child: KSpinner());
    final month = _month;
    if (month != null) return _grid(l, locale, month, events);
    if (events.isEmpty) return EmptyView(l.calendarText.noEvents, icon: LucideIcons.calendarCheck);
    final days = _byDay(events, _from, _from.add(const Duration(days: _span)));
    final today = _day(DateTime.now());
    final entries = days.entries.toList()..sort((a, b) => a.key.compareTo(b.key));
    return KRefresh(
      onRefresh: _load,
      child: ListView(
        children: [
          for (final MapEntry(key: day, value: list) in entries) ...[
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
              child: Text(
                day == today
                    ? '${l.today} · ${DateFormat.MMMMEEEEd(locale).format(day)}'
                    : DateFormat.MMMMEEEEd(locale).format(day),
                style: KText.heading(context.k)
                    .copyWith(fontSize: 14)
                    .copyWith(color: day == today ? context.k.accent : null),
              ),
            ),
            for (final e in list) _EventTile(event: e, color: _color(e), onTap: () => _open(e)),
          ],
        ],
      ),
    );
  }

  /// Every day from `from` to before `to` an event touches – one that runs over several days is on each.
  Map<DateTime, List<Event>> _byDay(List<Event> events, DateTime from, DateTime to) {
    final days = <DateTime, List<Event>>{};
    for (final e in events) {
      final start = _when(e, e.start);
      if (start == null) continue;
      final end = _when(e, e.end) ?? start;
      var day = _day(start).isBefore(from) ? from : _day(start);
      // An all-day event ends the day before its end; one at a time ends on the day it ends (not at midnight after).
      final lastDay = e.allDay
          ? _day(end).subtract(const Duration(days: 1))
          : _day(end.subtract(const Duration(seconds: 1)));
      do {
        if (day.isBefore(to)) days.putIfAbsent(day, () => []).add(e);
        day = day.add(const Duration(days: 1));
      } while (!day.isAfter(lastDay));
    }
    return days;
  }

  /// The month as six weeks of days, each with its events as far as they fit; the chosen day's events below.
  Widget _grid(AppLocalizations l, String locale, DateTime month, List<Event> events) {
    final start = _gridStart(month, _firstWeekday);
    final days = _byDay(events, start, start.add(const Duration(days: _gridDays)));
    final today = _day(DateTime.now());
    final weekdays = DateFormat.E(locale);
    final chosen = days[_chosen] ?? const <Event>[];
    return LayoutBuilder(
      builder: (context, constraints) {
        // Titles where a cell is wide enough, dots where it is not (phones).
        final titles = constraints.maxWidth / 7 >= 90;
        final grid = Column(
          children: [
            Row(
              children: [
                for (var i = 0; i < 7; i++)
                  Expanded(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      child: Text(
                        weekdays.format(start.add(Duration(days: i))),
                        textAlign: TextAlign.center,
                        style: KText.small(context.k).copyWith(fontSize: 12),
                      ),
                    ),
                  ),
              ],
            ),
            for (var week = 0; week < 6; week++)
              Expanded(
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    for (var i = 0; i < 7; i++)
                      Expanded(
                        child: _DayCell(
                          day: KDates.addDays(start, week * 7 + i),
                          inMonth: KDates.addDays(start, week * 7 + i).month == month.month,
                          today: KDates.addDays(start, week * 7 + i) == today,
                          chosen: KDates.addDays(start, week * 7 + i) == _chosen,
                          events: days[KDates.addDays(start, week * 7 + i)] ?? const [],
                          titles: titles,
                          color: _color,
                          onTap: () => setState(() => _chosen = KDates.addDays(start, week * 7 + i)),
                        ),
                      ),
                  ],
                ),
              ),
          ],
        );
        final list = ListView(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
              child: Text(
                DateFormat.MMMMEEEEd(locale).format(_chosen),
                style: KText.heading(context.k).copyWith(fontSize: 14),
              ),
            ),
            if (chosen.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                child: Text(l.calendarText.noEvents),
              ),
            for (final e in chosen) _EventTile(event: e, color: _color(e), onTap: () => _open(e)),
          ],
        );
        // Side by side where there is room, the list under the grid where there is not.
        if (constraints.maxWidth >= 900) {
          return Row(
            children: [
              Expanded(flex: 3, child: grid),
              const KDivider(),
              Expanded(flex: 2, child: list),
            ],
          );
        }
        return Column(
          children: [
            Expanded(flex: 3, child: grid),
            const KDivider(),
            Expanded(flex: 2, child: list),
          ],
        );
      },
    );
  }

  Future<void> _open(Event e) async {
    final answered = await Navigator.of(context).push<bool>(
      KPageRoute(
        builder: (_) => EventPage(account: widget.account, event: e, color: _color(e), calendars: _writable),
      ),
    );
    if (answered ?? false) _load();
  }
}

DateTime? _local(String? rfc3339) => rfc3339 == null ? null : DateTime.tryParse(rfc3339)?.toLocal();

/// A start or end: a time in the device's zone, or – for an all-day event – a date in none.
DateTime? _when(Event e, String? text) {
  if (text == null) return null;
  return e.allDay ? DateTime.tryParse(text) : _local(text);
}

/// One instance of a recurring event as a draft, to change it alone: its own title, times, place and description.
EventDraft instanceDraft(Event e) {
  final start = _when(e, e.start) ?? DateTime.now();
  final end = _when(e, e.end) ?? start;
  return EventDraft(
    calendarId: e.calendarIds.firstOrNull ?? '',
    accountId: e.accountId,
    title: e.title,
    allDay: e.allDay,
    start: localTime(start),
    // An all-day event's draft ends on its last day, not the day after.
    end: localTime(e.allDay ? end.subtract(const Duration(days: 1)) : end),
    location: e.location ?? '',
    description: e.description ?? '',
    participants: const [],
  );
}

Color? _parseColor(String? css) {
  final hex = css?.trim();
  if (hex == null || !RegExp(r'^#[0-9a-fA-F]{6}$').hasMatch(hex)) return null;
  return Color(int.parse('ff${hex.substring(1)}', radix: 16));
}

/// `09:00 – 10:30`, or "All day".
String _times(AppLocalizations l, String locale, Event e) {
  if (e.allDay) return l.calendarText.allDay;
  final start = _local(e.start);
  final end = _local(e.end);
  if (start == null) return '';
  final format = DateFormat.Hm(locale);
  return end == null ? format.format(start) : '${format.format(start)} – ${format.format(end)}';
}

/// A day of the month grid: its number, and its events – as titles, or as dots where there is no room.
class _DayCell extends StatelessWidget {
  const _DayCell({
    required this.day,
    required this.inMonth,
    required this.today,
    required this.chosen,
    required this.events,
    required this.titles,
    required this.color,
    required this.onTap,
  });

  final DateTime day;
  final bool inMonth;
  final bool today;
  final bool chosen;
  final List<Event> events;
  final bool titles;
  final Color? Function(Event) color;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final number = Container(
      width: 24,
      height: 24,
      alignment: Alignment.center,
      decoration: today ? BoxDecoration(color: context.k.accent, shape: BoxShape.circle) : null,
      child: Text(
        '${day.day}',
        style: KText.label(context.k)
            .copyWith(fontSize: 13)
            .copyWith(
              color: today
                  ? context.k.accentText
                  : inMonth
                  ? null
                  : context.k.text.withValues(alpha: 0.4),
            ),
      ),
    );
    return KTappable(
      key: ValueKey('day-${DateFormat('yyyy-MM-dd').format(day)}'),
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          color: chosen ? context.k.accentSoft.withValues(alpha: 0.5) : null,
          border: Border.all(color: context.k.line.withValues(alpha: 0.3), width: 0.5),
        ),
        padding: const EdgeInsets.all(2),
        child: Column(
          crossAxisAlignment: titles ? CrossAxisAlignment.start : CrossAxisAlignment.center,
          children: [
            number,
            if (titles)
              Expanded(
                child: ClipRect(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      for (final e in events)
                        Container(
                          margin: const EdgeInsets.only(top: 1),
                          padding: const EdgeInsets.symmetric(horizontal: 3),
                          decoration: BoxDecoration(
                            color: (color(e) ?? context.k.accent).withValues(alpha: 0.18),
                            borderRadius: BorderRadius.circular(3),
                          ),
                          child: Text(
                            e.title.isEmpty ? '–' : e.title,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: KText.small(context.k)
                                .copyWith(fontSize: 12)
                                .copyWith(decoration: e.cancelled ? TextDecoration.lineThrough : null),
                          ),
                        ),
                    ],
                  ),
                ),
              )
            else if (events.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Wrap(
                  spacing: 2,
                  runSpacing: 2,
                  alignment: WrapAlignment.center,
                  children: [
                    for (final e in events.take(4))
                      Container(
                        width: 5,
                        height: 5,
                        decoration: BoxDecoration(color: color(e) ?? context.k.accent, shape: BoxShape.circle),
                      ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _EventTile extends StatelessWidget {
  const _EventTile({required this.event, required this.color, required this.onTap});

  final Event event;
  final Color? color;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final locale = Localizations.localeOf(context).toLanguageTag();
    final details = [_times(l, locale, event), if (event.location != null) event.location!].join(' · ');
    return KListRow(
      leading: Container(
        width: 4,
        height: 36,
        decoration: BoxDecoration(color: color ?? context.k.accent, borderRadius: BorderRadius.circular(2)),
      ),
      title: Text(
        event.title.isEmpty ? l.noSubject : event.title,
        style: event.cancelled ? const TextStyle(decoration: TextDecoration.lineThrough) : null,
      ),
      subtitle: Text(event.cancelled ? '${l.calendarText.cancelled} · $details' : details),
      trailing: event.invitationKey != null && (event.myStatus ?? 'needs-action') == 'needs-action'
          ? Icon(LucideIcons.mailWarning, color: context.k.accent)
          : null,
      onTap: onTap,
    );
  }
}

String _statusText(AppLocalizations l, String? status) => switch (status) {
  'accepted' => l.calendarText.statusAccepted,
  'tentative' => l.calendarText.statusTentative,
  'declined' => l.calendarText.statusDeclined,
  _ => l.calendarText.statusNeedsAction,
};

/// One event: when, where, who, the description – and the answer to an invitation. Pops `true` once answered.
class EventPage extends StatefulWidget {
  const EventPage({super.key, required this.account, required this.event, this.color, this.calendars = const []});

  final Kernoid account;
  final Event event;
  final Color? color;

  /// The calendars events can be made in – the event can move between them when it is changed.
  final List<Calendar> calendars;

  @override
  State<EventPage> createState() => _EventPageState();
}

class _EventPageState extends State<EventPage> {
  late String? _status = widget.event.myStatus;
  bool _busy = false;
  bool _answered = false;

  Future<void> _answer(String status) async {
    final e = widget.event;
    setState(() => _busy = true);
    final messenger = KToast.of(context);
    final l = AppLocalizations.of(context);
    try {
      await widget.account.answerEvent(
        accountId: e.accountId,
        eventId: e.eventId,
        invitationKey: e.invitationKey!,
        status: status,
      );
      _answered = true;
      if (mounted) setState(() => _status = status);
      messenger.show(l.calendarText.answerSent);
    } catch (error) {
      messenger.show(l.error(errorText(error)));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// For an instance of a recurring event: whether the user means only it (`true`), the whole series (`false`), or
  /// neither (`null`).
  Future<bool?> _which(String question) {
    final l = AppLocalizations.of(context);
    return showKDialog<bool>(
      context,
      builder: (context) => KDialog(
        content: Text(question),
        actions: [
          KButton(tone: KTone.quiet, onPressed: () => Navigator.of(context).pop(), label: l.cancel),
          KButton(
            tone: KTone.quiet,
            key: const ValueKey('whole-series'),
            onPressed: () => Navigator.of(context).pop(false),
            label: l.calendarText.wholeSeries,
          ),
          KButton(
            tone: KTone.primary,
            key: const ValueKey('this-event'),
            onPressed: () => Navigator.of(context).pop(true),
            label: l.calendarText.thisEvent,
          ),
        ],
      ),
    );
  }

  Future<void> _edit() async {
    final e = widget.event;
    final messenger = KToast.of(context);
    final l = AppLocalizations.of(context);
    final one = e.recurrenceId == null ? false : await _which(l.calendarText.changeWhich);
    if (one == null || !mounted) return;
    try {
      final draft = one
          ? instanceDraft(e)
          : await widget.account.eventDraft(accountId: e.accountId, eventId: e.eventId);
      if (!mounted) return;
      final calendars = widget.calendars.isEmpty
          ? [Calendar(id: draft.calendarId, accountId: draft.accountId, name: '', writable: true)]
          : widget.calendars;
      final saved = await Navigator.of(context).push<bool>(
        KPageRoute(
          fullscreenDialog: true,
          builder: (_) => EventFormPage(
            account: widget.account,
            calendars: calendars,
            draft: draft,
            eventId: e.eventId,
            recurrenceId: one ? e.recurrenceId : null,
          ),
        ),
      );
      if ((saved ?? false) && mounted) {
        messenger.show(l.saved);
        Navigator.of(context).pop(true);
      }
    } catch (error) {
      messenger.show(l.error(errorText(error)));
    }
  }

  Future<void> _delete() async {
    final e = widget.event;
    final l = AppLocalizations.of(context);
    final messenger = KToast.of(context);
    final bool? one;
    if (e.recurrenceId != null) {
      one = await _which(l.calendarText.deleteWhich);
    } else {
      final sure = await showKDialog<bool>(
        context,
        builder: (context) => KDialog(
          content: Text(e.recurring ? l.calendarText.deleteRecurringConfirm : l.calendarText.deleteEventConfirm),
          actions: [
            KButton(tone: KTone.quiet, onPressed: () => Navigator.of(context).pop(false), label: l.cancel),
            KButton(
              tone: KTone.primary,
              key: const ValueKey('confirm-delete'),
              onPressed: () => Navigator.of(context).pop(true),
              label: l.delete,
            ),
          ],
        ),
      );
      one = (sure ?? false) ? false : null;
    }
    if (one == null) return;
    try {
      if (one) {
        await widget.account.deleteInstance(accountId: e.accountId, eventId: e.eventId, recurrenceId: e.recurrenceId!);
      } else {
        await widget.account.deleteEvent(accountId: e.accountId, eventId: e.eventId);
      }
      messenger.show(l.deleted);
      if (mounted) Navigator.of(context).pop(true);
    } catch (error) {
      messenger.show(l.error(errorText(error)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final locale = Localizations.localeOf(context).toLanguageTag();
    final e = widget.event;
    final start = _when(e, e.start);
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) Navigator.of(context).pop(_answered);
      },
      child: KScaffold(
        topBar: KTopBar(
          title: e.title.isEmpty ? l.noSubject : e.title,
          actions: [
            if (e.editable) ...[
              KIconButton(
                key: const ValueKey('edit-event'),
                tooltip: l.edit,
                onPressed: _edit,
                icon: LucideIcons.pencil,
              ),
              KIconButton(
                key: const ValueKey('delete-event'),
                tooltip: l.calendarText.deleteEvent,
                onPressed: _delete,
                icon: LucideIcons.trash2,
              ),
            ],
          ],
        ),
        body: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (e.cancelled)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text(l.calendarText.cancelled, style: TextStyle(color: context.k.error)),
              ),
            KListRow(
              leading: Icon(LucideIcons.clock, color: widget.color),
              title: Text(start == null ? '' : DateFormat.yMMMMEEEEd(locale).format(start)),
              subtitle: Text([_times(l, locale, e), if (e.recurring) l.calendarText.recurring].join(' · ')),
            ),
            if (e.location != null) KListRow(leading: const Icon(LucideIcons.mapPin), title: Text(e.location!)),
            if (e.description != null) ...[const SizedBox(height: 8), KSelectable.text(e.description!)],
            if (e.participants.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(l.calendarText.participants, style: KText.heading(context.k).copyWith(fontSize: 14)),
              for (final p in e.participants)
                KListRow(
                  leading: const Icon(LucideIcons.user),
                  title: Text(p.name ?? p.email ?? ''),
                  subtitle: Text(
                    [if (p.name != null && p.email != null) p.email!, _statusText(l, p.status)].join(' · '),
                  ),
                ),
            ],
            if (e.invitationKey != null && !e.cancelled) ...[
              const SizedBox(height: 16),
              Text(
                '${l.calendarText.yourAnswer}: ${_statusText(l, _status)}',
                style: KText.heading(context.k).copyWith(fontSize: 14),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                children: [
                  for (final (status, label) in [
                    ('accepted', l.calendarText.accept),
                    ('tentative', l.calendarText.maybe),
                    ('declined', l.calendarText.decline),
                  ])
                    KChip(
                      key: ValueKey('answer-$status'),
                      label: label,
                      selected: _status == status,
                      onTap: _busy || _status == status ? null : () => _answer(status),
                    ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }
}
