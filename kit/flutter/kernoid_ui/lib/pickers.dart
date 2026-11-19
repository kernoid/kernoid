// SPDX-License-Identifier: MIT
import 'package:flutter/widgets.dart';
import 'package:intl/intl.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'app.dart';
import 'dialogs.dart';
import 'tokens.dart';
import 'widgets.dart';

/// A time of day – what Material's `TimeOfDay` was.
@immutable
class KTime {
  const KTime({required this.hour, required this.minute});

  KTime.fromDateTime(DateTime at) : hour = at.hour, minute = at.minute;

  final int hour;
  final int minute;

  /// As the user's language writes it (`14:30`, `2:30 PM`).
  String format(BuildContext context) =>
      DateFormat.jm(Localizations.localeOf(context).toLanguageTag()).format(DateTime(2000, 1, 1, hour, minute));

  @override
  bool operator ==(Object other) => other is KTime && other.hour == hour && other.minute == minute;

  @override
  int get hashCode => Object.hash(hour, minute);
}

/// The first day of a week in the user's language, 0 for Sunday to 6 for Saturday (as Material's localizations
/// counted it).
int firstDayOfWeekIndex(BuildContext context) {
  final symbols = DateFormat.yMd(Localizations.localeOf(context).toLanguageTag()).dateSymbols;
  // intl counts from Monday (0) to Sunday (6).
  return (symbols.FIRSTDAYOFWEEK + 1) % 7;
}

/// Asks for a day between `first` and `last` and returns it, or `null` when cancelled.
Future<DateTime?> showKDatePicker(
  BuildContext context, {
  required DateTime initial,
  required DateTime first,
  required DateTime last,
}) => showKDialog<DateTime>(
  context,
  builder: (context) => _DatePicker(initial: KDates.dateOnly(initial), first: first, last: last),
);

class _DatePicker extends StatefulWidget {
  const _DatePicker({required this.initial, required this.first, required this.last});

  final DateTime initial;
  final DateTime first;
  final DateTime last;

  @override
  State<_DatePicker> createState() => _DatePickerState();
}

class _DatePickerState extends State<_DatePicker> {
  late DateTime _month = DateTime(widget.initial.year, widget.initial.month);

  void _move(int months) => setState(() => _month = DateTime(_month.year, _month.month + months));

  bool _allowed(DateTime day) =>
      !day.isBefore(KDates.dateOnly(widget.first)) && !day.isAfter(KDates.dateOnly(widget.last));

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final t = AppLocalizations.of(context);
    final locale = Localizations.localeOf(context).toLanguageTag();
    final firstWeekday = firstDayOfWeekIndex(context); // 0 = Sunday
    final lead = (_month.weekday % 7 - firstWeekday + 7) % 7;
    final days = KDates.daysInMonth(_month.year, _month.month);
    final today = KDates.dateOnly(DateTime.now());
    final cells = <Widget>[
      for (var i = 0; i < 7; i++)
        Center(
          child: Text(
            DateFormat.E(locale).format(DateTime(2023, 1, 1 + (firstWeekday + i) % 7)).substring(0, 2),
            style: KText.small(k).copyWith(fontSize: 12, color: k.faint),
          ),
        ),
      for (var i = 0; i < lead; i++) const SizedBox.shrink(),
      for (var d = 1; d <= days; d++) _day(context, DateTime(_month.year, _month.month, d), today),
    ];
    return KDialog(
      width: 340,
      title: t.pickDate,
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            children: [
              Expanded(child: Text(DateFormat.yMMMM(locale).format(_month), style: KText.heading(k))),
              KIconButton(icon: LucideIcons.chevronLeft, tooltip: t.previousMonth, onPressed: () => _move(-1)),
              KIconButton(icon: LucideIcons.chevronRight, tooltip: t.nextMonth, onPressed: () => _move(1)),
            ],
          ),
          const SizedBox(height: 8),
          GridView.count(
            crossAxisCount: 7,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            mainAxisSpacing: 2,
            crossAxisSpacing: 2,
            children: cells,
          ),
        ],
      ),
      actions: [
        KButton(
          label: t.today,
          tone: KTone.quiet,
          onPressed: _allowed(today) ? () => Navigator.of(context).pop(today) : null,
        ),
        KButton(label: t.cancel, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop()),
      ],
    );
  }

  Widget _day(BuildContext context, DateTime day, DateTime today) {
    final k = context.k;
    final chosen = KDates.sameDay(day, widget.initial);
    final allowed = _allowed(day);
    final isToday = KDates.sameDay(day, today);
    return Semantics(
      button: true,
      selected: chosen,
      enabled: allowed,
      label: DateFormat.yMMMMd(Localizations.localeOf(context).toLanguageTag()).format(day),
      child: MouseRegion(
        cursor: allowed ? SystemMouseCursors.click : SystemMouseCursors.basic,
        child: GestureDetector(
          key: ValueKey('day-${day.year}-${day.month}-${day.day}'),
          onTap: allowed ? () => Navigator.of(context).pop(day) : null,
          child: Container(
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: chosen ? k.accent : KColor.transparent,
              shape: BoxShape.circle,
              border: isToday && !chosen ? Border.all(color: k.accent) : null,
            ),
            child: ExcludeSemantics(
              child: Text(
                '${day.day}',
                style: KText.label(k).copyWith(
                  color: chosen
                      ? k.accentText
                      : allowed
                      ? k.text
                      : k.faint,
                  fontWeight: chosen || isToday ? FontWeight.w600 : FontWeight.w400,
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Asks for a time of day and returns it, or `null` when cancelled: hours and minutes on two wheels.
Future<KTime?> showKTimePicker(BuildContext context, {required KTime initial}) =>
    showKDialog<KTime>(context, builder: (context) => _TimePicker(initial: initial));

class _TimePicker extends StatefulWidget {
  const _TimePicker({required this.initial});

  final KTime initial;

  @override
  State<_TimePicker> createState() => _TimePickerState();
}

class _TimePickerState extends State<_TimePicker> {
  late final _hours = FixedExtentScrollController(initialItem: widget.initial.hour);
  late final _minutes = FixedExtentScrollController(initialItem: widget.initial.minute);

  @override
  void dispose() {
    _hours.dispose();
    _minutes.dispose();
    super.dispose();
  }

  Widget _wheel(BuildContext context, FixedExtentScrollController controller, int count, String label) {
    final k = context.k;
    return SizedBox(
      width: 72,
      height: 180,
      child: Semantics(
        label: label,
        child: ListWheelScrollView.useDelegate(
          controller: controller,
          itemExtent: 40,
          diameterRatio: 1.6,
          physics: const FixedExtentScrollPhysics(),
          childDelegate: ListWheelChildLoopingListDelegate(
            children: [
              for (var i = 0; i < count; i++)
                Center(
                  child: Text(
                    i.toString().padLeft(2, '0'),
                    style: KText.title(k).copyWith(fontFeatures: const [FontFeature.tabularFigures()]),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  KTime get _chosen => KTime(hour: _hours.selectedItem % 24, minute: _minutes.selectedItem % 60);

  @override
  Widget build(BuildContext context) {
    final k = context.k;
    final t = AppLocalizations.of(context);
    return KDialog(
      width: 300,
      title: t.pickTime,
      content: Stack(
        alignment: Alignment.center,
        children: [
          Container(
            height: 40,
            decoration: BoxDecoration(color: k.accentSoft, borderRadius: BorderRadius.circular(KSize.radiusSmall)),
          ),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              _wheel(context, _hours, 24, t.hour),
              Text(':', style: KText.title(k)),
              _wheel(context, _minutes, 60, t.minute),
            ],
          ),
        ],
      ),
      actions: [
        KButton(label: t.cancel, tone: KTone.quiet, onPressed: () => Navigator.of(context).pop()),
        KButton(
          key: const ValueKey('time-ok'),
          label: t.done,
          tone: KTone.primary,
          onPressed: () => Navigator.of(context).pop(_chosen),
        ),
      ],
    );
  }
}
