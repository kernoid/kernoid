// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'calendar_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class CalendarLocalizationsEn extends CalendarLocalizations {
  CalendarLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get calendar => 'Calendar';

  @override
  String get earlier => 'Earlier';

  @override
  String get later => 'Later';

  @override
  String get allDay => 'All day';

  @override
  String get noEvents => 'No events in these two weeks';

  @override
  String get location => 'Place';

  @override
  String get participants => 'Participants';

  @override
  String get accept => 'Accept';

  @override
  String get maybe => 'Maybe';

  @override
  String get decline => 'Decline';

  @override
  String get cancelled => 'Cancelled';

  @override
  String get recurring => 'Repeats';

  @override
  String get yourAnswer => 'Your answer';

  @override
  String get statusAccepted => 'accepted';

  @override
  String get statusTentative => 'maybe';

  @override
  String get statusDeclined => 'declined';

  @override
  String get statusNeedsAction => 'no answer yet';

  @override
  String get answerSent => 'Answer sent to the organizer';

  @override
  String sharedBy(String name) {
    return 'shared by $name';
  }

  @override
  String get newEvent => 'New event';

  @override
  String get editEvent => 'Change event';

  @override
  String get deleteEvent => 'Delete event';

  @override
  String get deleteEventConfirm => 'Delete this event? Everyone invited hears of it.';

  @override
  String get deleteRecurringConfirm => 'Delete this event with all its repetitions? Everyone invited hears of it.';

  @override
  String get title => 'Title';

  @override
  String get starts => 'Starts';

  @override
  String get ends => 'Ends';

  @override
  String get calendarField => 'Calendar';

  @override
  String get description => 'Description';

  @override
  String get invite => 'Invite';

  @override
  String get inviteHint => 'Addresses, separated by commas – they get an invitation by email';

  @override
  String get repeat => 'Repeats';

  @override
  String get repeatNone => 'Never';

  @override
  String get repeatDaily => 'Daily';

  @override
  String get repeatWeekly => 'Weekly';

  @override
  String get repeatMonthly => 'Monthly';

  @override
  String get repeatYearly => 'Yearly';

  @override
  String get endBeforeStart => 'The end is before the start';

  @override
  String get recurringEditsAll => 'Changes apply to every repetition.';

  @override
  String get thisEvent => 'This event';

  @override
  String get wholeSeries => 'The whole series';

  @override
  String get changeWhich => 'Change only this event or the whole series?';

  @override
  String get deleteWhich => 'Delete only this event or the whole series? Everyone invited hears of it.';

  @override
  String get editThisEvent => 'Change this event';

  @override
  String get instanceEditsOne => 'Only this event of the series changes; who is invited stays as in the series.';

  @override
  String get monthView => 'Month';

  @override
  String get listView => 'List';
}
