// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'calendar_localizations.dart';

// ignore_for_file: type=lint

/// The translations for German (`de`).
class CalendarLocalizationsDe extends CalendarLocalizations {
  CalendarLocalizationsDe([String locale = 'de']) : super(locale);

  @override
  String get calendar => 'Kalender';

  @override
  String get earlier => 'Früher';

  @override
  String get later => 'Später';

  @override
  String get allDay => 'Ganztägig';

  @override
  String get noEvents => 'Keine Termine in diesen zwei Wochen';

  @override
  String get location => 'Ort';

  @override
  String get participants => 'Teilnehmende';

  @override
  String get accept => 'Zusagen';

  @override
  String get maybe => 'Vielleicht';

  @override
  String get decline => 'Absagen';

  @override
  String get cancelled => 'Abgesagt';

  @override
  String get recurring => 'Wiederholt sich';

  @override
  String get yourAnswer => 'Deine Antwort';

  @override
  String get statusAccepted => 'zugesagt';

  @override
  String get statusTentative => 'vielleicht';

  @override
  String get statusDeclined => 'abgesagt';

  @override
  String get statusNeedsAction => 'noch keine Antwort';

  @override
  String get answerSent => 'Antwort an die Person gesendet, die eingeladen hat';

  @override
  String sharedBy(String name) {
    return 'geteilt von $name';
  }

  @override
  String get newEvent => 'Neuer Termin';

  @override
  String get editEvent => 'Termin ändern';

  @override
  String get deleteEvent => 'Termin löschen';

  @override
  String get deleteEventConfirm => 'Diesen Termin löschen? Alle Eingeladenen erfahren davon.';

  @override
  String get deleteRecurringConfirm =>
      'Diesen Termin mit allen Wiederholungen löschen? Alle Eingeladenen erfahren davon.';

  @override
  String get title => 'Titel';

  @override
  String get starts => 'Beginn';

  @override
  String get ends => 'Ende';

  @override
  String get calendarField => 'Kalender';

  @override
  String get description => 'Beschreibung';

  @override
  String get invite => 'Einladen';

  @override
  String get inviteHint => 'Adressen, durch Komma getrennt – sie bekommen eine Einladung per E-Mail';

  @override
  String get repeat => 'Wiederholung';

  @override
  String get repeatNone => 'Nie';

  @override
  String get repeatDaily => 'Täglich';

  @override
  String get repeatWeekly => 'Wöchentlich';

  @override
  String get repeatMonthly => 'Monatlich';

  @override
  String get repeatYearly => 'Jährlich';

  @override
  String get endBeforeStart => 'Das Ende liegt vor dem Beginn';

  @override
  String get recurringEditsAll => 'Änderungen gelten für alle Wiederholungen.';

  @override
  String get thisEvent => 'Nur dieser Termin';

  @override
  String get wholeSeries => 'Die ganze Serie';

  @override
  String get changeWhich => 'Nur diesen Termin oder die ganze Serie ändern?';

  @override
  String get deleteWhich => 'Nur diesen Termin oder die ganze Serie löschen? Alle Eingeladenen erfahren davon.';

  @override
  String get editThisEvent => 'Diesen Termin ändern';

  @override
  String get instanceEditsOne => 'Nur dieser Termin der Serie ändert sich; die Eingeladenen bleiben wie in der Serie.';

  @override
  String get monthView => 'Monat';

  @override
  String get listView => 'Liste';
}
