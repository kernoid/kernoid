import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'calendar_localizations_de.dart';
import 'calendar_localizations_en.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of CalendarLocalizations
/// returned by `CalendarLocalizations.of(context)`.
///
/// Applications need to include `CalendarLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/calendar_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: CalendarLocalizations.localizationsDelegates,
///   supportedLocales: CalendarLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the CalendarLocalizations.supportedLocales
/// property.
abstract class CalendarLocalizations {
  CalendarLocalizations(String locale) : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static CalendarLocalizations of(BuildContext context) {
    return Localizations.of<CalendarLocalizations>(context, CalendarLocalizations)!;
  }

  static const LocalizationsDelegate<CalendarLocalizations> delegate = _CalendarLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates = <LocalizationsDelegate<dynamic>>[
    delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
  ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[Locale('de'), Locale('en')];

  /// No description provided for @calendar.
  ///
  /// In en, this message translates to:
  /// **'Calendar'**
  String get calendar;

  /// No description provided for @earlier.
  ///
  /// In en, this message translates to:
  /// **'Earlier'**
  String get earlier;

  /// No description provided for @later.
  ///
  /// In en, this message translates to:
  /// **'Later'**
  String get later;

  /// No description provided for @allDay.
  ///
  /// In en, this message translates to:
  /// **'All day'**
  String get allDay;

  /// No description provided for @noEvents.
  ///
  /// In en, this message translates to:
  /// **'No events in these two weeks'**
  String get noEvents;

  /// No description provided for @location.
  ///
  /// In en, this message translates to:
  /// **'Place'**
  String get location;

  /// No description provided for @participants.
  ///
  /// In en, this message translates to:
  /// **'Participants'**
  String get participants;

  /// No description provided for @accept.
  ///
  /// In en, this message translates to:
  /// **'Accept'**
  String get accept;

  /// No description provided for @maybe.
  ///
  /// In en, this message translates to:
  /// **'Maybe'**
  String get maybe;

  /// No description provided for @decline.
  ///
  /// In en, this message translates to:
  /// **'Decline'**
  String get decline;

  /// No description provided for @cancelled.
  ///
  /// In en, this message translates to:
  /// **'Cancelled'**
  String get cancelled;

  /// No description provided for @recurring.
  ///
  /// In en, this message translates to:
  /// **'Repeats'**
  String get recurring;

  /// No description provided for @yourAnswer.
  ///
  /// In en, this message translates to:
  /// **'Your answer'**
  String get yourAnswer;

  /// No description provided for @statusAccepted.
  ///
  /// In en, this message translates to:
  /// **'accepted'**
  String get statusAccepted;

  /// No description provided for @statusTentative.
  ///
  /// In en, this message translates to:
  /// **'maybe'**
  String get statusTentative;

  /// No description provided for @statusDeclined.
  ///
  /// In en, this message translates to:
  /// **'declined'**
  String get statusDeclined;

  /// No description provided for @statusNeedsAction.
  ///
  /// In en, this message translates to:
  /// **'no answer yet'**
  String get statusNeedsAction;

  /// No description provided for @answerSent.
  ///
  /// In en, this message translates to:
  /// **'Answer sent to the organizer'**
  String get answerSent;

  /// No description provided for @sharedBy.
  ///
  /// In en, this message translates to:
  /// **'shared by {name}'**
  String sharedBy(String name);

  /// No description provided for @newEvent.
  ///
  /// In en, this message translates to:
  /// **'New event'**
  String get newEvent;

  /// No description provided for @editEvent.
  ///
  /// In en, this message translates to:
  /// **'Change event'**
  String get editEvent;

  /// No description provided for @deleteEvent.
  ///
  /// In en, this message translates to:
  /// **'Delete event'**
  String get deleteEvent;

  /// No description provided for @deleteEventConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete this event? Everyone invited hears of it.'**
  String get deleteEventConfirm;

  /// No description provided for @deleteRecurringConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete this event with all its repetitions? Everyone invited hears of it.'**
  String get deleteRecurringConfirm;

  /// No description provided for @title.
  ///
  /// In en, this message translates to:
  /// **'Title'**
  String get title;

  /// No description provided for @starts.
  ///
  /// In en, this message translates to:
  /// **'Starts'**
  String get starts;

  /// No description provided for @ends.
  ///
  /// In en, this message translates to:
  /// **'Ends'**
  String get ends;

  /// No description provided for @calendarField.
  ///
  /// In en, this message translates to:
  /// **'Calendar'**
  String get calendarField;

  /// No description provided for @description.
  ///
  /// In en, this message translates to:
  /// **'Description'**
  String get description;

  /// No description provided for @invite.
  ///
  /// In en, this message translates to:
  /// **'Invite'**
  String get invite;

  /// No description provided for @inviteHint.
  ///
  /// In en, this message translates to:
  /// **'Addresses, separated by commas – they get an invitation by email'**
  String get inviteHint;

  /// No description provided for @repeat.
  ///
  /// In en, this message translates to:
  /// **'Repeats'**
  String get repeat;

  /// No description provided for @repeatNone.
  ///
  /// In en, this message translates to:
  /// **'Never'**
  String get repeatNone;

  /// No description provided for @repeatDaily.
  ///
  /// In en, this message translates to:
  /// **'Daily'**
  String get repeatDaily;

  /// No description provided for @repeatWeekly.
  ///
  /// In en, this message translates to:
  /// **'Weekly'**
  String get repeatWeekly;

  /// No description provided for @repeatMonthly.
  ///
  /// In en, this message translates to:
  /// **'Monthly'**
  String get repeatMonthly;

  /// No description provided for @repeatYearly.
  ///
  /// In en, this message translates to:
  /// **'Yearly'**
  String get repeatYearly;

  /// No description provided for @endBeforeStart.
  ///
  /// In en, this message translates to:
  /// **'The end is before the start'**
  String get endBeforeStart;

  /// No description provided for @recurringEditsAll.
  ///
  /// In en, this message translates to:
  /// **'Changes apply to every repetition.'**
  String get recurringEditsAll;

  /// No description provided for @thisEvent.
  ///
  /// In en, this message translates to:
  /// **'This event'**
  String get thisEvent;

  /// No description provided for @wholeSeries.
  ///
  /// In en, this message translates to:
  /// **'The whole series'**
  String get wholeSeries;

  /// No description provided for @changeWhich.
  ///
  /// In en, this message translates to:
  /// **'Change only this event or the whole series?'**
  String get changeWhich;

  /// No description provided for @deleteWhich.
  ///
  /// In en, this message translates to:
  /// **'Delete only this event or the whole series? Everyone invited hears of it.'**
  String get deleteWhich;

  /// No description provided for @editThisEvent.
  ///
  /// In en, this message translates to:
  /// **'Change this event'**
  String get editThisEvent;

  /// No description provided for @instanceEditsOne.
  ///
  /// In en, this message translates to:
  /// **'Only this event of the series changes; who is invited stays as in the series.'**
  String get instanceEditsOne;

  /// No description provided for @monthView.
  ///
  /// In en, this message translates to:
  /// **'Month'**
  String get monthView;

  /// No description provided for @listView.
  ///
  /// In en, this message translates to:
  /// **'List'**
  String get listView;
}

class _CalendarLocalizationsDelegate extends LocalizationsDelegate<CalendarLocalizations> {
  const _CalendarLocalizationsDelegate();

  @override
  Future<CalendarLocalizations> load(Locale locale) {
    return SynchronousFuture<CalendarLocalizations>(lookupCalendarLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) => <String>['de', 'en'].contains(locale.languageCode);

  @override
  bool shouldReload(_CalendarLocalizationsDelegate old) => false;
}

CalendarLocalizations lookupCalendarLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'de':
      return CalendarLocalizationsDe();
    case 'en':
      return CalendarLocalizationsEn();
  }

  throw FlutterError(
    'CalendarLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
