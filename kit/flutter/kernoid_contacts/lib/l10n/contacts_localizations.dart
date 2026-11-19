import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'contacts_localizations_de.dart';
import 'contacts_localizations_en.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of ContactsLocalizations
/// returned by `ContactsLocalizations.of(context)`.
///
/// Applications need to include `ContactsLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/contacts_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: ContactsLocalizations.localizationsDelegates,
///   supportedLocales: ContactsLocalizations.supportedLocales,
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
/// be consistent with the languages listed in the ContactsLocalizations.supportedLocales
/// property.
abstract class ContactsLocalizations {
  ContactsLocalizations(String locale) : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static ContactsLocalizations of(BuildContext context) {
    return Localizations.of<ContactsLocalizations>(context, ContactsLocalizations)!;
  }

  static const LocalizationsDelegate<ContactsLocalizations> delegate = _ContactsLocalizationsDelegate();

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

  /// No description provided for @contacts.
  ///
  /// In en, this message translates to:
  /// **'Contacts'**
  String get contacts;

  /// No description provided for @searchContacts.
  ///
  /// In en, this message translates to:
  /// **'Search contacts'**
  String get searchContacts;

  /// No description provided for @noContacts.
  ///
  /// In en, this message translates to:
  /// **'No contacts'**
  String get noContacts;

  /// No description provided for @emails.
  ///
  /// In en, this message translates to:
  /// **'Email'**
  String get emails;

  /// No description provided for @phones.
  ///
  /// In en, this message translates to:
  /// **'Phone'**
  String get phones;

  /// No description provided for @notes.
  ///
  /// In en, this message translates to:
  /// **'Notes'**
  String get notes;

  /// No description provided for @writeEmail.
  ///
  /// In en, this message translates to:
  /// **'Write email'**
  String get writeEmail;

  /// No description provided for @organization.
  ///
  /// In en, this message translates to:
  /// **'Organisation'**
  String get organization;

  /// No description provided for @newContact.
  ///
  /// In en, this message translates to:
  /// **'New contact'**
  String get newContact;

  /// No description provided for @editContact.
  ///
  /// In en, this message translates to:
  /// **'Change contact'**
  String get editContact;

  /// No description provided for @deleteContactConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete this contact?'**
  String get deleteContactConfirm;

  /// No description provided for @emailsField.
  ///
  /// In en, this message translates to:
  /// **'Email addresses'**
  String get emailsField;

  /// No description provided for @phonesField.
  ///
  /// In en, this message translates to:
  /// **'Phone numbers'**
  String get phonesField;

  /// No description provided for @note.
  ///
  /// In en, this message translates to:
  /// **'Note'**
  String get note;

  /// No description provided for @labelWork.
  ///
  /// In en, this message translates to:
  /// **'work'**
  String get labelWork;

  /// No description provided for @labelPrivate.
  ///
  /// In en, this message translates to:
  /// **'private'**
  String get labelPrivate;

  /// No description provided for @labelMobile.
  ///
  /// In en, this message translates to:
  /// **'mobile'**
  String get labelMobile;

  /// No description provided for @labelVoice.
  ///
  /// In en, this message translates to:
  /// **'voice'**
  String get labelVoice;

  /// No description provided for @labelText.
  ///
  /// In en, this message translates to:
  /// **'text'**
  String get labelText;

  /// No description provided for @labelVideo.
  ///
  /// In en, this message translates to:
  /// **'video'**
  String get labelVideo;

  /// No description provided for @labelFax.
  ///
  /// In en, this message translates to:
  /// **'fax'**
  String get labelFax;

  /// No description provided for @labelPager.
  ///
  /// In en, this message translates to:
  /// **'pager'**
  String get labelPager;

  /// No description provided for @labelTextphone.
  ///
  /// In en, this message translates to:
  /// **'textphone'**
  String get labelTextphone;

  /// No description provided for @labels.
  ///
  /// In en, this message translates to:
  /// **'Labels'**
  String get labels;

  /// No description provided for @addEmail.
  ///
  /// In en, this message translates to:
  /// **'Add an address'**
  String get addEmail;

  /// No description provided for @addPhone.
  ///
  /// In en, this message translates to:
  /// **'Add a number'**
  String get addPhone;
}

class _ContactsLocalizationsDelegate extends LocalizationsDelegate<ContactsLocalizations> {
  const _ContactsLocalizationsDelegate();

  @override
  Future<ContactsLocalizations> load(Locale locale) {
    return SynchronousFuture<ContactsLocalizations>(lookupContactsLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) => <String>['de', 'en'].contains(locale.languageCode);

  @override
  bool shouldReload(_ContactsLocalizationsDelegate old) => false;
}

ContactsLocalizations lookupContactsLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'de':
      return ContactsLocalizationsDe();
    case 'en':
      return ContactsLocalizationsEn();
  }

  throw FlutterError(
    'ContactsLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
