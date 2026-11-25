import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_de.dart';
import 'app_localizations_en.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
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
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale) : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate = _AppLocalizationsDelegate();

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

  /// No description provided for @appTitle.
  ///
  /// In en, this message translates to:
  /// **'kernoid'**
  String get appTitle;

  /// No description provided for @signInTitle.
  ///
  /// In en, this message translates to:
  /// **'Sign in to kernoid'**
  String get signInTitle;

  /// No description provided for @server.
  ///
  /// In en, this message translates to:
  /// **'Server'**
  String get server;

  /// No description provided for @serverHint.
  ///
  /// In en, this message translates to:
  /// **'https://kernoid.example'**
  String get serverHint;

  /// No description provided for @address.
  ///
  /// In en, this message translates to:
  /// **'Address'**
  String get address;

  /// No description provided for @appPassword.
  ///
  /// In en, this message translates to:
  /// **'App password'**
  String get appPassword;

  /// No description provided for @appPasswordHint.
  ///
  /// In en, this message translates to:
  /// **'Make one on your account page.'**
  String get appPasswordHint;

  /// No description provided for @signIn.
  ///
  /// In en, this message translates to:
  /// **'Sign in'**
  String get signIn;

  /// No description provided for @onThisDevice.
  ///
  /// In en, this message translates to:
  /// **'On this device only'**
  String get onThisDevice;

  /// No description provided for @required.
  ///
  /// In en, this message translates to:
  /// **'Required'**
  String get required;

  /// No description provided for @account.
  ///
  /// In en, this message translates to:
  /// **'Account'**
  String get account;

  /// No description provided for @inbox.
  ///
  /// In en, this message translates to:
  /// **'Inbox'**
  String get inbox;

  /// No description provided for @drafts.
  ///
  /// In en, this message translates to:
  /// **'Drafts'**
  String get drafts;

  /// No description provided for @sent.
  ///
  /// In en, this message translates to:
  /// **'Sent'**
  String get sent;

  /// No description provided for @archive.
  ///
  /// In en, this message translates to:
  /// **'Archive'**
  String get archive;

  /// No description provided for @junk.
  ///
  /// In en, this message translates to:
  /// **'Junk'**
  String get junk;

  /// No description provided for @trash.
  ///
  /// In en, this message translates to:
  /// **'Trash'**
  String get trash;

  /// No description provided for @noSubject.
  ///
  /// In en, this message translates to:
  /// **'(no subject)'**
  String get noSubject;

  /// No description provided for @discard.
  ///
  /// In en, this message translates to:
  /// **'Discard'**
  String get discard;

  /// No description provided for @save.
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get save;

  /// No description provided for @savedTo.
  ///
  /// In en, this message translates to:
  /// **'Saved to {path}'**
  String savedTo(String path);

  /// No description provided for @signedInAs.
  ///
  /// In en, this message translates to:
  /// **'Signed in as'**
  String get signedInAs;

  /// No description provided for @signOut.
  ///
  /// In en, this message translates to:
  /// **'Sign out'**
  String get signOut;

  /// No description provided for @e2eTitle.
  ///
  /// In en, this message translates to:
  /// **'End-to-end encryption'**
  String get e2eTitle;

  /// No description provided for @e2eBody.
  ///
  /// In en, this message translates to:
  /// **'Coming next: your key is made on this device and unlocked with your passkey. Mail to people with a key is encrypted without a setting, and vaults keep files only you can read.'**
  String get e2eBody;

  /// No description provided for @error.
  ///
  /// In en, this message translates to:
  /// **'Something went wrong: {message}'**
  String error(String message);

  /// No description provided for @retry.
  ///
  /// In en, this message translates to:
  /// **'Try again'**
  String get retry;

  /// No description provided for @e2eUnavailable.
  ///
  /// In en, this message translates to:
  /// **'This server does not offer end-to-end encryption.'**
  String get e2eUnavailable;

  /// No description provided for @e2eNoKey.
  ///
  /// In en, this message translates to:
  /// **'Your account has no key yet. Make one here: it is made on this device, and the server keeps it only protected – by a recovery code that only you have.'**
  String get e2eNoKey;

  /// No description provided for @e2eMakeKey.
  ///
  /// In en, this message translates to:
  /// **'Make my key'**
  String get e2eMakeKey;

  /// No description provided for @e2eLocked.
  ///
  /// In en, this message translates to:
  /// **'Your key is locked. Enter your recovery code to read encrypted mail and to send encrypted.'**
  String get e2eLocked;

  /// No description provided for @e2eUnlocked.
  ///
  /// In en, this message translates to:
  /// **'Unlocked on this device. Mail to people with a key goes encrypted and signed – without a setting.'**
  String get e2eUnlocked;

  /// No description provided for @recoveryCode.
  ///
  /// In en, this message translates to:
  /// **'Recovery code'**
  String get recoveryCode;

  /// No description provided for @unlock.
  ///
  /// In en, this message translates to:
  /// **'Unlock'**
  String get unlock;

  /// No description provided for @lock.
  ///
  /// In en, this message translates to:
  /// **'Lock'**
  String get lock;

  /// No description provided for @fingerprint.
  ///
  /// In en, this message translates to:
  /// **'Fingerprint'**
  String get fingerprint;

  /// No description provided for @postQuantum.
  ///
  /// In en, this message translates to:
  /// **'post-quantum (ML-KEM and ML-DSA with Curve25519)'**
  String get postQuantum;

  /// No description provided for @compatibleKind.
  ///
  /// In en, this message translates to:
  /// **'compatible (Curve25519)'**
  String get compatibleKind;

  /// No description provided for @tenantRecovers.
  ///
  /// In en, this message translates to:
  /// **'Your organisation can recover your key.'**
  String get tenantRecovers;

  /// No description provided for @recoveryTitle.
  ///
  /// In en, this message translates to:
  /// **'Your recovery code'**
  String get recoveryTitle;

  /// No description provided for @recoveryBody.
  ///
  /// In en, this message translates to:
  /// **'Write it down or keep it in your password manager. It is shown only now. Without it – and without a passkey that unlocks your key – mail encrypted to you cannot be read again.'**
  String get recoveryBody;

  /// No description provided for @recoveryKept.
  ///
  /// In en, this message translates to:
  /// **'I have kept the code safe'**
  String get recoveryKept;

  /// No description provided for @copy.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get copy;

  /// No description provided for @copied.
  ///
  /// In en, this message translates to:
  /// **'Copied'**
  String get copied;

  /// No description provided for @done.
  ///
  /// In en, this message translates to:
  /// **'Done'**
  String get done;

  /// No description provided for @e2eEncrypted.
  ///
  /// In en, this message translates to:
  /// **'End-to-end encrypted'**
  String get e2eEncrypted;

  /// No description provided for @signatureVerified.
  ///
  /// In en, this message translates to:
  /// **'signature checked'**
  String get signatureVerified;

  /// No description provided for @signatureUnverified.
  ///
  /// In en, this message translates to:
  /// **'signature not checked'**
  String get signatureUnverified;

  /// No description provided for @notSigned.
  ///
  /// In en, this message translates to:
  /// **'not signed'**
  String get notSigned;

  /// No description provided for @cancel.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get cancel;

  /// No description provided for @today.
  ///
  /// In en, this message translates to:
  /// **'Today'**
  String get today;

  /// No description provided for @saved.
  ///
  /// In en, this message translates to:
  /// **'Saved'**
  String get saved;

  /// No description provided for @deleted.
  ///
  /// In en, this message translates to:
  /// **'Deleted'**
  String get deleted;

  /// No description provided for @delete.
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get delete;

  /// No description provided for @edit.
  ///
  /// In en, this message translates to:
  /// **'Change'**
  String get edit;

  /// No description provided for @name.
  ///
  /// In en, this message translates to:
  /// **'Name'**
  String get name;

  /// No description provided for @onePerLine.
  ///
  /// In en, this message translates to:
  /// **'One per line'**
  String get onePerLine;

  /// No description provided for @signInBrowser.
  ///
  /// In en, this message translates to:
  /// **'Sign in with kernoid'**
  String get signInBrowser;

  /// No description provided for @signInBrowserHint.
  ///
  /// In en, this message translates to:
  /// **'In your browser – with a passkey, a password or a second factor, as your organisation has it.'**
  String get signInBrowserHint;

  /// No description provided for @orAppPassword.
  ///
  /// In en, this message translates to:
  /// **'or with an app password'**
  String get orAppPassword;

  /// No description provided for @signInAppPassword.
  ///
  /// In en, this message translates to:
  /// **'Sign in with the app password'**
  String get signInAppPassword;

  /// No description provided for @signInCancelled.
  ///
  /// In en, this message translates to:
  /// **'Sign-in cancelled'**
  String get signInCancelled;

  /// No description provided for @remove.
  ///
  /// In en, this message translates to:
  /// **'Remove'**
  String get remove;

  /// No description provided for @open.
  ///
  /// In en, this message translates to:
  /// **'Open'**
  String get open;

  /// No description provided for @nothingFound.
  ///
  /// In en, this message translates to:
  /// **'Nothing found'**
  String get nothingFound;

  /// No description provided for @rename.
  ///
  /// In en, this message translates to:
  /// **'Rename'**
  String get rename;

  /// No description provided for @newFolder.
  ///
  /// In en, this message translates to:
  /// **'New folder'**
  String get newFolder;

  /// No description provided for @create.
  ///
  /// In en, this message translates to:
  /// **'Create'**
  String get create;

  /// No description provided for @appPasswordWrong.
  ///
  /// In en, this message translates to:
  /// **'The address or the app password is wrong.'**
  String get appPasswordWrong;

  /// No description provided for @drive.
  ///
  /// In en, this message translates to:
  /// **'Drive'**
  String get drive;

  /// No description provided for @appearance.
  ///
  /// In en, this message translates to:
  /// **'Appearance'**
  String get appearance;

  /// No description provided for @appearanceHint.
  ///
  /// In en, this message translates to:
  /// **'Kept on this device.'**
  String get appearanceHint;

  /// No description provided for @themeSystem.
  ///
  /// In en, this message translates to:
  /// **'As the system'**
  String get themeSystem;

  /// No description provided for @themeLight.
  ///
  /// In en, this message translates to:
  /// **'Light'**
  String get themeLight;

  /// No description provided for @themeDark.
  ///
  /// In en, this message translates to:
  /// **'Dark'**
  String get themeDark;

  /// No description provided for @vacationOn.
  ///
  /// In en, this message translates to:
  /// **'Answer mail'**
  String get vacationOn;

  /// No description provided for @security.
  ///
  /// In en, this message translates to:
  /// **'Sign-in and security'**
  String get security;

  /// No description provided for @securityHint.
  ///
  /// In en, this message translates to:
  /// **'Your password, two-factor sign-in, passkeys, app passwords and sessions – and your name, picture, language and mail settings – are changed in the web app, where you sign in with your password.'**
  String get securityHint;

  /// No description provided for @openWebApp.
  ///
  /// In en, this message translates to:
  /// **'Open in the browser'**
  String get openWebApp;

  /// No description provided for @profile.
  ///
  /// In en, this message translates to:
  /// **'Name and picture'**
  String get profile;

  /// No description provided for @displayName.
  ///
  /// In en, this message translates to:
  /// **'Display name'**
  String get displayName;

  /// No description provided for @changePicture.
  ///
  /// In en, this message translates to:
  /// **'Change picture'**
  String get changePicture;

  /// No description provided for @removePicture.
  ///
  /// In en, this message translates to:
  /// **'Remove picture'**
  String get removePicture;

  /// No description provided for @pictureHint.
  ///
  /// In en, this message translates to:
  /// **'PNG, JPEG or WebP, up to 1 MiB – best square. Others in your organisation see it.'**
  String get pictureHint;

  /// No description provided for @emailLanguage.
  ///
  /// In en, this message translates to:
  /// **'Language of emails from kernoid'**
  String get emailLanguage;

  /// No description provided for @emailLanguageHint.
  ///
  /// In en, this message translates to:
  /// **'Invitations sent for you and notices to you are written in it; the app follows your system.'**
  String get emailLanguageHint;

  /// No description provided for @asTenantLanguage.
  ///
  /// In en, this message translates to:
  /// **'As the organisation ({language})'**
  String asTenantLanguage(String language);

  /// No description provided for @languageNamede.
  ///
  /// In en, this message translates to:
  /// **'Deutsch'**
  String get languageNamede;

  /// No description provided for @languageNameen.
  ///
  /// In en, this message translates to:
  /// **'English'**
  String get languageNameen;

  /// No description provided for @securityHintApp.
  ///
  /// In en, this message translates to:
  /// **'Your password, two-factor sign-in, passkeys, app passwords and sessions are changed in the web app, where you sign in with your password.'**
  String get securityHintApp;

  /// No description provided for @asTenant.
  ///
  /// In en, this message translates to:
  /// **'As the organisation'**
  String get asTenant;

  /// No description provided for @back.
  ///
  /// In en, this message translates to:
  /// **'Back'**
  String get back;

  /// No description provided for @close.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get close;

  /// No description provided for @clear.
  ///
  /// In en, this message translates to:
  /// **'Clear'**
  String get clear;

  /// No description provided for @cut.
  ///
  /// In en, this message translates to:
  /// **'Cut'**
  String get cut;

  /// No description provided for @paste.
  ///
  /// In en, this message translates to:
  /// **'Paste'**
  String get paste;

  /// No description provided for @selectAll.
  ///
  /// In en, this message translates to:
  /// **'Select all'**
  String get selectAll;

  /// No description provided for @pickDate.
  ///
  /// In en, this message translates to:
  /// **'Choose a date'**
  String get pickDate;

  /// No description provided for @pickTime.
  ///
  /// In en, this message translates to:
  /// **'Choose a time'**
  String get pickTime;

  /// No description provided for @previousMonth.
  ///
  /// In en, this message translates to:
  /// **'Previous month'**
  String get previousMonth;

  /// No description provided for @nextMonth.
  ///
  /// In en, this message translates to:
  /// **'Next month'**
  String get nextMonth;

  /// No description provided for @hour.
  ///
  /// In en, this message translates to:
  /// **'Hour'**
  String get hour;

  /// No description provided for @minute.
  ///
  /// In en, this message translates to:
  /// **'Minute'**
  String get minute;

  /// No description provided for @moreOptions.
  ///
  /// In en, this message translates to:
  /// **'More'**
  String get moreOptions;
}

class _AppLocalizationsDelegate extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) => <String>['de', 'en'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'de':
      return AppLocalizationsDe();
    case 'en':
      return AppLocalizationsEn();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
