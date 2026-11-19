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

  /// No description provided for @required.
  ///
  /// In en, this message translates to:
  /// **'Required'**
  String get required;

  /// No description provided for @mail.
  ///
  /// In en, this message translates to:
  /// **'Mail'**
  String get mail;

  /// No description provided for @files.
  ///
  /// In en, this message translates to:
  /// **'Files'**
  String get files;

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

  /// No description provided for @noMessages.
  ///
  /// In en, this message translates to:
  /// **'No messages'**
  String get noMessages;

  /// No description provided for @noSubject.
  ///
  /// In en, this message translates to:
  /// **'(no subject)'**
  String get noSubject;

  /// No description provided for @selectMessage.
  ///
  /// In en, this message translates to:
  /// **'Select a message'**
  String get selectMessage;

  /// No description provided for @from.
  ///
  /// In en, this message translates to:
  /// **'From'**
  String get from;

  /// No description provided for @to.
  ///
  /// In en, this message translates to:
  /// **'To'**
  String get to;

  /// No description provided for @cc.
  ///
  /// In en, this message translates to:
  /// **'Cc'**
  String get cc;

  /// No description provided for @subject.
  ///
  /// In en, this message translates to:
  /// **'Subject'**
  String get subject;

  /// No description provided for @message.
  ///
  /// In en, this message translates to:
  /// **'Message'**
  String get message;

  /// No description provided for @write.
  ///
  /// In en, this message translates to:
  /// **'Write'**
  String get write;

  /// No description provided for @send.
  ///
  /// In en, this message translates to:
  /// **'Send'**
  String get send;

  /// No description provided for @discard.
  ///
  /// In en, this message translates to:
  /// **'Discard'**
  String get discard;

  /// No description provided for @messageSent.
  ///
  /// In en, this message translates to:
  /// **'Message sent'**
  String get messageSent;

  /// No description provided for @attachments.
  ///
  /// In en, this message translates to:
  /// **'Attachments'**
  String get attachments;

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

  /// No description provided for @loadMore.
  ///
  /// In en, this message translates to:
  /// **'Load more'**
  String get loadMore;

  /// No description provided for @myFiles.
  ///
  /// In en, this message translates to:
  /// **'My files'**
  String get myFiles;

  /// No description provided for @folderEmpty.
  ///
  /// In en, this message translates to:
  /// **'This folder is empty'**
  String get folderEmpty;

  /// No description provided for @refresh.
  ///
  /// In en, this message translates to:
  /// **'Refresh'**
  String get refresh;

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

  /// No description provided for @encryptedMessage.
  ///
  /// In en, this message translates to:
  /// **'Encrypted message'**
  String get encryptedMessage;

  /// No description provided for @unlockToRead.
  ///
  /// In en, this message translates to:
  /// **'Unlock your key to read it'**
  String get unlockToRead;

  /// No description provided for @lockedEmail.
  ///
  /// In en, this message translates to:
  /// **'This message is end-to-end encrypted. Unlock your key to read it.'**
  String get lockedEmail;

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

  /// No description provided for @willEncrypt.
  ///
  /// In en, this message translates to:
  /// **'Will be sent end-to-end encrypted and signed.'**
  String get willEncrypt;

  /// No description provided for @wontEncrypt.
  ///
  /// In en, this message translates to:
  /// **'Not end-to-end encrypted: {reason}'**
  String wontEncrypt(String reason);

  /// No description provided for @sentEncrypted.
  ///
  /// In en, this message translates to:
  /// **'Sent end-to-end encrypted'**
  String get sentEncrypted;

  /// No description provided for @cancel.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get cancel;

  /// No description provided for @calendar.
  ///
  /// In en, this message translates to:
  /// **'Calendar'**
  String get calendar;

  /// No description provided for @contacts.
  ///
  /// In en, this message translates to:
  /// **'Contacts'**
  String get contacts;

  /// No description provided for @today.
  ///
  /// In en, this message translates to:
  /// **'Today'**
  String get today;

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

  /// No description provided for @name.
  ///
  /// In en, this message translates to:
  /// **'Name'**
  String get name;

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

  /// No description provided for @onePerLine.
  ///
  /// In en, this message translates to:
  /// **'One per line'**
  String get onePerLine;

  /// No description provided for @note.
  ///
  /// In en, this message translates to:
  /// **'Note'**
  String get note;

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

  /// No description provided for @bcc.
  ///
  /// In en, this message translates to:
  /// **'Bcc'**
  String get bcc;

  /// No description provided for @reply.
  ///
  /// In en, this message translates to:
  /// **'Reply'**
  String get reply;

  /// No description provided for @replyAll.
  ///
  /// In en, this message translates to:
  /// **'Reply all'**
  String get replyAll;

  /// No description provided for @forward.
  ///
  /// In en, this message translates to:
  /// **'Forward'**
  String get forward;

  /// No description provided for @attachFile.
  ///
  /// In en, this message translates to:
  /// **'Attach a file'**
  String get attachFile;

  /// No description provided for @remove.
  ///
  /// In en, this message translates to:
  /// **'Remove'**
  String get remove;

  /// Above a quoted reply; {date} and {who} are filled in by the app, not by Flutter.
  ///
  /// In en, this message translates to:
  /// **'On {date}, {who} wrote:'**
  String quoteWrote(String date, String who);

  /// No description provided for @quoteForwarded.
  ///
  /// In en, this message translates to:
  /// **'---------- Forwarded message ----------'**
  String get quoteForwarded;

  /// How the date above a quote is written: a format of Rust's chrono (strftime).
  ///
  /// In en, this message translates to:
  /// **'%a, %d %b %Y %H:%M'**
  String get quoteDateFormat;

  /// No description provided for @date.
  ///
  /// In en, this message translates to:
  /// **'Date'**
  String get date;

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

  /// No description provided for @loadImages.
  ///
  /// In en, this message translates to:
  /// **'Load images'**
  String get loadImages;

  /// No description provided for @imagesBlocked.
  ///
  /// In en, this message translates to:
  /// **'Images from the internet are not loaded until you ask for them.'**
  String get imagesBlocked;

  /// No description provided for @openLink.
  ///
  /// In en, this message translates to:
  /// **'Open this link?'**
  String get openLink;

  /// No description provided for @open.
  ///
  /// In en, this message translates to:
  /// **'Open'**
  String get open;

  /// No description provided for @asText.
  ///
  /// In en, this message translates to:
  /// **'As text'**
  String get asText;

  /// No description provided for @asHtml.
  ///
  /// In en, this message translates to:
  /// **'Formatted'**
  String get asHtml;

  /// No description provided for @mailboxes.
  ///
  /// In en, this message translates to:
  /// **'Folders'**
  String get mailboxes;

  /// No description provided for @searchMail.
  ///
  /// In en, this message translates to:
  /// **'Search mail'**
  String get searchMail;

  /// No description provided for @searchResults.
  ///
  /// In en, this message translates to:
  /// **'Search results'**
  String get searchResults;

  /// No description provided for @myMailbox.
  ///
  /// In en, this message translates to:
  /// **'My mailbox'**
  String get myMailbox;

  /// No description provided for @nothingFound.
  ///
  /// In en, this message translates to:
  /// **'Nothing found'**
  String get nothingFound;

  /// No description provided for @chooseAll.
  ///
  /// In en, this message translates to:
  /// **'Choose all'**
  String get chooseAll;

  /// No description provided for @markRead.
  ///
  /// In en, this message translates to:
  /// **'Read or unread'**
  String get markRead;

  /// No description provided for @flag.
  ///
  /// In en, this message translates to:
  /// **'Flag'**
  String get flag;

  /// No description provided for @moveTo.
  ///
  /// In en, this message translates to:
  /// **'Move to'**
  String get moveTo;

  /// No description provided for @chosen.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 chosen} other{{count} chosen}}'**
  String chosen(int count);

  /// No description provided for @deleteForGood.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{Delete this email for good?} other{Delete these {count} emails for good?}}'**
  String deleteForGood(int count);

  /// No description provided for @newSubfolder.
  ///
  /// In en, this message translates to:
  /// **'New folder in it'**
  String get newSubfolder;

  /// No description provided for @rename.
  ///
  /// In en, this message translates to:
  /// **'Rename'**
  String get rename;

  /// No description provided for @moveFolder.
  ///
  /// In en, this message translates to:
  /// **'Move'**
  String get moveFolder;

  /// No description provided for @emptyFolder.
  ///
  /// In en, this message translates to:
  /// **'Empty'**
  String get emptyFolder;

  /// No description provided for @deleteFolder.
  ///
  /// In en, this message translates to:
  /// **'Delete folder'**
  String get deleteFolder;

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

  /// No description provided for @topLevel.
  ///
  /// In en, this message translates to:
  /// **'At the top'**
  String get topLevel;

  /// No description provided for @folders.
  ///
  /// In en, this message translates to:
  /// **'Folders'**
  String get folders;

  /// No description provided for @moveFolderTo.
  ///
  /// In en, this message translates to:
  /// **'Move “{name}” to'**
  String moveFolderTo(String name);

  /// No description provided for @emptyFolderConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete every email in “{name}” for good?'**
  String emptyFolderConfirm(String name);

  /// No description provided for @deleteFolderConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete the folder “{name}”?'**
  String deleteFolderConfirm(String name);

  /// No description provided for @deleteFolderWithEmails.
  ///
  /// In en, this message translates to:
  /// **'Delete the folder “{name}” and the {count, plural, =1{email} other{{count} emails}} only in it, for good?'**
  String deleteFolderWithEmails(String name, int count);

  /// No description provided for @appPasswordWrong.
  ///
  /// In en, this message translates to:
  /// **'The address or the app password is wrong.'**
  String get appPasswordWrong;

  /// No description provided for @drives.
  ///
  /// In en, this message translates to:
  /// **'Drives'**
  String get drives;

  /// No description provided for @sharedWithMe.
  ///
  /// In en, this message translates to:
  /// **'Shared with me'**
  String get sharedWithMe;

  /// No description provided for @upload.
  ///
  /// In en, this message translates to:
  /// **'Upload'**
  String get upload;

  /// No description provided for @uploading.
  ///
  /// In en, this message translates to:
  /// **'Uploading …'**
  String get uploading;

  /// No description provided for @searchFiles.
  ///
  /// In en, this message translates to:
  /// **'Search names and contents'**
  String get searchFiles;

  /// No description provided for @share.
  ///
  /// In en, this message translates to:
  /// **'Share'**
  String get share;

  /// No description provided for @shareTitle.
  ///
  /// In en, this message translates to:
  /// **'Share “{name}”'**
  String shareTitle(String name);

  /// No description provided for @findPeople.
  ///
  /// In en, this message translates to:
  /// **'Find people and groups'**
  String get findPeople;

  /// No description provided for @levelRead.
  ///
  /// In en, this message translates to:
  /// **'Can view'**
  String get levelRead;

  /// No description provided for @levelEdit.
  ///
  /// In en, this message translates to:
  /// **'Can edit'**
  String get levelEdit;

  /// No description provided for @levelFull.
  ///
  /// In en, this message translates to:
  /// **'Can edit and share'**
  String get levelFull;

  /// No description provided for @notShared.
  ///
  /// In en, this message translates to:
  /// **'Shared with nobody yet.'**
  String get notShared;

  /// No description provided for @shared.
  ///
  /// In en, this message translates to:
  /// **'Shared'**
  String get shared;

  /// No description provided for @link.
  ///
  /// In en, this message translates to:
  /// **'Link'**
  String get link;

  /// No description provided for @linksTitle.
  ///
  /// In en, this message translates to:
  /// **'Links to “{name}”'**
  String linksTitle(String name);

  /// No description provided for @linkView.
  ///
  /// In en, this message translates to:
  /// **'View'**
  String get linkView;

  /// No description provided for @linkAdd.
  ///
  /// In en, this message translates to:
  /// **'View and add'**
  String get linkAdd;

  /// No description provided for @linkDrop.
  ///
  /// In en, this message translates to:
  /// **'Only add'**
  String get linkDrop;

  /// No description provided for @expires.
  ///
  /// In en, this message translates to:
  /// **'Expires'**
  String get expires;

  /// No description provided for @never.
  ///
  /// In en, this message translates to:
  /// **'Never'**
  String get never;

  /// No description provided for @inDays.
  ///
  /// In en, this message translates to:
  /// **'In {days} days'**
  String inDays(int days);

  /// No description provided for @expiresOn.
  ///
  /// In en, this message translates to:
  /// **'Expires {date}'**
  String expiresOn(String date);

  /// No description provided for @withPassword.
  ///
  /// In en, this message translates to:
  /// **'With password'**
  String get withPassword;

  /// No description provided for @passwordOptional.
  ///
  /// In en, this message translates to:
  /// **'Password (optional)'**
  String get passwordOptional;

  /// No description provided for @createLink.
  ///
  /// In en, this message translates to:
  /// **'Make a link'**
  String get createLink;

  /// No description provided for @linkMade.
  ///
  /// In en, this message translates to:
  /// **'The link – it is shown only now:'**
  String get linkMade;

  /// No description provided for @noLinks.
  ///
  /// In en, this message translates to:
  /// **'No links yet.'**
  String get noLinks;

  /// No description provided for @versions.
  ///
  /// In en, this message translates to:
  /// **'Versions'**
  String get versions;

  /// No description provided for @currentVersion.
  ///
  /// In en, this message translates to:
  /// **'Current'**
  String get currentVersion;

  /// No description provided for @restore.
  ///
  /// In en, this message translates to:
  /// **'Restore'**
  String get restore;

  /// No description provided for @restoreConfirm.
  ///
  /// In en, this message translates to:
  /// **'Make this version the file\'s content again? The current one stays as a version.'**
  String get restoreConfirm;

  /// No description provided for @copyOrMove.
  ///
  /// In en, this message translates to:
  /// **'Copy or move'**
  String get copyOrMove;

  /// No description provided for @copyHere.
  ///
  /// In en, this message translates to:
  /// **'Copy here'**
  String get copyHere;

  /// No description provided for @moveHere.
  ///
  /// In en, this message translates to:
  /// **'Move here'**
  String get moveHere;

  /// No description provided for @deleteFileConfirm.
  ///
  /// In en, this message translates to:
  /// **'Delete “{name}” for good?'**
  String deleteFileConfirm(String name);

  /// No description provided for @trashEmptyNote.
  ///
  /// In en, this message translates to:
  /// **'The trash is empty'**
  String get trashEmptyNote;

  /// No description provided for @more.
  ///
  /// In en, this message translates to:
  /// **'More'**
  String get more;

  /// No description provided for @newFolderName.
  ///
  /// In en, this message translates to:
  /// **'Name of the new folder'**
  String get newFolderName;

  /// No description provided for @newName.
  ///
  /// In en, this message translates to:
  /// **'New name'**
  String get newName;

  /// No description provided for @drive.
  ///
  /// In en, this message translates to:
  /// **'Drive'**
  String get drive;

  /// No description provided for @deleteFileForGood.
  ///
  /// In en, this message translates to:
  /// **'Delete for good'**
  String get deleteFileForGood;

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

  /// No description provided for @vacation.
  ///
  /// In en, this message translates to:
  /// **'Vacation response'**
  String get vacation;

  /// No description provided for @vacationHint.
  ///
  /// In en, this message translates to:
  /// **'Answers mail while you are away – each sender once a week, not mailing lists or automatic mail.'**
  String get vacationHint;

  /// No description provided for @vacationOn.
  ///
  /// In en, this message translates to:
  /// **'Answer mail'**
  String get vacationOn;

  /// No description provided for @fromOptional.
  ///
  /// In en, this message translates to:
  /// **'From (optional)'**
  String get fromOptional;

  /// No description provided for @untilOptional.
  ///
  /// In en, this message translates to:
  /// **'Until (optional)'**
  String get untilOptional;

  /// No description provided for @vacationSubjectHint.
  ///
  /// In en, this message translates to:
  /// **'Auto: and the subject of the mail answered'**
  String get vacationSubjectHint;

  /// No description provided for @text.
  ///
  /// In en, this message translates to:
  /// **'Text'**
  String get text;

  /// No description provided for @notSet.
  ///
  /// In en, this message translates to:
  /// **'Not set'**
  String get notSet;

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

  /// No description provided for @mailSettings.
  ///
  /// In en, this message translates to:
  /// **'Writing and the Trash'**
  String get mailSettings;

  /// No description provided for @sendFrom.
  ///
  /// In en, this message translates to:
  /// **'Send from'**
  String get sendFrom;

  /// No description provided for @myAddress.
  ///
  /// In en, this message translates to:
  /// **'My address'**
  String get myAddress;

  /// No description provided for @undoSend.
  ///
  /// In en, this message translates to:
  /// **'Undo sending'**
  String get undoSend;

  /// No description provided for @off.
  ///
  /// In en, this message translates to:
  /// **'Off'**
  String get off;

  /// No description provided for @seconds.
  ///
  /// In en, this message translates to:
  /// **'{count} seconds'**
  String seconds(int count);

  /// No description provided for @keepTrash.
  ///
  /// In en, this message translates to:
  /// **'Keep emails in the Trash'**
  String get keepTrash;

  /// No description provided for @asTenantDays.
  ///
  /// In en, this message translates to:
  /// **'As the organisation sets it ({days} days)'**
  String asTenantDays(int days);

  /// No description provided for @asTenantForever.
  ///
  /// In en, this message translates to:
  /// **'As the organisation sets it (until deleted)'**
  String get asTenantForever;

  /// No description provided for @ownDays.
  ///
  /// In en, this message translates to:
  /// **'My own: days'**
  String get ownDays;

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

  /// No description provided for @openElsewhere.
  ///
  /// In en, this message translates to:
  /// **'Open in another app'**
  String get openElsewhere;

  /// No description provided for @noAppFor.
  ///
  /// In en, this message translates to:
  /// **'No app on this device opens {name}.'**
  String noAppFor(String name);

  /// No description provided for @textCut.
  ///
  /// In en, this message translates to:
  /// **'Only the first megabyte is shown – save the file to see all of it.'**
  String get textCut;

  /// No description provided for @cannotShow.
  ///
  /// In en, this message translates to:
  /// **'This file cannot be shown here.'**
  String get cannotShow;

  /// No description provided for @dropToUpload.
  ///
  /// In en, this message translates to:
  /// **'Drop to upload here'**
  String get dropToUpload;

  /// No description provided for @uploadFolder.
  ///
  /// In en, this message translates to:
  /// **'Upload a folder'**
  String get uploadFolder;

  /// No description provided for @newVault.
  ///
  /// In en, this message translates to:
  /// **'New vault'**
  String get newVault;

  /// No description provided for @newVaultName.
  ///
  /// In en, this message translates to:
  /// **'Name of the vault'**
  String get newVaultName;

  /// No description provided for @newVaultHint.
  ///
  /// In en, this message translates to:
  /// **'New vault – only those it is shared with can read what is in it'**
  String get newVaultHint;

  /// No description provided for @vaultLocked.
  ///
  /// In en, this message translates to:
  /// **'Unlock your key to read what is in vaults.'**
  String get vaultLocked;

  /// No description provided for @lockedVault.
  ///
  /// In en, this message translates to:
  /// **'Locked vault'**
  String get lockedVault;

  /// No description provided for @lockedFolder.
  ///
  /// In en, this message translates to:
  /// **'Encrypted folder'**
  String get lockedFolder;

  /// No description provided for @lockedFile.
  ///
  /// In en, this message translates to:
  /// **'Encrypted file'**
  String get lockedFile;

  /// No description provided for @vaultMoveNo.
  ///
  /// In en, this message translates to:
  /// **'Nothing moves into or out of a vault – only into the trash.'**
  String get vaultMoveNo;

  /// No description provided for @vaultKeysWaiting.
  ///
  /// In en, this message translates to:
  /// **'These can open the vault once they have a key of their own and you share it again: {names}'**
  String vaultKeysWaiting(String names);

  /// No description provided for @syncTitle.
  ///
  /// In en, this message translates to:
  /// **'Folders on this computer'**
  String get syncTitle;

  /// No description provided for @syncHint.
  ///
  /// In en, this message translates to:
  /// **'A folder of this computer kept in step with a store: what changes on one side reaches the other every few minutes while the app is open. Changed on both sides, both versions are kept.'**
  String get syncHint;

  /// No description provided for @syncChoose.
  ///
  /// In en, this message translates to:
  /// **'Choose a folder'**
  String get syncChoose;

  /// No description provided for @syncNow.
  ///
  /// In en, this message translates to:
  /// **'Sync now'**
  String get syncNow;

  /// No description provided for @syncStop.
  ///
  /// In en, this message translates to:
  /// **'Stop syncing'**
  String get syncStop;

  /// No description provided for @syncRunning.
  ///
  /// In en, this message translates to:
  /// **'Syncing …'**
  String get syncRunning;

  /// No description provided for @syncNever.
  ///
  /// In en, this message translates to:
  /// **'Not synced yet'**
  String get syncNever;

  /// No description provided for @syncDone.
  ///
  /// In en, this message translates to:
  /// **'Synced {time}: {down} down, {up} up'**
  String syncDone(String time, int down, int up);

  /// No description provided for @syncIssues.
  ///
  /// In en, this message translates to:
  /// **'{conflicts} changed on both sides (kept as copies), {failed} not done – tried again'**
  String syncIssues(int conflicts, int failed);

  /// No description provided for @documentsTitle.
  ///
  /// In en, this message translates to:
  /// **'Files app'**
  String get documentsTitle;

  /// No description provided for @documentsHint.
  ///
  /// In en, this message translates to:
  /// **'Your stores in Android\'s Files app and wherever an app lets you pick a file. It signs in on its own, once – the browser opens for it.'**
  String get documentsHint;

  /// No description provided for @documentsOn.
  ///
  /// In en, this message translates to:
  /// **'Your stores are shown in the Files app.'**
  String get documentsOn;

  /// No description provided for @documentsOff.
  ///
  /// In en, this message translates to:
  /// **'Not shown in the Files app.'**
  String get documentsOff;

  /// No description provided for @documentsEnable.
  ///
  /// In en, this message translates to:
  /// **'Show in Files'**
  String get documentsEnable;

  /// No description provided for @documentsDisable.
  ///
  /// In en, this message translates to:
  /// **'Remove from Files'**
  String get documentsDisable;

  /// No description provided for @syncFailed.
  ///
  /// In en, this message translates to:
  /// **'Not synced: {error}'**
  String syncFailed(String error);

  /// No description provided for @syncLocked.
  ///
  /// In en, this message translates to:
  /// **'{count} vaults left as they are – unlock your key to sync them'**
  String syncLocked(int count);

  /// No description provided for @syncAtLogin.
  ///
  /// In en, this message translates to:
  /// **'Start with the computer, so that the folders are kept in step without opening the app'**
  String get syncAtLogin;

  /// No description provided for @trayOpen.
  ///
  /// In en, this message translates to:
  /// **'Open kernoid'**
  String get trayOpen;

  /// No description provided for @traySync.
  ///
  /// In en, this message translates to:
  /// **'Sync folders now'**
  String get traySync;

  /// No description provided for @trayQuit.
  ///
  /// In en, this message translates to:
  /// **'Quit kernoid'**
  String get trayQuit;

  /// No description provided for @explorerTitle.
  ///
  /// In en, this message translates to:
  /// **'Files in Explorer'**
  String get explorerTitle;

  /// No description provided for @explorerHint.
  ///
  /// In en, this message translates to:
  /// **'Your stores as folders in Explorer: files show at once and are downloaded when they are opened, and what you change there reaches kernoid within a minute while the app is open. Explorer gets a login of its own – kernoid\'s login page opens once more for it.'**
  String get explorerHint;

  /// No description provided for @explorerSetUp.
  ///
  /// In en, this message translates to:
  /// **'Show in Explorer'**
  String get explorerSetUp;

  /// No description provided for @explorerRemove.
  ///
  /// In en, this message translates to:
  /// **'Remove from Explorer'**
  String get explorerRemove;

  /// No description provided for @explorerStarting.
  ///
  /// In en, this message translates to:
  /// **'Starting …'**
  String get explorerStarting;

  /// No description provided for @explorerLast.
  ///
  /// In en, this message translates to:
  /// **'Last compared {time}'**
  String explorerLast(String time);

  /// No description provided for @explorerSignedOut.
  ///
  /// In en, this message translates to:
  /// **'The login for Explorer has ended – show the files again to sign in anew.'**
  String get explorerSignedOut;

  /// No description provided for @explorerFailed.
  ///
  /// In en, this message translates to:
  /// **'Not shown in Explorer: {error}'**
  String explorerFailed(String error);

  /// No description provided for @fileProviderTitle.
  ///
  /// In en, this message translates to:
  /// **'Files in Finder'**
  String get fileProviderTitle;

  /// No description provided for @fileProviderTitleIos.
  ///
  /// In en, this message translates to:
  /// **'Files in the Files app'**
  String get fileProviderTitleIos;

  /// No description provided for @fileProviderHint.
  ///
  /// In en, this message translates to:
  /// **'Your stores as places of the system\'s file manager: files appear before they are downloaded and open when you need them. It has a login of its own – you sign in once more in the browser. Vaults stay locked there.'**
  String get fileProviderHint;

  /// No description provided for @fileProviderOn.
  ///
  /// In en, this message translates to:
  /// **'Turn on'**
  String get fileProviderOn;

  /// No description provided for @fileProviderUpdate.
  ///
  /// In en, this message translates to:
  /// **'Update the stores'**
  String get fileProviderUpdate;

  /// No description provided for @fileProviderOff.
  ///
  /// In en, this message translates to:
  /// **'Turn off'**
  String get fileProviderOff;

  /// No description provided for @fileProviderShown.
  ///
  /// In en, this message translates to:
  /// **'Shown: {stores}'**
  String fileProviderShown(String stores);

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
