import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'mail_localizations_de.dart';
import 'mail_localizations_en.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of MailLocalizations
/// returned by `MailLocalizations.of(context)`.
///
/// Applications need to include `MailLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/mail_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: MailLocalizations.localizationsDelegates,
///   supportedLocales: MailLocalizations.supportedLocales,
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
/// be consistent with the languages listed in the MailLocalizations.supportedLocales
/// property.
abstract class MailLocalizations {
  MailLocalizations(String locale) : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static MailLocalizations of(BuildContext context) {
    return Localizations.of<MailLocalizations>(context, MailLocalizations)!;
  }

  static const LocalizationsDelegate<MailLocalizations> delegate = _MailLocalizationsDelegate();

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

  /// No description provided for @mail.
  ///
  /// In en, this message translates to:
  /// **'Mail'**
  String get mail;

  /// No description provided for @noMessages.
  ///
  /// In en, this message translates to:
  /// **'No messages'**
  String get noMessages;

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

  /// No description provided for @loadMore.
  ///
  /// In en, this message translates to:
  /// **'Load more'**
  String get loadMore;

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
}

class _MailLocalizationsDelegate extends LocalizationsDelegate<MailLocalizations> {
  const _MailLocalizationsDelegate();

  @override
  Future<MailLocalizations> load(Locale locale) {
    return SynchronousFuture<MailLocalizations>(lookupMailLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) => <String>['de', 'en'].contains(locale.languageCode);

  @override
  bool shouldReload(_MailLocalizationsDelegate old) => false;
}

MailLocalizations lookupMailLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'de':
      return MailLocalizationsDe();
    case 'en':
      return MailLocalizationsEn();
  }

  throw FlutterError(
    'MailLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
