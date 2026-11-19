// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'mail_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class MailLocalizationsEn extends MailLocalizations {
  MailLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get mail => 'Mail';

  @override
  String get noMessages => 'No messages';

  @override
  String get selectMessage => 'Select a message';

  @override
  String get from => 'From';

  @override
  String get to => 'To';

  @override
  String get cc => 'Cc';

  @override
  String get subject => 'Subject';

  @override
  String get message => 'Message';

  @override
  String get write => 'Write';

  @override
  String get send => 'Send';

  @override
  String get messageSent => 'Message sent';

  @override
  String get attachments => 'Attachments';

  @override
  String get loadMore => 'Load more';

  @override
  String get encryptedMessage => 'Encrypted message';

  @override
  String get unlockToRead => 'Unlock your key to read it';

  @override
  String get lockedEmail => 'This message is end-to-end encrypted. Unlock your key to read it.';

  @override
  String get willEncrypt => 'Will be sent end-to-end encrypted and signed.';

  @override
  String wontEncrypt(String reason) {
    return 'Not end-to-end encrypted: $reason';
  }

  @override
  String get sentEncrypted => 'Sent end-to-end encrypted';

  @override
  String get bcc => 'Bcc';

  @override
  String get reply => 'Reply';

  @override
  String get replyAll => 'Reply all';

  @override
  String get forward => 'Forward';

  @override
  String get attachFile => 'Attach a file';

  @override
  String quoteWrote(String date, String who) {
    return 'On $date, $who wrote:';
  }

  @override
  String get quoteForwarded => '---------- Forwarded message ----------';

  @override
  String get quoteDateFormat => '%a, %d %b %Y %H:%M';

  @override
  String get date => 'Date';

  @override
  String get loadImages => 'Load images';

  @override
  String get imagesBlocked => 'Images from the internet are not loaded until you ask for them.';

  @override
  String get openLink => 'Open this link?';

  @override
  String get asText => 'As text';

  @override
  String get asHtml => 'Formatted';

  @override
  String get mailboxes => 'Folders';

  @override
  String get searchMail => 'Search mail';

  @override
  String get searchResults => 'Search results';

  @override
  String get myMailbox => 'My mailbox';

  @override
  String get chooseAll => 'Choose all';

  @override
  String get markRead => 'Read or unread';

  @override
  String get flag => 'Flag';

  @override
  String get moveTo => 'Move to';

  @override
  String chosen(int count) {
    String _temp0 = intl.Intl.pluralLogic(count, locale: localeName, other: '$count chosen', one: '1 chosen');
    return '$_temp0';
  }

  @override
  String deleteForGood(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'Delete these $count emails for good?',
      one: 'Delete this email for good?',
    );
    return '$_temp0';
  }

  @override
  String get newSubfolder => 'New folder in it';

  @override
  String get moveFolder => 'Move';

  @override
  String get emptyFolder => 'Empty';

  @override
  String get deleteFolder => 'Delete folder';

  @override
  String get topLevel => 'At the top';

  @override
  String get folders => 'Folders';

  @override
  String moveFolderTo(String name) {
    return 'Move “$name” to';
  }

  @override
  String emptyFolderConfirm(String name) {
    return 'Delete every email in “$name” for good?';
  }

  @override
  String deleteFolderConfirm(String name) {
    return 'Delete the folder “$name”?';
  }

  @override
  String deleteFolderWithEmails(String name, int count) {
    String _temp0 = intl.Intl.pluralLogic(count, locale: localeName, other: '$count emails', one: 'email');
    return 'Delete the folder “$name” and the $_temp0 only in it, for good?';
  }

  @override
  String get vacation => 'Vacation response';

  @override
  String get vacationHint =>
      'Answers mail while you are away – each sender once a week, not mailing lists or automatic mail.';

  @override
  String get fromOptional => 'From (optional)';

  @override
  String get untilOptional => 'Until (optional)';

  @override
  String get vacationSubjectHint => 'Auto: and the subject of the mail answered';

  @override
  String get text => 'Text';

  @override
  String get notSet => 'Not set';

  @override
  String get mailSettings => 'Writing and the Trash';

  @override
  String get sendFrom => 'Send from';

  @override
  String get myAddress => 'My address';

  @override
  String get undoSend => 'Undo sending';

  @override
  String get off => 'Off';

  @override
  String seconds(int count) {
    return '$count seconds';
  }

  @override
  String get keepTrash => 'Keep emails in the Trash';

  @override
  String asTenantDays(int days) {
    return 'As the organisation sets it ($days days)';
  }

  @override
  String get asTenantForever => 'As the organisation sets it (until deleted)';

  @override
  String get ownDays => 'My own: days';
}
