// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appTitle => 'kernoid';

  @override
  String get signInTitle => 'Sign in to kernoid';

  @override
  String get server => 'Server';

  @override
  String get serverHint => 'https://kernoid.example';

  @override
  String get address => 'Address';

  @override
  String get appPassword => 'App password';

  @override
  String get appPasswordHint => 'Make one on your account page.';

  @override
  String get signIn => 'Sign in';

  @override
  String get required => 'Required';

  @override
  String get mail => 'Mail';

  @override
  String get files => 'Files';

  @override
  String get account => 'Account';

  @override
  String get inbox => 'Inbox';

  @override
  String get drafts => 'Drafts';

  @override
  String get sent => 'Sent';

  @override
  String get archive => 'Archive';

  @override
  String get junk => 'Junk';

  @override
  String get trash => 'Trash';

  @override
  String get noMessages => 'No messages';

  @override
  String get noSubject => '(no subject)';

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
  String get discard => 'Discard';

  @override
  String get messageSent => 'Message sent';

  @override
  String get attachments => 'Attachments';

  @override
  String get save => 'Save';

  @override
  String savedTo(String path) {
    return 'Saved to $path';
  }

  @override
  String get loadMore => 'Load more';

  @override
  String get myFiles => 'My files';

  @override
  String get folderEmpty => 'This folder is empty';

  @override
  String get refresh => 'Refresh';

  @override
  String get signedInAs => 'Signed in as';

  @override
  String get signOut => 'Sign out';

  @override
  String get e2eTitle => 'End-to-end encryption';

  @override
  String get e2eBody =>
      'Coming next: your key is made on this device and unlocked with your passkey. Mail to people with a key is encrypted without a setting, and vaults keep files only you can read.';

  @override
  String error(String message) {
    return 'Something went wrong: $message';
  }

  @override
  String get retry => 'Try again';

  @override
  String get e2eUnavailable => 'This server does not offer end-to-end encryption.';

  @override
  String get e2eNoKey =>
      'Your account has no key yet. Make one here: it is made on this device, and the server keeps it only protected – by a recovery code that only you have.';

  @override
  String get e2eMakeKey => 'Make my key';

  @override
  String get e2eLocked => 'Your key is locked. Enter your recovery code to read encrypted mail and to send encrypted.';

  @override
  String get e2eUnlocked =>
      'Unlocked on this device. Mail to people with a key goes encrypted and signed – without a setting.';

  @override
  String get recoveryCode => 'Recovery code';

  @override
  String get unlock => 'Unlock';

  @override
  String get lock => 'Lock';

  @override
  String get fingerprint => 'Fingerprint';

  @override
  String get postQuantum => 'post-quantum (ML-KEM and ML-DSA with Curve25519)';

  @override
  String get compatibleKind => 'compatible (Curve25519)';

  @override
  String get tenantRecovers => 'Your organisation can recover your key.';

  @override
  String get recoveryTitle => 'Your recovery code';

  @override
  String get recoveryBody =>
      'Write it down or keep it in your password manager. It is shown only now. Without it – and without a passkey that unlocks your key – mail encrypted to you cannot be read again.';

  @override
  String get recoveryKept => 'I have kept the code safe';

  @override
  String get copy => 'Copy';

  @override
  String get copied => 'Copied';

  @override
  String get done => 'Done';

  @override
  String get encryptedMessage => 'Encrypted message';

  @override
  String get unlockToRead => 'Unlock your key to read it';

  @override
  String get lockedEmail => 'This message is end-to-end encrypted. Unlock your key to read it.';

  @override
  String get e2eEncrypted => 'End-to-end encrypted';

  @override
  String get signatureVerified => 'signature checked';

  @override
  String get signatureUnverified => 'signature not checked';

  @override
  String get notSigned => 'not signed';

  @override
  String get willEncrypt => 'Will be sent end-to-end encrypted and signed.';

  @override
  String wontEncrypt(String reason) {
    return 'Not end-to-end encrypted: $reason';
  }

  @override
  String get sentEncrypted => 'Sent end-to-end encrypted';

  @override
  String get cancel => 'Cancel';

  @override
  String get calendar => 'Calendar';

  @override
  String get contacts => 'Contacts';

  @override
  String get today => 'Today';

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
  String get searchContacts => 'Search contacts';

  @override
  String get noContacts => 'No contacts';

  @override
  String get emails => 'Email';

  @override
  String get phones => 'Phone';

  @override
  String get notes => 'Notes';

  @override
  String get writeEmail => 'Write email';

  @override
  String get organization => 'Organisation';

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
  String get saved => 'Saved';

  @override
  String get deleted => 'Deleted';

  @override
  String get delete => 'Delete';

  @override
  String get edit => 'Change';

  @override
  String get endBeforeStart => 'The end is before the start';

  @override
  String get recurringEditsAll => 'Changes apply to every repetition.';

  @override
  String get newContact => 'New contact';

  @override
  String get editContact => 'Change contact';

  @override
  String get deleteContactConfirm => 'Delete this contact?';

  @override
  String get name => 'Name';

  @override
  String get emailsField => 'Email addresses';

  @override
  String get phonesField => 'Phone numbers';

  @override
  String get onePerLine => 'One per line';

  @override
  String get note => 'Note';

  @override
  String get signInBrowser => 'Sign in with kernoid';

  @override
  String get signInBrowserHint =>
      'In your browser – with a passkey, a password or a second factor, as your organisation has it.';

  @override
  String get orAppPassword => 'or with an app password';

  @override
  String get signInAppPassword => 'Sign in with the app password';

  @override
  String get signInCancelled => 'Sign-in cancelled';

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
  String get remove => 'Remove';

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

  @override
  String get labelWork => 'work';

  @override
  String get labelPrivate => 'private';

  @override
  String get labelMobile => 'mobile';

  @override
  String get labelVoice => 'voice';

  @override
  String get labelText => 'text';

  @override
  String get labelVideo => 'video';

  @override
  String get labelFax => 'fax';

  @override
  String get labelPager => 'pager';

  @override
  String get labelTextphone => 'textphone';

  @override
  String get labels => 'Labels';

  @override
  String get addEmail => 'Add an address';

  @override
  String get addPhone => 'Add a number';

  @override
  String get loadImages => 'Load images';

  @override
  String get imagesBlocked => 'Images from the internet are not loaded until you ask for them.';

  @override
  String get openLink => 'Open this link?';

  @override
  String get open => 'Open';

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
  String get nothingFound => 'Nothing found';

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
  String get rename => 'Rename';

  @override
  String get moveFolder => 'Move';

  @override
  String get emptyFolder => 'Empty';

  @override
  String get deleteFolder => 'Delete folder';

  @override
  String get newFolder => 'New folder';

  @override
  String get create => 'Create';

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
  String get appPasswordWrong => 'The address or the app password is wrong.';

  @override
  String get drives => 'Drives';

  @override
  String get sharedWithMe => 'Shared with me';

  @override
  String get upload => 'Upload';

  @override
  String get uploading => 'Uploading …';

  @override
  String get searchFiles => 'Search names and contents';

  @override
  String get share => 'Share';

  @override
  String shareTitle(String name) {
    return 'Share “$name”';
  }

  @override
  String get findPeople => 'Find people and groups';

  @override
  String get levelRead => 'Can view';

  @override
  String get levelEdit => 'Can edit';

  @override
  String get levelFull => 'Can edit and share';

  @override
  String get notShared => 'Shared with nobody yet.';

  @override
  String get shared => 'Shared';

  @override
  String get link => 'Link';

  @override
  String linksTitle(String name) {
    return 'Links to “$name”';
  }

  @override
  String get linkView => 'View';

  @override
  String get linkAdd => 'View and add';

  @override
  String get linkDrop => 'Only add';

  @override
  String get expires => 'Expires';

  @override
  String get never => 'Never';

  @override
  String inDays(int days) {
    return 'In $days days';
  }

  @override
  String expiresOn(String date) {
    return 'Expires $date';
  }

  @override
  String get withPassword => 'With password';

  @override
  String get passwordOptional => 'Password (optional)';

  @override
  String get createLink => 'Make a link';

  @override
  String get linkMade => 'The link – it is shown only now:';

  @override
  String get noLinks => 'No links yet.';

  @override
  String get versions => 'Versions';

  @override
  String get currentVersion => 'Current';

  @override
  String get restore => 'Restore';

  @override
  String get restoreConfirm => 'Make this version the file\'s content again? The current one stays as a version.';

  @override
  String get copyOrMove => 'Copy or move';

  @override
  String get copyHere => 'Copy here';

  @override
  String get moveHere => 'Move here';

  @override
  String deleteFileConfirm(String name) {
    return 'Delete “$name” for good?';
  }

  @override
  String get trashEmptyNote => 'The trash is empty';

  @override
  String get more => 'More';

  @override
  String get newFolderName => 'Name of the new folder';

  @override
  String get newName => 'New name';

  @override
  String get drive => 'Drive';

  @override
  String get deleteFileForGood => 'Delete for good';

  @override
  String get appearance => 'Appearance';

  @override
  String get appearanceHint => 'Kept on this device.';

  @override
  String get themeSystem => 'As the system';

  @override
  String get themeLight => 'Light';

  @override
  String get themeDark => 'Dark';

  @override
  String get vacation => 'Vacation response';

  @override
  String get vacationHint =>
      'Answers mail while you are away – each sender once a week, not mailing lists or automatic mail.';

  @override
  String get vacationOn => 'Answer mail';

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
  String get security => 'Sign-in and security';

  @override
  String get securityHint =>
      'Your password, two-factor sign-in, passkeys, app passwords and sessions – and your name, picture, language and mail settings – are changed in the web app, where you sign in with your password.';

  @override
  String get openWebApp => 'Open in the browser';

  @override
  String get profile => 'Name and picture';

  @override
  String get displayName => 'Display name';

  @override
  String get changePicture => 'Change picture';

  @override
  String get removePicture => 'Remove picture';

  @override
  String get pictureHint => 'PNG, JPEG or WebP, up to 1 MiB – best square. Others in your organisation see it.';

  @override
  String get emailLanguage => 'Language of emails from kernoid';

  @override
  String get emailLanguageHint =>
      'Invitations sent for you and notices to you are written in it; the app follows your system.';

  @override
  String asTenantLanguage(String language) {
    return 'As the organisation ($language)';
  }

  @override
  String get languageNamede => 'Deutsch';

  @override
  String get languageNameen => 'English';

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

  @override
  String get securityHintApp =>
      'Your password, two-factor sign-in, passkeys, app passwords and sessions are changed in the web app, where you sign in with your password.';

  @override
  String get asTenant => 'As the organisation';

  @override
  String get openElsewhere => 'Open in another app';

  @override
  String noAppFor(String name) {
    return 'No app on this device opens $name.';
  }

  @override
  String get textCut => 'Only the first megabyte is shown – save the file to see all of it.';

  @override
  String get cannotShow => 'This file cannot be shown here.';

  @override
  String get dropToUpload => 'Drop to upload here';

  @override
  String get uploadFolder => 'Upload a folder';

  @override
  String get newVault => 'New vault';

  @override
  String get newVaultName => 'Name of the vault';

  @override
  String get newVaultHint => 'New vault – only those it is shared with can read what is in it';

  @override
  String get vaultLocked => 'Unlock your key to read what is in vaults.';

  @override
  String get lockedVault => 'Locked vault';

  @override
  String get lockedFolder => 'Encrypted folder';

  @override
  String get lockedFile => 'Encrypted file';

  @override
  String get vaultMoveNo => 'Nothing moves into or out of a vault – only into the trash.';

  @override
  String vaultKeysWaiting(String names) {
    return 'These can open the vault once they have a key of their own and you share it again: $names';
  }

  @override
  String get syncTitle => 'Folders on this computer';

  @override
  String get syncHint =>
      'A folder of this computer kept in step with a store: what changes on one side reaches the other every few minutes while the app is open. Changed on both sides, both versions are kept.';

  @override
  String get syncChoose => 'Choose a folder';

  @override
  String get syncNow => 'Sync now';

  @override
  String get syncStop => 'Stop syncing';

  @override
  String get syncRunning => 'Syncing …';

  @override
  String get syncNever => 'Not synced yet';

  @override
  String syncDone(String time, int down, int up) {
    return 'Synced $time: $down down, $up up';
  }

  @override
  String syncIssues(int conflicts, int failed) {
    return '$conflicts changed on both sides (kept as copies), $failed not done – tried again';
  }

  @override
  String get documentsTitle => 'Files app';

  @override
  String get documentsHint =>
      'Your stores in Android\'s Files app and wherever an app lets you pick a file. It signs in on its own, once – the browser opens for it.';

  @override
  String get documentsOn => 'Your stores are shown in the Files app.';

  @override
  String get documentsOff => 'Not shown in the Files app.';

  @override
  String get documentsEnable => 'Show in Files';

  @override
  String get documentsDisable => 'Remove from Files';

  @override
  String syncFailed(String error) {
    return 'Not synced: $error';
  }

  @override
  String syncLocked(int count) {
    return '$count vaults left as they are – unlock your key to sync them';
  }

  @override
  String get syncAtLogin => 'Start with the computer, so that the folders are kept in step without opening the app';

  @override
  String get trayOpen => 'Open kernoid';

  @override
  String get traySync => 'Sync folders now';

  @override
  String get trayQuit => 'Quit kernoid';

  @override
  String get explorerTitle => 'Files in Explorer';

  @override
  String get explorerHint =>
      'Your stores as folders in Explorer: files show at once and are downloaded when they are opened, and what you change there reaches kernoid within a minute while the app is open. Explorer gets a login of its own – kernoid\'s login page opens once more for it.';

  @override
  String get explorerSetUp => 'Show in Explorer';

  @override
  String get explorerRemove => 'Remove from Explorer';

  @override
  String get explorerStarting => 'Starting …';

  @override
  String explorerLast(String time) {
    return 'Last compared $time';
  }

  @override
  String get explorerSignedOut => 'The login for Explorer has ended – show the files again to sign in anew.';

  @override
  String explorerFailed(String error) {
    return 'Not shown in Explorer: $error';
  }

  @override
  String get fileProviderTitle => 'Files in Finder';

  @override
  String get fileProviderTitleIos => 'Files in the Files app';

  @override
  String get fileProviderHint =>
      'Your stores as places of the system\'s file manager: files appear before they are downloaded and open when you need them. It has a login of its own – you sign in once more in the browser. Vaults stay locked there.';

  @override
  String get fileProviderOn => 'Turn on';

  @override
  String get fileProviderUpdate => 'Update the stores';

  @override
  String get fileProviderOff => 'Turn off';

  @override
  String fileProviderShown(String stores) {
    return 'Shown: $stores';
  }

  @override
  String get back => 'Back';

  @override
  String get close => 'Close';

  @override
  String get clear => 'Clear';

  @override
  String get cut => 'Cut';

  @override
  String get paste => 'Paste';

  @override
  String get selectAll => 'Select all';

  @override
  String get pickDate => 'Choose a date';

  @override
  String get pickTime => 'Choose a time';

  @override
  String get previousMonth => 'Previous month';

  @override
  String get nextMonth => 'Next month';

  @override
  String get hour => 'Hour';

  @override
  String get minute => 'Minute';

  @override
  String get moreOptions => 'More';
}
