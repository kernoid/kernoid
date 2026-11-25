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
  String get onThisDevice => 'On this device only';

  @override
  String get required => 'Required';

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
  String get noSubject => '(no subject)';

  @override
  String get discard => 'Discard';

  @override
  String get save => 'Save';

  @override
  String savedTo(String path) {
    return 'Saved to $path';
  }

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
  String get e2eEncrypted => 'End-to-end encrypted';

  @override
  String get signatureVerified => 'signature checked';

  @override
  String get signatureUnverified => 'signature not checked';

  @override
  String get notSigned => 'not signed';

  @override
  String get cancel => 'Cancel';

  @override
  String get today => 'Today';

  @override
  String get saved => 'Saved';

  @override
  String get deleted => 'Deleted';

  @override
  String get delete => 'Delete';

  @override
  String get edit => 'Change';

  @override
  String get name => 'Name';

  @override
  String get onePerLine => 'One per line';

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
  String get remove => 'Remove';

  @override
  String get open => 'Open';

  @override
  String get nothingFound => 'Nothing found';

  @override
  String get rename => 'Rename';

  @override
  String get newFolder => 'New folder';

  @override
  String get create => 'Create';

  @override
  String get appPasswordWrong => 'The address or the app password is wrong.';

  @override
  String get drive => 'Drive';

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
  String get vacationOn => 'Answer mail';

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
  String get securityHintApp =>
      'Your password, two-factor sign-in, passkeys, app passwords and sessions are changed in the web app, where you sign in with your password.';

  @override
  String get asTenant => 'As the organisation';

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
