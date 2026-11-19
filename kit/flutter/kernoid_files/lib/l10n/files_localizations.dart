import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'files_localizations_de.dart';
import 'files_localizations_en.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of FilesLocalizations
/// returned by `FilesLocalizations.of(context)`.
///
/// Applications need to include `FilesLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/files_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: FilesLocalizations.localizationsDelegates,
///   supportedLocales: FilesLocalizations.supportedLocales,
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
/// be consistent with the languages listed in the FilesLocalizations.supportedLocales
/// property.
abstract class FilesLocalizations {
  FilesLocalizations(String locale) : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static FilesLocalizations of(BuildContext context) {
    return Localizations.of<FilesLocalizations>(context, FilesLocalizations)!;
  }

  static const LocalizationsDelegate<FilesLocalizations> delegate = _FilesLocalizationsDelegate();

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

  /// No description provided for @files.
  ///
  /// In en, this message translates to:
  /// **'Files'**
  String get files;

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

  /// No description provided for @deleteFileForGood.
  ///
  /// In en, this message translates to:
  /// **'Delete for good'**
  String get deleteFileForGood;

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

  /// No description provided for @vaultWaiting.
  ///
  /// In en, this message translates to:
  /// **'No member has given you access to this vault yet. Once one shares it with you again, it opens here.'**
  String get vaultWaiting;

  /// No description provided for @vaultMoveOnto.
  ///
  /// In en, this message translates to:
  /// **'Move onto a space'**
  String get vaultMoveOnto;

  /// No description provided for @vaultMoveOntoConfirm.
  ///
  /// In en, this message translates to:
  /// **'Copy this vault into a new one beside it, kept end to end with post-quantum keys? The old vault stays until you remove it.'**
  String get vaultMoveOntoConfirm;

  /// No description provided for @vaultMoved.
  ///
  /// In en, this message translates to:
  /// **'Copied into a new vault. Check it, then remove the old one.'**
  String get vaultMoved;

  /// No description provided for @vaultTrash.
  ///
  /// In en, this message translates to:
  /// **'Trash of the vault'**
  String get vaultTrash;

  /// No description provided for @vaultTrashHide.
  ///
  /// In en, this message translates to:
  /// **'Back to the vault'**
  String get vaultTrashHide;

  /// No description provided for @vaultRestore.
  ///
  /// In en, this message translates to:
  /// **'Restore'**
  String get vaultRestore;

  /// No description provided for @vaultMoveTo.
  ///
  /// In en, this message translates to:
  /// **'Move to …'**
  String get vaultMoveTo;

  /// No description provided for @vaultTop.
  ///
  /// In en, this message translates to:
  /// **'Top of the vault'**
  String get vaultTop;

  /// No description provided for @vaultOpening.
  ///
  /// In en, this message translates to:
  /// **'Opening the vault …'**
  String get vaultOpening;
}

class _FilesLocalizationsDelegate extends LocalizationsDelegate<FilesLocalizations> {
  const _FilesLocalizationsDelegate();

  @override
  Future<FilesLocalizations> load(Locale locale) {
    return SynchronousFuture<FilesLocalizations>(lookupFilesLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) => <String>['de', 'en'].contains(locale.languageCode);

  @override
  bool shouldReload(_FilesLocalizationsDelegate old) => false;
}

FilesLocalizations lookupFilesLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'de':
      return FilesLocalizationsDe();
    case 'en':
      return FilesLocalizationsEn();
  }

  throw FlutterError(
    'FilesLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
