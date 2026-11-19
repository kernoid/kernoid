// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'files_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class FilesLocalizationsEn extends FilesLocalizations {
  FilesLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get files => 'Files';

  @override
  String get myFiles => 'My files';

  @override
  String get folderEmpty => 'This folder is empty';

  @override
  String get refresh => 'Refresh';

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
  String get deleteFileForGood => 'Delete for good';

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
  String get vaultWaiting =>
      'No member has given you access to this vault yet. Once one shares it with you again, it opens here.';

  @override
  String get vaultMoveOnto => 'Move onto a space';

  @override
  String get vaultMoveOntoConfirm =>
      'Copy this vault into a new one beside it, kept end to end with post-quantum keys? The old vault stays until you remove it.';

  @override
  String get vaultMoved => 'Copied into a new vault. Check it, then remove the old one.';

  @override
  String get vaultTrash => 'Trash of the vault';

  @override
  String get vaultTrashHide => 'Back to the vault';

  @override
  String get vaultRestore => 'Restore';

  @override
  String get vaultMoveTo => 'Move to …';

  @override
  String get vaultTop => 'Top of the vault';

  @override
  String get vaultOpening => 'Opening the vault …';
}
