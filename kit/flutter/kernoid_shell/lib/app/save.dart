// SPDX-License-Identifier: MIT

import 'package:path_provider/path_provider.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

import 'format.dart';

/// Where saved files go: the Downloads folder, or the app's documents where a system has none (iOS, Android).
Future<String> saveDirectory() async =>
    (await getDownloadsDirectory() ?? await getApplicationDocumentsDirectory()).path;

/// Saves a blob in the Downloads folder – or the app's documents where a system has none (iOS, Android) – and says
/// where. **OPEN**: opening it, and the system's share sheet on phones.
Future<void> saveBlob(
  BuildContext context,
  Kernoid account, {
  required String? accountId,
  required String blobId,
  required String name,
  required String mediaType,
}) async {
  final messenger = KToast.of(context);
  final l = AppLocalizations.of(context);
  try {
    final directory = await getDownloadsDirectory() ?? await getApplicationDocumentsDirectory();
    final path = await account.download(
      accountId: accountId,
      blobId: blobId,
      name: name,
      mediaType: mediaType,
      directory: directory.path,
    );
    messenger.show(l.savedTo(path));
  } catch (error) {
    messenger.show(l.error(errorText(error)));
  }
}

/// Saves an attachment of an end-to-end encrypted message – taken from the message decrypted on this device.
Future<void> savePart(
  BuildContext context,
  Kernoid account, {
  required String emailId,
  required int part,
  required String name,
}) async {
  final messenger = KToast.of(context);
  final l = AppLocalizations.of(context);
  try {
    final directory = await getDownloadsDirectory() ?? await getApplicationDocumentsDirectory();
    final path = await account.savePart(emailId: emailId, partIndex: part, name: name, directory: directory.path);
    messenger.show(l.savedTo(path));
  } catch (error) {
    messenger.show(l.error(errorText(error)));
  }
}
