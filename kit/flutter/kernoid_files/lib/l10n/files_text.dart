// SPDX-License-Identifier: MIT
// The strings of kernoid_files alone, reached from the shared ones: `l.filesText.…` (RFC 0011, 8).

import 'dart:ui';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'files_localizations.dart';

export 'files_localizations.dart';

extension FilesText on AppLocalizations {
  /// This package's strings in the language of the shared ones.
  FilesLocalizations get filesText => lookupFilesLocalizations(Locale(localeName));
}
