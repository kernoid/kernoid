// SPDX-License-Identifier: MIT
// The strings of kernoid_mail alone, reached from the shared ones: `l.mailText.…` (RFC 0011, 8).

import 'dart:ui';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'mail_localizations.dart';

export 'mail_localizations.dart';

extension MailText on AppLocalizations {
  /// This package's strings in the language of the shared ones.
  MailLocalizations get mailText => lookupMailLocalizations(Locale(localeName));
}
