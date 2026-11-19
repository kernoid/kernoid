// SPDX-License-Identifier: MIT
// The strings of kernoid_contacts alone, reached from the shared ones: `l.contactsText.…` (RFC 0011, 8).

import 'dart:ui';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'contacts_localizations.dart';

export 'contacts_localizations.dart';

extension ContactsText on AppLocalizations {
  /// This package's strings in the language of the shared ones.
  ContactsLocalizations get contactsText => lookupContactsLocalizations(Locale(localeName));
}
