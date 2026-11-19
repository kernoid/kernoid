// SPDX-License-Identifier: MIT
/// Contacts in an app on kernoid (RFC 0011, 2): address books, contacts, writing to them.
library;

import 'package:flutter/widgets.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_shell/kernoid_shell.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'contacts.dart';

/// Contacts, where the server offers them.
class ContactsFeature extends KFeature {
  const ContactsFeature();

  @override
  String get id => 'contacts';

  @override
  IconData get icon => LucideIcons.bookUser;

  @override
  String label(AppLocalizations l) => l.contacts;

  @override
  bool offeredBy(Kernoid account) => account.offers(capability: KCapability.contacts);

  @override
  Widget page(Kernoid account) => ContactsPage(account: account);
}
