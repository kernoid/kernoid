// SPDX-License-Identifier: MIT
/// Mail in an app on kernoid (RFC 0011, 2): folders, the list, reading – HTML, end to end –, writing.
library;

import 'package:flutter/widgets.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_shell/kernoid_shell.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'account_sections.dart';
import 'mail.dart';
import 'l10n/mail_text.dart';

export 'compose.dart' show ComposePage;

/// Mail, where the server offers it; its settings and the vacation response on the account page.
class MailFeature extends KFeature {
  const MailFeature();

  @override
  String get id => 'mail';

  @override
  IconData get icon => LucideIcons.mail;

  @override
  String label(AppLocalizations l) => l.mailText.mail;

  @override
  bool offeredBy(Kernoid account) => account.offers(capability: KCapability.mail);

  @override
  Widget page(Kernoid account) => MailPage(account: account);

  @override
  List<Widget> accountSections(BuildContext context, Kernoid account, KFeatureSession session) => [
    if (account.settingsAvailable()) MailSettingsSection(account: account),
    VacationSection(account: account),
  ];
}
