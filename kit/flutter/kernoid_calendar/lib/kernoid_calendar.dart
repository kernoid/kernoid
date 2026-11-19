// SPDX-License-Identifier: MIT
/// Calendars in an app on kernoid (RFC 0011, 2): months, weeks and days, events and their invitations.
library;

import 'package:flutter/widgets.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_shell/kernoid_shell.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'calendar.dart';

/// Calendars, where the server offers them.
class CalendarFeature extends KFeature {
  const CalendarFeature();

  @override
  String get id => 'calendar';

  @override
  IconData get icon => LucideIcons.calendar;

  @override
  String label(AppLocalizations l) => l.calendar;

  @override
  bool offeredBy(Kernoid account) => account.offers(capability: KCapability.calendars);

  @override
  Widget page(Kernoid account) => CalendarPage(account: account);
}
