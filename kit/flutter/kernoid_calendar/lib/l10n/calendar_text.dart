// SPDX-License-Identifier: MIT
// The strings of kernoid_calendar alone, reached from the shared ones: `l.calendarText.…` (RFC 0011, 8).

import 'dart:ui';

import 'package:kernoid_l10n/l10n/app_localizations.dart';

import 'calendar_localizations.dart';

export 'calendar_localizations.dart';

extension CalendarText on AppLocalizations {
  /// This package's strings in the language of the shared ones.
  CalendarLocalizations get calendarText => lookupCalendarLocalizations(Locale(localeName));
}
