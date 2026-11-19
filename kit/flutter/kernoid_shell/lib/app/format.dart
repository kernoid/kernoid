// SPDX-License-Identifier: MIT

import 'package:flutter/services.dart';
import 'package:intl/intl.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

import 'package:kernoid_l10n/l10n/app_localizations.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_ui/ui.dart';

/// A sender or recipient as people read it: the name, else the address.
String person(Address a) => (a.name?.trim().isNotEmpty ?? false) ? a.name!.trim() : a.email;

String people(List<Address> list) => list.map(person).join(', ');

/// A date of the server (RFC 3339): the time today, the day this year, else the date.
String shortDate(BuildContext context, String rfc3339) {
  final at = DateTime.tryParse(rfc3339)?.toLocal();
  if (at == null) return '';
  final locale = Localizations.localeOf(context).toLanguageTag();
  final now = DateTime.now();
  if (at.year == now.year && at.month == now.month && at.day == now.day) return DateFormat.Hm(locale).format(at);
  if (at.year == now.year) return DateFormat.MMMd(locale).format(at);
  return DateFormat.yMd(locale).format(at);
}

String longDate(BuildContext context, String rfc3339) {
  final at = DateTime.tryParse(rfc3339)?.toLocal();
  if (at == null) return '';
  return DateFormat.yMMMMEEEEd(Localizations.localeOf(context).toLanguageTag()).add_Hm().format(at);
}

String bytes(int n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  var value = n.toDouble();
  var unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  return unit == 0 ? '$n B' : '${value.toStringAsFixed(value < 10 ? 1 : 0)} ${units[unit]}';
}

/// The name of a mailbox: the special ones in the user's language.
String mailboxName(AppLocalizations l, Mailbox m) => switch (m.role) {
  'inbox' => l.inbox,
  'drafts' => l.drafts,
  'sent' => l.sent,
  'archive' => l.archive,
  'junk' => l.junk,
  'trash' => l.trash,
  _ => m.name,
};

IconData mailboxIcon(Mailbox m) => switch (m.role) {
  'inbox' => LucideIcons.inbox,
  'drafts' => LucideIcons.filePen,
  'sent' => LucideIcons.send,
  'archive' => LucideIcons.archive,
  'junk' => LucideIcons.shieldAlert,
  'trash' => LucideIcons.trash2,
  _ => LucideIcons.folder,
};

/// The message of an error from Rust, from the platform's side (a method channel), or of anything else.
String errorText(Object error) => switch (error) {
  KernoidError(:final message) => message,
  PlatformException(:final message, :final code) => message ?? code,
  _ => error.toString(),
};
