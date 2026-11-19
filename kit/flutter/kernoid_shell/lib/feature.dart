// SPDX-License-Identifier: MIT
import 'package:flutter/widgets.dart';
import 'package:kernoid_bridge/kernoid_bridge.dart';
import 'package:kernoid_l10n/l10n/app_localizations.dart';

/// A part of an app – mail, calendars, files, or a program's own – that the shell shows when the account's server
/// offers it (RFC 0011, 3). What an app contains is fixed when it is built; what it shows comes from its server.
abstract class KFeature {
  const KFeature();

  /// A short name: `mail`, `files` … – also the key of its item in the side bar (`nav-<id>`).
  String get id;

  IconData get icon;

  String label(AppLocalizations l);

  /// Whether the account's server offers it – from the capabilities of its JMAP session.
  bool offeredBy(Kernoid account);

  /// The feature's page.
  Widget page(Kernoid account);

  /// Work that runs while the account is signed in, whatever page is shown – folders kept in step, say. The shell
  /// starts it with the home and disposes of it with the home.
  KFeatureSession start(BuildContext context, Kernoid account) => KFeatureSession();

  /// Sections the feature adds to the account page.
  List<Widget> accountSections(BuildContext context, Kernoid account, KFeatureSession session) => const [];

  /// Before the account signs out: what the feature registered with the system goes with it.
  Future<void> signingOut() async {}
}

/// What a feature keeps while the account is signed in.
class KFeatureSession {
  void dispose() {}
}

/// The capabilities of JMAP the features of kernoid's apps look for.
abstract final class KCapability {
  static const mail = 'urn:ietf:params:jmap:mail';
  static const calendars = 'urn:ietf:params:jmap:calendars';
  static const contacts = 'urn:ietf:params:jmap:contacts';
  static const files = 'urn:ietf:params:jmap:filenode';
}
