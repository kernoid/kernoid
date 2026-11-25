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

  /// Whether the account's server offers it – from the capabilities of its JMAP session. A feature that works on the
  /// device ([onDevice]) and keeps working while signed in answers `true` whatever the server offers.
  bool offeredBy(Kernoid account);

  /// Whether the feature works on this device alone, before anyone signs in (RFC 0011, 3) – a program's personal
  /// archive, say. An app with one such feature starts at its home without an account and offers signing in from its
  /// side bar; until then the shell shows only these features, with [pageOnDevice] and [startOnDevice].
  bool get onDevice => false;

  /// The feature's page without an account. Asked only of a feature that works [onDevice].
  Widget pageOnDevice() => throw UnsupportedError('$id needs an account');

  /// Work that runs while no account is signed in – disposed of when one signs in, and [start] takes over.
  KFeatureSession startOnDevice(BuildContext context) => KFeatureSession();

  /// The feature's page.
  Widget page(Kernoid account);

  /// Work that runs while the account is signed in, whatever page is shown – folders kept in step, say. The shell
  /// starts it with the home and disposes of it with the home.
  KFeatureSession start(BuildContext context, Kernoid account) => KFeatureSession();

  /// Sections the feature adds to the account page.
  List<Widget> accountSections(BuildContext context, Kernoid account, KFeatureSession session) => const [];

  /// The delegates of the feature's own strings, for a feature that looks them up with `…Localizations.of(context)`
  /// (RFC 0011, 8). kernoid's features reach theirs through the shared ones (`l.mailText.…`) and need none.
  List<LocalizationsDelegate<dynamic>> get localizationsDelegates => const [];

  /// Before the account signs out: what the feature registered with the system goes with it. What a feature keeps on
  /// the device without an account stays.
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
