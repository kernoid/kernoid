// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for German (`de`).
class AppLocalizationsDe extends AppLocalizations {
  AppLocalizationsDe([String locale = 'de']) : super(locale);

  @override
  String get appTitle => 'kernoid';

  @override
  String get signInTitle => 'Bei kernoid anmelden';

  @override
  String get server => 'Server';

  @override
  String get serverHint => 'https://kernoid.example';

  @override
  String get address => 'Adresse';

  @override
  String get appPassword => 'App-Passwort';

  @override
  String get appPasswordHint => 'Lege eines auf deiner Kontoseite an.';

  @override
  String get signIn => 'Anmelden';

  @override
  String get onThisDevice => 'Nur auf diesem Gerät';

  @override
  String get required => 'Pflichtfeld';

  @override
  String get account => 'Konto';

  @override
  String get inbox => 'Posteingang';

  @override
  String get drafts => 'Entwürfe';

  @override
  String get sent => 'Gesendet';

  @override
  String get archive => 'Archiv';

  @override
  String get junk => 'Spam';

  @override
  String get trash => 'Papierkorb';

  @override
  String get noSubject => '(kein Betreff)';

  @override
  String get discard => 'Verwerfen';

  @override
  String get save => 'Speichern';

  @override
  String savedTo(String path) {
    return 'Gespeichert unter $path';
  }

  @override
  String get signedInAs => 'Angemeldet als';

  @override
  String get signOut => 'Abmelden';

  @override
  String get e2eTitle => 'Ende-zu-Ende-Verschlüsselung';

  @override
  String get e2eBody =>
      'Kommt als Nächstes: Dein Schlüssel entsteht auf diesem Gerät und wird mit deinem Passkey entsperrt. Mail an Menschen mit Schlüssel wird ohne Einstellung verschlüsselt, und Tresore halten Dateien, die nur du lesen kannst.';

  @override
  String error(String message) {
    return 'Etwas ist schiefgegangen: $message';
  }

  @override
  String get retry => 'Erneut versuchen';

  @override
  String get e2eUnavailable => 'Dieser Server bietet keine Ende-zu-Ende-Verschlüsselung.';

  @override
  String get e2eNoKey =>
      'Dein Konto hat noch keinen Schlüssel. Lege ihn hier an: Er entsteht auf diesem Gerät, und der Server bewahrt ihn nur geschützt auf – mit einem Wiederherstellungscode, den nur du hast.';

  @override
  String get e2eMakeKey => 'Schlüssel anlegen';

  @override
  String get e2eLocked =>
      'Dein Schlüssel ist gesperrt. Gib deinen Wiederherstellungscode ein, um verschlüsselte Mail zu lesen und verschlüsselt zu senden.';

  @override
  String get e2eUnlocked =>
      'Auf diesem Gerät entsperrt. Mail an Menschen mit Schlüssel geht verschlüsselt und signiert – ohne Einstellung.';

  @override
  String get recoveryCode => 'Wiederherstellungscode';

  @override
  String get unlock => 'Entsperren';

  @override
  String get lock => 'Sperren';

  @override
  String get fingerprint => 'Fingerabdruck';

  @override
  String get postQuantum => 'Post-Quanten (ML-KEM und ML-DSA mit Curve25519)';

  @override
  String get compatibleKind => 'kompatibel (Curve25519)';

  @override
  String get tenantRecovers => 'Deine Organisation kann deinen Schlüssel wiederherstellen.';

  @override
  String get recoveryTitle => 'Dein Wiederherstellungscode';

  @override
  String get recoveryBody =>
      'Schreib ihn auf oder leg ihn in deinem Passwort-Manager ab. Er wird nur jetzt angezeigt. Ohne ihn – und ohne einen Passkey, der deinen Schlüssel entsperrt – lässt sich an dich verschlüsselte Mail nicht mehr lesen.';

  @override
  String get recoveryKept => 'Ich habe den Code sicher aufbewahrt';

  @override
  String get copy => 'Kopieren';

  @override
  String get copied => 'Kopiert';

  @override
  String get done => 'Fertig';

  @override
  String get e2eEncrypted => 'Ende-zu-Ende verschlüsselt';

  @override
  String get signatureVerified => 'Signatur geprüft';

  @override
  String get signatureUnverified => 'Signatur nicht geprüft';

  @override
  String get notSigned => 'nicht signiert';

  @override
  String get cancel => 'Abbrechen';

  @override
  String get today => 'Heute';

  @override
  String get saved => 'Gespeichert';

  @override
  String get deleted => 'Gelöscht';

  @override
  String get delete => 'Löschen';

  @override
  String get edit => 'Ändern';

  @override
  String get name => 'Name';

  @override
  String get onePerLine => 'Eine pro Zeile';

  @override
  String get signInBrowser => 'Mit kernoid anmelden';

  @override
  String get signInBrowserHint =>
      'Im Browser – mit Passkey, Passwort oder zweitem Faktor, wie es deine Organisation vorsieht.';

  @override
  String get orAppPassword => 'oder mit einem App-Passwort';

  @override
  String get signInAppPassword => 'Mit App-Passwort anmelden';

  @override
  String get signInCancelled => 'Anmeldung abgebrochen';

  @override
  String get remove => 'Entfernen';

  @override
  String get open => 'Öffnen';

  @override
  String get nothingFound => 'Nichts gefunden';

  @override
  String get rename => 'Umbenennen';

  @override
  String get newFolder => 'Neuer Ordner';

  @override
  String get create => 'Anlegen';

  @override
  String get appPasswordWrong => 'Die Adresse oder das App-Passwort ist falsch.';

  @override
  String get drive => 'Ablage';

  @override
  String get appearance => 'Erscheinungsbild';

  @override
  String get appearanceHint => 'Gilt auf diesem Gerät.';

  @override
  String get themeSystem => 'Wie das System';

  @override
  String get themeLight => 'Hell';

  @override
  String get themeDark => 'Dunkel';

  @override
  String get vacationOn => 'Mail beantworten';

  @override
  String get security => 'Anmeldung und Sicherheit';

  @override
  String get securityHint =>
      'Passwort, Zwei-Faktor-Anmeldung, Passkeys, App-Passwörter und Sitzungen – sowie Name, Bild, Sprache und Mail-Einstellungen – änderst du in der Web-App, wo du dich mit deinem Passwort anmeldest.';

  @override
  String get openWebApp => 'Im Browser öffnen';

  @override
  String get profile => 'Name und Bild';

  @override
  String get displayName => 'Anzeigename';

  @override
  String get changePicture => 'Bild ändern';

  @override
  String get removePicture => 'Bild entfernen';

  @override
  String get pictureHint =>
      'PNG, JPEG oder WebP, bis 1 MiB – am besten quadratisch. Andere in deiner Organisation sehen es.';

  @override
  String get emailLanguage => 'Sprache der E-Mails von kernoid';

  @override
  String get emailLanguageHint =>
      'Einladungen in deinem Namen und Hinweise an dich sind in dieser Sprache; die App folgt deinem System.';

  @override
  String asTenantLanguage(String language) {
    return 'Wie die Organisation ($language)';
  }

  @override
  String get languageNamede => 'Deutsch';

  @override
  String get languageNameen => 'English';

  @override
  String get securityHintApp =>
      'Passwort, Zwei-Faktor-Anmeldung, Passkeys, App-Passwörter und Sitzungen änderst du in der Web-App, wo du dich mit deinem Passwort anmeldest.';

  @override
  String get asTenant => 'Wie die Organisation';

  @override
  String get back => 'Zurück';

  @override
  String get close => 'Schließen';

  @override
  String get clear => 'Leeren';

  @override
  String get cut => 'Ausschneiden';

  @override
  String get paste => 'Einfügen';

  @override
  String get selectAll => 'Alles auswählen';

  @override
  String get pickDate => 'Datum wählen';

  @override
  String get pickTime => 'Uhrzeit wählen';

  @override
  String get previousMonth => 'Voriger Monat';

  @override
  String get nextMonth => 'Nächster Monat';

  @override
  String get hour => 'Stunde';

  @override
  String get minute => 'Minute';

  @override
  String get moreOptions => 'Mehr';
}
