// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'mail_localizations.dart';

// ignore_for_file: type=lint

/// The translations for German (`de`).
class MailLocalizationsDe extends MailLocalizations {
  MailLocalizationsDe([String locale = 'de']) : super(locale);

  @override
  String get mail => 'Mail';

  @override
  String get noMessages => 'Keine Nachrichten';

  @override
  String get selectMessage => 'Wähle eine Nachricht';

  @override
  String get from => 'Von';

  @override
  String get to => 'An';

  @override
  String get cc => 'Cc';

  @override
  String get subject => 'Betreff';

  @override
  String get message => 'Nachricht';

  @override
  String get write => 'Schreiben';

  @override
  String get send => 'Senden';

  @override
  String get messageSent => 'Nachricht gesendet';

  @override
  String get attachments => 'Anhänge';

  @override
  String get loadMore => 'Mehr laden';

  @override
  String get encryptedMessage => 'Verschlüsselte Nachricht';

  @override
  String get unlockToRead => 'Entsperre deinen Schlüssel, um sie zu lesen';

  @override
  String get lockedEmail =>
      'Diese Nachricht ist Ende-zu-Ende verschlüsselt. Entsperre deinen Schlüssel, um sie zu lesen.';

  @override
  String get willEncrypt => 'Wird Ende-zu-Ende verschlüsselt und signiert gesendet.';

  @override
  String wontEncrypt(String reason) {
    return 'Nicht Ende-zu-Ende verschlüsselt: $reason';
  }

  @override
  String get sentEncrypted => 'Ende-zu-Ende verschlüsselt gesendet';

  @override
  String get bcc => 'Bcc';

  @override
  String get reply => 'Antworten';

  @override
  String get replyAll => 'Allen antworten';

  @override
  String get forward => 'Weiterleiten';

  @override
  String get attachFile => 'Datei anhängen';

  @override
  String quoteWrote(String date, String who) {
    return 'Am $date schrieb $who:';
  }

  @override
  String get quoteForwarded => '---------- Weitergeleitete Nachricht ----------';

  @override
  String get quoteDateFormat => '%d.%m.%Y %H:%M';

  @override
  String get date => 'Datum';

  @override
  String get loadImages => 'Bilder laden';

  @override
  String get imagesBlocked => 'Bilder aus dem Internet werden erst geladen, wenn du es willst.';

  @override
  String get openLink => 'Diesen Link öffnen?';

  @override
  String get asText => 'Als Text';

  @override
  String get asHtml => 'Formatiert';

  @override
  String get mailboxes => 'Ordner';

  @override
  String get searchMail => 'Mail durchsuchen';

  @override
  String get searchResults => 'Suchergebnisse';

  @override
  String get myMailbox => 'Mein Postfach';

  @override
  String get chooseAll => 'Alle auswählen';

  @override
  String get markRead => 'Gelesen oder ungelesen';

  @override
  String get flag => 'Markieren';

  @override
  String get moveTo => 'Verschieben nach';

  @override
  String chosen(int count) {
    String _temp0 = intl.Intl.pluralLogic(count, locale: localeName, other: '$count ausgewählt', one: '1 ausgewählt');
    return '$_temp0';
  }

  @override
  String deleteForGood(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'Diese $count Mails endgültig löschen?',
      one: 'Diese Mail endgültig löschen?',
    );
    return '$_temp0';
  }

  @override
  String get newSubfolder => 'Neuer Ordner darin';

  @override
  String get moveFolder => 'Verschieben';

  @override
  String get emptyFolder => 'Leeren';

  @override
  String get deleteFolder => 'Ordner löschen';

  @override
  String get topLevel => 'Ganz oben';

  @override
  String get folders => 'Ordner';

  @override
  String moveFolderTo(String name) {
    return '„$name“ verschieben nach';
  }

  @override
  String emptyFolderConfirm(String name) {
    return 'Alle Mails in „$name“ endgültig löschen?';
  }

  @override
  String deleteFolderConfirm(String name) {
    return 'Den Ordner „$name“ löschen?';
  }

  @override
  String deleteFolderWithEmails(String name, int count) {
    String _temp0 = intl.Intl.pluralLogic(count, locale: localeName, other: 'die $count Mails', one: 'die Mail');
    return 'Den Ordner „$name“ und $_temp0 nur darin endgültig löschen?';
  }

  @override
  String get vacation => 'Abwesenheitsnotiz';

  @override
  String get vacationHint =>
      'Beantwortet Mail, während du weg bist – jeden Absender einmal pro Woche, keine Verteiler und keine automatischen Mails.';

  @override
  String get fromOptional => 'Ab (optional)';

  @override
  String get untilOptional => 'Bis (optional)';

  @override
  String get vacationSubjectHint => 'Auto: und der Betreff der beantworteten Mail';

  @override
  String get text => 'Text';

  @override
  String get notSet => 'Nicht gesetzt';

  @override
  String get mailSettings => 'Schreiben und Papierkorb';

  @override
  String get sendFrom => 'Senden von';

  @override
  String get myAddress => 'Meine Adresse';

  @override
  String get undoSend => 'Senden zurücknehmen';

  @override
  String get off => 'Aus';

  @override
  String seconds(int count) {
    return '$count Sekunden';
  }

  @override
  String get keepTrash => 'E-Mails im Papierkorb behalten';

  @override
  String asTenantDays(int days) {
    return 'Wie die Organisation es festlegt ($days Tage)';
  }

  @override
  String get asTenantForever => 'Wie die Organisation es festlegt (bis zum Löschen)';

  @override
  String get ownDays => 'Eigene Angabe: Tage';
}
