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
  String get required => 'Pflichtfeld';

  @override
  String get mail => 'Mail';

  @override
  String get files => 'Dateien';

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
  String get noMessages => 'Keine Nachrichten';

  @override
  String get noSubject => '(kein Betreff)';

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
  String get discard => 'Verwerfen';

  @override
  String get messageSent => 'Nachricht gesendet';

  @override
  String get attachments => 'Anhänge';

  @override
  String get save => 'Speichern';

  @override
  String savedTo(String path) {
    return 'Gespeichert unter $path';
  }

  @override
  String get loadMore => 'Mehr laden';

  @override
  String get myFiles => 'Meine Dateien';

  @override
  String get folderEmpty => 'Dieser Ordner ist leer';

  @override
  String get refresh => 'Aktualisieren';

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
  String get encryptedMessage => 'Verschlüsselte Nachricht';

  @override
  String get unlockToRead => 'Entsperre deinen Schlüssel, um sie zu lesen';

  @override
  String get lockedEmail =>
      'Diese Nachricht ist Ende-zu-Ende verschlüsselt. Entsperre deinen Schlüssel, um sie zu lesen.';

  @override
  String get e2eEncrypted => 'Ende-zu-Ende verschlüsselt';

  @override
  String get signatureVerified => 'Signatur geprüft';

  @override
  String get signatureUnverified => 'Signatur nicht geprüft';

  @override
  String get notSigned => 'nicht signiert';

  @override
  String get willEncrypt => 'Wird Ende-zu-Ende verschlüsselt und signiert gesendet.';

  @override
  String wontEncrypt(String reason) {
    return 'Nicht Ende-zu-Ende verschlüsselt: $reason';
  }

  @override
  String get sentEncrypted => 'Ende-zu-Ende verschlüsselt gesendet';

  @override
  String get cancel => 'Abbrechen';

  @override
  String get calendar => 'Kalender';

  @override
  String get contacts => 'Kontakte';

  @override
  String get today => 'Heute';

  @override
  String get earlier => 'Früher';

  @override
  String get later => 'Später';

  @override
  String get allDay => 'Ganztägig';

  @override
  String get noEvents => 'Keine Termine in diesen zwei Wochen';

  @override
  String get location => 'Ort';

  @override
  String get participants => 'Teilnehmende';

  @override
  String get accept => 'Zusagen';

  @override
  String get maybe => 'Vielleicht';

  @override
  String get decline => 'Absagen';

  @override
  String get cancelled => 'Abgesagt';

  @override
  String get recurring => 'Wiederholt sich';

  @override
  String get yourAnswer => 'Deine Antwort';

  @override
  String get statusAccepted => 'zugesagt';

  @override
  String get statusTentative => 'vielleicht';

  @override
  String get statusDeclined => 'abgesagt';

  @override
  String get statusNeedsAction => 'noch keine Antwort';

  @override
  String get answerSent => 'Antwort an die Person gesendet, die eingeladen hat';

  @override
  String get searchContacts => 'Kontakte durchsuchen';

  @override
  String get noContacts => 'Keine Kontakte';

  @override
  String get emails => 'E-Mail';

  @override
  String get phones => 'Telefon';

  @override
  String get notes => 'Notizen';

  @override
  String get writeEmail => 'E-Mail schreiben';

  @override
  String get organization => 'Organisation';

  @override
  String sharedBy(String name) {
    return 'geteilt von $name';
  }

  @override
  String get newEvent => 'Neuer Termin';

  @override
  String get editEvent => 'Termin ändern';

  @override
  String get deleteEvent => 'Termin löschen';

  @override
  String get deleteEventConfirm => 'Diesen Termin löschen? Alle Eingeladenen erfahren davon.';

  @override
  String get deleteRecurringConfirm =>
      'Diesen Termin mit allen Wiederholungen löschen? Alle Eingeladenen erfahren davon.';

  @override
  String get title => 'Titel';

  @override
  String get starts => 'Beginn';

  @override
  String get ends => 'Ende';

  @override
  String get calendarField => 'Kalender';

  @override
  String get description => 'Beschreibung';

  @override
  String get invite => 'Einladen';

  @override
  String get inviteHint => 'Adressen, durch Komma getrennt – sie bekommen eine Einladung per E-Mail';

  @override
  String get repeat => 'Wiederholung';

  @override
  String get repeatNone => 'Nie';

  @override
  String get repeatDaily => 'Täglich';

  @override
  String get repeatWeekly => 'Wöchentlich';

  @override
  String get repeatMonthly => 'Monatlich';

  @override
  String get repeatYearly => 'Jährlich';

  @override
  String get saved => 'Gespeichert';

  @override
  String get deleted => 'Gelöscht';

  @override
  String get delete => 'Löschen';

  @override
  String get edit => 'Ändern';

  @override
  String get endBeforeStart => 'Das Ende liegt vor dem Beginn';

  @override
  String get recurringEditsAll => 'Änderungen gelten für alle Wiederholungen.';

  @override
  String get newContact => 'Neuer Kontakt';

  @override
  String get editContact => 'Kontakt ändern';

  @override
  String get deleteContactConfirm => 'Diesen Kontakt löschen?';

  @override
  String get name => 'Name';

  @override
  String get emailsField => 'E-Mail-Adressen';

  @override
  String get phonesField => 'Telefonnummern';

  @override
  String get onePerLine => 'Eine pro Zeile';

  @override
  String get note => 'Notiz';

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
  String get remove => 'Entfernen';

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
  String get thisEvent => 'Nur dieser Termin';

  @override
  String get wholeSeries => 'Die ganze Serie';

  @override
  String get changeWhich => 'Nur diesen Termin oder die ganze Serie ändern?';

  @override
  String get deleteWhich => 'Nur diesen Termin oder die ganze Serie löschen? Alle Eingeladenen erfahren davon.';

  @override
  String get editThisEvent => 'Diesen Termin ändern';

  @override
  String get instanceEditsOne => 'Nur dieser Termin der Serie ändert sich; die Eingeladenen bleiben wie in der Serie.';

  @override
  String get monthView => 'Monat';

  @override
  String get listView => 'Liste';

  @override
  String get labelWork => 'Arbeit';

  @override
  String get labelPrivate => 'privat';

  @override
  String get labelMobile => 'Mobil';

  @override
  String get labelVoice => 'Sprache';

  @override
  String get labelText => 'SMS';

  @override
  String get labelVideo => 'Video';

  @override
  String get labelFax => 'Fax';

  @override
  String get labelPager => 'Pager';

  @override
  String get labelTextphone => 'Schreibtelefon';

  @override
  String get labels => 'Labels';

  @override
  String get addEmail => 'Adresse hinzufügen';

  @override
  String get addPhone => 'Nummer hinzufügen';

  @override
  String get loadImages => 'Bilder laden';

  @override
  String get imagesBlocked => 'Bilder aus dem Internet werden erst geladen, wenn du es willst.';

  @override
  String get openLink => 'Diesen Link öffnen?';

  @override
  String get open => 'Öffnen';

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
  String get nothingFound => 'Nichts gefunden';

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
  String get rename => 'Umbenennen';

  @override
  String get moveFolder => 'Verschieben';

  @override
  String get emptyFolder => 'Leeren';

  @override
  String get deleteFolder => 'Ordner löschen';

  @override
  String get newFolder => 'Neuer Ordner';

  @override
  String get create => 'Anlegen';

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
  String get appPasswordWrong => 'Die Adresse oder das App-Passwort ist falsch.';

  @override
  String get drives => 'Ablagen';

  @override
  String get sharedWithMe => 'Mit mir geteilt';

  @override
  String get upload => 'Hochladen';

  @override
  String get uploading => 'Wird hochgeladen …';

  @override
  String get searchFiles => 'Namen und Inhalte durchsuchen';

  @override
  String get share => 'Teilen';

  @override
  String shareTitle(String name) {
    return '„$name“ teilen';
  }

  @override
  String get findPeople => 'Personen und Gruppen suchen';

  @override
  String get levelRead => 'Darf ansehen';

  @override
  String get levelEdit => 'Darf bearbeiten';

  @override
  String get levelFull => 'Darf bearbeiten und teilen';

  @override
  String get notShared => 'Noch mit niemandem geteilt.';

  @override
  String get shared => 'Geteilt';

  @override
  String get link => 'Link';

  @override
  String linksTitle(String name) {
    return 'Links zu „$name“';
  }

  @override
  String get linkView => 'Ansehen';

  @override
  String get linkAdd => 'Ansehen und hinzufügen';

  @override
  String get linkDrop => 'Nur hinzufügen';

  @override
  String get expires => 'Läuft ab';

  @override
  String get never => 'Nie';

  @override
  String inDays(int days) {
    return 'In $days Tagen';
  }

  @override
  String expiresOn(String date) {
    return 'Läuft ab $date';
  }

  @override
  String get withPassword => 'Mit Passwort';

  @override
  String get passwordOptional => 'Passwort (optional)';

  @override
  String get createLink => 'Link erstellen';

  @override
  String get linkMade => 'Der Link – er wird nur jetzt angezeigt:';

  @override
  String get noLinks => 'Noch keine Links.';

  @override
  String get versions => 'Versionen';

  @override
  String get currentVersion => 'Aktuell';

  @override
  String get restore => 'Wiederherstellen';

  @override
  String get restoreConfirm =>
      'Diese Version wieder zum Inhalt der Datei machen? Der jetzige bleibt als Version erhalten.';

  @override
  String get copyOrMove => 'Kopieren oder verschieben';

  @override
  String get copyHere => 'Hierher kopieren';

  @override
  String get moveHere => 'Hierher verschieben';

  @override
  String deleteFileConfirm(String name) {
    return '„$name“ endgültig löschen?';
  }

  @override
  String get trashEmptyNote => 'Der Papierkorb ist leer';

  @override
  String get more => 'Mehr';

  @override
  String get newFolderName => 'Name des neuen Ordners';

  @override
  String get newName => 'Neuer Name';

  @override
  String get drive => 'Ablage';

  @override
  String get deleteFileForGood => 'Endgültig löschen';

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
  String get vacation => 'Abwesenheitsnotiz';

  @override
  String get vacationHint =>
      'Beantwortet Mail, während du weg bist – jeden Absender einmal pro Woche, keine Verteiler und keine automatischen Mails.';

  @override
  String get vacationOn => 'Mail beantworten';

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

  @override
  String get securityHintApp =>
      'Passwort, Zwei-Faktor-Anmeldung, Passkeys, App-Passwörter und Sitzungen änderst du in der Web-App, wo du dich mit deinem Passwort anmeldest.';

  @override
  String get asTenant => 'Wie die Organisation';

  @override
  String get openElsewhere => 'In anderer App öffnen';

  @override
  String noAppFor(String name) {
    return 'Keine App auf diesem Gerät öffnet $name.';
  }

  @override
  String get textCut => 'Nur das erste Megabyte wird gezeigt – speichere die Datei, um alles zu sehen.';

  @override
  String get cannotShow => 'Diese Datei kann hier nicht gezeigt werden.';

  @override
  String get dropToUpload => 'Hier ablegen zum Hochladen';

  @override
  String get uploadFolder => 'Ordner hochladen';

  @override
  String get newVault => 'Neuer Tresor';

  @override
  String get newVaultName => 'Name des Tresors';

  @override
  String get newVaultHint => 'Neuer Tresor – nur die, mit denen er geteilt ist, können lesen, was darin liegt';

  @override
  String get vaultLocked => 'Entsperre deinen Schlüssel, um zu lesen, was in Tresoren liegt.';

  @override
  String get lockedVault => 'Gesperrter Tresor';

  @override
  String get lockedFolder => 'Verschlüsselter Ordner';

  @override
  String get lockedFile => 'Verschlüsselte Datei';

  @override
  String get vaultMoveNo =>
      'Nichts wird in einen Tresor hinein oder aus ihm heraus verschoben – nur in den Papierkorb.';

  @override
  String vaultKeysWaiting(String names) {
    return 'Diese können den Tresor öffnen, sobald sie einen eigenen Schlüssel haben und du ihn erneut teilst: $names';
  }

  @override
  String get syncTitle => 'Ordner auf diesem Computer';

  @override
  String get syncHint =>
      'Ein Ordner dieses Computers, der mit einem Speicher abgeglichen wird: Was sich auf einer Seite ändert, kommt alle paar Minuten auf der anderen an, solange die App offen ist. Auf beiden Seiten geändert, bleiben beide Fassungen erhalten.';

  @override
  String get syncChoose => 'Ordner wählen';

  @override
  String get syncNow => 'Jetzt abgleichen';

  @override
  String get syncStop => 'Abgleich beenden';

  @override
  String get syncRunning => 'Wird abgeglichen …';

  @override
  String get syncNever => 'Noch nicht abgeglichen';

  @override
  String syncDone(String time, int down, int up) {
    return 'Abgeglichen $time: $down geladen, $up hochgeladen';
  }

  @override
  String syncIssues(int conflicts, int failed) {
    return '$conflicts auf beiden Seiten geändert (als Kopie behalten), $failed nicht erledigt – wird wiederholt';
  }

  @override
  String get documentsTitle => 'Dateien-App';

  @override
  String get documentsHint =>
      'Deine Speicher in Androids Dateien-App und überall, wo eine App dich eine Datei wählen lässt. Sie meldet sich einmal eigens an – dafür öffnet sich der Browser.';

  @override
  String get documentsOn => 'Deine Speicher stehen in der Dateien-App.';

  @override
  String get documentsOff => 'Nicht in der Dateien-App.';

  @override
  String get documentsEnable => 'In Dateien zeigen';

  @override
  String get documentsDisable => 'Aus Dateien entfernen';

  @override
  String syncFailed(String error) {
    return 'Nicht abgeglichen: $error';
  }

  @override
  String syncLocked(int count) {
    return '$count Tresore bleiben unverändert – entsperre deinen Schlüssel, um sie abzugleichen';
  }

  @override
  String get syncAtLogin => 'Mit dem Computer starten, damit die Ordner abgeglichen werden, ohne die App zu öffnen';

  @override
  String get trayOpen => 'kernoid öffnen';

  @override
  String get traySync => 'Ordner jetzt abgleichen';

  @override
  String get trayQuit => 'kernoid beenden';

  @override
  String get explorerTitle => 'Dateien im Explorer';

  @override
  String get explorerHint =>
      'Deine Speicher als Ordner im Explorer: Dateien erscheinen sofort und werden geladen, wenn man sie öffnet, und was du dort änderst, kommt binnen einer Minute bei kernoid an, solange die App offen ist. Der Explorer bekommt eine eigene Anmeldung – die Anmeldeseite von kernoid öffnet sich dafür noch einmal.';

  @override
  String get explorerSetUp => 'Im Explorer zeigen';

  @override
  String get explorerRemove => 'Aus dem Explorer entfernen';

  @override
  String get explorerStarting => 'Wird gestartet …';

  @override
  String explorerLast(String time) {
    return 'Zuletzt abgeglichen $time';
  }

  @override
  String get explorerSignedOut =>
      'Die Anmeldung für den Explorer ist abgelaufen – zeige die Dateien erneut, um dich neu anzumelden.';

  @override
  String explorerFailed(String error) {
    return 'Nicht im Explorer gezeigt: $error';
  }

  @override
  String get fileProviderTitle => 'Dateien im Finder';

  @override
  String get fileProviderTitleIos => 'Dateien in der Dateien-App';

  @override
  String get fileProviderHint =>
      'Deine Speicher als Orte im Dateimanager des Systems: Dateien erscheinen, bevor sie geladen sind, und öffnen sich, wenn du sie brauchst. Er hat eine eigene Anmeldung – du meldest dich dafür noch einmal im Browser an. Tresore bleiben dort gesperrt.';

  @override
  String get fileProviderOn => 'Einschalten';

  @override
  String get fileProviderUpdate => 'Speicher aktualisieren';

  @override
  String get fileProviderOff => 'Ausschalten';

  @override
  String fileProviderShown(String stores) {
    return 'Angezeigt: $stores';
  }

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
