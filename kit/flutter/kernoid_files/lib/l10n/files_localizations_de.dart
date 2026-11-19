// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'files_localizations.dart';

// ignore_for_file: type=lint

/// The translations for German (`de`).
class FilesLocalizationsDe extends FilesLocalizations {
  FilesLocalizationsDe([String locale = 'de']) : super(locale);

  @override
  String get files => 'Dateien';

  @override
  String get myFiles => 'Meine Dateien';

  @override
  String get folderEmpty => 'Dieser Ordner ist leer';

  @override
  String get refresh => 'Aktualisieren';

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
  String get deleteFileForGood => 'Endgültig löschen';

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
}
