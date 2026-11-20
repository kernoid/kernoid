<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0011 – The app kit

- **Status:** draft, 2026-11-19; the direction decided by the maintainer the same day (RFC 0008, 1), the mechanism a
  proposal. Implemented with 0.5.1: the packages in `kit/flutter/`, `KFeature` with `Kernoid.offers` (the server's
  capabilities), kernoid/apps on them. Each feature also adds sections to the account page and keeps what it needs
  while the account is signed in (`KFeatureSession`: the folders kept in step and the tray of `kernoid_files`).
- **Scope:** how kernoid's apps – and the apps of programs built on kernoid – are put together from Flutter packages
  in this repository, how one app shows only what its server offers, and what stays in `kernoid/apps`.

## 1. Decisions

The maintainer decided (2026-11-19): kernoid is a kit of crates **and Flutter libraries**, all in this repository;
`kernoid/apps` holds only kernoid's own apps, built from them. Everything an app uses is MIT (RFC 0008, 6).

## 2. The packages

In `kit/flutter/`, each a Dart package under MIT:

| Package | Holds | Was in `kernoid/apps` |
|---|---|---|
| `kernoid_ui` | the design system: `KApp`, `KTheme`/`KTokens`, text input, dialogs, menus, pickers, controls; IBM Plex and Lucide | `lib/ui/` |
| `kernoid_bridge` | the Rust side (`rust/`, crate `kernoid_bridge` on `kit/client`, `kit/e2e`, `kit/sync` by path), the Dart code flutter_rust_bridge generates from it, cargokit to build it; the core of the file shells (`provider`) | `rust/`, `rust_builder/`, `lib/src/rust/` |
| `kernoid_l10n` | the strings of the kit, English and German, as one `KernoidLocalizations` | `lib/l10n/` |
| `kernoid_shell` | the frame of an app: logging in (OpenID Connect, app passwords, kept login), the home with its side bar built from **features**, the account page, appearance, the tray, what the server offers | `lib/app/`, `pages/home.dart`, `login.dart`, `account.dart` |
| `kernoid_mail` | mail: folders, list, reading (HTML, end to end), writing | `pages/mail.dart`, `compose.dart`, `widgets/html_body.dart`, `e2e.dart` |
| `kernoid_calendar` | calendars and events | `pages/calendar.dart`, `event_form.dart` |
| `kernoid_contacts` | address books and contacts | `pages/contacts.dart`, `contact_form.dart` |
| `kernoid_files` | file stores, drives, sharing, links, versions, vaults, the viewer, folders kept in step, the Dart side of the file shells | `pages/files.dart`, `file_dialogs.dart`, `viewer.dart`, `widgets/pdf_view.dart`, `app/sync_folders.dart` … |

`kernoid/apps` keeps `lib/main.dart` (which features, which brand), the platform folders with the native parts that
belong to one app bundle – the File Provider extension, the DocumentsProvider, Windows' cloud files registration, icons,
entitlements –, the integration tests, the release workflow and the app's changelog.

**Strings:** `kernoid_l10n` keeps those the shell, the design system and several features share; each feature package
has its own (`lib/l10n/<feature>_*.arb`, `flutter gen-l10n` there, a class `<Feature>Localizations`), reached from
the shared ones as `l.mailText.…`, `l.filesText.…` – no delegate needed. A program's feature with strings of its
own gives the shell their delegates (`KFeature.localizationsDelegates`) and looks them up as usual (implemented in
0.5.1).

## 3. Features

`kernoid_shell` knows no mail, calendar or file: an app hands it a list of **features**:

```dart
abstract class KFeature {
  String get id;                                   // "mail"
  IconData get icon;
  String label(BuildContext context);
  bool offeredBy(KServer server);                  // from the JMAP session and GET /v1/services
  Widget build(BuildContext context, KAccount account);
}

void main() => runKernoidApp(features: [MailFeature(), CalendarFeature(), ContactsFeature(), FilesFeature()]);
```

- **What an app contains** is fixed when it is built – app stores allow no code loaded later.
- **What it shows** comes from its server: a feature appears when `offeredBy` says the server has it – mail when the
  session has `urn:ietf:params:jmap:mail`, files when it has the FileNode capability, and so on (RFC 0008, 4: a
  service that is off is missing from the session and from `GET /v1/services`). Against a kernoid that is identity
  alone, the app shows the account and nothing else.
- A **program built on kernoid** writes its own features (`aktujo_documents` …) in its own packages and puts together
  its own app from `kernoid_shell`, `kernoid_ui` and whichever of kernoid's features it wants – under its own name,
  bundle and brand (`KTokens` per brand).

## 4. One native library per app

Two Rust libraries in one app would each carry a standard library and an async runtime, and on iOS they would clash
when linked. So an app has **one** Rust library: kernoid's apps take `kernoid_bridge` as it is; a program's app makes
its own bridge crate that depends on kernoid's Rust crates and adds its own API – and generates its own Dart code.
**OPEN:** whether kernoid's feature packages can then call the program's bridge (flutter_rust_bridge with several
crates in one library) or each program generates kernoid's API once more – a spike, when aktujo's app moves (RFC
0008, 1).

## 5. The system's file integration

The File Provider (Apple), the DocumentsProvider (Android) and Cloud Files (Windows) belong to an app bundle: two apps
registering the same account would show it twice in Finder or Explorer. Only **kernoid's** app integrates file stores
with the system; the apps of programs built on kernoid show files inside the app. The Rust core of the shells is in
`kernoid_bridge` (`provider`), the Swift and Kotlin around it in `kernoid/apps`.

## 6. Building from two repositories

- **Releases:** `kernoid/apps` depends on the packages by git – `kernoid/kernoid` at the tag of a release, with `path:
  kit/flutter/<package>`. kernoid and its apps are released together, in one version, as before. The bridge depends on
  the kit's crates **by path inside this repository** – there is no SDK release to wait for between a change of the kit
  and the app.
- **Development:** a `pubspec_overrides.yaml` in `kernoid/apps` (not tracked) points every package at a checkout of
  this repository beside it.
- **CI:** this repository checks the packages (`dart format`, `flutter analyze`, `flutter test`, the bridge's Rust
  checks and its generated code); `kernoid/apps` checks out `kernoid/kernoid` at `KERNOID_REF` beside it, as aktujo's
  apps do with aktujo, and builds the apps.
- **OPEN:** publishing the packages on pub.dev (RFC 0008, 8) – needed only when apps outside falkOSS want them.

## 7. 0.5.1

1. The packages of section 2 in `kit/flutter/`, with their tests and CI.
2. `kernoid_shell` builds the side bar from features and hides those the server does not offer.
3. `kernoid/apps` is only the app (section 2), on the packages, with every integration test of 0.4 passing against a
   kernoid 0.5 – and against one that is identity alone.

## 8. Open

- **OPEN:** several bridges in one native library (section 4).
