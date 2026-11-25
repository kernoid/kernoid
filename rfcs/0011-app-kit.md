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
| `kernoid_bridge` | the Rust side (`rust/`, crate `kernoid_bridge` on `kit/client`, `kit/e2e`, `kit/sync` by path), the Dart code flutter_rust_bridge generates from it – no native build (section 4); a program's part (`program`); the core of the file shells (`provider`) | `rust/`, `lib/src/rust/` |
| `kernoid_native` | the FFI plugin that builds the bridge's crate into kernoid's app with cargokit, the platform folders for it – no Dart (section 4) | `rust_builder/` |
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
- **Without an account** (aktujo RFC 0012, 8, item 4): a feature may work on the device alone – a program's personal
  archive, say – and says so with `onDevice`; it then has a page and a session without an account (`pageOnDevice`,
  `startOnDevice`). An app with one such feature starts at its home before anyone signs in, shows only those features
  and puts the login where the account would be (the foot of the side bar, the end of the bottom bar). Once an account
  signs in, the home starts again with it: the sessions on the device end, `start` and `page` take over, and a
  feature that works on the device answers `offeredBy` with `true` whatever the server offers. Signing out returns
  to the home without an account; what a feature keeps on the device stays. A kept login that cannot be resumed
  (offline) leaves the app at that home, the reason shown with the login. An app whose features all need an account –
  kernoid's own – starts at the login, as before.
- A **program built on kernoid** writes its own features (`aktujo_documents` …) in its own packages and puts together
  its own app from `kernoid_shell`, `kernoid_ui` and whichever of kernoid's features it wants – under its own name,
  bundle and brand (`KTokens` per brand).

## 4. One native library per app

Two Rust libraries in one app would each carry a standard library and an async runtime, and on iOS they would clash
when linked. So an app has **one** Rust library: kernoid's apps take `kernoid_bridge` as it is; a program's app makes
its own crate on `kernoid_bridge` – the app's library – and reaches its own Rust through kernoid's generated API.

**Not two generations in one library** (spike, 2026-11-25, flutter_rust_bridge 2.13.0): the generated code exports
fixed global symbols – `frb_pde_ffi_dispatcher_primary`, `frb_get_rust_content_hash`, `store_dart_post_cobject` and
more – and dispatches by the function ids of one generation. Two crates exporting the same symbol link without an
error on macOS, and one of them silently wins. And a program generating kernoid's API once more would give Dart types
of its own, which kernoid's feature packages do not take.

**So kernoid's generated API is the only one, and a program's part goes through it** (`kernoid_bridge::program`):

- The program's crate depends on `kernoid_bridge` and is built as the app's library; kernoid's generated symbols come
  along with it (checked in the `cdylib` and the `staticlib`). It implements `Program` – `call` answers bytes,
  `watch` sends bytes to a `Sink` – and exports `kernoid_programs`, a C function without arguments that registers it
  (`program::register("aktujo", …)`).
- Dart calls it with `programCall`/`programWatch` before anyone signs in, and with `Kernoid.programCall`/
  `programWatch` for the account – then the program's Rust is handed kernoid's `Kernoid` of that login. What the bytes
  are is the program's: JSON, CBOR, its own types behind a Dart class of its own – as the file shells talk JSON to
  Swift and Kotlin.
- `runKernoidApp(features: …, library: 'aktujo_bridge')` loads that library (`loadKernoid`): kernoid's `RustLib` from
  it – flutter_rust_bridge's content hash refuses a library built on another version of the bridge –, then
  `kernoid_programs`, if the library has it. kernoid's own app names no library.
- The program's crate takes `kernoid_bridge` from git at the tag of the release whose Dart packages the app uses.

Checked on macOS with a debug build: a crate on `kernoid_bridge` as the one library, kernoid's own calls (an async
login, its error), a program's call, its errors and a stream, all from Dart; `kernoid_bridge`'s test of the registry.
**OPEN:** the other platforms and release builds, and a program's call with a signed-in account.

**The bridge's Dart code apart from its native build** (implemented 2026-11-25): an FFI plugin's crate is built into
every app that depends on the plugin, so `kernoid_bridge` holds the crate and the generated Dart code and is no plugin,
and `kernoid_native` – cargokit and the platform folders – builds the crate into kernoid's app as `kernoid_bridge`.
kernoid's app depends on both; a program's app depends on `kernoid_bridge` and on a package of its own like
`kernoid_native` that builds its crate – never on `kernoid_native`. iOS and macOS link the static library with
`-force_load`, so `kernoid_programs` stays in it. There the framework is named after the plugin package, not the
library, so `loadKernoid` finds the symbols in the process (`ExternalLibrary.process`) – safe, since an app has one
library with flutter_rust_bridge's symbols; elsewhere it opens the library by name. Checked: kernoid's macOS app
built with `kernoid_native` has that one framework with Rust in it, and starts.

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

- **OPEN:** a program's library on the platforms besides macOS, and in release builds (section 4).
