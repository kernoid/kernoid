<!-- SPDX-License-Identifier: MIT -->
# kernoid's app kit – Flutter

The Flutter packages kernoid's apps are made of ([RFC 0011](../../rfcs/0011-app-kit.md)), MIT like the whole kit:

| Package | Holds |
|---|---|
| `kernoid_l10n` | the strings the packages share, English and German (`lib/l10n/*.arb`; `flutter gen-l10n` here) – each feature package has its own beside them (`lib/l10n/`, `l.mailText.…`) |
| `kernoid_ui` | the design system on Flutter's widgets layer – no Material, no Cupertino – with IBM Plex and Lucide |
| `kernoid_bridge` | the Rust side: the crate in `rust/` on the kit's SDK (by path), the Dart code `flutter_rust_bridge_codegen generate` makes from it, cargokit |
| `kernoid_shell` | the frame: logging in, the home with the features the server offers – or, before anyone signs in, those that work on the device (`KFeature.onDevice`) –, the account; `KFeature`, `runKernoidApp` |
| `kernoid_mail`, `kernoid_calendar`, `kernoid_contacts`, `kernoid_files` | the features of kernoid's own app |

An app is a list of features:

```dart
Future<void> main() => runKernoidApp(features: const [MailFeature(), CalendarFeature(), ContactsFeature(), FilesFeature()]);
```

The packages refer to each other by path; an app takes them from git at a release's tag and names every one of them in
`dependency_overrides` (kernoid/apps does). Each package: `flutter pub get && flutter analyze && flutter test`; the
bridge's Rust side: `(cd kernoid_bridge/rust && cargo fmt --check && cargo clippy --locked --all-targets && cargo test
--locked && cargo deny check)` – CI's job `flutter`.
