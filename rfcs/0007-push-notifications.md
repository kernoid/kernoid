<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0007 – Push notifications

- **Status:** draft, 2026-10-30; nothing implemented yet.
- **Scope:** how kernoid tells a device that something changed while no app holds a connection to it – browsers
  (Web Push), Android (UnifiedPush, Firebase) and iOS (Apple Push Notification service) –, what an operator sets up
  for it, and what a relay is. It closes the open point "push subscriptions" of RFC 0002, 11.1.

An app that is open holds a connection to its kernoid and hears every change there: JMAP over EventSource or
WebSocket (RFC 0002, 11.1), IMAP `IDLE`. Desktop programs need nothing more. A phone closes such connections soon,
and a browser tab that is closed holds none; they are woken by a push service – the browser's, the phone maker's or
one the user chose. Statements about Apple and Google below come from their documentation as generally known;
**OPEN:** check each against the current documentation and terms before implementing.

## 1. Decisions

The maintainer decided (2026-10-30):

1. **Whatever kernoid cannot do by itself is a setting of the operator.** kernoid sends to Apple, Google or a relay
   only what the operator configured; nothing is set by default, and no installation talks to a service of falkOSS
   on its own (no telemetry, whitepaper).
2. **Every operator sets up push to Apple and Google themselves** – with their own keys, or through a relay of their
   choice (section 5).
3. **falkOSS runs no relay for now.** It may run one later, if its income allows; that is not planned. falkOSS's own
   installation uses falkOSS's own keys directly (section 4).

## 2. What a notification says

A notification says **that** something changed, not what: the JMAP `StateChange` of RFC 8620, 7.1 – account and
type, the new state. The app then asks its kernoid over its own connection. Nothing of a message, an event or a file
passes through a push service.

**OPEN:** notifications that show the sender and subject on a locked phone before the app runs. Such content would
be encrypted for the device (as Web Push encrypts, RFC 8291) and decrypted on it – on iOS by a notification service
extension. With end-to-end encrypted mail (RFC 0006, 5) the device decrypts the summary itself.

## 3. Without settings: Web Push and UnifiedPush

JMAP **`PushSubscription`** (RFC 8620, 7.2) is the one way a device asks to be woken: a URL, the types it wants, an
expiry, and optionally `keys` to encrypt to (RFC 8291). kernoid verifies the URL with a `PushVerification` first and
sends to it through the outbound client – HTTPS, public addresses only (RFC 0001, 7.7), as for every request kernoid
makes.

- **Web Push** ([RFC 8030](https://www.rfc-editor.org/rfc/rfc8030)): the web app's service worker subscribes at the
  browser's push service and registers the endpoint as a `PushSubscription`. kernoid identifies itself with VAPID
  ([RFC 8292](https://www.rfc-editor.org/rfc/rfc8292)) keys it makes per instance, sealed like other keys. This works
  in every current browser, including Safari on iOS for a web app added to the home screen – no account with Apple
  or Google.
- **UnifiedPush**: the Android app gets an endpoint from the distributor the user chose (for example ntfy) and
  registers it the same way; UnifiedPush speaks Web Push. No Google service is involved.

Neither needs a setting: what a device registers, kernoid sends to. A tenant may forbid push subscriptions
(**OPEN:** whether that is needed).

## 4. Apple and Google: the operator's own keys

Apple's push service (APNs) and Firebase Cloud Messaging (FCM) accept notifications only from whoever publishes the
app: APNs with a key of the Apple developer team that owns the app's bundle id, FCM with a service account of the
Firebase project the app is built with. A key works only for that publisher's apps.

- `[push.apns]`: the key file (`.p8`), its key id, the team id, the bundle ids it covers, and whether to use Apple's
  sandbox. `[push.fcm]`: the service account file and the project id. Both are off until set; the key files are read
  like TLS keys (`mail.tls`), never stored in the database.
- The app registers through a JMAP extension (`https://kernoid.dev/jmap/push`, **OPEN:** its exact form): a
  `PushSubscription` that names its platform, its bundle id or Firebase project, and its device token instead of a
  URL. kernoid sends to APNs or FCM directly when its own keys cover that app.
- **Whose app:** the apps in the stores are published by falkOSS (once incorporated, with its developer accounts).
  Their bundle ids belong to falkOSS's team, so only falkOSS's keys reach them. An operator who wants push for their
  users on iOS without a relay builds the app (MIT) under their own bundle id and Apple account, and sets their own
  keys. falkOSS's installation sets falkOSS's keys and reaches the store apps directly.

## 5. A relay

A **relay** passes notifications on to APNs or FCM for installations that do not hold the publisher's keys. It is
kernoid itself, in a process role of its own (`push-relay`), so anyone can run one:

- The relay holds the publisher's keys (`[push.apns]`, `[push.fcm]`) and accepts notifications from the
  installations it lists, each with a secret of its own (**OPEN:** registration, limits per installation).
- An installation sends to a relay only if `[push.relay]` names it (URL and secret). There is no default. Whatever its
  own keys cover goes directly; the rest goes to the relay; without either, devices of that kind get no push.
- A relay sees an installation, a device token and the content of section 2 (or ciphertext, once section 2's open
  point is done) – nothing about the account beyond that.

falkOSS runs no relay for now (section 1). So, for the store apps on iOS and with Firebase, an installation other
than falkOSS's has push only through a relay someone else runs, or not at all; UnifiedPush and Web Push work
everywhere.

## 6. Order

- **0.x:** `PushSubscription` with Web Push and UnifiedPush; the web app's notifications when it is closed.
- **1.0, with the app for desktop and mobile:** `[push.apns]`, `[push.fcm]`, the JMAP extension and the role
  `push-relay`.

## 7. Open

- The current documentation and terms of APNs and FCM (introduction), in particular whether a relay may hold a
  publisher's key for others.
- Content for the device, encrypted (2).
- The JMAP extension's form (4); a relay's registration and limits (5).
- Whether a tenant may forbid push subscriptions (3).
