<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0006 – End-to-end and post-quantum encryption

- **Status:** draft, 2026-10-30; implemented: section 2 (post-quantum TLS), 4 (keys: `apps/e2e`, `kernoid-identity`'s
  `openpgp`, migration 0048; WKD and Autocrypt), 5.1–5.2 on the server (`kernoid-mail`'s `e2e`), 8 (policy, recovery
  key) and the JMAP extension; the web app's side of 5 and 8; section 6 (vaults: `kernoid-files`' `vault`, migration
  0049, the web app). Sections 7 and 9 are next.
- **Scope:** what kernoid encrypts so that quantum computers cannot read it later (sections 2–3), and how mail, files,
  calendars and contacts can be encrypted so that only their owners can read them – not the operator, not kernoid
  (sections 4–9).

Until now kernoid's promise was: content is sealed with a key per tenant before it reaches object storage (RFC 0001,
6), so whoever holds the bucket reads nothing; whoever runs kernoid can. This RFC adds the second promise: **content
that only its owners can read**, for those who choose it.

## 1. The rule

The maintainer decided (2026-10-30):

1. **What adds security and disturbs no other system is always on and has no setting.** Nobody has to know it exists.
2. **What could break the use with other software is a setting** – of the account, the folder or the collection – and
   the tenant's policy may forbid or require it (section 8).

End-to-end encryption breaks things other software relies on: an IMAP client without OpenPGP shows encrypted mail as
an attachment it cannot open, a CalDAV client cannot read an encrypted event, WebDAV shows files nobody can open, and
the server can no longer search, preview or scan what it cannot read. So end-to-end encryption is a setting; all that
merely makes it work (keys, their directory, headers that announce them) is not.

| Always on | Setting |
|---|---|
| Post-quantum key exchange in TLS (2) | End-to-end encrypted mail of an account (5) |
| Content sealed with 256-bit keys (3) | The kind of an account's key: post-quantum or compatible (4.1) |
| Keys made only by clients; secret keys stored only as clients protected them (4.2) | Encrypted folders – vaults (6) |
| Publishing the public keys of accounts that have them: WKD, Autocrypt (4.4) | Encrypted calendars and address books (7) |
| Encrypting mail to recipients whose keys are known, when sent from kernoid's apps (5.3) | Recovery through the tenant (8.2) |

## 2. Post-quantum key exchange in TLS (implemented)

Recorded traffic can be decrypted once a quantum computer breaks today's key exchange ("harvest now, decrypt later").
Every TLS connection kernoid makes or takes – HTTPS, SMTP in and out, IMAP, POP3, LDAP, PostgreSQL, ACME, the
operator's and the terminal app's – prefers the hybrid **X25519MLKEM768** (ML-KEM-768 with X25519, as browsers offer
it) over X25519. Clients without it still connect with X25519; it is a preference, not a requirement, so nothing
breaks. It comes from rustls with AWS-LC and its feature `prefer-post-quantum`; `crates/kernoid-server/tests/tls.rs`
fails if a build loses it.

Signatures stay classic for now: certificates (Web PKI), DKIM, OpenID Connect tokens and SAML have no post-quantum
algorithms their counterparts accept. A signature cannot be forged after the fact by recording it, so they matter
only once quantum computers exist. **OPEN:** ML-DSA in JOSE and X.509 once the standards and their users are there.

## 3. Content at rest

Content is sealed with XChaCha20-Poly1305 under 256-bit tenant keys, which are wrapped by a 256-bit main key with the
same cipher (RFC 0001, 6). Symmetric ciphers with 256-bit keys keep about 128 bits of security against Grover's
algorithm – enough. Nothing changes; end-to-end encrypted content (sections 5–7) is sealed this way as well.

## 4. Keys of accounts

### 4.1 OpenPGP

End-to-end encryption in kernoid is **OpenPGP** ([RFC 9580](https://www.rfc-editor.org/rfc/rfc9580)) with its
post-quantum algorithms ([RFC 9980](https://www.rfc-editor.org/rfc/rfc9980), June 2026). OpenPGP rather than
something of kernoid's own: mail clients understand it (PGP/MIME, [RFC 3156](https://www.rfc-editor.org/rfc/rfc3156)),
people outside kernoid have keys, and "do not invent cryptography" (CLAUDE.md). S/MIME needs certificates from a CA
for every person – **OPEN**, perhaps later as a second way for mail.

There is **one implementation**: [rpgp](https://github.com/rpgp/rpgp) (crate `pgp`, MIT OR Apache-2.0) with its
feature `pqc`. The server uses it for what it does (5.2, 4.4); the apps use it through `apps/e2e` (MIT, section 10),
compiled to WebAssembly for the web app and natively for the terminal app – the same code everywhere. rpgp's ML-KEM
and ML-DSA come from RustCrypto's `ml-kem` 0.2 and `ml-dsa` 0.0.4, which have had no external audit: part of the
audit before 1.0 (whitepaper), like bergshamra. `ml-dsa` 0.0.4 signs in variable time (RUSTSEC-2025-0144, fixed in
0.1, which rpgp 0.21 does not take yet); signing happens only in the user's own client, so nobody can time it on
request – **OPEN** until rpgp moves on. Secret keys of other kinds (RSA, NIST curves, X448) are not taken: their
arithmetic in rpgp's dependencies is not constant-time (RUSTSEC-2023-0071, RUSTSEC-2026-0387).

An account's key is one of two kinds (a setting of the account, chosen when the key is made):

| Kind | Primary key | Encryption subkey | For |
|---|---|---|---|
| `pqc` (default) | v6, ML-DSA-65+Ed25519 | ML-KEM-768+X25519 | kernoid's apps and every program that implements RFC 9980 |
| `compatible` | v4, Ed25519 | X25519 (ECDH, Curve25519) | correspondents whose programs know only v4 keys (GnuPG and many mail clients – **OPEN:** which support RFC 9980 now) |

Both are secure against today's computers; only `pqc` is secure against recorded mail being decrypted later. An
account may make a new key at any time; the old one is **retired** – kept to decrypt what was encrypted to it, never
used to encrypt again.

### 4.2 Who holds the secret key

- Keys are **made by the client** (the web app, the terminal app, later the native apps). The secret key never
  reaches the server unprotected; kernoid has no function that takes one.
- So that the account can use its key on another device, the client stores **protected copies** of the secret key
  on the server – each the OpenPGP secret key protected as RFC 9580 (3.7) defines it (Argon2 with AEAD), each with
  another passphrase:
  - **`passkey:<credential id>`** – the passphrase is the output of the passkey's PRF extension (WebAuthn Level 3) for
    a salt kernoid stores with the copy. Logging in with that passkey unlocks the key; nothing to type.
  - **`recovery`** – a recovery code of 32 random characters the client shows once (as Tuta does). The only way back
    when every passkey is lost.
  - **`device:<id>`** – a passphrase the client keeps on the device (the terminal app's key ring; **OPEN:** the
    platform's key store).
  - **`tenant`** – section 8.2, only if the tenant's policy asks for it.
- A copy is data of the account, not an event (credentials never go into events, CLAUDE.md); the event
  `account.openpgp_key_added` says a key exists, with its fingerprint and kind.
- Without any copy it can unlock, the account can no longer read what was encrypted to it. That is the price;
  the web app says so before it makes the key and asks to keep the recovery code.

### 4.3 Finding the keys of others

JMAP gets an extension, `https://kernoid.dev/jmap/openpgp` (only in the caller's own account), and the account's
settings with its tenant's policy are the singleton `E2eSettings` (`/get`, `/set` of `mail`):

- `OpenPgpKey/get` – the account's own keys: public key, kind, fingerprint, created, retired, and the protected copies.
- `OpenPgpKey/set` – add a key with its copies (made by the client; at least one, every address of the key the
  account's), retire one (`retired: true`), add or remove a copy (`copies/<label>`). Keys are never destroyed. The last
  copy of the key in use stays, and so does the `tenant` copy while the tenant recovers keys.
- `OpenPgpKey/lookup` – the public keys for a list of addresses: local accounts from the directory; others through
  their domain's **Web Key Directory**, which kernoid asks over HTTPS through `kernoid_oidc::outbound` (public
  addresses only). No public key servers: they would learn whom one writes to.

### 4.4 Publishing keys (always on)

- **Web Key Directory** (WKD, [draft-koch-openpgp-webkey-service](https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/);
  **OPEN:** its latest revision): kernoid answers `/.well-known/openpgpkey/…` for the addresses of accounts with a
  key – the direct method on the instance's own domains, the advanced one on `openpgpkey.<domain>` for the tenant's
  mail domains (the DNS check of RFC 0002, 10.5 names the record to add). Unknown addresses and accounts without a
  key get the same `404`.
- **Autocrypt** ([Autocrypt Level 1](https://autocrypt.org/level1.html)): mail an account with a key sends through
  kernoid carries an `Autocrypt:` header with its public key, added by the queue before DKIM signs. Programs that do
  not know it ignore it. **OPEN:** Autocrypt Level 1 names only v4 Curve25519 keys; for `pqc` keys the header waits
  for Autocrypt's next version.

## 5. Mail

### 5.1 The setting

An account switches **end-to-end encrypted mail** on (in the web app; the tenant's policy may forbid or require it,
section 8). It needs a key (section 4). What changes:

| | Off (as before) | On |
|---|---|---|
| Stored mail | sealed with the tenant's key | in addition encrypted to the account's key (5.2) |
| Search on the server | headers and text | addresses and dates; text only in kernoid's apps (5.4) |
| IMAP, POP3 | any client | clients with OpenPGP and the account's secret key |
| Sieve, spam filter, malware scan, invitations | as before | as before – they act on arrival, before 5.2 |

Switching it off encrypts no new mail; what is encrypted stays encrypted (the apps can decrypt and store it again –
**OPEN**).

### 5.2 Encryption on arrival

kernoid sees mail from outside in plain text when it arrives – SMTP is like that. With the setting on, the delivery
(RFC 0002, 9.4) encrypts each message to the account's current key **after** Sieve, the spam filter and the malware
scan and **before** it stores it:

- The message becomes PGP/MIME (RFC 3156): `multipart/encrypted` with the original message inside.
- **Header protection** after [RFC 9788](https://www.rfc-editor.org/rfc/rfc9788): the subject inside, `[...]`
  outside; addresses, date, `Message-ID`, `In-Reply-To` and `References` stay outside, as delivery, threads (RFC
  0002, 5) and sorting need them.
- The **summary** the apps show in lists (subject, preview, whether it has attachments) is encrypted to the same key as
  a small OpenPGP message of its own, so an app need not fetch every message to show the list: the JMAP property
  `kernoid:encryptedSummary` (in `https://kernoid.dev/jmap/openpgp`).
- Mail that arrives already encrypted (PGP/MIME or inline) is stored as it is.
- When the setting is switched on, a worker job encrypts the mail already stored the same way. An email's content
  never changes (RFC 8621, 4), so each is **replaced** – a new email with the same mailboxes, keywords and time of
  receipt, the old one destroyed in the same transaction; IMAP clients see it expunged and new. Drafts stay as their
  program wrote them.
- **Only on arrival over SMTP**, not when a client stores a message (JMAP `Email/set`, `Email/import`, IMAP `APPEND`):
  a client that is not end-to-end aware sends what it stored, and encrypting its draft would send ciphertext to its
  recipients. kernoid's apps encrypt their copies themselves (5.3).
- **OPEN:** an encrypted reply does not join the thread of a plain original (its subject is `[...]` outside), and an
  account too full for both copies at once is not encrypted until it has room.

This protects stored mail against everyone who comes later – a stolen backup, a seized server, an operator who
looks tomorrow. It does not protect against an operator who changes kernoid to copy mail as it arrives; only mail
that the sender encrypted does that (5.3).

### 5.3 Sending

- kernoid's apps **encrypt automatically** when every recipient has a key (4.3), sign what they encrypt, and keep the
  copy in Sent encrypted to the sender's key; drafts are encrypted to it as well. Mail to someone without a key goes as
  it always went, and the app shows that it is not end-to-end encrypted.
- Mail from accounts with a key carries Autocrypt (4.4).
- **OPEN:** mail to people without a key, encrypted with a password through a link (as Tuta and Proton do) – it
  would use the links of RFC 0005, 11.3.

### 5.4 Reading

The apps decrypt in the client: the summary for lists, the message (parsed with mail-parser in `apps/e2e`, the same
parser as the server) for reading. Search over text happens in the app over what it has decrypted; **OPEN:** an
encrypted search index kept by the app.

## 6. Files: vaults

A **vault** is a directory whose content only its members can read – chosen when it is made (a setting of the
directory, not of the account; it cannot be switched later: making a new vault and moving files into it does that).

- A vault has its own OpenPGP key (kind `pqc`), made by the client. Its secret key is stored **encrypted to the key
  of each account that may read the vault** (`file_vault_keys`). Sharing a vault (RFC 0005, 11) with an account means
  a member's app encrypts the vault key to that account's key; until one does, the grant waits. For a group, each
  member gets a copy, and a new member's copy waits for a member's app.
- **Content** is an OpenPGP message encrypted to the vault key, stored in parts like any content (and sealed with the
  tenant's key as well). Versions are encrypted the same way.
- **Names** are encrypted too: the node's `name` is an id the client chooses (`k-<uuid>`, unique among siblings), the
  real name an OpenPGP message in the property `kernoid:encryptedName` – also the vault's own name.
- A vault does not lie in another; nothing moves or is copied into, out of or between vaults – except into the Trash
  and back, which deleting needs. A copy within a vault keeps the encrypted name.
- `required` (8.1) for vaults means nothing new may lie outside one.
- JMAP: `kernoid:vault` (the vault a node lies in, its own id on the root), `kernoid:vaultKey` (the public key, on the
  root), `kernoid:encryptedName`; `kernoid:newVault` (`publicKey`, `sealed` – the secret key wrapped for the creator)
  on a new directory; `VaultKey/get` (`ids`: the caller's wrapped key, or null, and the accounts that have one) and
  `VaultKey/set` (`update` with `members/<account id>`: a wrapped key, or null). Giving a key to another account needs
  the right to share.
- **What it costs:** WebDAV does not show vaults; neither content search nor the malware scan sees inside; links
  (RFC 0005, 11.3) to a file in a vault are to carry the file's session key in the fragment of the URL (`#…`), which
  browsers never send to the server – **OPEN**, as are groups as members (each member's copy needs a member's app),
  a new vault key when a member leaves (what they had, they keep), and files encrypted in pieces (the web app
  encrypts a file in one piece).

## 7. Calendars and address books

A calendar or address book can be made **encrypted** (a setting chosen when it is made, like a vault): its events and
contacts are OpenPGP messages encrypted to the collection's key, which is shared like a vault's key.

- **What it costs:** CalDAV and CardDAV do not show it; the server cannot know when an event takes place, so free/busy
  and queries by time come from the apps; invitations to people outside are sent by the app, decrypted (iMIP has no
  encrypted form most clients read).

## 8. The tenant's policy

### 8.1 Allowed, required, forbidden

For each setting (mail, vaults, encrypted calendars and address books) the tenant decides `allowed` (default),
`required` or `forbidden` – an event `tenant.e2e_policy_set`. `required` for mail means accounts with mail must make a
key at their next login in the web app; until then their mail arrives as before. `forbidden` exists because an
organisation may have to read its mail (archiving duties); it does not touch what is already encrypted.

### 8.2 Recovery through the tenant

A tenant may require that its accounts' secret keys can be recovered by the tenant: the tenant has a **recovery key**
of its own (made by an administrator's app, its secret key never on the server), and each account's app stores one
more protected copy (`tenant`) – the secret key encrypted to the recovery key. An administrator restores an account's
key with the recovery key's secret in their own app. It is off by default; the web app tells each account when its
tenant has it on – then end-to-end means "only you and your organisation".

## 9. Trust in the web app

The web app comes from the server it protects against: an operator could change its code. The strict CSP (RFC 0001,
7.6) keeps others from it; against the operator, only code the user does not load from the server helps – the
terminal app and native apps (section 10). **OPEN:** publishing the hashes of each release's web app so that others
can check what a server delivers.

## 10. The apps

`apps/e2e` (MIT, a Cargo workspace of its own like the terminal app) is the end-to-end layer of kernoid's apps:
keys and their copies, encrypting and decrypting messages, PGP/MIME and parsing mail, vaults – on rpgp. The web app
uses it as WebAssembly (`@kernoid/e2e`), the terminal app as a library, native apps later the same way.

In kernoid's own apps end-to-end encryption needs no setting – they understand it. The settings of this RFC exist for
other software (IMAP, CalDAV, WebDAV clients). **OPEN** (maintainer): bringing native apps forward, where end-to-end
encryption is simply on.

## 11. Open

- Which mail clients read RFC 9980 keys (4.1); Autocrypt for `pqc` keys (4.4).
- S/MIME (4.1); password-protected mail to people without a key (5.3); an encrypted search index (5.4).
- Decrypting again when mail encryption is switched off (5.1).
- Post-quantum signatures in TLS, JOSE, DKIM (2).
- `ml-dsa` 0.1 once rpgp takes it (4.1).
- Published hashes of the web app (9).
