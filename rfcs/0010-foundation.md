<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0010 – The foundation: spaces, end to end

- **Status:** draft, 2026-11-19; the direction decided by the maintainer the same day (RFC 0008, 1), the mechanism a
  proposal. Implemented with 0.5.0 as section 7 says: the six crates in `kit/`, `kernoid-relay` and the service
  `relay`.
- **Scope:** the crates that end-to-end encrypted data of any program stands on – originals by their hash, a log of
  events per space, keys of the members, storage on a device, sync, and the relay – taken over from aktujo; and how
  kernoid hosts spaces.

## 1. Where it comes from

aktujo built a core of its own for an archive that works offline and end to end (aktujo RFC 0001): originals stored by
their hash on any storage, an event log that merges by union, the keys of a space's members, SQLite on a device, a
relay that sees nothing. spezado's sync and relay went into it. With RFC 0008 that core becomes kernoid's foundation,
so that kernoid, aktujo, notenwart and spezado keep data in one way. The maintainer holds the rights to that code and
takes it over (2026-11-19); the files say where they come from.

It is taken over **as it is at aktujo 0.4.1** – renamed, its licences set as section 2 says, its SQL in kernoid's rules
(section 4). What aktujo has designed since (streams, a tree of keys, erasure, visibility, a server as a node – aktujo
RFCs 0007–0011) comes after 0.5.0, in this repository, when aktujo moves onto it (RFC 0008, 1).

## 2. The crates

| aktujo | kernoid | Licence | What |
|---|---|---|---|
| `aktujo-base` | `kernoid-base` | MIT | canonical encoding (RFC 8785, as far as used), hashes `sha256:…`, identities of spaces, base64url |
| `aktujo-blob` | `kernoid-blob` | MIT | originals by SHA-256: the trait `Blobs`, in memory, in a folder, in object storage (feature `object`) |
| `aktujo-log` | `kernoid-log` | MIT | devices, hybrid logical clocks, events of any kind, the log of a space, merging, the agreed order |
| `aktujo-crypt` | `kernoid-crypt` | MIT | members and their keys from a seed, the chain of space keys, envelopes, signed requests, invitations, recovery codes |
| `aktujo-store` (SQLite) | `kernoid-space-store` | MIT | a device's spaces in SQLite: events, member records, settings, what was sent |
| `aktujo-sync` | `kernoid-replica` | MIT | a device's replica of its spaces: writing, syncing through a relay, invitations, removing members, recovery |
| `aktujo-relay` | `kernoid-relay` | **AGPL** | the relay: member lists and envelopes per space over HTTP, on kernoid's PostgreSQL and object storage |
| `aktujo-store` (PostgreSQL) | – | – | not taken over: a server keeps spaces through `kernoid-relay`; aktujo's own server mode follows aktujo RFC 0011, after 0.5.0 |

The MIT crates are in `kit/` (RFC 0008, 3): the apps of every program built on kernoid use them on the device. The
relay is a server crate.

The labels of key derivation and signatures stay a parameter (`Domain`): kernoid's own labels are `kernoid/…`; a
program passes its own, so that its keys open nothing of another program's. aktujo's labels go with aktujo.

## 3. What a space is

As in aktujo RFC 0001: a **space** is what is shared and encrypted as a whole; its **events** are immutable facts,
identified by their hash, merged by union; its **members** – devices, backends, recovery codes – are an ordered list a
relay keeps; originals are stored by hash, in envelopes. kernoid adds no kinds of events: the kinds are the programs'.

## 4. kernoid as a relay

With the service `relay` (RFC 0008, 4) the role `api` serves the relay protocol – aktujo's, unchanged – below
`/relay/<scheme>/v1/spaces/{space}/…`, `<scheme>` being the program's domain as its signed requests name it
(`kernoid`, `aktujo` …). `relay.domains` says which programs' spaces an installation keeps (`kernoid` by default); a
space is its program's – under another scheme it is not there.

- **Storage:** member lists, envelopes and their order in PostgreSQL – through sqlx's checked macros, in tables of
  kernoid's one history (`relay_spaces`, `relay_records`, `relay_envelopes`, `relay_requests`, migration 0054);
  envelopes larger than 64 KiB through `BlobStore` (sealed with the tenant's key, as all content – a second layer, the
  first is the space's), garbage once their space is removed. One writer per space at a time (`FOR UPDATE`).
- **Who may found a space:** an account of the installation, with its session or an access token of kernoid's apps in
  the header `kernoid-session` (`kernoid_replica::Replica::start_sync_for`) – the space is its tenant's; or anyone, on a
  relay open for a tenant (`relay.open_for_tenant`, for a relay that is all an installation does) – the space is that
  tenant's. A space counts against its tenant: a tenant's spaces together may take at most its **relay quota**
  (`tenant.relay_quota_set`; REST `/v1/relay/quota`, GraphQL `relayQuota`, `kernoid relay quota`); an envelope that
  would exceed it is refused (`413`), what is there stays.
- **Who may write and read:** members, by signed requests – the relay checks signatures against the ordered list, as
  aktujo's does; it never sees a key of a space.
- **Limits:** a request at most 64 MiB (aktujo's limit); larger originals in parts – protocol 2 splits them into parts
  of 16 MiB on the device (`kernoid_replica::streams::PART`).
- **Administration:** a tenant's spaces (identity, program, founder, size, last write) and removing one – REST
  (`/v1/relay/spaces`), GraphQL (`relaySpaces`, `removeRelaySpace`), CLI (`kernoid relay`).

aktujo's own relay in SQLite, for a person who runs one on their computer, stays aktujo's program (aktujo RFC 0004);
kernoid's is the one for servers.

## 5. Files and vaults

Files stay as RFC 0005 says – data in tables, the server reads them, WebDAV and JMAP FileNode on top. This is the
**managed** way of keeping files. Vaults (RFC 0006, 6) were OpenPGP in 0.5.0.

The **end-to-end** way is spaces. Once streams exist (aktujo RFC 0009: a log per folder and document, keys in a tree),
vaults move onto them and kernoid has one end-to-end design for files, documents and everything else: a vault becomes
a space shown as a folder of the file store.

With streams in place ([0012](0012-streams.md)), the maintainer gave the go ahead on 2026-11-19 ("Yes, start"). The
move, as built so far:

1. **A vault is a space of protocol 2 at the account's kernoid** (`kernoid_client::e2e::Vaults`). Its root directory
   is the space stream; every directory and file is a stream linked below its directory. A directory's events name what
   lies in it (`entry`: stream, name, directory or file, in the vault's trash or not; `gone`), the space stream also the
   vault's name (`vault`); a file's events are its versions (`version`: the parts of its original, size, type, time);
   contents are originals in parts of 16 MiB. Moving links the stream below its new directory and leaves the old one.
   Removing for good purges the streams where the device may (`purge`).
2. **The file store keeps only the vault's directory**, naming the space (`kernoid:space`, migration 0058); it holds
   nothing, its name is an id, and the server checks that the space is one the creator founded at this relay. When the
   directory is destroyed, the worker removes the space (`relay_space_removals`). The relay is on wherever files are
   unless `[services] relay` says otherwise; the JMAP session names it (`https://kernoid.dev/jmap/space-vaults`,
   `relayUrl`).
3. **Members are accounts.** Each is a person of the space named by the account's id. Making a vault and sharing it
   give the account a recovery code of its person (`Streams::add_person`), encrypted to the account's OpenPGP key and
   kept by the server where the OpenPGP vault's wrapped key was (`VaultKey/set`, `file_vault_keys`); every device of the
   account comes in with it (`Vaults::enter`, `Streams::recover`). Whoever added a person knew its code, as whoever
   wrapped an OpenPGP vault's key knew that key. Ending a membership removes the person – what is written afterwards
   is out of its reach – and its code.
4. **Existing OpenPGP vaults** are copied into a new vault beside them by a member's app (`Vaults::move_vault`: name,
   directories, files, members); the OpenPGP vault stays until whoever moved it checked the copy and removes it. The
   server keeps taking OpenPGP vaults until every client moved.

**OPEN:** `kernoid-sync`, the apps (through the bridge), the terminal app and the web app – the web app needs streams in
the browser (`kernoid-crypt` built for WebAssembly as `kernoid-e2e` is, requests and a store in TypeScript on
IndexedDB); making a vault needs a login by token (the relay takes no app passwords); members' permissions follow the
grant only when they are made (`members` for everyone shared with), not when it changes; groups as members.

## 6. Post-quantum

aktujo's keys are classical (Ed25519, X25519 through HPKE); kernoid's rule is to prefer post-quantum where it disturbs
nothing (RFC 0006, 1). The format of today's spaces stays as it is; the tree of keys of aktujo RFC 0009 is built on
**hybrid keys** – one change of the format rather than two. They are in `kernoid_crypt::pq` (implemented in 0.5.0):

- **Receiving:** X-Wing (draft-connolly-cfrg-xwing-kem-11) – ML-KEM-768 and X25519, combined with SHA3-256 –, a key of
  32 bytes, public 1216, ciphertext 1120. Sealing to it is a KEM–DEM: HKDF-SHA256 over X-Wing's secret, bound to the
  ciphertext, the receiving key and a context the caller names (a stream and a generation), then XChaCha20-Poly1305.
- **Signing:** Ed25519 and ML-DSA-65 (FIPS 204, deterministic, the domain's label as context) over the same message,
  prefixed with a label of the construction and the domain; a signature holds only when both do. Public 1984 bytes,
  signature 3373.
- **From one seed:** both pairs are derived with HKDF-SHA256 and a label per half, so that a recovery code still gives
  back every key.

X-Wing is put together from ml-kem 0.2 and x25519-dalek rather than taken from the HPKE library: that one needs ml-kem
0.3, which rpgp 0.21 (kernoid-e2e) does not accept beside its own (they share the crate `kem`). It is checked against
the draft's three test vectors; the bytes do not change when the library's X-Wing replaces it (OPEN: with rpgp's next
version). ML-DSA is ml-dsa 0.1, which signs in constant time – the server signs as a node of a space (aktujo RFC 0009,
5), on request. **OPEN:** a review of `pq` by someone besides its author, before a space depends on it.

## 7. 0.5.0

1. The six MIT crates in `kit/`, with aktujo's tests; two devices found a space, write offline, sync through
   `kernoid-relay`, add and remove a member, recover – against a real kernoid (`kit/replica/tests/server.rs`, run by
   `scripts/client-check.sh`).
2. `kernoid-relay` with section 4, the role and service `relay`, its administration, and the replica's tests against a
   real kernoid in CI.
3. Published on crates.io with the rest of the kit.

## 8. Open

- Streams, with what the foundation gives erasure and visibility – purging a stream, removing a person, streams shown to
  one person, links and their generations –, are [0012](0012-streams.md) (implemented in 0.5.0). Locks, roles and the
  other permissions of aktujo RFCs 0007–0009 are a program's data in its streams, checked at a record's `at`.
- **OPEN:** vaults on spaces (section 5) – with streams.
- **OPEN:** a space's events read by the server for an account that allows it (a node with keys, aktujo RFC 0009) –
  with aktujo's server mode.
