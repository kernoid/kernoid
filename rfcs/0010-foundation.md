<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0010 – The foundation: spaces, end to end

- **Status:** draft, 2026-11-19; the direction decided by the maintainer the same day (RFC 0008, 1), the mechanism a
  proposal. Implemented with 0.5.0 as far as section 7 says.
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

The role **`relay`** of the service `relay` (RFC 0008, 4) serves the relay protocol at `/relay/v1/…`:

- **Storage:** member lists, envelopes and their order in PostgreSQL – through sqlx's checked macros, in tables of
  kernoid's one history (`relay_spaces`, `relay_members`, `relay_envelopes`); originals and envelopes larger than
  64 KiB through `BlobStore` (sealed with the tenant's key, as all content – a second layer, the first is the space's).
- **Who may found a space:** an account of a tenant with the service `relay`, logged in with a bearer token or a
  session (`relay.open = false`, the default); or anyone (`relay.open = true`, for a relay that is all an installation
  does – then spaces belong to the instance). A space counts against the quota of whoever founded it (OPEN: quotas of
  the relay, section 8).
- **Who may write and read:** members, by signed requests – the relay checks signatures against the ordered list, as
  aktujo's does; it never sees a key of a space.
- **Limits:** a request at most 64 MiB (aktujo's limit); larger originals in parts (OPEN, aktujo RFC 0001).
- **Administration:** a tenant's spaces (identity, founder, size, last write) and removing one – REST, GraphQL, CLI.

## 5. Files and vaults

Files stay as RFC 0005 says – data in tables, the server reads them, WebDAV and JMAP FileNode on top. This is the
**managed** way of keeping files. Vaults (RFC 0006, 6) stay OpenPGP in 0.5.0.

The **end-to-end** way is spaces. Once streams exist (aktujo RFC 0009: a log per folder and document, keys in a tree),
vaults move onto them and kernoid has one end-to-end design for files, documents and everything else: a vault becomes
a space shown as a folder of the file store. Until then, a vault and a space are two things – OPEN, to be closed in
the step after 0.5.0.

## 6. Post-quantum

aktujo's keys are classical (Ed25519, X25519 through HPKE); kernoid's rule is to prefer post-quantum where it disturbs
nothing (RFC 0006, 1). **OPEN:** hybrid keys (ML-KEM-768 with X25519, ML-DSA-65 with Ed25519) for spaces, decided with
the tree of keys of aktujo RFC 0009 – one change of the format rather than two.

## 7. 0.5.0

1. The six MIT crates in `kit/`, with aktujo's tests (two devices found a space, write offline, sync through a relay,
   add and remove a member, recover – against the relay in memory and against `kernoid-relay`).
2. `kernoid-relay` with section 4, the role and service `relay`, its administration, and the replica's tests against a
   real kernoid in CI.
3. Published on crates.io with the rest of the kit.

## 8. Open

- **OPEN:** quotas and limits of the relay per tenant and per space.
- **OPEN:** streams, erasure and visibility (aktujo RFCs 0007–0009) – after 0.5.0.
- **OPEN:** vaults on spaces (section 5) and post-quantum keys (section 6) – with streams.
- **OPEN:** a space's events read by the server for an account that allows it (a node with keys, aktujo RFC 0009) –
  with aktujo's server mode.
