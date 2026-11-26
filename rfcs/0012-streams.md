<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# RFC 0012 – Streams in the foundation

- **Status:** accepted by the maintainer on 2026-11-19 ("Alles umsetzen"), implemented in 0.5.1 – `kernoid_crypt::stream`,
  the relay's protocol 2 (`kernoid-relay`, migration 0057), `kernoid_spaces::store::streams` and
  `kernoid_spaces::streams`, checked end to end against kernoid (`kit/spaces/tests/streams.rs`). The direction is
  aktujo RFC 0009; this RFC is the mechanism. Building it settled three points, marked *(settled while building)*
  below. Changes [0010](0010-foundation.md), sections 3, 4 and 6.
- **Scope:** what is generic about streams – identities, keys and their tree, records, tokens, the relay, removing a
  device, a server as a node. What a program keeps in its streams – documents, folders, branches, locks, purges, guest
  links, the names of roles (aktujo RFCs 0007, 0008) – stays the program's.

## 1. Why a mechanism of its own

aktujo RFC 0009 says what streams do; it leaves open how bytes look, which keys seal what, how the relay checks a
reader it never knows, and what "due" means on a device. Every program on the foundation – aktujo, notenwart, spezado,
kernoid's vaults – would depend on those answers, and they are cryptography: kernoid's rule is that such a change gets a
review before code (`CLAUDE.md`, Rules). This RFC is what is reviewed.

## 2. Keys

| Key | What | Made from |
|---|---|---|
| **device** | signs what the device writes, receives what is sealed to it | `pq::HybridKeys` of the device's seed ([0010](0010-foundation.md), 6) |
| **person** | receives links to what is shown to the person | `pq::HybridKeys` of the person's seed; the seed is sealed to each device of the person |
| **stream** | seals the records of one stream, one key per **generation** | 32 random bytes |
| **recovery** | gives back a person's seed | a recovery code, as today, now deriving `HybridKeys` |

Everything new is hybrid (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519); nothing of 0.4's classical member keys is kept
(aktujo RFC 0009, decision 6).

## 3. Streams and records

A **stream** has an identity `s-` and 26 characters of `a-z0-9` (random, 130 bits) and a chain of generations. A
**record** of a stream is:

```text
record = {
  stream, generation,           // which stream, sealed under which generation's key
  author,                       // the device: SHA-256 of its hybrid verifying key
  at,                           // the position in the space stream the author had seen (rights are checked there)
  previous,                     // hash of the author's previous record in this stream (a chain per device and stream)
  clock,                        // the device's hybrid logical clock – one across all of its streams
  nonce, ciphertext,            // XChaCha20-Poly1305 under the generation's key; the payload is the program's event
  signature                     // pq hybrid signature of the canonical encoding of everything above (RFC 8785)
}
```

The associated data of the encryption is the canonical encoding of `stream`, `generation`, `author`, `at`, `previous`
and `clock`, so that a ciphertext moved into another record does not open. A record is identified by the SHA-256 of
its canonical encoding, as events are today ([0010](0010-foundation.md), 3); merging stays union.

**Generations.** A stream's first generation is made with it. A new one is a record of kind `generation` in the
stream, written under the **new** key, holding the previous key sealed with the new one – so that whoever gets the
newest key reads back to the beginning, as space keys chain today.

**Roster.** The member list of protocol 2 is the **roster** (section 7). Besides devices and persons it carries what a
device needs before it can read any stream *(settled while building)*: each person's key per generation – its seed
sealed to each of the person's devices, the seed before chained to it – and the links of the space stream to every
person. A device's own person stream could not hold them: its key comes from the person's seed.

## 4. The tree of keys

A **link** gives a stream's key to whoever can open something above it:

```text
link = { stream, generation, sealed }   // a record in the stream above
```

- To a **stream** above (a folder for a document in it): `sealed` is XChaCha20-Poly1305 under that stream's current
  key, associated data `link`, the stream and the generation.
- To a **person** (a document shown to them; the space stream to every person): `sealed` is `pq::seal` to the person's
  receiving key, context the same.
- A **person stream** has a derived identity (`StreamId::of_person`: SHA-256 of the domain, the space and the person)
  so that any device can find it, and a key per generation of the person's key (`StreamKey::of_person`). It is an
  **inbox** *(settled while building)*: a device with `write` appends records of kind `sealed` to it **without** its
  write token – a link sealed to the person, which only the person opens; everything else there needs the token, and
  reading always does.

A device starts at its person stream, opens the links there and follows them down; it knows every stream it may read
and no other ([aktujo RFC 0009](https://github.com/aktujo/aktujo/blob/main/docs/rfc/0009-streams.md), 2). Which links a
program writes – into folders, persons, groups – is the program's.

## 5. Tokens: reading without the relay knowing readers

For each generation of a stream, two tokens are derived from its key:

```text
read  = HKDF-SHA256(stream key, info = "<domain label> stream read "  || stream || generation)
write = HKDF-SHA256(stream key, info = "<domain label> stream write " || stream || generation)
```

The relay keeps only `SHA-256(token)`. Whoever makes a stream or a generation registers both hashes. A request to read
a stream carries a read token of one of its generations; a request to write carries the write token **and** is signed
by a device that is a member with `write` at the relay's head of the member list. Both also need the device to be a
member now (section 7): the relay checks the request's signature against the member list, as it does today.

A reader with an old generation's token reads the stream's records **up to** the next generation and the `generation`
record that follows, which it cannot open without the new key – it learns that there is a newer one, nothing more.

## 6. The relay

Beside today's `/relay/<scheme>/v1/spaces/…`, a protocol `v2` below `/relay/<scheme>/v2/spaces/{space}/`:

| Request | What |
|---|---|
| `GET members?after=` / `POST members` | the member list, ordered by the relay, as today – now with hybrid keys (section 7) |
| `PUT streams/{stream}` | makes a stream with its first generation's token hashes (write signature) |
| `POST streams/{stream}/generations` | adds a generation's token hashes (write token of the previous generation, write signature) |
| `POST streams/{stream}/records` | appends records (write token, write signature); the relay gives each a position |
| `GET streams/{stream}/records?after=` | records after a position (read token) |
| `POST follow` | for a list of `{stream, position, read token}`: what is new, and which streams said `changed` |
| `PUT`/`GET streams/{stream}/originals/{hash}` | originals of a stream, by their hash (write / read token) |
| `DELETE streams/{stream}` | removes a stream with its originals (a member with `purge`, write token) |

The relay learns identities, sizes and times of streams and who follows which together – not what is in them (aktujo
RFC 0009, 3). Storage, quotas and limits stay as [0010](0010-foundation.md), 4 says, in new tables of kernoid's one
history (`relay_streams`, `relay_generations`, `relay_stream_records`, `relay_stream_originals`).

## 7. Members, persons and rights

The **member list** stays the one strictly ordered list a relay reads – the only thing it reads. Its records are
signed hybrid and name:

- **devices** – verifying and receiving key, their person, and the permissions the relay enforces: `write`, `members`,
  `purge`, besides being a member at all (reading) – a device without `write` still makes its own person's stream and
  its generations *(settled while building)*, which every device of the person needs;
- **persons** – an identity (`p-` and 26 characters) and their receiving key;
- **servers** – a device marked `server` (aktujo RFC 0009, 5): every member sees that the server's operator can read
  everything.

**Who writes what of a person** (settled 2026-11-26, section 11): a person's key – a new generation, or seals of
the current one for new devices – comes from a device of that person, from the device that adds the person in the
same record, or, after removing one of the person's devices, from a device with `members`. Seals and links of the space
stream are written once and never replaced; a link names the person's current key, and a link of the current
generation goes only to a person added in the same record. The relay lets only a person's own devices make the
person's stream, the only stream that is an inbox.

Roles and the other permissions of aktujo RFC 0009, 6 (`roles`, `groups`, `share`, `link`, `lock`, `unlock`) are data
of the space stream, checked by the devices at a record's `at` – the relay cannot see them. A program defines its
permissions and roles; the foundation knows the four the relay enforces.

## 8. Removing a device or a person

1. A record of the member list removes the device: the relay serves it **nothing more** at once – no stream, no
   original, sealed or not (its signatures no longer verify against the list).
2. Its person gets a new seed, sealed to the person's other devices (a new generation of the person's key in the
   roster). The person's own device chains the seed before to it; a device of another person with `members` cannot
   *(settled while building)* – the person's devices then keep the keys they had learned, and links sealed to the old
   generation are read by devices that already read them, not by devices added later.
3. Every device of the space marks **due** each stream the removed device could open – those it reached from that
   person stream. A device knows them: it follows the same links.
4. The first device that writes into a due stream first makes a new generation, writes the links for the stream's
   current audience, and then writes. Nothing new is ever written under a key the removed device knows. A stream nobody
   writes to again keeps its key – what is in it, the device had already.

A person is removed the same way, without step 2.

## 9. On a device

`kernoid_spaces::store` keeps the roster, streams, their keys, parents, records, events, positions and the due marks in
SQLite (schema version 2, `kernoid_spaces::store::streams`); `kernoid_spaces::streams::Streams` founds a space with a
recovery code, invites devices of the inviting person and new persons, follows the streams a device can open, writes
into one (making a generation first when it is due, and the generation of a stream above when that is due too), makes
streams below a stream or for a person, shares a stream with a person, keeps originals in parts of 16 MiB, removes
devices and persons, recovers, and purges. Protocol 1 (`Replica`) stays beside it until every program has moved.

## 10. What changes for 0.4's spaces

Nothing is kept compatible (aktujo RFC 0009, decision 6): `v1` and today's format stay until every program has moved,
then go. kernoid's own vaults move onto `v2` with [0010](0010-foundation.md), 5.

## 11. Open

- **OPEN:** a review of sections 3 to 5, `kernoid_crypt::stream` and `kernoid_crypt::pq` by someone who reviews
  cryptography, besides their author. A first reading by a separate model (2026-11-26) – no replacement for it –
  found X-Wing (draft-11, its three vectors), the KEM–DEM, the hybrid signatures and the separation of keys sound,
  and led to these changes:
  - **The roster checks who writes a person's key** (section 7): a device of that person, the device adding the
    person in the same record, or – after removing one of the person's devices – a device with `members`. Before,
    any device could rotate another person's key to a seed of its own and read what was sealed to that person.
  - **Seals and links of the space stream are never replaced**, and a link names the person's current key. A link
    of the current generation goes only to a person added in the same record. Before, any device could replace
    another person's link and lock that person out of the space stream.
  - A device opens a person's seed only if its receiving key is the one the roster published.
  - **The relay lets only a person's own devices make the person's stream**, and only that stream is an inbox.
    Before, any device with `write` could make another person's inbox first and hold its tokens.
  - A device's receiving key must have the right length; printing a short key no longer panics.

  **OPEN** for the review, from the same reading:
  - A device with `members` that removes another person's device makes that person's next seed itself and so knows
    it (section 8). That is part of trusting `members`. Should the person's own device re-key after such a rotation?
  - Request signatures cover the method, the path and the time (±300 s), not the body or the token headers. A header
    seen by a proxy can be replayed for five minutes with another body. The fix needs a new version of the request
    signature.
  - The write token comes from the stream key like the read token (section 5): whoever reads a stream can compute
    its write token, and only the device's `write` stands between them. Finer rights are the devices' check of `at`.
  - The code and this text differ in details: `StreamRecord` has no `previous` or `clock`; a record's id hashes the
    nonce and ciphertext; an id carries 128 bits; the link context leaves out the space.
  - Secrets are not zeroized (stream keys, seeds, X25519 and ML-KEM keys; ml-kem's `zeroize` is off).
  - The stream key is both the AEAD key and the input of the tokens; signatures of roster records, stream records and
    requests are told apart by their encoding alone, not by a label.
  - The relay builds the roster again for every request and checks every signature, which costs O(n²) as the roster
    grows.
  - Whether ml-kem 0.2's `EncapsulationKey::from_bytes` reduces coefficients modulo q, so that the check in `pq`
    really is FIPS 203's. Whether a person's inbox gets a new generation when the person's key rotates.
- Settled for kernoid's vaults ([0010](0010-foundation.md), 5, 9): their store is kept sealed under a key of the
  system's key store. **OPEN** for the foundation's other programs: keys of streams and seeds are kept in the store on
  the device, not yet in the key store of the operating
  system (as for protocol 1).
- **OPEN:** whether the relay's `follow` hides which streams a device asks for together (it does not, by decision 5 of
  aktujo RFC 0009).
- **OPEN:** following tens of thousands of streams, and new generations in large groups – to be measured (aktujo RFC
  0009, Open).
