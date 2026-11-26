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
  space, stream, generation,    // which stream, sealed under which generation's key
  author,                       // the device: SHA-256 of its hybrid verifying key
  at,                           // the position in the roster the author had seen (rights are checked there)
  kind,                         // event, generation, link or sealed
  previous,                     // identity of the author's previous record in this stream (a chain per device and stream)
  nonce, ciphertext,            // XChaCha20-Poly1305 under a key derived from the generation's key
  id,                           // SHA-256 of the header above, the nonce and the ciphertext
  signature                     // pq hybrid signature of the canonical encoding of everything above (RFC 8785)
}
```

The associated data of the encryption is the canonical encoding of the header – `space`, `stream`, `generation`,
`author`, `at`, `kind` and `previous` –, so that a ciphertext moved into another record does not open. The payload of
an `event` is the program's event, which carries its device's hybrid logical clock, its position in the device's chain
of events and the hash of the event before ([0010](0010-foundation.md), 3); merging stays union. A reader that is
handed a record whose `previous` is not the last record it saw of that device counts it
(`StreamsReport::missing`): the relay left one out, or changed their order.

**A key is used for one thing.** The key of a generation seals nothing itself: the key that seals
(`HKDF(key, "kernoid stream seal v1")`) and the two tokens (section 5) are derived from it.

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
  receiving key, context the same – with the space, so that a link is of one space.
- A **person stream** has a derived identity (`StreamId::of_person`: SHA-256 of the domain, the space and the person)
  so that any device can find it, and a key per generation of the person's key (`StreamKey::of_person`). **The roster
  makes it** *(settled 2026-11-26)*: each generation of a person's key names the hashes of the stream's tokens
  (`PersonKey::inbox_read`, `inbox_write`), and the relay makes the stream and its generations from them as it takes
  the record – no device makes or removes a person's stream, and none can be there first. It is an **inbox**
  *(settled while building)*: a device with `write` appends records of kind `sealed` to it **without** its write
  token – a link sealed to the person, which only the person opens; everything else there needs the token, and
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
a stream carries a read token of one of its generations; a request to write – a record, an original, the stream's
removal – carries the write token of its **latest** generation **and** is signed by a device that is a member with
`write` at the relay's head of the member list, and a record is of that generation: the key of a generation before is
one somebody was to lose (section 8), and writes nothing more. Both also need the device to be a member now (section
7): the relay checks the request's signature against the member list.

**A request's signature** (`<scheme>-pq2`, since 0.7.0) is over the method, the path with its query, the time (±300 s)
and the SHA-256 of the body, of the read token and of the write token – so that what a proxy sees of a request serves
no other one. The first form (`-pq`: method, path and time alone) is no longer taken.

**The space stream is the roster's.** Its generations are records of the roster (section 3), each naming the hash of
its read token (`SpaceLinks::read`). The relay takes a generation's token hashes from the device that made it there,
under that read hash, with no write token: a generation whose links open for nobody (section 7) must not be the last
one. Devices take the space stream's keys from the roster alone, and only a key whose read token has the hash named –
so whoever makes a generation cannot give different persons different keys.

**Who reads a stream can write it**, if its device has `write`: the write token comes from the stream's key like the
read token. That is meant *(settled 2026-11-26)*: the relay's rights are per device (`write`), finer ones – who may
change what in a stream – are the program's, checked by the devices at a record's `at` (section 7). A stream that
some may only read is two streams to the foundation: one they are linked to, and one they are not.

A reader with an old generation's token reads the stream's records **up to** the next generation and the `generation`
record that follows, which it cannot open without the new key – it learns that there is a newer one, nothing more.

## 6. The relay

Beside today's `/relay/<scheme>/v1/spaces/…`, a protocol `v2` below `/relay/<scheme>/v2/spaces/{space}/`:

| Request | What |
|---|---|
| `GET roster?after=` / `POST roster` | the member list, ordered by the relay – read by the space's devices and by a device that asked to join, no one else (section 7) |
| `PUT streams/{stream}` | makes a stream with its first generation's token hashes (write signature); not a person's stream – the roster makes those |
| `POST streams/{stream}/generations` | adds a generation's token hashes (write token of the previous generation, write signature; the space stream's: by who made the generation in the roster) |
| `POST streams/{stream}/records` | appends a record (write token, write signature); the relay gives it a position and answers with it |
| `GET streams/{stream}/records?after=` | records after a position (read token) |
| `POST follow` | for a list of `{stream, position, read token}`: what is new, and which streams said `changed` |
| `PUT`/`GET streams/{stream}/originals/{hash}` | originals of a stream, by their hash (write / read token) |
| `DELETE streams/{stream}` | removes a stream with its originals (a member with `purge`, write token); not the space stream or a person's |

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
  what the server is shown. A device says so of itself (`Streams::as_server`, which a server's node sets); the mark
  asks for less trust, so anyone may carry it, and nothing can make a server that hides it show it – whoever adds a
  device knows whose it is.

**Who writes what of a person** (settled 2026-11-26, section 11): a person's key – a new generation, or seals of
the current one for new devices – comes from a device of that person, from the device that adds the person in the
same record, or, after removing one of the person's devices, from a device with `members`. Seals and links of the space
stream are written once and never replaced; a link names the person's current key, and a link of the current
generation goes only to a person added in the same record. The relay lets only a person's own devices make the
person's stream, the only stream that is an inbox.

**What a device takes** (settled 2026-11-26, section 11). The relay and the other devices of a space are not trusted to
mean well; a device checks what it is handed before it keeps it:

- **A roster** begins with the record this device knows the space by: an invitation carries the hash of record 0
  (`…#streams=<space>.<secret>.<p|d>.<hash>`), a recovery code's device carries the code's proof of it
  (`recovery_proof`: HMAC-SHA256, keyed from the code's seed, over the space and that hash), a device that founded or
  joined keeps it. A relay that makes a roster up – its own founder, the invited device taken in – is found out.
- **An invited device gets `write`**, whatever its request asks for; a request the roster's rules refuse is passed
  over. A person who asked to join checks that the roster gives the person the key its device made.
- **A record** is its author's as the roster was at the position it names (`at`): a member then, with `write`, under
  the device name it had then. A record of a generation that had ended in the relay's order is not taken.
- **A link's key** is taken only when the stream vouches for it: a newer generation of a stream the device reads
  must lead back, through the stream's generation records, to the key it holds – only who held that key could have
  made them; a stream it does not read yet must be one the relay keeps under that key's read token. A link names
  neither the space stream nor a person's stream. Any device with `write` seals a link into anyone's stream; without
  this check it could hand a person a key of its own for a stream the person reads.
- **What does not open is passed over** and counted (`StreamsReport::refused`): a record, a link, a seal or a chain
  written to do harm costs itself, never the synchronisation. Keys of persons and of the space stream are read link
  by link and seal by seal; a generation of the space stream may chain to an older one than the one before
  (`previous_generation`), so that the device that follows a broken generation makes one that reads back past it.
- **Who names a group's members is one of them** (below): an audience written by someone not in the audience before
  it is not taken.

**Groups** (aktujo RFC 0012, 8, item 7; implemented 2026-11-26) are streams of the foundation: a group is a stream
whose key is sealed into its members' person streams, and which names them in an event of kind `kernoid_audience`
(`{"kind": "kernoid_audience", "persons": [...]}`) – inside the stream, so encrypted and signed like every event, and
read by every device that opens the group. What is shown to a group is linked below it; whoever opens the group opens
it. A person's links into a stream are sealed into that person's stream, which only the person reads – so a device
renewing a stream knows only the persons it linked itself; with an audience it links every person the newest audience
names instead. Taking a person out writes the audience without the person and renews the group; every device that
reads the new audience forgets the person as a target and marks the streams below the group due, so that the next
write gives each a new generation the person cannot open – it compares the audience before and after the records
it read, so that also a device that never linked the person renews. Taken in again, a person reads on, also what was
written while out: a device takes the keys of older generations from the generation records of newer ones it holds,
before it reads. No record kind is new and the relay sees nothing of it.
`kernoid-spaces`: `new_group`, `show_to_group`, `add_to_group`, `remove_from_group`, `audience`. Kinds beginning with
`kernoid_` are the foundation's; who may change a group (aktujo's `groups`) is the program's, checked at `at`.

Roles and the other permissions of aktujo RFC 0009, 6 (`roles`, `groups`, `share`, `link`, `lock`, `unlock`) are data
of the space stream, checked by the devices at a record's `at` – the relay cannot see them. A program defines its
permissions and roles; the foundation knows the four the relay enforces.

## 8. Removing a device or a person

1. A record of the member list removes the device: the relay serves it **nothing more** at once – no stream, no
   original, sealed or not (its signatures no longer verify against the list).
2. Its person gets a new seed, sealed to the person's other devices (a new generation of the person's key in the
   roster). The person's own device chains the seed before to it; a device of another person with `members` cannot
   *(settled while building)* and may not pretend to – the person's devices then keep the keys they had learned, and
   links sealed to the old generation are read by devices that already read them, not by devices added later. That
   device knows the new seed: the first device of the person that reads the roster moves the person on to a seed of
   its own, chained to that one *(settled 2026-11-26)*.
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

  A second reading (2026-11-26, as an outside reviewer would: the code as an attacker with `write`, an invitation or
  the relay has it; again no replacement for the review) found `pq` sound – X-Wing as the draft has it, and ml-kem
  0.2.3 reduces a key's coefficients modulo q as it decodes, so the check in `pq` is FIPS 203's – and the weaknesses
  around `stream`, in how the roster's rules, `kernoid-spaces` and the relay use it. Changed since (section 7, "What a
  device takes"; sections 5 and 8):
  - **Joining and recovering had no anchor**: a relay could hand a new device a roster of its own making and read
    what the device wrote. Invitations name record 0; recovery codes prove it.
  - **An invited person chose its own permissions** (`members`, `purge`): the inviting device signed the device of
    the request as it came.
  - **A link was taken as its writer said**, the first one for a generation kept: any device with `write` could lock
    a person out of any stream by sealing a key of its own into the person's stream – or, with the relay's help, have
    the person write under that key.
  - **One record that did not open stopped a device's synchronisation for good** – an event sealed with another
    key, a link with a key of the wrong length, an audience naming no person.
  - **A generation of the space stream with links or a chain of bytes that open nothing** – any device with `write`
    could write one – left nobody with any key of the space stream, for good; the same for a person's key with a
    chain that did not open.
  - **A write token of an older generation still wrote**: a person taken out of a group, or a device not yet
    removed everywhere, went on writing – also an audience naming itself.
  - **Records were checked against a device as it was last added**, at no position: `at` and `write` are checked now.
  - **Requests were signed without their body and tokens**, and the roster was handed to anyone who knew a space's
    identity, with the names of its persons and devices.
  - Removing several devices in one record (`Streams::remove_devices`) and naming the devices a device added
    (`Roster::added_by`): a device adds devices of its own person without anyone's leave, so one that fell into other
    hands may have added others first.

  With them, for 0.7.0 (2026-11-26, "nothing needs to stay compatible"): a record names its author's record before
  it and its identity covers its header (section 3); the key that seals is derived from the stream's key, apart
  from the tokens; a link's context names the space; a generation of the space stream names its read token's hash
  (section 5); persons' streams are made by the roster (section 4); the roster is read by the space's devices alone;
  seeds, stream keys and shared secrets are wiped when dropped (`zeroize`, ml-kem's too); the relay keeps the rosters
  it checked and reads only what was added; a server's node marks its devices; recovery codes without a proof and
  the first form of the request's signature are gone.

  **OPEN** for the review:
  - A device adds devices of its own person without `members`: whoever removes a device must look at what it added
    (`Roster::added_by`, `Streams::remove_devices`) – no rule does it, because a phone that added a laptop is the
    usual case. Should a device added by one without `members` need a second word?
  - A removed device that kept a stream's key can still, with the relay's help, have records taken that name a
    position at which it was a member: nothing orders records and the roster against each other but the relay.
    A relay can also withhold the end of a stream, or of the roster – a device sees what is missing in between
    (`previous`), not what never came.
  - Whoever writes a stream can make a generation of it whose key nobody else gets: the stream is then read up to
    there and written no more. For the space stream the next writer makes a generation past it; for other streams
    the program makes a new stream.
  - XChaCha20-Poly1305 does not commit to its key. A stream's key is checked against the relay's token hash (the
    roster's, for the space stream), so two keys for one generation need the relay's help – then one ciphertext
    could open to two texts.
  - A seed handed out of `kernoid_crypt` (`HybridKeys::seed`, `Roster::person_seeds`) is a plain array: its holder
    wipes it, or does not. Keys in the store on the device are another question (below).
  - `Device::server` is what a device says of itself (section 7).
  - Groups (section 7) came after that reading: the audience is the newest event of its kind in the log's order, so
    two devices changing a group at once end with one of them; a device that reads a stream below a group but not
    the group itself does not learn that someone left it, and does not renew before it writes.
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
