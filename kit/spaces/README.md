<!-- SPDX-License-Identifier: MIT -->
# kernoid-spaces

A device's end-to-end encrypted spaces: their store in SQLite (`store`; SQLCipher with the feature `sqlcipher`) –
events, member records and rosters, streams with their keys, settings, what was sent – and their synchronisation
through a relay – kernoid's (`kernoid-relay`, the service `relay`): founding, invitations, recovery, members, streams
with generations of keys (`streams`), and protocol 1 (`Replica`). Until 0.5.0 the crates `kernoid-replica` and
`kernoid-space-store`.

Part of kernoid's foundation ([RFC 0010](https://github.com/kernoid/kernoid/blob/main/rfcs/0010-foundation.md)) –
end-to-end encrypted spaces, which kernoid, aktujo, notenwart and spezado keep data in. Taken over from aktujo's core
(aktujo 0.4.1). In kernoid's kit: MIT ([LICENSE](LICENSE)), so that apps under any licence may use it; kernoid's
server is AGPL-3.0.
