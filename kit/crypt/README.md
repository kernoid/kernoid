<!-- SPDX-License-Identifier: MIT -->
# kernoid-crypt

End-to-end encryption of a space: members and their keys from a seed, the chain of space keys, the ordered member list, envelopes, signed requests to a relay, invitations, recovery codes. The labels of key derivation are a `Domain`: kernoid's own is `Domain::KERNOID`; a program passes its own, so that its keys open nothing of another program's.

Part of kernoid's foundation ([RFC 0010](https://github.com/kernoid/kernoid/blob/main/rfcs/0010-foundation.md)) –
end-to-end encrypted spaces, which kernoid, aktujo, notenwart and spezado keep data in. Taken over from aktujo's core
(aktujo 0.4.1). In kernoid's kit: MIT ([LICENSE](LICENSE)), so that apps under any licence may use it; kernoid's
server is AGPL-3.0.
