<!-- SPDX-License-Identifier: MIT -->
# kernoid-e2e

End-to-end encryption of [kernoid](https://kernoid.dev)'s apps (kernoid's RFC 0006) – OpenPGP through
[rpgp](https://github.com/rpgp/rpgp), nothing of its own:

- **Keys** (`keys`): an account's OpenPGP key of one of two kinds – `pqc`, a v6 key with ML-DSA-65+Ed25519 and
  ML-KEM-768+X25519 (RFC 9980), or `compatible`, a v4 Curve25519 key for older software – and protected copies of its
  secret key (Argon2 with AES-256-OCB), unlocked with a recovery code or a passkey's PRF.
- **Messages** (`message`): encrypting to several recipients and signing, decrypting and verifying.
- **Mail** (`mime`, `compose`): PGP/MIME with header protection (RFC 9788) and the encrypted summary kernoid's apps
  show in lists; mail built and read in the client.

With the feature `wasm` it builds the `Keyring` of kernoid's web app (wasm-bindgen). The protocol around it – finding
keys, publishing them, the copies kept by the server – is in `kernoid-client`.

MIT – see [LICENSE](LICENSE).
