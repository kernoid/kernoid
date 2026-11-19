<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# kernoid-auth

Logging in with [kernoid](https://kernoid.dev) – or any OpenID provider – for the server of another program
(kernoid's RFC 0009). The program is a relying party of OpenID Connect:

- **Login** with the authorization code flow and PKCE, the ID token checked against the provider's keys
  (`relying::RelyingParty`).
- **Who logged in** as a `Principal`: the subject, and with kernoid its tenant (`urn:kernoid:tenant`) and its roles in
  the program's project (`urn:kernoid:project:roles`); another provider's roles through a claim the program names.
- **Sessions** of the program's own behind a trait (`sessions::Sessions`; `MemorySessions` for one process,
  `PgSessions` in PostgreSQL – `PgSessions::migrate` makes its table, with a history of its own), ended by the
  provider's **back-channel logout**.
- **Access tokens** of the program's apps (JWT, RFC 9068) checked without asking the provider.
- On **axum** (feature `axum`, on by default): the routes `/auth/login`, `/auth/callback`, `/auth/logout` and
  `/auth/backchannel-logout`, and the extractor `web::Authenticated`. The session cookie is HttpOnly and
  `SameSite=Lax`; requests that change something with it need the header `kernoid-csrf` and the program's origin.

Requests to the provider go only to HTTPS and public addresses unless `allow_private` is set (a provider in the
program's own network, or development).

AGPL-3.0-or-later, like kernoid's server: only servers use it. Apps log in with `kernoid-client` (MIT).
