<!-- SPDX-License-Identifier: MIT -->
# kernoid-client

kernoid's Rust SDK: the protocols of [kernoid](https://kernoid.dev) for clients, async on tokio.

- **JMAP** (RFC 8620) over HTTPS – the session, method calls with result references, uploads and downloads of any
  size with progress, push over EventSource; typed calls for mail (threads, sending through Drafts, the vacation
  response), files (versions, sharing, links, search), calendars (with scheduling) and contacts, and principals.
- **End-to-end encryption** (kernoid's RFC 0006) on `kernoid-e2e`: unlocking the account's key, reading and sending
  encrypted mail, finding the keys of recipients.
- **Logging in** with an app password, or with OpenID Connect as kernoid's apps do (`oidc`): PKCE, kernoid's
  built-in client of the apps, the scope `urn:kernoid:data`, renewing the access token with the refresh token.
- **Finding a server** of a domain through `_jmap._tcp` SRV records.
- **iCalendar and vCard files** to and from JSCalendar and JSContact, through calcard.

It sends the credentials – HTTP Basic, or the access token – only to the origin it logged in to; plain HTTP only to this
machine unless asked for. TLS through rustls on AWS-LC with the system's trust store, the post-quantum key exchange
X25519MLKEM768 preferred.

kernoid's terminal app (`apps/tui`) is built on it, and so will be the apps of
[kernoid/apps](https://github.com/kernoid/apps).

```rust
let url = kernoid_client::session_url(None, "alice@example.org")?;
let client = kernoid_client::Client::connect(&url, "alice@example.org", &app_password, &Default::default()).await?;
let account = client.primary(kernoid_client::MAIL)?;
let mailboxes = kernoid_client::mail::mailboxes(&client, &account).await?;
```

MIT – see [LICENSE](LICENSE).
