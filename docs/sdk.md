---
title: TypeScript SDK
nav_order: 5.5
permalink: /sdk/
---

# TypeScript SDK

`@kernoid/sdk` (in [`web/sdk`](https://github.com/kernoid/kernoid/tree/main/web/sdk), MIT) lets a web app log in with
kernoid, and lets anyone build a login UI or account page of their own. It has no runtime dependencies and runs in
every current browser.

{: .note }
The package is not published on npm yet; build it from the repository (`cd web && pnpm install && pnpm --filter @kernoid/sdk run build`).

## Logging in to a web app

`OidcClient` is an OpenID Connect client for apps without a secret (single-page apps, PWAs): authorization code with
PKCE. Register the app as a **public** application in a project of the tenant, with its redirect URI.

```ts
import { OidcClient } from "@kernoid/sdk";

const kernoid = new OidcClient({
  issuer: "https://login.example.org",
  clientId: "<the application's id>",
  redirectUri: "https://app.example.org/callback",
  scopes: ["profile", "email"],
});

// Send the browser to kernoid to log in.
window.location.assign(await kernoid.authorizationUrl({ appState: window.location.pathname }));

// On the redirect URI: check the answer and get the tokens.
const { tokens, appState } = await kernoid.handleCallback(window.location.href);
tokens.claims.sub;    // the account id
tokens.claims.name;   // with the scope profile
```

`handleCallback` checks the `state` and the issuer of the answer, exchanges the code with the PKCE verifier and
verifies the ID token – its RS256 signature against the instance's keys, issuer, audience, expiry and nonce – before
it returns the claims.

| Method | Does |
|---|---|
| `authorizationUrl({ prompt, maxAge, tenant, appState })` | the URL to send the browser to; `tenant` limits the login to one tenant's accounts |
| `handleCallback(url)` | completes the login; returns verified tokens and the `appState` |
| `refresh(refreshToken)` | new tokens; the refresh token is replaced – keep the new one |
| `userinfo(accessToken)` | the claims userinfo gives |
| `revoke(token)` | revokes a token – a refresh token with every token of its login |
| `logoutUrl({ idToken, postLogoutRedirectUri })` | logs out at kernoid and sends the browser back |
| `verifyIdToken(idToken, nonce?)` | verifies an ID token from elsewhere |

Errors from kernoid's protocol endpoints are thrown as `OidcError` with the OAuth `error` (e.g. `access_denied`).
The flow keeps its state in `sessionStorage` unless you pass a `storage` of your own.

### Project roles

If the application's project asserts roles, or the app asks for the scope `urn:kernoid:project:roles`, the claims
carry them: role key, then tenant id and tenant name.

```ts
const roles = tokens.claims["urn:kernoid:project:roles"] ?? {};
const canEdit = "editor" in roles;
```

## Building a login UI

`LoginClient` wraps kernoid's session API – what [kernoid's own login UI]({{ '/login/' | relative_url }}#the-login-ui)
uses. It runs on the instance's own origin, or at the instance's own login UI URL (`PUT /v1/instance/login-ui`),
whose origin may call the API.

```ts
import { KernoidError, LoginClient } from "@kernoid/sdk";

const login = new LoginClient({ cookies: true });     // the session in kernoid's HttpOnly cookie
const id = new URLSearchParams(location.search).get("authRequest")!;
const request = await login.authRequest(id);          // who is asking

await login.login(address, password);                // or login.loginWithPasskey()
try {
  location.assign(await login.finishAuthRequest(id));
} catch (error) {
  if (error instanceof KernoidError && error.kind === "mfa-required") {
    await login.checkTotp(code);                     // or checkPasskey(), checkRecoveryCode()
    location.assign(await login.finishAuthRequest(id));
  }
}
```

`KernoidError.kind` says what to do: `login-required` (log in again), `mfa-required` (ask for a second factor),
`consent-required` (show what the application asks for, then `finishAuthRequest(id, { consent: true })`),
`unauthenticated`, `forbidden`, `not-found`, `conflict`, `too-many-attempts` (with `retryAfter`), `bad-request`,
`unavailable`. The account methods – `secondFactors`, `startTotp`/`confirmTotp`, `registerPasskey`,
`generateRecoveryCodes`, `changePassword`, `consents`/`revokeConsent`, `sessions`, `endSession` – follow the
[API]({{ '/api/' | relative_url }}).

- **Cookies:** with `cookies: true`, logins ask for the session in kernoid's HttpOnly cookie, requests carry it and
  the `kernoid-csrf` header, and `token` stays empty – for a login UI on the instance's own origin (or a login UI of
  its own on the same site, as `baseUrl`). Without it, the SDK sends the session as a bearer token.
- **Known devices:** `login()` answers with a `device_token`; keep it per address and pass it to the next `login()`
  (fourth argument), so that others failing on purpose cannot lock the person out on this device.
- **TOTP:** `startTotp()` returns the secret, the `otpauth://` URI and `qr_code` – an SVG image as a `data:` URL for
  an `<img>`; the page needs no QR library and builds no markup.
- **Passkeys in the autofill:** give the address field `autocomplete="username webauthn"`; if
  `passkeyAutofillAvailable()`, call `loginWithPasskey(undefined, { conditional: true, signal })` when the page shows –
  the browser then offers the person's passkeys in the field's autofill. Abort it (`signal`) before any other passkey
  request, e.g. when the person presses a "log in with a passkey" button, which calls `loginWithPasskey()` for the
  dialog.
