// SPDX-License-Identifier: MIT
// The authorization code flow against a fake kernoid that signs ID tokens with a real RSA key.
import { beforeAll, describe, expect, it } from "vitest";

import { base64urlEncode, type FlowStorage, OidcClient, OidcError, pkceChallenge } from "../src/index.js";

const ISSUER = "https://login.example.org";
let keys: CryptoKeyPair;
let jwk: JsonWebKey;

beforeAll(async () => {
  keys = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  jwk = { ...(await crypto.subtle.exportKey("jwk", keys.publicKey)), kid: "k1" } as JsonWebKey;
});

async function sign(claims: Record<string, unknown>, kid = "k1"): Promise<string> {
  const part = (value: unknown) => base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));
  const input = `${part({ alg: "RS256", kid, typ: "JWT" })}.${part(claims)}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, new TextEncoder().encode(input));
  return `${input}.${base64urlEncode(signature)}`;
}

function memory(): FlowStorage {
  const map = new Map<string, string>();
  return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => void map.set(k, v), removeItem: (k) => void map.delete(k) };
}

/** A fake kernoid: discovery, JWKS and a token endpoint that checks PKCE. */
function server(claims: (nonce: string) => Record<string, unknown>) {
  const issued: { challenge?: string | undefined; nonce?: string | undefined } = {};
  const fetcher: typeof fetch = async (input, init) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
    if (url.endsWith("/.well-known/openid-configuration")) {
      return json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth/v2/authorize`,
        token_endpoint: `${ISSUER}/oauth/v2/token`,
        userinfo_endpoint: `${ISSUER}/oidc/v1/userinfo`,
        end_session_endpoint: `${ISSUER}/oidc/v1/end_session`,
        revocation_endpoint: `${ISSUER}/oauth/v2/revoke`,
        jwks_uri: `${ISSUER}/oauth/v2/keys`,
      });
    }
    if (url.endsWith("/oauth/v2/keys")) return json({ keys: [jwk] });
    if (url.endsWith("/oauth/v2/token")) {
      const form = new URLSearchParams(String(init?.body));
      if (form.get("grant_type") === "authorization_code") {
        if ((await pkceChallenge(form.get("code_verifier") ?? "")) !== issued.challenge) {
          return json({ error: "invalid_grant", error_description: "the code is not valid" }, 400);
        }
      }
      return json({
        access_token: "kat1.x",
        token_type: "Bearer",
        expires_in: 3600,
        id_token: await sign(claims(issued.nonce ?? "")),
        refresh_token: "krt1.y",
        scope: "openid profile",
      });
    }
    return json({}, 404);
  };
  return { fetcher, issued };
}

function claimsFor(nonce: string, overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, sub: "acc", aud: "app", exp: now + 3600, iat: now, nonce, ...overrides };
}

async function start(client: OidcClient, issued: { challenge?: string | undefined; nonce?: string | undefined }) {
  const url = new URL(await client.authorizationUrl({ appState: "/inbox", prompt: "login" }));
  issued.challenge = url.searchParams.get("code_challenge") ?? undefined;
  issued.nonce = url.searchParams.get("nonce") ?? undefined;
  return url;
}

describe("OidcClient", () => {
  it("logs in with PKCE and verifies the ID token", async () => {
    const { fetcher, issued } = server((nonce) => claimsFor(nonce, { name: "Alice" }));
    const client = new OidcClient({ issuer: `${ISSUER}/`, clientId: "app", redirectUri: "https://app/cb", scopes: ["profile"], storage: memory(), fetch: fetcher });
    const url = await start(client, issued);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/oauth/v2/authorize`);
    expect(url.searchParams.get("scope")).toBe("openid profile");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("prompt")).toBe("login");

    const callback = `https://app/cb?code=kac1.c&state=${url.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`;
    const { tokens, appState } = await client.handleCallback(callback);
    expect(appState).toBe("/inbox");
    expect(tokens.claims.name).toBe("Alice");
    expect(tokens.refreshToken).toBe("krt1.y");
    // A callback is used once.
    await expect(client.handleCallback(callback)).rejects.toThrow(/unknown state/);
  });

  it("refuses tokens that do not check out", async () => {
    for (const [overrides, message] of [
      [{ aud: "other" }, /another application/],
      [{ iss: "https://evil.example" }, /another issuer/],
      [{ exp: 1 }, /expired/],
      [{ nonce: "wrong" }, /nonce/],
    ] as const) {
      const { fetcher, issued } = server((nonce) => claimsFor(nonce, overrides));
      const client = new OidcClient({ issuer: ISSUER, clientId: "app", redirectUri: "https://app/cb", storage: memory(), fetch: fetcher });
      const url = await start(client, issued);
      await expect(client.handleCallback(`https://app/cb?code=c&state=${url.searchParams.get("state")}`)).rejects.toThrow(message);
    }
  });

  it("reports errors from the authorization server", async () => {
    const { fetcher, issued } = server((nonce) => claimsFor(nonce));
    const client = new OidcClient({ issuer: ISSUER, clientId: "app", redirectUri: "https://app/cb", storage: memory(), fetch: fetcher });
    const url = await start(client, issued);
    const error = await client.handleCallback(`https://app/cb?error=access_denied&state=${url.searchParams.get("state")}`).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OidcError);
    expect((error as OidcError).error).toBe("access_denied");
    const forged = await start(client, issued);
    await expect(client.handleCallback(`https://app/cb?code=c&state=${forged.searchParams.get("state")}&iss=https%3A%2F%2Fevil`)).rejects.toThrow(/another issuer/);
  });

  it("builds the logout URL", async () => {
    const { fetcher } = server((nonce) => claimsFor(nonce));
    const client = new OidcClient({ issuer: ISSUER, clientId: "app", redirectUri: "https://app/cb", storage: memory(), fetch: fetcher });
    const url = new URL(await client.logoutUrl({ idToken: "t", postLogoutRedirectUri: "https://app/", state: "s" }));
    expect(url.pathname).toBe("/oidc/v1/end_session");
    expect(Object.fromEntries(url.searchParams)).toEqual({ id_token_hint: "t", client_id: "app", post_logout_redirect_uri: "https://app/", state: "s" });
  });
});
