// SPDX-License-Identifier: MIT
import { describe, expect, it } from "vitest";

import { base64urlDecode, base64urlEncode, creationOptions, getCredential, isMultiFactor, KernoidError, LoginClient, passkeyAutofillAvailable, pkceChallenge, requestOptions } from "../src/index.js";

function fakeFetch(status: number, body: unknown, headers: Record<string, string> = {}): typeof fetch {
  return async () => new Response(body === undefined ? null : JSON.stringify(body), { status, headers });
}

describe("base64url", () => {
  it("round-trips without padding", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0x00, 0x01]);
    expect(base64urlEncode(bytes)).toBe("-_-_AAE");
    expect([...base64urlDecode("-_-_AAE")]).toEqual([...bytes]);
    expect(() => base64urlDecode("a+b")).toThrow();
  });
});

describe("PKCE", () => {
  it("matches RFC 7636, appendix B", async () => {
    expect(await pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
});

describe("LoginClient", () => {
  it("keeps the token of a new session and sends it", async () => {
    const seen: string[] = [];
    const client = new LoginClient({
      baseUrl: "https://login.example.org/",
      fetch: async (input, init) => {
        seen.push(`${init?.method} ${String(input)} ${(init?.headers as Record<string, string>).authorization ?? "-"}`);
        return new Response(JSON.stringify({ token: "ks1.a.b", id: "s", expires_at: "", account: {} }), { status: 201 });
      },
    });
    await client.login("alice@firma.de", "secret");
    await client.session();
    expect(seen).toEqual(["POST https://login.example.org/v1/sessions -", "GET https://login.example.org/v1/sessions/current Bearer ks1.a.b"]);
  });

  it("throws problems with what to do about them", async () => {
    const mfa = new LoginClient({ fetch: fakeFetch(401, { type: "urn:kernoid:problem:mfa-required", title: "Unauthorized", status: 401 }) });
    await expect(mfa.finishAuthRequest("ar1.x")).rejects.toMatchObject({ kind: "mfa-required", status: 401 });
    const throttled = new LoginClient({ fetch: fakeFetch(429, { type: "about:blank", title: "Too Many Requests", status: 429 }, { "retry-after": "60" }) });
    const error = await throttled.login("a@b.de", "x").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(KernoidError);
    expect((error as KernoidError).retryAfter).toBe(60);
  });

  it("keeps the session in the cookie when asked", async () => {
    const seen: RequestInit[] = [];
    const client = new LoginClient({
      cookies: true,
      fetch: async (_input, init) => {
        seen.push(init ?? {});
        return new Response(JSON.stringify({ id: "s", expires_at: "", account: {} }), { status: 201 });
      },
    });
    const session = await client.login("alice@firma.de", "secret");
    expect(session.token).toBeUndefined();
    expect(client.token).toBeUndefined();
    expect(JSON.parse(String(seen[0]?.body))).toMatchObject({ cookie: true });
    expect(seen[0]?.credentials).toBe("same-origin");
    expect((seen[0]?.headers as Record<string, string>)["kernoid-csrf"]).toBe("1");
    // Without cookies, no credentials go along.
    const bearer = new LoginClient({ fetch: async (_input, init) => (seen.push(init ?? {}), new Response("{}", { status: 200 })) });
    await bearer.session();
    expect(seen[1]?.credentials).toBe("omit");
  });

  it("sends the device token of an earlier login", async () => {
    const bodies: unknown[] = [];
    const client = new LoginClient({
      fetch: async (_input, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify({ token: "ks1.a.b", id: "s", expires_at: "", account: {}, device_token: "kdt1.d" }), { status: 201 });
      },
    });
    const first = await client.login("alice@firma.de", "secret");
    await client.login("alice@firma.de", "secret", undefined, first.device_token);
    expect(bodies).toEqual([
      { address: "alice@firma.de", password: "secret" },
      { address: "alice@firma.de", password: "secret", device_token: "kdt1.d" },
    ]);
  });

  it("finishes with consent when asked for it", async () => {
    const seen: string[] = [];
    const client = new LoginClient({
      fetch: async (input, init) => {
        seen.push(`${init?.method} ${String(input)} ${String(init?.body ?? "-")}`);
        if (!init?.body) return new Response(JSON.stringify({ type: "urn:kernoid:problem:consent-required", title: "Forbidden", status: 403 }), { status: 403 });
        return new Response(JSON.stringify({ callback_url: "https://app.example/cb?code=x" }), { status: 200 });
      },
    });
    await expect(client.finishAuthRequest("ar1.x")).rejects.toMatchObject({ kind: "consent-required", status: 403 });
    expect(await client.finishAuthRequest("ar1.x", { consent: true })).toBe("https://app.example/cb?code=x");
    expect(seen).toEqual(["POST /v1/auth-requests/ar1.x -", 'POST /v1/auth-requests/ar1.x {"consent":true}']);
  });

  it("counts a passkey or two checks as multi-factor", () => {
    expect(isMultiFactor({ checks: ["password"] })).toBe(false);
    expect(isMultiFactor({ checks: ["password", "totp"] })).toBe(true);
    expect(isMultiFactor({ checks: ["passkey"] })).toBe(true);
  });
});

describe("passkey requests", () => {
  const options = { publicKey: { challenge: "AQID", rpId: "login.firma.de" }, mediation: "conditional" };
  function container(seen: CredentialRequestOptions[]): CredentialsContainer {
    return {
      get: async (asked: CredentialRequestOptions) => {
        seen.push(asked);
        throw new DOMException("no authenticator in tests", "NotAllowedError");
      },
    } as unknown as CredentialsContainer;
  }

  it("asks in a dialog unless autofill is wanted", async () => {
    const seen: CredentialRequestOptions[] = [];
    await expect(getCredential(options, container(seen))).rejects.toThrow();
    const controller = new AbortController();
    await expect(getCredential(options, container(seen), { conditional: true, signal: controller.signal })).rejects.toThrow();
    expect(seen[0]?.mediation).toBeUndefined();
    expect(seen[1]?.mediation).toBe("conditional");
    expect(seen[1]?.signal).toBe(controller.signal);
  });

  it("knows when the browser offers no autofill", async () => {
    expect(await passkeyAutofillAvailable()).toBe(false);
  });
});

describe("WebAuthn options", () => {
  it("turns base64url values into bytes", () => {
    const creation = creationOptions({
      publicKey: {
        challenge: "AQID",
        rp: { id: "login.example.org", name: "Example" },
        user: { id: "BAUG", name: "alice@firma.de", displayName: "Alice" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [{ type: "public-key", id: "Bwg" }],
      },
    });
    expect([...new Uint8Array(creation.challenge as ArrayBuffer)]).toEqual([1, 2, 3]);
    expect([...new Uint8Array(creation.user.id as ArrayBuffer)]).toEqual([4, 5, 6]);
    expect([...new Uint8Array(creation.excludeCredentials![0]!.id as ArrayBuffer)]).toEqual([7, 8]);
    const request = requestOptions({ publicKey: { challenge: "AQID", allowCredentials: [] }, mediation: "conditional" });
    expect(request.mediation).toBe("conditional");
    expect(request.publicKey.allowCredentials).toEqual([]);
  });
});
