// SPDX-License-Identifier: MIT
// Logging in to a web app with kernoid: OpenID Connect's authorization code flow with PKCE, as a public client (the
// app has no secret). The ID token is verified – signature against the instance's keys, issuer, audience, expiry,
// nonce – before its claims are trusted.

import { decode, decodeText, encode } from "./base64url.js";


/** Where the flow keeps state between the redirect and the callback; `sessionStorage` in a browser. */
export interface FlowStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface OidcOptions {
  /** The instance's issuer, e.g. `https://login.example.org`. */
  issuer: string;
  /** The application's client id. */
  clientId: string;
  /** Registered exactly so at the application. */
  redirectUri: string;
  /** `openid` is added; e.g. `["profile", "email"]`. */
  scopes?: string[];
  storage?: FlowStorage;
  fetch?: typeof fetch;
  /** Seconds of clock difference to accept when checking expiry. */
  leeway?: number;
}

export interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  end_session_endpoint: string;
  revocation_endpoint: string;
  jwks_uri: string;
}

export interface Tokens {
  accessToken: string;
  idToken: string;
  refreshToken: string | undefined;
  /** Milliseconds since the epoch. */
  expiresAt: number;
  scope: string;
  /** The verified claims of the ID token. */
  claims: IdTokenClaims;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  sid?: string;
  amr?: string[];
  name?: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  /** Project roles: role key → tenant id → tenant name. */
  "urn:kernoid:project:roles"?: Record<string, Record<string, string>>;
  [claim: string]: unknown;
}

export interface AuthorizeOptions {
  /** `login` forces a fresh login, `none` fails instead of showing a login. */
  prompt?: "none" | "login" | "consent" | "select_account";
  /** The login may be at most this many seconds old. */
  maxAge?: number;
  /** Only accounts of this tenant: adds the scope `urn:kernoid:tenant:id:<tenant>`. */
  tenant?: string;
  /** Kept and handed back by `handleCallback`, e.g. the page to return to. */
  appState?: string;
}

interface Pending {
  verifier: string;
  nonce: string;
  appState?: string;
}

const PREFIX = "kernoid:oidc:";

function random(bytes = 32): string {
  return encode(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** The PKCE challenge of a verifier: base64url(SHA-256(verifier)) (RFC 7636, S256). */
export async function pkceChallenge(verifier: string): Promise<string> {
  return encode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
}

export class OidcClient {
  readonly options: OidcOptions;
  private readonly fetcher: typeof fetch;
  private discovery: Promise<Discovery> | undefined;
  private keys: Promise<JsonWebKey[]> | undefined;

  constructor(options: OidcOptions) {
    this.options = { ...options, issuer: options.issuer.replace(/\/+$/, "") };
    this.fetcher = options.fetch ?? ((input, init) => fetch(input, init));
  }

  private get storage(): FlowStorage {
    return this.options.storage ?? sessionStorage;
  }

  /** The discovery document, fetched once. */
  discover(): Promise<Discovery> {
    this.discovery ??= this.json<Discovery>(`${this.options.issuer}/.well-known/openid-configuration`).then((document) => {
      if (document.issuer !== this.options.issuer) throw new Error(`the issuer is ${document.issuer}, not ${this.options.issuer}`);
      return document;
    });
    return this.discovery;
  }

  /** The URL to send the browser to for a login; remembers what the callback needs. */
  async authorizationUrl(options: AuthorizeOptions = {}): Promise<string> {
    const discovery = await this.discover();
    const state = random();
    const pending: Pending = { verifier: random(), nonce: random() };
    if (options.appState !== undefined) pending.appState = options.appState;
    this.storage.setItem(PREFIX + state, JSON.stringify(pending));
    const scopes = new Set(["openid", ...(this.options.scopes ?? [])]);
    if (options.tenant) scopes.add(`urn:kernoid:tenant:id:${options.tenant}`);
    const url = new URL(discovery.authorization_endpoint);
    const params: Record<string, string> = {
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      scope: [...scopes].join(" "),
      state,
      nonce: pending.nonce,
      code_challenge: await pkceChallenge(pending.verifier),
      code_challenge_method: "S256",
    };
    if (options.prompt) params.prompt = options.prompt;
    if (options.maxAge !== undefined) params.max_age = String(options.maxAge);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    return url.toString();
  }

  /** Completes a login from the callback URL: checks state and issuer, exchanges the code, verifies the ID token. */
  async handleCallback(callbackUrl: string): Promise<{ tokens: Tokens; appState: string | undefined }> {
    const params = new URL(callbackUrl).searchParams;
    const state = params.get("state") ?? "";
    const stored = this.storage.getItem(PREFIX + state);
    this.storage.removeItem(PREFIX + state);
    if (!stored) throw new Error("this callback was not expected (unknown state)");
    const pending = JSON.parse(stored) as Pending;
    const issuer = params.get("iss");
    if (issuer !== null && issuer !== this.options.issuer) throw new Error("the callback comes from another issuer");
    const error = params.get("error");
    if (error) throw new OidcError(error, params.get("error_description") ?? undefined);
    const code = params.get("code");
    if (!code) throw new Error("the callback has no code");
    const tokens = await this.tokenRequest({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.options.redirectUri,
      code_verifier: pending.verifier,
    }, pending.nonce);
    return { tokens, appState: pending.appState };
  }

  /** New tokens for a refresh token; the refresh token is replaced – keep the new one. */
  refresh(refreshToken: string): Promise<Tokens> {
    return this.tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
  }

  /** The claims userinfo gives for an access token. */
  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const discovery = await this.discover();
    return this.json(discovery.userinfo_endpoint, { headers: { authorization: `Bearer ${accessToken}` } });
  }

  /** Revokes a token – a refresh token together with every token of its login. */
  async revoke(token: string): Promise<void> {
    const discovery = await this.discover();
    await this.form(discovery.revocation_endpoint, { token, client_id: this.options.clientId });
  }

  /** The URL that logs the person out at kernoid (RP-initiated logout) and sends them back. */
  async logoutUrl(options: { idToken: string; postLogoutRedirectUri?: string; state?: string }): Promise<string> {
    const discovery = await this.discover();
    const url = new URL(discovery.end_session_endpoint);
    url.searchParams.set("id_token_hint", options.idToken);
    url.searchParams.set("client_id", this.options.clientId);
    if (options.postLogoutRedirectUri) url.searchParams.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
    if (options.state) url.searchParams.set("state", options.state);
    return url.toString();
  }

  /** Verifies an ID token's signature (RS256, against the instance's JWKS) and its claims. */
  async verifyIdToken(idToken: string, nonce?: string): Promise<IdTokenClaims> {
    const [header, payload, signature] = idToken.split(".");
    if (!header || !payload || !signature) throw new Error("not a JWT");
    const head = JSON.parse(decodeText(header)) as { alg?: string; kid?: string };
    if (head.alg !== "RS256") throw new Error(`unexpected algorithm ${String(head.alg)}`);
    let jwk = (await this.jwks()).find((key) => (key as { kid?: string }).kid === head.kid);
    if (!jwk) {
      // A key published after the JWKS was fetched: fetch again once.
      this.keys = undefined;
      jwk = (await this.jwks()).find((key) => (key as { kid?: string }).kid === head.kid);
    }
    if (!jwk) throw new Error("the ID token was signed with an unknown key");
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true } as JsonWebKey,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const signed = new TextEncoder().encode(`${header}.${payload}`);
    if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decode(signature), signed))) {
      throw new Error("the ID token's signature is not valid");
    }
    const claims = JSON.parse(decodeText(payload)) as IdTokenClaims;
    const now = Date.now() / 1000;
    const leeway = this.options.leeway ?? 60;
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.iss !== this.options.issuer) throw new Error("the ID token comes from another issuer");
    if (!audiences.includes(this.options.clientId)) throw new Error("the ID token is for another application");
    if (claims.exp + leeway < now) throw new Error("the ID token has expired");
    if (nonce !== undefined && claims.nonce !== nonce) throw new Error("the ID token's nonce does not match");
    return claims;
  }

  private async tokenRequest(fields: Record<string, string>, nonce?: string): Promise<Tokens> {
    const discovery = await this.discover();
    const response = await this.form<{
      access_token: string;
      id_token: string;
      refresh_token?: string;
      expires_in: number;
      scope: string;
    }>(discovery.token_endpoint, { ...fields, client_id: this.options.clientId });
    const claims = await this.verifyIdToken(response.id_token, nonce);
    return {
      accessToken: response.access_token,
      idToken: response.id_token,
      refreshToken: response.refresh_token,
      expiresAt: Date.now() + response.expires_in * 1000,
      scope: response.scope,
      claims,
    };
  }

  private jwks(): Promise<JsonWebKey[]> {
    this.keys ??= this.discover()
      .then((discovery) => this.json<{ keys: JsonWebKey[] }>(discovery.jwks_uri))
      .then((jwks) => jwks.keys);
    return this.keys;
  }

  private async json<T>(url: string, init: RequestInit = {}): Promise<T> {
    const response = await this.fetcher(url, { ...init, credentials: "omit" });
    if (!response.ok) throw new Error(`${url}: ${response.status}`);
    return (await response.json()) as T;
  }

  private async form<T>(url: string, fields: Record<string, string>): Promise<T> {
    const response = await this.fetcher(url, {
      method: "POST",
      credentials: "omit",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields).toString(),
    });
    const text = await response.text();
    const body: unknown = text ? JSON.parse(text) : undefined;
    if (!response.ok) {
      const error = body as { error?: string; error_description?: string } | undefined;
      throw new OidcError(error?.error ?? `http_${response.status}`, error?.error_description);
    }
    return body as T;
  }
}

/** An OAuth error, e.g. `invalid_grant` or `access_denied`. */
export class OidcError extends Error {
  readonly error: string;

  constructor(error: string, description?: string) {
    super(description ? `${error}: ${description}` : error);
    this.name = "OidcError";
    this.error = error;
  }
}


