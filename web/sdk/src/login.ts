// SPDX-License-Identifier: MIT
// The session API: what a login UI needs – logging in, further checks, finishing OpenID Connect auth requests – and
// what an account does for itself (second factors, password, sessions).

import { Http, type HttpOptions } from "./http.js";
import { createCredential, getCredential, type PasskeyRequest } from "./webauthn.js";

export interface Account {
  id: string;
  tenant: string;
  /** The login name. */
  address: string;
  display_name: string;
}

export interface NewSession {
  id: string;
  /** Shown once; send it as the bearer token. Not there when the session is kept in the cookie (`cookies`). */
  token?: string;
  expires_at: string;
  account: Account;
  /**
   * After a password login: this device's token for the address. Keep it and send it with the next login – failed
   * logins of others then cannot lock the account out on this device.
   */
  device_token?: string;
}

export interface Session {
  id: string;
  account: Account;
  /** `password`, `totp`, `passkey`, `recovery`. */
  checks: string[];
  created_at: string;
  expires_at: string;
}

export interface SessionSummary {
  id: string;
  checks: string[];
  created_at: string;
  expires_at: string;
  client_address: string | null;
  user_agent: string | null;
}

export interface AuthRequest {
  id: string;
  /** The name of the application asking. */
  application: string;
  scopes: string[];
  /** `none`, `login`, `consent`, `select_account`. */
  prompt: string[];
  /** The session may be at most this many seconds old. */
  max_age: number | null;
  expires_at: string;
}

/** What an account agreed an application may have. */
export interface Consent {
  application: string;
  application_name: string;
  scopes: string[];
  granted_at: string;
}

/** Errors a login UI may end an auth request with. */
export type DeclineReason =
  | "login_required"
  | "consent_required"
  | "interaction_required"
  | "account_selection_required"
  | "access_denied";

export interface SecondFactors {
  totp: boolean;
  passkeys: number;
  recovery_codes_left: number;
  /** The tenant requires a second factor. */
  required: boolean;
  /** Without one yet: until when the account may still log in without one (the tenant's grace period). */
  setup_due: string | null;
}

export interface TotpSetup {
  /** Base32, for typing in. */
  secret: string;
  /** `otpauth://` URI, to open in an authenticator app on this device. */
  uri: string;
  /** The URI as a QR code: an SVG image as a `data:` URL, for an `<img>`. */
  qr_code: string;
}

export interface Passkey {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

/** Where an address logs in. */
export interface LoginOptions {
  /** If set, the address logs in at this identity provider instead of with a password. */
  identity_provider: { id: string; name: string } | null;
}

/** What registering offers at an instance. */
export interface RegistrationOptions {
  /** People without an address of their own may register. */
  open: boolean;
  /** Domains on which a new account may take an address – a mailbox. */
  domains: string[];
  usernames: boolean;
  /** kernoid sends codes; without it, registering works only with the providers. */
  by_email: boolean;
}

export interface NewRegistration {
  /** Where the code goes; becomes the verified contact address. */
  email: string;
  password: string;
  displayName: string;
  /** An address of one's own on one of the offered domains. */
  nativeAddress?: string;
  username?: string;
}

/** A provider login that found an account with its verified address: link it, or create a separate account. */
export interface LinkProposal {
  email: string;
  provider: string;
  may_register: boolean;
}

interface Challenge {
  challenge_id: string;
  options: unknown;
}

/** Whether a session has passed more than one factor (two different checks, or a passkey). */
export function isMultiFactor(session: Pick<Session, "checks">): boolean {
  return new Set(session.checks).size > 1 || session.checks.includes("passkey");
}

export class LoginClient {
  readonly http: Http;

  constructor(options: HttpOptions = {}) {
    this.http = new Http(options);
  }

  /** The session token in use, if any. */
  get token(): string | undefined {
    return this.http.token;
  }

  set token(token: string | undefined) {
    this.http.token = token;
  }

  // Logging in

  /**
   * Checks address and password and creates a session; the client uses its token from then on. `deviceToken` is the
   * `device_token` of an earlier login with this address on this device.
   */
  async login(address: string, password: string, lifetimeSeconds?: number, deviceToken?: string): Promise<NewSession> {
    const body: Record<string, unknown> = { address, password };
    if (lifetimeSeconds !== undefined) body.lifetime_seconds = lifetimeSeconds;
    if (deviceToken !== undefined) body.device_token = deviceToken;
    if (this.http.cookies) body.cookie = true;
    const session = await this.http.request<NewSession>("POST", "/v1/sessions", body);
    this.token = session.token;
    return session;
  }

  /**
   * Logs in with a passkey alone – the browser offers the person's passkeys, in a dialog or (`conditional`) in the
   * autofill of the address field.
   */
  async loginWithPasskey(lifetimeSeconds?: number, request: PasskeyRequest = {}): Promise<NewSession> {
    const challenge = await this.http.request<Challenge>("POST", "/v1/sessions/passkey/start");
    const credential = await getCredential(challenge.options, navigator.credentials, request);
    const body: Record<string, unknown> = { challenge_id: challenge.challenge_id, credential };
    if (lifetimeSeconds !== undefined) body.lifetime_seconds = lifetimeSeconds;
    if (this.http.cookies) body.cookie = true;
    const session = await this.http.request<NewSession>("POST", "/v1/sessions/passkey/finish", body);
    this.token = session.token;
    return session;
  }

  /** Where an address logs in – at an identity provider its domain is routed to, or with a password. */
  loginOptions(address: string): Promise<LoginOptions> {
    return this.http.request("GET", `/v1/login-options?address=${encodeURIComponent(address)}`);
  }

  /** Starts a login at an identity provider; returns where to send the browser. */
  async startIdpLogin(identityProvider: string, options: { authRequest?: string; loginHint?: string } = {}): Promise<string> {
    const body: Record<string, string> = { identity_provider: identityProvider };
    if (options.authRequest) body.auth_request = options.authRequest;
    if (options.loginHint) body.login_hint = options.loginHint;
    return (await this.http.request<{ url: string }>("POST", "/v1/idp-logins", body)).url;
  }

  /** Exchanges what `/login/idp` received after a login at an identity provider for a session – once. */
  async exchangeIdpLogin(login: string, lifetimeSeconds?: number): Promise<{ session: NewSession; authRequest: string | null }> {
    const body: Record<string, unknown> = { login };
    if (lifetimeSeconds !== undefined) body.lifetime_seconds = lifetimeSeconds;
    if (this.http.cookies) body.cookie = true;
    const result = await this.http.request<{ session: NewSession; auth_request: string | null }>("POST", "/v1/idp-logins/session", body);
    this.token = result.session.token;
    return { session: result.session, authRequest: result.auth_request };
  }

  /** The providers offered to everyone on the login page ("Sign in with …"). */
  loginProviders(): Promise<{ id: string; name: string }[]> {
    return this.http.request("GET", "/v1/login-providers");
  }

  // Registering

  registrationOptions(): Promise<RegistrationOptions> {
    return this.http.request("GET", "/v1/registration");
  }

  /** Starts a registration; kernoid sends a code to the email address. Returns the registration's id. */
  async register(registration: NewRegistration): Promise<string> {
    const body: Record<string, string> = {
      email: registration.email,
      password: registration.password,
      display_name: registration.displayName,
    };
    if (registration.nativeAddress) body.native_address = registration.nativeAddress;
    if (registration.username) body.username = registration.username;
    return (await this.http.request<{ id: string }>("POST", "/v1/registrations", body)).id;
  }

  /** Finishes a registration with the code from the message; returns the new account's id. */
  async confirmRegistration(id: string, code: string): Promise<string> {
    const path = `/v1/registrations/${encodeURIComponent(id)}/confirm`;
    return (await this.http.request<{ account: string }>("POST", path, { code })).account;
  }

  // Linking

  /** What a provider login proposes (`/login/idp#link=…`); does not use the code up. */
  linkProposal(login: string): Promise<LinkProposal> {
    return this.http.request("POST", "/v1/idp-logins/proposal", { login });
  }

  /** Links the provider login of a proposal to the account this client is logged in as. */
  confirmIdpLink(login: string): Promise<void> {
    return this.http.request("POST", "/v1/idp-logins/link", { login });
  }

  /** Creates a separate account for the provider login of a proposal and logs it in. */
  async registerInstead(login: string, lifetimeSeconds?: number): Promise<{ session: NewSession; authRequest: string | null }> {
    const body: Record<string, unknown> = { login };
    if (lifetimeSeconds !== undefined) body.lifetime_seconds = lifetimeSeconds;
    if (this.http.cookies) body.cookie = true;
    const result = await this.http.request<{ session: NewSession; auth_request: string | null }>("POST", "/v1/idp-logins/register", body);
    this.token = result.session.token;
    return { session: result.session, authRequest: result.auth_request };
  }

  /** Starts linking a provider to the account this client is logged in as; returns where to send the browser. */
  async startIdpLink(identityProvider: string): Promise<string> {
    return (await this.http.request<{ url: string }>("POST", "/v1/account/idp-links", { identity_provider: identityProvider })).url;
  }

  session(): Promise<Session> {
    return this.http.request("GET", "/v1/sessions/current");
  }

  /**
   * Logs out: ends the session and forgets its token. If the session came from a SAML provider with single logout,
   * returns where to send the browser next, to log out there too.
   */
  async logout(): Promise<string | null> {
    const answer = await this.http.request<{ redirect: string | null }>("POST", "/v1/sessions/current/logout");
    this.token = undefined;
    return answer.redirect;
  }

  // Further checks of the session

  checkTotp(code: string): Promise<Session> {
    return this.http.request("POST", "/v1/sessions/current/totp", { code });
  }

  checkRecoveryCode(code: string): Promise<Session> {
    return this.http.request("POST", "/v1/sessions/current/recovery", { code });
  }

  async checkPasskey(): Promise<Session> {
    const challenge = await this.http.request<Challenge>("POST", "/v1/sessions/current/passkey/start");
    const credential = await getCredential(challenge.options);
    return this.http.request("POST", "/v1/sessions/current/passkey/finish", {
      challenge_id: challenge.challenge_id,
      credential,
    });
  }

  // OpenID Connect auth requests

  authRequest(id: string): Promise<AuthRequest> {
    return this.http.request("GET", `/v1/auth-requests/${encodeURIComponent(id)}`);
  }

  /**
   * Finishes an auth request with the session; returns where to send the browser. If it fails with
   * `consent-required`, show what the application asks for and finish again with `{ consent: true }`.
   */
  async finishAuthRequest(id: string, options: { consent?: boolean } = {}): Promise<string> {
    const path = `/v1/auth-requests/${encodeURIComponent(id)}`;
    const body = options.consent ? { consent: true } : undefined;
    const finished = await this.http.request<{ callback_url: string }>("POST", path, body);
    return finished.callback_url;
  }

  /** Ends an auth request without a login; returns where to send the browser. */
  async declineAuthRequest(id: string, error: DeclineReason): Promise<string> {
    const path = `/v1/auth-requests/${encodeURIComponent(id)}/decline`;
    const finished = await this.http.request<{ callback_url: string }>("POST", path, { error });
    return finished.callback_url;
  }

  // One's own account

  secondFactors(): Promise<SecondFactors> {
    return this.http.request("GET", "/v1/account/factors");
  }

  /** Proposes a TOTP secret (needs a recent session); confirm it with a first code. */
  startTotp(): Promise<TotpSetup> {
    return this.http.request("POST", "/v1/account/totp");
  }

  confirmTotp(code: string): Promise<void> {
    return this.http.request("POST", "/v1/account/totp/confirm", { code });
  }

  removeTotp(): Promise<void> {
    return this.http.request("DELETE", "/v1/account/totp");
  }

  passkeys(): Promise<Passkey[]> {
    return this.http.request("GET", "/v1/account/passkeys");
  }

  /** Creates a passkey for the account (needs a recent session); returns its id. */
  async registerPasskey(name: string): Promise<string> {
    const challenge = await this.http.request<Challenge>("POST", "/v1/account/passkeys/start");
    const credential = await createCredential(challenge.options);
    const created = await this.http.request<{ id: string }>("POST", "/v1/account/passkeys/finish", {
      challenge_id: challenge.challenge_id,
      credential,
      name,
    });
    return created.id;
  }

  removePasskey(id: string): Promise<void> {
    return this.http.request("DELETE", `/v1/account/passkeys/${encodeURIComponent(id)}`);
  }

  /** New recovery codes, replacing earlier ones (needs a recent session); shown once. */
  async generateRecoveryCodes(): Promise<string[]> {
    return (await this.http.request<{ codes: string[] }>("POST", "/v1/account/recovery-codes")).codes;
  }

  /** Needs the current password and a recent session; the account's other sessions end. */
  changePassword(currentPassword: string, newPassword: string): Promise<void> {
    return this.http.request("PUT", "/v1/account/password", {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  updateProfile(displayName: string): Promise<void> {
    return this.http.request("PATCH", "/v1/account", { display_name: displayName });
  }

  /** The applications the account agreed to. */
  consents(): Promise<Consent[]> {
    return this.http.request("GET", "/v1/account/consents");
  }

  /** Withdraws a consent, and the application's tokens – offline access included. */
  revokeConsent(application: string): Promise<void> {
    return this.http.request("DELETE", `/v1/account/consents/${encodeURIComponent(application)}`);
  }

  sessions(): Promise<SessionSummary[]> {
    return this.http.request("GET", "/v1/sessions");
  }

  endSession(id: string): Promise<void> {
    return this.http.request("DELETE", `/v1/sessions/${encodeURIComponent(id)}`);
  }
}
