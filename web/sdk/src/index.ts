// SPDX-License-Identifier: MIT
// @kernoid/sdk – log in with kernoid. `OidcClient` is for web apps that let people log in with kernoid;
// `LoginClient` is for login UIs and account pages that use kernoid's session API directly.

export { decode as base64urlDecode, encode as base64urlEncode } from "./base64url.js";
export { type ErrorKind, KernoidError, type Problem } from "./errors.js";
export { Http, type HttpOptions } from "./http.js";
export {
  type Account,
  type AuthRequest,
  type Consent,
  type DeclineReason,
  isMultiFactor,
  type LinkProposal,
  LoginClient,
  type LoginOptions,
  type NewRegistration,
  type NewSession,
  type Passkey,
  type RegistrationOptions,
  type SecondFactors,
  type Session,
  type SessionSummary,
  type TotpSetup,
} from "./login.js";
export {
  type AuthorizeOptions,
  type Discovery,
  type FlowStorage,
  type IdTokenClaims,
  OidcClient,
  OidcError,
  type OidcOptions,
  pkceChallenge,
  type Tokens,
} from "./oidc.js";
export {
  assertionJson,
  createCredential,
  creationOptions,
  getCredential,
  type PasskeyRequest,
  passkeyAutofillAvailable,
  registrationJson,
  requestOptions,
} from "./webauthn.js";
