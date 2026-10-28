// SPDX-License-Identifier: MIT
// Passkeys: kernoid sends WebAuthn options as JSON (binary values in base64url, as webauthn-rs writes them) and
// expects the browser's answer as JSON in the same encoding. These functions translate both ways.

import { decode, encode } from "./base64url.js";

type Json = Record<string, unknown>;

function binary(value: unknown): BufferSource {
  if (typeof value !== "string") throw new TypeError("expected a base64url value");
  return decode(value);
}

function credentialList(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((entry: Json) => ({ ...(entry as object), id: binary(entry.id) }) as PublicKeyCredentialDescriptor);
}

/** WebAuthn creation options from kernoid's JSON (`{ publicKey: … }`). */
export function creationOptions(options: unknown): PublicKeyCredentialCreationOptions {
  const publicKey = (options as { publicKey: Json }).publicKey;
  const user = publicKey.user as Json;
  const exclude = credentialList(publicKey.excludeCredentials);
  return {
    ...(publicKey as object),
    challenge: binary(publicKey.challenge),
    user: { ...(user as object), id: binary(user.id) } as PublicKeyCredentialUserEntity,
    ...(exclude ? { excludeCredentials: exclude } : {}),
  } as PublicKeyCredentialCreationOptions;
}

/** WebAuthn request options from kernoid's JSON (`{ publicKey: …, mediation? }`). */
export function requestOptions(options: unknown): { publicKey: PublicKeyCredentialRequestOptions; mediation?: CredentialMediationRequirement } {
  const { publicKey, mediation } = options as { publicKey: Json; mediation?: CredentialMediationRequirement };
  const allow = credentialList(publicKey.allowCredentials);
  const result: { publicKey: PublicKeyCredentialRequestOptions; mediation?: CredentialMediationRequirement } = {
    publicKey: {
      ...(publicKey as object),
      challenge: binary(publicKey.challenge),
      ...(allow ? { allowCredentials: allow } : {}),
    } as PublicKeyCredentialRequestOptions,
  };
  if (mediation) result.mediation = mediation;
  return result;
}

/** A new credential (`navigator.credentials.create`) as kernoid expects it. */
export function registrationJson(credential: PublicKeyCredential): Json {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: encode(response.attestationObject),
      clientDataJSON: encode(response.clientDataJSON),
    },
    extensions: credential.getClientExtensionResults(),
  };
}

/** An assertion (`navigator.credentials.get`) as kernoid expects it. */
export function assertionJson(credential: PublicKeyCredential): Json {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: encode(response.authenticatorData),
      clientDataJSON: encode(response.clientDataJSON),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults(),
  };
}

/** Asks the browser to create a passkey. */
export async function createCredential(options: unknown, credentials: CredentialsContainer = navigator.credentials): Promise<Json> {
  const credential = await credentials.create({ publicKey: creationOptions(options) });
  if (!(credential instanceof PublicKeyCredential)) throw new Error("no passkey was created");
  return registrationJson(credential);
}

/** How to ask for a passkey: in a dialog (the default), or offered in the browser's autofill of a field with
 * `autocomplete="username webauthn"` (`conditional`), which waits until the person picks one or `signal` aborts. */
export interface PasskeyRequest {
  conditional?: boolean;
  signal?: AbortSignal;
}

/** Whether the browser offers passkeys in its autofill (WebAuthn conditional mediation). */
export async function passkeyAutofillAvailable(): Promise<boolean> {
  const credential = globalThis.PublicKeyCredential as
    | (typeof PublicKeyCredential & { isConditionalMediationAvailable?: () => Promise<boolean> })
    | undefined;
  return (await credential?.isConditionalMediationAvailable?.().catch(() => false)) ?? false;
}

/** Asks the browser for a passkey assertion. */
export async function getCredential(
  options: unknown,
  credentials: CredentialsContainer = navigator.credentials,
  request: PasskeyRequest = {},
): Promise<Json> {
  const { publicKey } = requestOptions(options);
  const asked: CredentialRequestOptions = { publicKey };
  if (request.conditional) asked.mediation = "conditional";
  if (request.signal) asked.signal = request.signal;
  const credential = await credentials.get(asked);
  if (!(credential instanceof PublicKeyCredential)) throw new Error("no passkey was used");
  return assertionJson(credential);
}
