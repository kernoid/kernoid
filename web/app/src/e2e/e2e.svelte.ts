// SPDX-License-Identifier: MIT
// End-to-end encryption in the web app (RFC 0006): kernoid's own OpenPGP code as WebAssembly (`@kernoid/e2e`), loaded
// only when needed; the account's key made here and kept on the server only as protected copies; unlocked with a
// passkey (its PRF extension gives the passphrase) or the recovery code; the keys of others looked up over JMAP.
// The unlocked key lives in the WebAssembly memory of this page and is gone when it closes.

import { base64urlEncode, requestOptions } from "@kernoid/sdk";

import { type Jmap, MAIL } from "../jmap.js";

export const OPENPGP = "https://kernoid.dev/jmap/openpgp";

type Wasm = typeof import("@kernoid/e2e");
type Keyring = InstanceType<Wasm["Keyring"]>;

export type Rule = "allowed" | "required" | "forbidden";

export interface Settings {
  mail: boolean;
  policy: { mail: Rule; vaults: Rule; collections: Rule; recovery: boolean };
  recoveryKey: { id: string; publicKey: string } | null;
}

export interface KeyCopy {
  protected: string;
  salt: string | null;
}

export interface Key {
  id: string;
  kind: "pqc" | "compatible";
  publicKey: string;
  created: string;
  retired: string | null;
  copies: Record<string, KeyCopy>;
}

let wasm: Promise<Wasm> | undefined;

/** The WebAssembly module, loaded at its first use. */
export function library(): Promise<Wasm> {
  wasm ??= import("@kernoid/e2e").then(async (module) => {
    await module.default();
    return module;
  });
  return wasm;
}

const bytes = (base64: string): Uint8Array => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
export const base64 = (data: Uint8Array): string => {
  let text = "";
  for (let i = 0; i < data.length; i += 0x8000) text += String.fromCharCode(...data.subarray(i, i + 0x8000));
  return btoa(text);
};

/** What this page knows: the settings, the account's keys, and whether its key is unlocked here. */
export const e2e = $state({
  available: false,
  settings: undefined as Settings | undefined,
  keys: [] as Key[],
  /** The fingerprint of the account's key in use, once unlocked. */
  unlocked: undefined as string | undefined,
});

let ring: Keyring | undefined;
/** Public keys looked up, by address: fingerprints in the keyring, or none. */
const known = new Map<string, string[]>();

async function keyring(): Promise<Keyring> {
  const module = await library();
  ring ??= new module.Keyring();
  return ring;
}

/** The key in use. */
export function current(): Key | undefined {
  return e2e.keys.find((key) => !key.retired);
}

function own(jmap: Jmap): string {
  return jmap.account(OPENPGP);
}

/** Reads the settings and keys – nothing is loaded if the server has no end-to-end extension. */
export async function refresh(jmap: Jmap): Promise<void> {
  e2e.available = OPENPGP in (jmap.session.capabilities ?? {});
  if (!e2e.available) return;
  const responses = await jmap.request(
    [OPENPGP],
    [
      ["E2eSettings/get", { accountId: own(jmap) }, "s"],
      ["OpenPgpKey/get", { accountId: own(jmap) }, "k"],
    ],
  );
  e2e.settings = (responses.get("s")?.[0]?.list as Settings[] | undefined)?.[0];
  e2e.keys = (responses.get("k")?.[0]?.list as Key[] | undefined) ?? [];
}

/** A passkey's label (RFC 0006, 4.2): the SHA-256 of its credential id, as credential ids may be long. */
async function passkeyLabel(rawId: ArrayBuffer): Promise<string> {
  return `passkey:${base64urlEncode(await crypto.subtle.digest("SHA-256", rawId))}`;
}

/** Asks for a passkey of the account with its PRF extension – the step-up challenge of the session names the
 * account's passkeys and the relying party. `salts` by label, or one `fresh` salt for a passkey yet to be added. */
async function passkeyPrf(salts: Record<string, Uint8Array> | Uint8Array): Promise<{ label: string; secret: string; salt: Uint8Array }> {
  const response = await fetch("/v1/sessions/current/passkey/start", {
    method: "POST",
    headers: { "kernoid-csrf": "1", accept: "application/json" },
    credentials: "same-origin",
  });
  if (!response.ok) throw new Error("no passkey to ask");
  const { options } = (await response.json()) as { options: unknown };
  const { publicKey } = requestOptions(options);
  let prf: Record<string, unknown>;
  const byLabel = new Map<string, Uint8Array>();
  if (salts instanceof Uint8Array) {
    prf = { eval: { first: salts } };
  } else {
    const byCredential: Record<string, { first: Uint8Array }> = {};
    for (const credential of publicKey.allowCredentials ?? []) {
      const id = credential.id instanceof ArrayBuffer ? credential.id : (credential.id as Uint8Array).slice().buffer;
      const label = await passkeyLabel(id);
      const salt = salts[label];
      if (salt) {
        byCredential[base64urlEncode(id)] = { first: salt };
        byLabel.set(label, salt);
      }
    }
    if (Object.keys(byCredential).length === 0) throw new Error("no passkey unlocks the key");
    prf = { evalByCredential: byCredential };
  }
  const credential = (await navigator.credentials.get({ publicKey: { ...publicKey, extensions: { prf } as AuthenticationExtensionsClientInputs } })) as PublicKeyCredential | null;
  const first = (credential?.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } }).prf?.results?.first;
  if (!credential || !first) throw new Error("this passkey cannot unlock keys (no PRF)");
  const label = await passkeyLabel(credential.rawId);
  return { label, secret: base64(new Uint8Array(first)), salt: salts instanceof Uint8Array ? salts : (byLabel.get(label) ?? new Uint8Array()) };
}

/** Makes the account's key here: returns the recovery code, shown once. The tenant's copy is added when it recovers. */
export async function setup(jmap: Jmap, kind: "pqc" | "compatible", addresses: string[]): Promise<string> {
  const module = await library();
  const keys = await keyring();
  const fingerprint = keys.generate(kind, addresses);
  const code = module.recoveryCode();
  const copies: Record<string, KeyCopy> = {
    recovery: { protected: base64(keys.protect(fingerprint, module.normalizeRecoveryCode(code))), salt: null },
  };
  const tenant = await tenantCopy(fingerprint);
  if (tenant) copies.tenant = tenant;
  await jmap.set([OPENPGP], "OpenPgpKey", own(jmap), {
    create: { key: { publicKey: base64(keys.publicKey(fingerprint)), copies } },
  });
  e2e.unlocked = fingerprint;
  await refresh(jmap);
  return code;
}

/** The copy for the tenant's recovery key (RFC 0006, 8.2): the secret key, armored, encrypted to that key. */
async function tenantCopy(fingerprint: string): Promise<KeyCopy | undefined> {
  const recovery = e2e.settings?.recoveryKey;
  if (!e2e.settings?.policy.recovery || !recovery) return undefined;
  const keys = await keyring();
  const tenant = keys.addPublic(bytes(recovery.publicKey));
  const secret = new TextEncoder().encode(keys.exportSecret(fingerprint));
  return { protected: base64(keys.encrypt(secret, [tenant], undefined, false)), salt: null };
}

/** Once unlocked: if the tenant recovers keys and the key in use has no copy for it yet – made before the tenant
 * switched recovery on, or before a new recovery key –, the copy is added. */
async function completeCopies(jmap: Jmap): Promise<void> {
  const key = current();
  if (!key || e2e.unlocked !== key.id || key.copies.tenant) return;
  const copy = await tenantCopy(key.id);
  if (!copy) return;
  await jmap.set([OPENPGP], "OpenPgpKey", own(jmap), { update: { [key.id]: { "copies/tenant": copy } } });
  await refresh(jmap);
}

/** Unlocks the key in use with the recovery code. */
export async function unlockWithCode(code: string, jmap?: Jmap): Promise<void> {
  const key = current();
  const copy = key?.copies.recovery;
  if (!key || !copy) throw new Error("no key to unlock");
  const module = await library();
  e2e.unlocked = (await keyring()).unlock(bytes(copy.protected), module.normalizeRecoveryCode(code));
  if (jmap) await completeCopies(jmap).catch(() => undefined);
}

/** Sets in the key recovered by the organisation (or kept elsewhere): it must be the key in use. Unlocks it and gives
 * it a new recovery code – the old one may be lost – which is returned to be shown once. */
export async function importRecovered(jmap: Jmap, armored: Uint8Array): Promise<string> {
  const key = current();
  if (!key) throw new Error("no key to recover");
  const module = await library();
  const keys = await keyring();
  const fingerprint = keys.importSecret(armored);
  if (fingerprint !== key.id) {
    keys.forget(fingerprint);
    throw new Error("this is not the key in use");
  }
  e2e.unlocked = fingerprint;
  const code = module.recoveryCode();
  const copy = { protected: base64(keys.protect(fingerprint, module.normalizeRecoveryCode(code))), salt: null };
  await jmap.set([OPENPGP], "OpenPgpKey", own(jmap), { update: { [key.id]: { "copies/recovery": copy } } });
  await refresh(jmap);
  await completeCopies(jmap).catch(() => undefined);
  return code;
}

/** Unlocks every key (in use and retired) that has a copy for the passkey used. */
export async function unlockWithPasskey(jmap?: Jmap): Promise<void> {
  const salts: Record<string, Uint8Array> = {};
  for (const key of e2e.keys) {
    for (const [label, copy] of Object.entries(key.copies)) if (label.startsWith("passkey:") && copy.salt) salts[label] = bytes(copy.salt);
  }
  const { label, secret } = await passkeyPrf(salts);
  const keys = await keyring();
  for (const key of e2e.keys) {
    const copy = key.copies[label];
    if (!copy) continue;
    const fingerprint = keys.unlock(bytes(copy.protected), secret);
    if (!key.retired) e2e.unlocked = fingerprint;
  }
  if (!e2e.unlocked) throw new Error("this passkey has no copy of the key in use");
  if (jmap) await completeCopies(jmap).catch(() => undefined);
}

/** Lets a passkey unlock the key in use from now on (it must be unlocked here). */
export async function addPasskey(jmap: Jmap): Promise<void> {
  const key = current();
  if (!key || e2e.unlocked !== key.id) throw new Error("unlock the key first");
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const { label, secret } = await passkeyPrf(salt);
  const copy = { protected: base64((await keyring()).protect(key.id, secret)), salt: base64(salt) };
  await jmap.set([OPENPGP], "OpenPgpKey", own(jmap), { update: { [key.id]: { [`copies/${label}`]: copy } } });
  await refresh(jmap);
}

export async function removeCopy(jmap: Jmap, label: string): Promise<void> {
  const key = current();
  if (!key) return;
  await jmap.set([OPENPGP], "OpenPgpKey", own(jmap), { update: { [key.id]: { [`copies/${label}`]: null } } });
  await refresh(jmap);
}

/** Switches encryption of the account's mail on arrival on or off. */
export async function setMail(jmap: Jmap, on: boolean): Promise<void> {
  await jmap.set([OPENPGP], "E2eSettings", own(jmap), { update: { singleton: { mail: on } } });
  await refresh(jmap);
}

/** The key, armored and unprotected – for the user to keep elsewhere. */
export async function exportSecret(): Promise<string> {
  if (!e2e.unlocked) throw new Error("unlock the key first");
  return (await keyring()).exportSecret(e2e.unlocked);
}

/** Forgets the unlocked keys on this page. */
export async function lock(): Promise<void> {
  if (!ring) return;
  for (const key of e2e.keys) ring.forget(key.id);
  e2e.unlocked = undefined;
}

/** The fingerprints of the keys of `addresses` (looked up once per page): an address without any has none. */
export async function lookup(jmap: Jmap, addresses: string[]): Promise<Map<string, string[]>> {
  const wanted = [...new Set(addresses.map((a) => a.toLowerCase()))].filter((a) => !known.has(a));
  if (wanted.length > 0) {
    const result = await jmap.call<{ list: { email: string; keys: { publicKey: string }[] }[] }>([OPENPGP], "OpenPgpKey/lookup", {
      accountId: own(jmap),
      emails: wanted,
    });
    const keys = await keyring();
    for (const entry of result.list) {
      const fingerprints: string[] = [];
      for (const key of entry.keys) {
        try {
          fingerprints.push(keys.addPublic(bytes(key.publicKey)));
        } catch {
          // Not a key this app can use.
        }
      }
      known.set(entry.email.toLowerCase(), fingerprints);
    }
  }
  return new Map(addresses.map((a) => [a.toLowerCase(), known.get(a.toLowerCase()) ?? []]));
}

/** The keyring, for decrypting and encrypting – only once the key is unlocked. */
export async function unlockedRing(): Promise<Keyring | undefined> {
  return e2e.unlocked ? keyring() : undefined;
}

/** Whether mail could be sent end-to-end encrypted from here at all. */
export function canEncrypt(jmap: Jmap): boolean {
  return e2e.available && !!e2e.unlocked && MAIL in jmap.session.capabilities;
}
