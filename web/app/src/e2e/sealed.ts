// SPDX-License-Identifier: MIT
// Encrypted calendars and address books in the web app (RFC 0006, 7): a collection with a key of its own, made here,
// its secret wrapped for each member's key (`CollectionKey`). Its entries are JSON objects – events and contacts as
// the app describes them – encrypted to the collection's key and signed (`SealedItem`); kernoid stores them blind.

import { type Jmap, JmapError } from "../jmap.js";
import { base64, e2e, OPENPGP, unlockedRing } from "./e2e.svelte.js";

const binary = (text: string): Uint8Array => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

/** Unlocked collections on this page: collection id → the fingerprint of its key in the keyring. */
const unlocked = new Map<string, string>();

/** The collection's key in this page's keyring – `undefined` while the account's key is locked or nobody gave it. */
async function collectionKey(jmap: Jmap, using: string, accountId: string, collection: string): Promise<string | undefined> {
  const known = unlocked.get(collection);
  if (known) return known;
  const ring = await unlockedRing();
  if (!ring) return undefined;
  const result = await jmap.call<{ list: { sealed: string | null }[] }>([using, OPENPGP], "CollectionKey/get", { accountId, ids: [collection] });
  const sealed = result.list[0]?.sealed;
  if (!sealed) return undefined;
  try {
    const fingerprint = ring.importSecret(ring.decrypt(binary(sealed), []).data);
    unlocked.set(collection, fingerprint);
    return fingerprint;
  } catch {
    return undefined;
  }
}

/** The decrypted entries of an encrypted collection; `locked` if they cannot be read here. */
export async function sealedEntries<T>(
  jmap: Jmap,
  using: string,
  accountId: string,
  collection: string,
): Promise<{ locked: boolean; entries: { id: string; value: T }[] }> {
  const fingerprint = await collectionKey(jmap, using, accountId, collection);
  const ring = await unlockedRing();
  if (!fingerprint || !ring) return { locked: true, entries: [] };
  const result = await jmap.call<{ list: { id: string; data: string }[] }>([using, OPENPGP], "SealedItem/get", { accountId, collectionId: collection });
  const entries: { id: string; value: T }[] = [];
  for (const item of result.list) {
    try {
      entries.push({ id: item.id, value: JSON.parse(new TextDecoder().decode(ring.decrypt(binary(item.data), []).data)) as T });
    } catch {
      // Not readable with this key.
    }
  }
  return { locked: false, entries };
}

/** Stores an entry – new, or replacing `id` – encrypted to the collection and signed with the account's key. */
export async function putSealed(jmap: Jmap, using: string, accountId: string, collection: string, id: string | undefined, value: unknown): Promise<void> {
  const fingerprint = await collectionKey(jmap, using, accountId, collection);
  const ring = await unlockedRing();
  if (!fingerprint || !ring) throw new JmapError("locked", "unlock your key first (account page)");
  const data = base64(ring.encrypt(new TextEncoder().encode(JSON.stringify(value)), [fingerprint], e2e.unlocked, false));
  const change = id ? { update: { [id]: { data } } } : { create: { e: { data } } };
  const result = await jmap.call<{ notCreated?: Record<string, { type: string; description?: string }> | null; notUpdated?: Record<string, { type: string; description?: string }> | null }>(
    [using, OPENPGP],
    "SealedItem/set",
    { accountId, collectionId: collection, ...change },
  );
  const failed = Object.values(result.notCreated ?? {})[0] ?? Object.values(result.notUpdated ?? {})[0];
  if (failed) throw new JmapError(failed.type, failed.description);
}

export async function removeSealed(jmap: Jmap, using: string, accountId: string, collection: string, id: string): Promise<void> {
  await jmap.call([using, OPENPGP], "SealedItem/set", { accountId, collectionId: collection, destroy: [id] });
}

/** Makes an encrypted calendar or address book: its key here, the secret wrapped for the account's own key. */
export async function createSealedCollection(jmap: Jmap, using: string, type: "Calendar" | "AddressBook", accountId: string, name: string): Promise<void> {
  const ring = await unlockedRing();
  const own = e2e.unlocked;
  if (!ring || !own) throw new JmapError("locked", "unlock your key first (account page)");
  const fingerprint = ring.generate("pqc", [`collection-${crypto.randomUUID()}@vault.invalid`]);
  const secret = new TextEncoder().encode(ring.exportSecret(fingerprint));
  const result = await jmap.set([using, OPENPGP], type, accountId, {
    create: {
      c: { name, "kernoid:newEncrypted": { publicKey: base64(ring.publicKey(fingerprint)), sealed: base64(ring.encrypt(secret, [own], undefined, false)) } },
    },
  });
  const id = (result.created as Record<string, { id: string }> | undefined)?.c?.id;
  if (id) unlocked.set(id, fingerprint);
}
