// SPDX-License-Identifier: AGPL-3.0-or-later
// The worker of vaults on spaces (RFC 0010, 5): kit/vault as WebAssembly (`@kernoid/vault`) – the foundation's streams,
// their keys and a SQLite store in memory – with the relay reached by synchronous requests, which only a worker may
// make. After each change the store is kept in IndexedDB (one per account, under its login name) and read back when
// the worker starts – sealed with AES-GCM under a key the browser made for it and keeps as a non-extractable
// CryptoKey: no script, this page's included, can read the key out; the stored bytes alone say nothing.
//
// Messages: `{ id, method, args }` in, `{ id, result }` or `{ id, error }` out; `open` first, with the account.

import init, { WebVaults } from "@kernoid/vault";

const DB = "kernoid-vaults";
const STORE = "stores";
const KEYS = "keys";

let vaults: WebVaults | undefined;
let key = "";

function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      if (!db.objectStoreNames.contains(KEYS)) db.createObjectStore(KEYS);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function get<T>(db: IDBDatabase, store: string, name: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(store).objectStore(store).get(name);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
  });
}

function put(db: IDBDatabase, store: string, name: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(store, "readwrite");
    transaction.objectStore(store).put(value, name);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

let sealing: CryptoKey | undefined;

/** The account's sealing key: made once, kept as a CryptoKey that cannot be exported. */
async function sealingKey(name: string): Promise<CryptoKey> {
  const db = await database();
  sealing = await get<CryptoKey>(db, KEYS, name);
  if (!sealing) {
    sealing = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await put(db, KEYS, name, sealing);
  }
  return sealing;
}

/** The store as last kept – unsealed; none, or what the key no longer opens, starts afresh (the vaults come again from
 * the relay with the account's code). */
async function load(name: string): Promise<Uint8Array | undefined> {
  const kept = await get<{ iv: Uint8Array<ArrayBuffer>; data: ArrayBuffer } | Uint8Array>(await database(), STORE, name);
  if (!kept || kept instanceof Uint8Array) return undefined;
  try {
    const key = await sealingKey(name);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: kept.iv }, key, kept.data));
  } catch {
    return undefined;
  }
}

async function keep(): Promise<void> {
  if (!vaults) return;
  const bytes = vaults.save();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, sealing ?? (await sealingKey(key)), bytes.slice().buffer);
  await put(await database(), STORE, key, { iv, data });
}

/** A request to the relay, synchronous: the cookie of the instance goes with it, marked as the app's own. */
function send(method: string, url: string, headers: [string, string][], body: Uint8Array | null): { status: number; body: Uint8Array } {
  const request = new XMLHttpRequest();
  request.open(method, url, false);
  request.responseType = "arraybuffer";
  request.withCredentials = true;
  for (const [name, value] of headers) request.setRequestHeader(name, value);
  request.setRequestHeader("kernoid-csrf", "1");
  request.send(body ? body.slice().buffer : null);
  return { status: request.status, body: new Uint8Array((request.response as ArrayBuffer | null) ?? new ArrayBuffer(0)) };
}

type Args = unknown[];

/** What changes the store, and is kept after it. */
const CHANGES = new Set([
  "found",
  "recover",
  "sync",
  "renameVault",
  "makeDirectory",
  "putFile",
  "rename",
  "setTrashed",
  "moveTo",
  "remove",
  "setMembers",
  "removeMember",
]);

async function run(method: string, args: Args): Promise<unknown> {
  if (method === "open") {
    const [account, device] = args as [string, string];
    await init();
    key = account;
    await sealingKey(account);
    vaults = new WebVaults(await load(account), device, send);
    return null;
  }
  if (!vaults) throw new Error("the vaults are not open");
  const target = vaults as unknown as Record<string, (...a: Args) => unknown>;
  const fn = target[method];
  if (typeof fn !== "function") throw new Error(`no such method: ${method}`);
  let result = fn.apply(vaults, args);
  if (result && typeof result === "object" && "space" in result && "code" in result) {
    const founded = result as { space: string; code: Uint8Array; free(): void };
    result = { space: founded.space, code: founded.code };
    founded.free();
  }
  if (CHANGES.has(method)) await keep();
  return result;
}

self.onmessage = async (event: MessageEvent<{ id: number; method: string; args: Args }>) => {
  const { id, method, args } = event.data;
  try {
    const result = await run(method, args);
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: error instanceof Error ? error.message : String(error) });
  }
};
