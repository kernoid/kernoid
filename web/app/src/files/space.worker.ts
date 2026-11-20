// SPDX-License-Identifier: AGPL-3.0-or-later
// The worker of vaults on spaces (RFC 0010, 5): kit/vault as WebAssembly (`@kernoid/vault`) – the foundation's streams,
// their keys and a SQLite store in memory – with the relay reached by synchronous requests, which only a worker may
// make. After each change the store is kept in IndexedDB (one per account, under its login name) and read back when
// the worker starts. Keys of streams are in it: **OPEN**, as on devices – not in a key store of the system.
//
// Messages: `{ id, method, args }` in, `{ id, result }` or `{ id, error }` out; `open` first, with the account.

import init, { WebVaults } from "@kernoid/vault";

const DB = "kernoid-vaults";
const STORE = "stores";

let vaults: WebVaults | undefined;
let key = "";

function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function load(name: string): Promise<Uint8Array | undefined> {
  const db = await database();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(name);
    request.onsuccess = () => resolve(request.result as Uint8Array | undefined);
    request.onerror = () => reject(request.error);
  });
}

async function keep(): Promise<void> {
  if (!vaults) return;
  const bytes = vaults.save();
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).put(bytes, key);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
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
