// SPDX-License-Identifier: MIT
// Vaults in the web app (RFC 0006, 6): directories whose content only their members read. A vault has an OpenPGP key
// of its own, made here; its secret key goes to the server only wrapped – encrypted to the key of each member. Inside,
// files are uploaded encrypted to the vault's key and names are an id with the real name encrypted beside it
// (`kernoid:encryptedName`). Everything here needs the account's own key unlocked (`e2e.svelte.ts`).

import { base64, e2e, lookup, OPENPGP, unlockedRing } from "../e2e/e2e.svelte.js";
import { FILENODE, type Jmap, JmapError } from "../jmap.js";
import type { FileNode, Principal } from "./model.js";

const USING = [FILENODE, OPENPGP];

const binary = (text: string): Uint8Array => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

/** Unlocked vaults on this page: vault id → the fingerprint of its key in the keyring. */
const unlocked = new Map<string, string>();

/** Whether a node lies in a vault (or is one). */
export function inVault(node: Pick<FileNode, "kernoid:vault">): boolean {
  return Boolean(node["kernoid:vault"]);
}

/** A name for a node inside a vault: an id, unique among siblings; the real name goes encrypted beside it. */
function opaqueName(): string {
  return `k-${crypto.randomUUID()}`;
}

/** The vault's key in this page's keyring: its wrapped secret fetched and unwrapped with the account's key. */
async function vaultKey(jmap: Jmap, accountId: string, vault: string): Promise<string | undefined> {
  const known = unlocked.get(vault);
  if (known) return known;
  const ring = await unlockedRing();
  if (!ring) return undefined;
  const result = await jmap.call<{ list: { id: string; sealed: string | null }[] }>(USING, "VaultKey/get", { accountId, ids: [vault] });
  const sealed = result.list[0]?.sealed;
  if (!sealed) return undefined;
  try {
    const secret = ring.decrypt(binary(sealed), []).data;
    const fingerprint = ring.importSecret(secret);
    unlocked.set(vault, fingerprint);
    return fingerprint;
  } catch {
    return undefined;
  }
}

/** Fills in the real names of nodes in vaults whose key is at hand; the others are shown as locked. */
export async function openNames(jmap: Jmap, accountId: string, nodes: FileNode[]): Promise<FileNode[]> {
  const ring = await unlockedRing();
  for (const node of nodes) {
    const vault = node["kernoid:vault"];
    const sealed = node["kernoid:encryptedName"];
    if (!vault || !sealed) continue;
    node.locked = true;
    if (!ring || !(await vaultKey(jmap, accountId, vault))) continue;
    try {
      node.name = new TextDecoder().decode(ring.decrypt(binary(sealed), []).data);
      node.locked = false;
    } catch {
      // Encrypted to a key not at hand.
    }
  }
  return nodes;
}

/** The fingerprint of an unlocked vault's key, or an error saying why there is none. */
async function needKey(jmap: Jmap, accountId: string, vault: string): Promise<string> {
  if (!e2e.unlocked) throw new JmapError("locked", "unlock your key first (account page)");
  const fingerprint = await vaultKey(jmap, accountId, vault);
  if (!fingerprint) throw new JmapError("locked", "no member gave you this vault's key yet");
  return fingerprint;
}

/** The encrypted name of a node in a vault, base64. */
async function sealName(vaultFingerprint: string, name: string): Promise<string> {
  const ring = await unlockedRing();
  if (!ring) throw new JmapError("locked", "unlock your key first");
  return base64(ring.encrypt(new TextEncoder().encode(name), [vaultFingerprint], undefined, false));
}

/** Makes a vault: its key here, its secret wrapped for the account's own key, its name encrypted. */
export async function createVault(jmap: Jmap, accountId: string, parent: string | null, name: string): Promise<void> {
  const ring = await unlockedRing();
  const own = e2e.unlocked;
  if (!ring || !own) throw new JmapError("locked", "unlock your key first (account page)");
  const fingerprint = ring.generate("pqc", [`vault-${crypto.randomUUID()}@vault.invalid`]);
  const secret = new TextEncoder().encode(ring.exportSecret(fingerprint));
  const created = await jmap.set(USING, "FileNode", accountId, {
    create: {
      v: {
        "@type": "Directory",
        parentId: parent,
        name: opaqueName(),
        "kernoid:encryptedName": await sealName(fingerprint, name),
        "kernoid:newVault": { publicKey: base64(ring.publicKey(fingerprint)), sealed: base64(ring.encrypt(secret, [own], undefined, false)) },
      },
    },
  });
  const id = (created.created as Record<string, { id: string }> | undefined)?.v?.id;
  if (id) unlocked.set(id, fingerprint);
}

/** A directory inside a vault. */
export async function createDirectoryIn(jmap: Jmap, accountId: string, vault: string, parent: string, name: string): Promise<void> {
  const fingerprint = await needKey(jmap, accountId, vault);
  await jmap.set(USING, "FileNode", accountId, {
    create: { d: { "@type": "Directory", parentId: parent, name: opaqueName(), "kernoid:encryptedName": await sealName(fingerprint, name) } },
  });
}

/** Uploads a file into a vault, encrypted here – whole, in memory (**OPEN**: streaming for very large files). A file of
 * the same real name gets the new content. */
export async function uploadInto(
  jmap: Jmap,
  accountId: string,
  vault: string,
  parent: string,
  file: File,
  progress: (sent: number, total: number) => void,
  existing?: FileNode,
): Promise<void> {
  const fingerprint = await needKey(jmap, accountId, vault);
  const ring = await unlockedRing();
  if (!ring) throw new JmapError("locked", "unlock your key first");
  const sealed = ring.encrypt(new Uint8Array(await file.arrayBuffer()), [fingerprint], e2e.unlocked, false);
  const { blobId } = await jmap.uploadInPieces(accountId, new Blob([sealed.slice().buffer], { type: "application/octet-stream" }), progress);
  const modified = new Date(file.lastModified).toISOString();
  const mediaType = file.type || null;
  if (existing && existing["@type"] === "File") {
    await jmap.set(USING, "FileNode", accountId, { update: { [existing.id]: { blobId, mediaType, modified } } });
    return;
  }
  await jmap.set(USING, "FileNode", accountId, {
    create: { f: { "@type": "File", parentId: parent, name: opaqueName(), "kernoid:encryptedName": await sealName(fingerprint, file.name), blobId, mediaType, modified } },
  });
}

/** Renames a node in a vault: a new id for a name, the real one encrypted anew. */
export async function renameIn(jmap: Jmap, accountId: string, node: FileNode, name: string): Promise<void> {
  const vault = node["kernoid:vault"];
  if (!vault) return;
  const fingerprint = await needKey(jmap, accountId, vault);
  await jmap.set(USING, "FileNode", accountId, {
    update: { [node.id]: { name: opaqueName(), "kernoid:encryptedName": await sealName(fingerprint, name) } },
  });
}

/** A file of a vault, downloaded and decrypted here, saved under its real name – never opened in the app. */
export async function saveFrom(jmap: Jmap, accountId: string, node: FileNode, path: string): Promise<void> {
  const vault = node["kernoid:vault"];
  if (!vault) return;
  await needKey(jmap, accountId, vault);
  const ring = await unlockedRing();
  if (!ring) throw new JmapError("locked", "unlock your key first");
  const response = await fetch(path, { credentials: "same-origin" });
  if (!response.ok) throw new JmapError("downloadFailed", String(response.status));
  const plain = ring.decrypt(new Uint8Array(await response.arrayBuffer()), []).data;
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([plain.slice().buffer], { type: node.mediaType ?? "application/octet-stream" }));
  link.download = node.name;
  link.click();
}

/** After sharing a vault: gives its key to every person shared with who has a key and has none of it yet. Groups and
 * people without a key wait (**OPEN**: a group's members). Returns those who still wait. */
export async function giveKeys(jmap: Jmap, accountId: string, vault: string, people: Principal[]): Promise<Principal[]> {
  const fingerprint = await needKey(jmap, accountId, vault);
  const ring = await unlockedRing();
  if (!ring) throw new JmapError("locked", "unlock your key first");
  const state = await jmap.call<{ list: { members: string[] }[] }>(USING, "VaultKey/get", { accountId, ids: [vault] });
  const members = new Set(state.list[0]?.members ?? []);
  const waiting: Principal[] = [];
  const secret = new TextEncoder().encode(ring.exportSecret(fingerprint));
  const update: Record<string, string> = {};
  for (const person of people) {
    if (members.has(person.id)) continue;
    const keys = person.type === "individual" && person.email ? ((await lookup(jmap, [person.email])).get(person.email.toLowerCase()) ?? []) : [];
    if (keys.length === 0) {
      waiting.push(person);
      continue;
    }
    update[`members/${person.id}`] = base64(ring.encrypt(secret, keys, undefined, false));
  }
  if (Object.keys(update).length > 0) {
    const result = await jmap.call<{ notUpdated?: Record<string, { type: string; description?: string }> | null }>(USING, "VaultKey/set", {
      accountId,
      update: { [vault]: update },
    });
    const failed = result.notUpdated?.[vault];
    if (failed) throw new JmapError(failed.type, failed.description);
  }
  return waiting;
}
