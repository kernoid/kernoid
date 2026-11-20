// SPDX-License-Identifier: AGPL-3.0-or-later
// Vaults on spaces in the web app (RFC 0010, 5): a vault is a space of kernoid's relay, kept end to end through the
// foundation's streams – in a worker (`space.worker.ts`), as WebAssembly. Its directory in the file store only names
// the space (`kernoid:space`) and holds nothing. Here, on the page: the JMAP side – making the directory, each member's
// recovery code of the space sealed to their OpenPGP key with the page's keyring (`VaultKey/*`) – and the calls into
// the worker. Members are accounts, named in the space by their id.

import { base64, e2e, lookup, OPENPGP, unlockedRing } from "../e2e/e2e.svelte.js";
import { FILENODE, type Jmap, JmapError } from "../jmap.js";
import { children, type FileNode, level as levelOf, type Principal, principals } from "./model.js";
import { openContent, openNames } from "./vault.js";

const USING = [FILENODE, OPENPGP];
export const SPACE_VAULTS = "https://kernoid.dev/jmap/space-vaults";

/** Something in a directory of a vault on a space. */
export interface Entry {
  id: string;
  name: string;
  directory: boolean;
  trashed: boolean;
  size: number;
  mediaType: string | null;
  modified: string | null;
}

const binary = (text: string): Uint8Array => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

let worker: Worker | undefined;
let opened: Promise<void> | undefined;
let next = 0;
const waiting = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();

function call<T>(method: string, ...args: unknown[]): Promise<T> {
  worker ??= (() => {
    const made = new Worker(new URL("./space.worker.ts", import.meta.url), { type: "module" });
    made.onmessage = (event: MessageEvent<{ id: number; result?: unknown; error?: string }>) => {
      const handler = waiting.get(event.data.id);
      if (!handler) return;
      waiting.delete(event.data.id);
      if (event.data.error !== undefined) handler.reject(new JmapError("vault", event.data.error));
      else handler.resolve(event.data.result);
    };
    return made;
  })();
  const id = ++next;
  return new Promise<T>((resolve, reject) => {
    waiting.set(id, { resolve: resolve as (value: unknown) => void, reject });
    worker!.postMessage({ id, method, args });
  });
}

/** The account's vaults in the worker, opened once per page. */
async function vaults(jmap: Jmap): Promise<void> {
  opened ??= call<void>("open", jmap.session.username, "web");
  return opened;
}

/** Whether new vaults are made on spaces here: the server names a relay for them. */
export function available(jmap: Jmap): boolean {
  return SPACE_VAULTS in (jmap.session.capabilities ?? {});
}

/** The relay of vaults, on this page's origin (the session's URLs may name another port in development). */
function relay(jmap: Jmap): string {
  const named = (jmap.session.capabilities[SPACE_VAULTS] as { relayUrl?: string } | undefined)?.relayUrl;
  if (!named) throw new JmapError("unknownCapability", "this server keeps no vaults on spaces");
  return location.origin + new URL(named).pathname;
}

function spaceOf(node: FileNode): string {
  const space = node["kernoid:space"];
  if (!space) throw new JmapError("invalidArguments", "not a vault on a space");
  return space;
}

async function sealCode(code: Uint8Array, to: string[]): Promise<string> {
  const ring = await unlockedRing();
  if (!ring) throw new JmapError("locked", "unlock your key first (account page)");
  return base64(ring.encrypt(code, to, undefined, false));
}

/** Makes a vault on a space in `parent`: founded at the relay with this page's session, the account's recovery code
 * sealed to its own key, the directory naming the space. Returns the directory's id. */
export async function create(jmap: Jmap, accountId: string, parent: string | null, name: string): Promise<string> {
  const own = e2e.unlocked;
  if (!own) throw new JmapError("locked", "unlock your key first (account page)");
  await vaults(jmap);
  const me = jmap.account(FILENODE);
  const founded = await call<{ space: string; code: Uint8Array }>("found", relay(jmap), null, "web", me, name);
  const created = await jmap.set(USING, "FileNode", accountId, {
    create: {
      v: {
        "@type": "Directory",
        parentId: parent,
        name: `k-${founded.space}`,
        "kernoid:newVault": { space: founded.space, sealed: await sealCode(founded.code, [own]) },
      },
    },
  });
  const id = (created.created as Record<string, { id: string }> | undefined)?.v?.id;
  if (!id) throw new JmapError("serverFail", "the vault's directory was not made");
  return id;
}

/** Brings this page into the vault – with the account's code of it, opened with its key – or reads what is new.
 * False while no member made the account one. */
export async function enter(jmap: Jmap, accountId: string, node: FileNode): Promise<boolean> {
  await vaults(jmap);
  const space = spaceOf(node);
  // A page removed from the vault – its member came in again at another level – forgets it and comes in anew.
  if ((await call<boolean>("hasSpace", space)) && (await call<boolean>("sync", space))) return true;
  const ring = await unlockedRing();
  if (!ring) throw new JmapError("locked", "unlock your key first (account page)");
  const result = await jmap.call<{ list: { sealed: string | null }[] }>(USING, "VaultKey/get", { accountId, ids: [node.id] });
  const sealed = result.list[0]?.sealed;
  if (!sealed) return false;
  const code = ring.decrypt(binary(sealed), []).data;
  await call("recover", relay(jmap), space, code, "web");
  return true;
}

/** How far this page may go in the vault. */
export async function level(jmap: Jmap, node: FileNode): Promise<Level> {
  await vaults(jmap);
  return call<Level>("myLevel", spaceOf(node));
}

/** The vault's name, once this page has it. */
export async function name(jmap: Jmap, node: FileNode): Promise<string | undefined> {
  await vaults(jmap);
  return (await call<string | undefined>("name", spaceOf(node))) ?? undefined;
}

export async function list(jmap: Jmap, node: FileNode, directory: string | null): Promise<Entry[]> {
  await vaults(jmap);
  return JSON.parse(await call<string>("list", spaceOf(node), directory)) as Entry[];
}

export async function makeDirectory(jmap: Jmap, node: FileNode, parent: string | null, directoryName: string): Promise<string> {
  await vaults(jmap);
  return call<string>("makeDirectory", spaceOf(node), parent, directoryName);
}

/** Puts a file of the device into a directory of the vault; one of the same name gets a new version. */
export async function upload(jmap: Jmap, node: FileNode, parent: string | null, file: File): Promise<void> {
  const here = await list(jmap, node, parent);
  const same = here.find((e) => !e.directory && e.name === file.name);
  const data = new Uint8Array(await file.arrayBuffer());
  await call("putFile", spaceOf(node), parent, file.name, data, file.type || null, new Date(file.lastModified).toISOString(), same?.id ?? null);
}

export async function read(jmap: Jmap, node: FileNode, file: string): Promise<Uint8Array> {
  await vaults(jmap);
  return call<Uint8Array>("readFile", spaceOf(node), file);
}

/** A file of the vault, decrypted here and saved under its name. */
export async function save(jmap: Jmap, node: FileNode, entry: Entry): Promise<void> {
  const data = await read(jmap, node, entry.id);
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([data.slice().buffer], { type: entry.mediaType ?? "application/octet-stream" }));
  link.download = entry.name;
  link.click();
}

export async function rename(jmap: Jmap, node: FileNode, parent: string | null, entry: string, newName: string): Promise<void> {
  await vaults(jmap);
  await call("rename", spaceOf(node), parent, entry, newName);
}

export async function setTrashed(jmap: Jmap, node: FileNode, parent: string | null, entry: string, trashed: boolean): Promise<void> {
  await vaults(jmap);
  await call("setTrashed", spaceOf(node), parent, entry, trashed);
}

export async function moveTo(jmap: Jmap, node: FileNode, from: string | null, entry: string, to: string | null): Promise<void> {
  await vaults(jmap);
  await call("moveTo", spaceOf(node), from, entry, to);
}

export async function remove(jmap: Jmap, node: FileNode, parent: string | null, entry: string): Promise<void> {
  await vaults(jmap);
  await call("remove", spaceOf(node), parent, entry);
}

/** Every directory of the vault but `except` and what lies below it, with its path – where something may move. */
export async function directories(jmap: Jmap, node: FileNode, except: string): Promise<{ id: string | null; path: string }[]> {
  const found: { id: string | null; path: string }[] = [{ id: null, path: "" }];
  const pending: { id: string | null; path: string }[] = [{ id: null, path: "" }];
  while (pending.length > 0) {
    const at = pending.pop()!;
    for (const e of await list(jmap, node, at.id)) {
      if (!e.directory || e.trashed || e.id === except) continue;
      const path = at.path ? `${at.path} / ${e.name}` : e.name;
      found.push({ id: e.id, path });
      pending.push({ id: e.id, path });
    }
  }
  return found;
}

export type Level = "read" | "edit" | "full";

/** After sharing a vault: brings its members in line with whom it is shared with and how far – who is new becomes a
 * member with a code sealed to their key, who is gone leaves, who has another level comes in again with it. Groups and
 * people without a key wait (**OPEN**: a group's members); a member already there without a key keeps their level.
 * Returns those who wait. */
export async function share(jmap: Jmap, accountId: string, node: FileNode, people: { principal: Principal; level: Level }[]): Promise<Principal[]> {
  await enter(jmap, accountId, node);
  const space = spaceOf(node);
  const current = JSON.parse(await call<string>("memberLevels", space)) as [string, Level][];
  const waitingFor: Principal[] = [];
  const wanted: [string, Level][] = [];
  const keysOf = new Map<string, string[]>();
  // A group's members each become a member at the group's level – or higher, where shared with them too.
  const rank: Record<Level, number> = { read: 0, edit: 1, full: 2 };
  const persons = people.filter(({ principal }) => principal.type !== "group").map((entry) => ({ ...entry }));
  for (const { principal: group, level } of people.filter(({ principal }) => principal.type === "group")) {
    for (const member of await principals(jmap, group["kernoid:members"] ?? [])) {
      const known = persons.find(({ principal }) => principal.id === member.id);
      if (!known) persons.push({ principal: member, level });
      else if (rank[level] > rank[known.level]) known.level = level;
    }
  }
  for (const { principal, level } of persons) {
    const keys = principal.type === "individual" && principal.email ? ((await lookup(jmap, [principal.email])).get(principal.email.toLowerCase()) ?? []) : [];
    if (keys.length === 0) {
      const now = current.find(([account]) => account === principal.id);
      if (now) wanted.push(now);
      else waitingFor.push(principal);
      continue;
    }
    wanted.push([principal.id, level]);
    keysOf.set(principal.id, keys);
  }
  const done = JSON.parse(await call<string>("setMembers", space, jmap.account(FILENODE), JSON.stringify(wanted))) as {
    codes: [string, number[]][];
    removed: string[];
  };
  const update: Record<string, string | null> = {};
  for (const [member, code] of done.codes) {
    const keys = keysOf.get(member);
    if (keys) update[`members/${member}`] = await sealCode(Uint8Array.from(code), keys);
  }
  for (const member of done.removed) update[`members/${member}`] = null;
  if (Object.keys(update).length > 0) {
    const result = await jmap.call<{ notUpdated?: Record<string, { type: string; description?: string }> | null }>(USING, "VaultKey/set", {
      accountId,
      update: { [node.id]: update },
    });
    const failed = result.notUpdated?.[node.id];
    if (failed) throw new JmapError(failed.type, failed.description);
  }
  return waitingFor;
}

/** Brings the members in line with whom the vault's directory is shared with now – after a grant changed elsewhere
 * (the administration, another app). Only a page that may add members does it. */
export async function reconcile(jmap: Jmap, accountId: string, node: FileNode): Promise<Principal[]> {
  if ((await level(jmap, node)) !== "full") return [];
  const got = await jmap.call<{ list: FileNode[] }>([FILENODE], "FileNode/get", { accountId, ids: [node.id], properties: ["shareWith"] });
  const shares = got.list[0]?.shareWith ?? {};
  const people = (await principals(jmap, Object.keys(shares))).map((principal) => ({
    principal,
    level: levelOf(shares[principal.id]!) as Level,
  }));
  return share(jmap, accountId, node, people);
}

/** Renames the vault itself. */
export async function renameVault(jmap: Jmap, accountId: string, node: FileNode, newName: string): Promise<void> {
  await enter(jmap, accountId, node);
  await call("renameVault", spaceOf(node), newName);
}

/** Ends a member's membership: what is written from now on is out of their reach; their code at the server goes. */
export async function removeMember(jmap: Jmap, accountId: string, node: FileNode, member: string): Promise<void> {
  await enter(jmap, accountId, node);
  await call("removeMember", spaceOf(node), member);
  await jmap.call(USING, "VaultKey/set", { accountId, update: { [node.id]: { [`members/${member}`]: null } } });
}

/** Copies an OpenPGP vault (RFC 0006, 6) into a new vault on a space beside it – name, directories, files, members –;
 * returns the new vault's id. The old one stays until it is removed. */
export async function moveVault(jmap: Jmap, accountId: string, old: FileNode): Promise<string> {
  if (old.locked || !old["kernoid:vault"]) throw new JmapError("locked", "the vault's key is not at hand");
  const id = await create(jmap, accountId, old.parentId, old.name);
  const got = await jmap.call<{ list: FileNode[] }>([FILENODE], "FileNode/get", { accountId, ids: [id], properties: ["kernoid:space"] });
  const target: FileNode = { ...old, id, "kernoid:space": got.list[0]?.["kernoid:space"] ?? null };
  const pending: { from: string; into: string | null }[] = [{ from: old.id, into: null }];
  while (pending.length > 0) {
    const { from, into } = pending.pop()!;
    const nodes = await openNames(jmap, accountId, await children(jmap, accountId, from));
    for (const child of nodes) {
      if (child["@type"] === "Directory") {
        pending.push({ from: child.id, into: await makeDirectory(jmap, target, into, child.name) });
      } else {
        const data = await openContent(jmap, accountId, child);
        await call("putFile", spaceOf(target), into, child.name, data, child.mediaType ?? null, child.modified ?? null, null);
      }
    }
  }
  const keys = await jmap.call<{ list: { members: string[] }[] }>(USING, "VaultKey/get", { accountId, ids: [old.id] });
  const me = jmap.account(FILENODE);
  const others = (keys.list[0]?.members ?? []).filter((m) => m !== me);
  if (others.length > 0) {
    const people = await jmap.call<{ list: Principal[] }>(["urn:ietf:params:jmap:principals"], "Principal/get", {
      accountId: jmap.session.primaryAccounts["urn:ietf:params:jmap:principals"],
      ids: others,
    });
    // The OpenPGP vault knew no levels: whoever had its key may edit.
    await share(jmap, accountId, target, people.list.map((principal) => ({ principal, level: "edit" as Level })));
  }
  return id;
}
