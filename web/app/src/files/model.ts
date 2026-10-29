// SPDX-License-Identifier: MIT
// Files over JMAP (draft-ietf-jmap-filenode): the stores the user reaches – their own, those shared with them, the
// tenant's drives –, directories and files with the rights on them, uploads, sharing, versions, the trash.

import { FILENODE, FILE_LINKS, FILE_VERSIONS, type Jmap, PRINCIPALS } from "../jmap.js";

export interface Rights {
  mayRead: boolean;
  mayAddChildren: boolean;
  mayRename: boolean;
  mayDelete: boolean;
  mayModifyContent: boolean;
  mayShare: boolean;
}

export interface FileNode {
  "@type": "Directory" | "File";
  id: string;
  parentId: string | null;
  name: string;
  role?: string | null;
  blobId?: string | null;
  size?: number | null;
  mediaType?: string | null;
  modified?: string | null;
  myRights?: Rights;
  shareWith?: Record<string, Rights> | null;
}

/** A store the user reaches. */
export interface Store {
  id: string;
  name: string;
  kind: "own" | "shared" | "drive";
  mayCreateTopLevel: boolean;
}

export interface Version {
  id: string;
  blobId: string;
  size: number;
  modified: string;
  created: string;
  isCurrent: boolean;
}

export interface Principal {
  id: string;
  type: string;
  name: string;
  email: string | null;
}

const PROPERTIES = ["parentId", "name", "role", "blobId", "size", "mediaType", "modified", "myRights", "shareWith"];
const USING = [FILENODE, FILE_VERSIONS, PRINCIPALS];

export const NO_RIGHTS: Rights = { mayRead: false, mayAddChildren: false, mayRename: false, mayDelete: false, mayModifyContent: false, mayShare: false };

/** The levels the app offers when sharing. */
export const LEVELS: Record<"read" | "edit" | "full", Rights> = {
  read: { ...NO_RIGHTS, mayRead: true },
  edit: { mayRead: true, mayAddChildren: true, mayRename: true, mayDelete: true, mayModifyContent: true, mayShare: false },
  full: { mayRead: true, mayAddChildren: true, mayRename: true, mayDelete: true, mayModifyContent: true, mayShare: true },
};

/** The level rights amount to, as the app names it. */
export function level(rights: Rights): "read" | "edit" | "full" {
  if (rights.mayShare) return "full";
  if (rights.mayModifyContent || rights.mayAddChildren) return "edit";
  return "read";
}

export function isDirectory(node: FileNode): boolean {
  return node["@type"] === "Directory";
}

/** Directories first, then by name as people sort them. */
export function sortNodes(nodes: FileNode[], locale: string): FileNode[] {
  return [...nodes].sort((a, b) => Number(isDirectory(b)) - Number(isDirectory(a)) || a.name.localeCompare(b.name, locale));
}

/** A size for people: bytes, kB, MB, GB (powers of 1000). */
export function formatSize(bytes: number, locale: string): string {
  const units = ["B", "kB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const digits = unit === 0 || value >= 100 ? 0 : 1;
  return `${value.toLocaleString(locale, { maximumFractionDigits: digits })} ${units[unit]}`;
}

/** The stores the session lists: the own first, then drives, then other people's. */
export function stores(jmap: Jmap): Store[] {
  const own = jmap.session.primaryAccounts[FILENODE];
  const out: Store[] = [];
  for (const [id, account] of Object.entries(jmap.session.accounts)) {
    const capability = account.accountCapabilities[FILENODE] as { mayCreateTopLevelFileNode?: boolean } | undefined;
    if (!capability) continue;
    const kind = id === own ? "own" : account["kernoid:drive"] ? "drive" : "shared";
    out.push({ id, name: account.name, kind, mayCreateTopLevel: capability.mayCreateTopLevelFileNode ?? false });
  }
  const rank = { own: 0, drive: 1, shared: 2 };
  return out.sort((a, b) => rank[a.kind] - rank[b.kind] || a.name.localeCompare(b.name));
}

/** The nodes in a directory of a store – or at its top, for `null`. */
export async function children(jmap: Jmap, accountId: string, parent: string | null): Promise<FileNode[]> {
  const filter = parent ? { parentId: parent } : { isTopLevel: true };
  const responses = await jmap.request(USING, [
    ["FileNode/query", { accountId, filter }, "q"],
    ["FileNode/get", { accountId, properties: PROPERTIES, "#ids": { resultOf: "q", name: "FileNode/query", path: "/ids" } }, "g"],
  ]);
  return (responses.get("g")?.[0] as { list: FileNode[] } | undefined)?.list ?? [];
}

/** A directory and the ones above it, from the top down. */
export async function path(jmap: Jmap, accountId: string, id: string | null): Promise<FileNode[]> {
  if (!id) return [];
  const result = await jmap.call<{ list: FileNode[] }>(USING, "FileNode/get", { accountId, ids: [id], properties: PROPERTIES, fetchParents: true });
  const byId = new Map(result.list.map((node) => [node.id, node]));
  const out: FileNode[] = [];
  for (let node = byId.get(id); node; node = node.parentId ? byId.get(node.parentId) : undefined) out.unshift(node);
  return out;
}

/** The directory with the role `trash`, if the store has one. */
export async function trash(jmap: Jmap, accountId: string): Promise<FileNode | undefined> {
  const responses = await jmap.request(USING, [
    ["FileNode/query", { accountId, filter: { role: "trash" } }, "q"],
    ["FileNode/get", { accountId, properties: PROPERTIES, "#ids": { resultOf: "q", name: "FileNode/query", path: "/ids" } }, "g"],
  ]);
  return (responses.get("g")?.[0] as { list: FileNode[] } | undefined)?.list[0];
}

async function set(jmap: Jmap, accountId: string, change: Parameters<Jmap["set"]>[3], extra: Record<string, unknown> = {}): Promise<void> {
  await jmap.set(USING, "FileNode", accountId, change, extra);
}

export async function createDirectory(jmap: Jmap, accountId: string, parent: string | null, name: string): Promise<void> {
  await set(jmap, accountId, { create: { d: { "@type": "Directory", parentId: parent, name } } });
}

/** Uploads a file into a directory, telling how far it got. A file of the same name there gets it as new content –
 * the content it had stays as a version; a directory of that name makes the new file's name get a number. */
export async function uploadFile(
  jmap: Jmap,
  accountId: string,
  parent: string | null,
  file: File,
  progress: (sent: number, total: number) => void,
  existing?: FileNode,
): Promise<void> {
  const { blobId } = await jmap.uploadInPieces(accountId, file, progress);
  const modified = new Date(file.lastModified).toISOString();
  if (existing && !isDirectory(existing)) {
    await set(jmap, accountId, { update: { [existing.id]: { blobId, mediaType: file.type || null, modified } } });
    return;
  }
  const created = { "@type": "File", parentId: parent, name: file.name, blobId, mediaType: file.type || null, modified };
  await set(jmap, accountId, { create: { f: created } }, { onExists: "rename" });
}

export async function rename(jmap: Jmap, accountId: string, node: FileNode, name: string): Promise<void> {
  await set(jmap, accountId, { update: { [node.id]: { name } } });
}

/** Moves a node into another directory; a name that is taken there gets a number. */
export async function move(jmap: Jmap, accountId: string, node: FileNode, parent: string | null): Promise<void> {
  await set(jmap, accountId, { update: { [node.id]: { parentId: parent } } }, { onExists: "rename" });
}

/** Destroys a node and all it holds, for good. */
export async function destroy(jmap: Jmap, accountId: string, node: FileNode): Promise<void> {
  await set(jmap, accountId, { destroy: [node.id] }, { onDestroyRemoveChildren: true });
}

export function downloadPath(jmap: Jmap, accountId: string, blobId: string, name: string, type: string | null | undefined): string {
  return jmap.downloadPath(accountId, blobId, name, type ?? "application/octet-stream");
}

/** The current content and the earlier versions of a file, newest first. */
export async function versions(jmap: Jmap, accountId: string, node: FileNode): Promise<Version[]> {
  return (await jmap.call<{ list: Version[] }>(USING, "FileVersion/get", { accountId, nodeId: node.id })).list;
}

/** Makes an earlier version a file's content again. */
export async function restore(jmap: Jmap, accountId: string, node: FileNode, version: Version): Promise<void> {
  await set(jmap, accountId, { update: { [node.id]: { blobId: version.blobId } } });
}

/** People and groups of the tenant whose name or address holds `text`. */
export async function findPrincipals(jmap: Jmap, text: string): Promise<Principal[]> {
  const accountId = jmap.account(PRINCIPALS);
  const responses = await jmap.request(USING, [
    ["Principal/query", { accountId, filter: text.trim() ? { text: text.trim() } : {}, limit: 20 }, "q"],
    ["Principal/get", { accountId, "#ids": { resultOf: "q", name: "Principal/query", path: "/ids" } }, "g"],
  ]);
  return (responses.get("g")?.[0] as { list: Principal[] } | undefined)?.list ?? [];
}

export async function principals(jmap: Jmap, ids: string[]): Promise<Principal[]> {
  if (ids.length === 0) return [];
  return (await jmap.call<{ list: Principal[] }>(USING, "Principal/get", { accountId: jmap.account(PRINCIPALS), ids })).list;
}

/** Sets with whom a directory is shared, replacing what was. */
export async function share(jmap: Jmap, accountId: string, node: FileNode, shareWith: Record<string, Rights>): Promise<void> {
  await set(jmap, accountId, { update: { [node.id]: { shareWith } } });
}

/** A link for people without an account (kernoid's `FileLink`); its token is known only when it is made. */
export interface FileLink {
  id: string;
  nodeId: string;
  expires: string | null;
  hasPassword: boolean;
  created: string;
}

const LINKS = [FILENODE, FILE_LINKS];

/** Whether the server makes links at all. */
export function linksAvailable(jmap: Jmap): boolean {
  return FILE_LINKS in (jmap.session.capabilities ?? {});
}

export async function links(jmap: Jmap, accountId: string, node: FileNode): Promise<FileLink[]> {
  return (await jmap.call<{ list: FileLink[] }>(LINKS, "FileLink/get", { accountId, nodeId: node.id })).list;
}

/** Makes a link; answers its address – the only time it can be shown. */
export async function createLink(jmap: Jmap, accountId: string, node: FileNode, expires: string | null, password: string | null): Promise<string> {
  const result = await jmap.call<{ created?: Record<string, { token: string }>; notCreated?: Record<string, { type: string; description?: string }> }>(
    LINKS,
    "FileLink/set",
    { accountId, create: { l: { nodeId: node.id, expires, password } } },
  );
  const made = result.created?.l;
  if (!made) {
    const failure = result.notCreated?.l;
    throw new Error(failure?.description ?? failure?.type ?? "notCreated");
  }
  const template = String(jmap.session.capabilities[FILE_LINKS]?.urlTemplate ?? "");
  return template.replace("{token}", made.token);
}

export async function removeLink(jmap: Jmap, accountId: string, link: FileLink): Promise<void> {
  await jmap.call(LINKS, "FileLink/set", { accountId, destroy: [link.id] });
}

