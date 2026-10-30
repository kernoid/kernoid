// SPDX-License-Identifier: MIT
// Mail over JMAP (RFC 8621): mailboxes, the emails of one, one email to read, and sending.

import { type Jmap, MAIL, SUBMISSION } from "../jmap.js";

export interface Mailbox {
  id: string;
  name: string;
  parentId: string | null;
  role: string | null;
  sortOrder: number;
  totalEmails: number;
  unreadEmails: number;
}

export interface Address {
  name: string | null;
  email: string;
}

export interface EmailSummary {
  id: string;
  threadId: string;
  mailboxIds: Record<string, boolean>;
  keywords: Record<string, boolean>;
  from: Address[] | null;
  to: Address[] | null;
  subject: string | null;
  receivedAt: string;
  preview: string;
  hasAttachment: boolean;
}

export interface BodyPart {
  partId: string | null;
  blobId: string | null;
  type: string;
  name: string | null;
  size: number;
}

export interface Email extends EmailSummary {
  cc: Address[] | null;
  replyTo: Address[] | null;
  messageId: string[] | null;
  references: string[] | null;
  sentAt: string | null;
  textBody: BodyPart[];
  htmlBody: BodyPart[];
  attachments: BodyPart[];
  bodyValues: Record<string, { value: string }>;
}

export interface Identity {
  id: string;
  name: string;
  email: string;
}

const ROLE_ORDER = ["inbox", "drafts", "sent", "archive", "junk", "trash"];

export async function mailboxes(jmap: Jmap): Promise<Mailbox[]> {
  const result = await jmap.call<{ list: Mailbox[] }>([MAIL], "Mailbox/get", { accountId: jmap.account(MAIL) });
  return result.list.sort((a, b) => {
    const ra = a.role ? ROLE_ORDER.indexOf(a.role) : 99;
    const rb = b.role ? ROLE_ORDER.indexOf(b.role) : 99;
    return ra - rb || a.sortOrder - b.sortOrder || a.name.localeCompare(b.name);
  });
}

const SUMMARY = ["threadId", "mailboxIds", "keywords", "from", "to", "subject", "receivedAt", "preview", "hasAttachment"];

export async function emails(jmap: Jmap, mailbox: string, text: string, limit: number): Promise<{ list: EmailSummary[]; total: number }> {
  const accountId = jmap.account(MAIL);
  const filter: Record<string, unknown> = { inMailbox: mailbox };
  if (text.trim()) filter.text = text.trim();
  const responses = await jmap.request(
    [MAIL],
    [
      ["Email/query", { accountId, filter, sort: [{ property: "receivedAt", isAscending: false }], limit, calculateTotal: true }, "q"],
      ["Email/get", { accountId, "#ids": { resultOf: "q", name: "Email/query", path: "/ids" }, properties: SUMMARY }, "g"],
    ],
  );
  const query = responses.get("q")?.[0] as { total?: number } | undefined;
  const get = responses.get("g")?.[0] as { list: EmailSummary[] } | undefined;
  return { list: get?.list ?? [], total: query?.total ?? 0 };
}

export async function email(jmap: Jmap, id: string): Promise<Email | undefined> {
  const result = await jmap.call<{ list: Email[] }>([MAIL], "Email/get", {
    accountId: jmap.account(MAIL),
    ids: [id],
    properties: [...SUMMARY, "cc", "replyTo", "messageId", "references", "sentAt", "textBody", "htmlBody", "attachments", "bodyValues"],
    fetchTextBodyValues: true,
    fetchHTMLBodyValues: true,
    maxBodyValueBytes: 2_000_000,
  });
  return result.list[0];
}

/** The HTML of an email, if it has an HTML body. */
export function bodyHtml(email: Email): string | undefined {
  if (!email.htmlBody.some((part) => part.type === "text/html")) return undefined;
  return email.htmlBody
    .map((part) => {
      const value = part.partId ? email.bodyValues[part.partId]?.value : undefined;
      if (value === undefined) return "";
      return part.type === "text/html" ? value : `<pre>${value.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c] ?? c)}</pre>`;
    })
    .join("");
}

/** Where an email's HTML is shown as its sender laid it out – a page of its own, sandboxed by the server (`/jmap/view`). */
export function originalPath(jmap: Jmap, email: Email): string | undefined {
  const part = email.htmlBody.find((entry) => entry.type === "text/html" && entry.blobId);
  if (!part?.blobId) return undefined;
  return `/jmap/view/${encodeURIComponent(jmap.account(MAIL))}/${encodeURIComponent(part.blobId)}`;
}

/** The text of an email: its text parts, or its HTML parts as text. */
export function bodyText(email: Email): string {
  const text = email.textBody.map((part) => (part.partId ? email.bodyValues[part.partId]?.value : undefined)).filter((value) => value !== undefined);
  if (text.length > 0 && !email.textBody.every((part) => part.type === "text/html")) return text.join("\n\n");
  const html = email.htmlBody.map((part) => (part.partId ? email.bodyValues[part.partId]?.value : undefined)).filter((value) => value !== undefined);
  return html.map(htmlToText).join("\n\n");
}

/** HTML as text, without running or loading anything: the parser builds an inert document. */
export function htmlToText(html: string): string {
  const document = new DOMParser().parseFromString(html, "text/html");
  for (const element of document.querySelectorAll("script, style, head")) element.remove();
  for (const element of document.querySelectorAll("br")) element.replaceWith("\n");
  for (const element of document.querySelectorAll("p, div, li, tr, h1, h2, h3, h4, blockquote")) element.append("\n");
  return (document.body.textContent ?? "").replace(/\n{3,}/g, "\n\n").trim();
}

export async function setKeyword(jmap: Jmap, id: string, keyword: string, on: boolean): Promise<void> {
  await jmap.set([MAIL], "Email", jmap.account(MAIL), { update: { [id]: { [`keywords/${keyword}`]: on ? true : null } } });
}

export async function move(jmap: Jmap, id: string, to: string): Promise<void> {
  await jmap.set([MAIL], "Email", jmap.account(MAIL), { update: { [id]: { mailboxIds: { [to]: true } } } });
}

export async function destroy(jmap: Jmap, id: string): Promise<void> {
  await jmap.set([MAIL], "Email", jmap.account(MAIL), { destroy: [id] });
}

export async function upload(jmap: Jmap, file: File): Promise<Attachment> {
  const done = await jmap.upload(jmap.account(MAIL), file);
  return { blobId: done.blobId, type: done.type || file.type || "application/octet-stream", name: file.name, size: done.size };
}

export async function identities(jmap: Jmap): Promise<Identity[]> {
  const result = await jmap.call<{ list: Identity[] }>([MAIL, SUBMISSION], "Identity/get", { accountId: jmap.account(MAIL) });
  return result.list;
}

export function parseAddresses(text: string): Address[] {
  return text
    .split(/[,;]/)
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const match = /^(.*?)\s*<([^>]+)>$/.exec(part);
      return match ? { name: match[1]?.replace(/^"|"$/g, "") || null, email: match[2] ?? "" } : { name: null, email: part };
    });
}

export function formatAddresses(list: Address[] | null): string {
  return (list ?? []).map((address) => (address.name ? `${address.name} <${address.email}>` : address.email)).join(", ");
}

export interface Attachment {
  blobId: string;
  type: string;
  name: string;
  size: number;
}

export interface Draft {
  identity: Identity;
  attachments?: Attachment[];
  to: Address[];
  cc: Address[];
  subject: string;
  /** The plain text – alone, or alongside `html`. */
  body: string;
  /** The same as HTML, if written with formatting. */
  html?: string;
  inReplyTo?: string[] | null;
  references?: string[] | null;
}

/** Stores the message in Drafts and submits it; once sent it moves to Sent (RFC 8621, 7.5). */
export async function send(jmap: Jmap, draft: Draft, boxes: Mailbox[]): Promise<void> {
  const accountId = jmap.account(MAIL);
  const drafts = boxes.find((box) => box.role === "drafts");
  const sent = boxes.find((box) => box.role === "sent");
  if (!drafts) throw new Error("no Drafts mailbox");
  const email: Record<string, unknown> = {
    mailboxIds: { [drafts.id]: true },
    keywords: { $draft: true, $seen: true },
    from: [{ name: draft.identity.name || null, email: draft.identity.email }],
    to: draft.to,
    subject: draft.subject,
    bodyValues: draft.html ? { body: { value: draft.body }, html: { value: draft.html } } : { body: { value: draft.body } },
    textBody: [{ partId: "body", type: "text/plain" }],
  };
  if (draft.html) email.htmlBody = [{ partId: "html", type: "text/html" }];
  if (draft.cc.length > 0) email.cc = draft.cc;
  if (draft.attachments?.length) {
    email.attachments = draft.attachments.map((file) => ({ blobId: file.blobId, type: file.type, name: file.name, disposition: "attachment" }));
  }
  if (draft.inReplyTo) email.inReplyTo = draft.inReplyTo;
  if (draft.references) email.references = draft.references;
  const update: Record<string, unknown> = { "keywords/$draft": null };
  if (sent) update.mailboxIds = { [sent.id]: true };
  const responses = await jmap.request(
    [MAIL, SUBMISSION],
    [
      ["Email/set", { accountId, create: { draft: email } }, "e"],
      [
        "EmailSubmission/set",
        { accountId, create: { send: { identityId: draft.identity.id, emailId: "#draft" } }, onSuccessUpdateEmail: { "#send": update } },
        "s",
      ],
    ],
  );
  for (const [, results] of responses) {
    for (const result of results) {
      const failed = (result.notCreated ?? {}) as Record<string, { type: string; description?: string }>;
      const first = Object.values(failed)[0];
      if (first) throw new Error(first.description ?? first.type);
    }
  }
}

// Mailboxes of one's own (RFC 8621, 2.5): made, renamed, moved under another and destroyed.

export async function createMailbox(jmap: Jmap, name: string, parentId: string | null): Promise<void> {
  await jmap.set([MAIL], "Mailbox", jmap.account(MAIL), { create: { box: { name, parentId } } });
}

export async function updateMailbox(jmap: Jmap, id: string, change: { name?: string; parentId?: string | null }): Promise<void> {
  await jmap.set([MAIL], "Mailbox", jmap.account(MAIL), { update: { [id]: change } });
}

/** Destroys a mailbox; its emails go to the Trash first (they would be lost otherwise). */
export async function destroyMailbox(jmap: Jmap, box: Mailbox, trash: Mailbox | undefined): Promise<void> {
  if (trash && box.totalEmails > 0) await moveAll(jmap, box.id, trash.id);
  await jmap.set([MAIL], "Mailbox", jmap.account(MAIL), { destroy: [box.id] }, { onDestroyRemoveEmails: !trash });
}

/** The ids of every email in a mailbox, page by page. */
async function idsIn(jmap: Jmap, mailbox: string): Promise<string[]> {
  const accountId = jmap.account(MAIL);
  const ids: string[] = [];
  for (;;) {
    const page = await jmap.call<{ ids: string[] }>([MAIL], "Email/query", { accountId, filter: { inMailbox: mailbox }, position: ids.length, limit: 500 });
    ids.push(...page.ids);
    if (page.ids.length < 500) return ids;
  }
}

/** Moves emails to another mailbox – out of every other. */
export async function moveMany(jmap: Jmap, ids: string[], to: string): Promise<void> {
  for (let start = 0; start < ids.length; start += 200) {
    const update = Object.fromEntries(ids.slice(start, start + 200).map((id) => [id, { mailboxIds: { [to]: true } }]));
    await jmap.set([MAIL], "Email", jmap.account(MAIL), { update });
  }
}

async function moveAll(jmap: Jmap, from: string, to: string): Promise<void> {
  await moveMany(jmap, await idsIn(jmap, from), to);
}

/** Destroys every email in a mailbox (emptying the Trash). */
export async function emptyMailbox(jmap: Jmap, mailbox: string): Promise<void> {
  for (;;) {
    const ids = (await idsIn(jmap, mailbox)).slice(0, 500);
    if (ids.length === 0) return;
    await jmap.set([MAIL], "Email", jmap.account(MAIL), { destroy: ids });
  }
}

export interface TreeEntry {
  box: Mailbox;
  depth: number;
}

/** The mailboxes as a tree in reading order: the roles first, then the account's own folders by name – each with its
 * subfolders beneath it –, Junk and Trash last. */
export function mailboxTree(boxes: Mailbox[]): TreeEntry[] {
  const children = new Map<string | null, Mailbox[]>();
  for (const box of boxes) {
    const parent = box.parentId && boxes.some((other) => other.id === box.parentId) ? box.parentId : null;
    children.set(parent, [...(children.get(parent) ?? []), box]);
  }
  const rank = (box: Mailbox) => {
    if (box.role === "junk") return 90;
    if (box.role === "trash") return 91;
    const index = box.role ? ROLE_ORDER.indexOf(box.role) : -1;
    return index >= 0 ? index : 50;
  };
  const sorted = (list: Mailbox[]) => [...list].sort((a, b) => rank(a) - rank(b) || a.sortOrder - b.sortOrder || a.name.localeCompare(b.name));
  const out: TreeEntry[] = [];
  const walk = (parent: string | null, depth: number) => {
    for (const box of sorted(children.get(parent) ?? [])) {
      out.push({ box, depth });
      walk(box.id, depth + 1);
    }
  };
  walk(null, 0);
  return out;
}

/** Whether `inside` is `box` or lies beneath it – a folder cannot move into itself. */
export function within(boxes: Mailbox[], inside: string | null, box: string): boolean {
  for (let current = inside; current; current = boxes.find((other) => other.id === current)?.parentId ?? null) {
    if (current === box) return true;
  }
  return false;
}
