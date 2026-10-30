// SPDX-License-Identifier: MIT
// Mail over JMAP (RFC 8621): mailboxes, the emails of one, one email to read, and sending.

import { base64, e2e, lookup, OPENPGP, unlockedRing } from "../e2e/e2e.svelte.js";
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
  /** End-to-end encrypted (RFC 0006): subject and preview come from its encrypted summary, if the key is unlocked. */
  "kernoid:encrypted"?: boolean;
  "kernoid:encryptedSummary"?: string | null;
}

export interface BodyPart {
  partId: string | null;
  blobId: string | null;
  type: string;
  name: string | null;
  size: number;
  /** A part decrypted here: its content as a `blob:` URL, never sent anywhere. */
  url?: string;
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
  blobId?: string;
  /** For an encrypted email: locked (the key is not unlocked here), or decrypted – and whose signature it carries. */
  sealed?: { locked: boolean; signed: boolean; verified: boolean };
}

export interface Identity {
  id: string;
  name: string;
  email: string;
  /** The mail account it sends from: one's own, or a shared mailbox one may send as. */
  accountId: string;
}

/** A mail account the user reaches: the own one, or a shared mailbox (RFC 0002, 12.2). */
export interface MailStore {
  id: string;
  name: string;
  own: boolean;
}

/** The mail accounts of the session: the own one first, then the shared mailboxes by name. */
export function mailStores(jmap: Jmap): MailStore[] {
  const own = jmap.account(MAIL);
  return Object.entries(jmap.session.accounts)
    .filter(([id, account]) => id === own || account.accountCapabilities[MAIL])
    .map(([id, account]) => ({ id, name: account.name, own: id === own }))
    .sort((a, b) => Number(b.own) - Number(a.own) || a.name.localeCompare(b.name));
}

const ROLE_ORDER = ["inbox", "drafts", "sent", "archive", "junk", "trash"];

export async function mailboxes(jmap: Jmap, accountId: string): Promise<Mailbox[]> {
  const result = await jmap.call<{ list: Mailbox[] }>([MAIL], "Mailbox/get", { accountId });
  return result.list.sort((a, b) => {
    const ra = a.role ? ROLE_ORDER.indexOf(a.role) : 99;
    const rb = b.role ? ROLE_ORDER.indexOf(b.role) : 99;
    return ra - rb || a.sortOrder - b.sortOrder || a.name.localeCompare(b.name);
  });
}

const SUMMARY = ["threadId", "mailboxIds", "keywords", "from", "to", "subject", "receivedAt", "preview", "hasAttachment"];
const SEALED = ["kernoid:encrypted", "kernoid:encryptedSummary"];

const binary = (text: string): Uint8Array => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

/** The properties to ask for: with the end-to-end ones where the server has them. */
function summaryProperties(jmap: Jmap): string[] {
  return OPENPGP in (jmap.session.capabilities ?? {}) ? [...SUMMARY, ...SEALED] : SUMMARY;
}

/** Fills in subject and preview of encrypted emails from their summaries, where the key is unlocked here. */
async function openSummaries(list: EmailSummary[]): Promise<void> {
  const ring = await unlockedRing();
  for (const email of list) {
    if (!email["kernoid:encrypted"]) continue;
    const sealed = email["kernoid:encryptedSummary"];
    if (!ring || !sealed) continue;
    try {
      const summary = JSON.parse(ring.decryptSummary(binary(sealed))) as { subject: string | null; preview: string; hasAttachment: boolean };
      email.subject = summary.subject;
      email.preview = summary.preview;
      email.hasAttachment = summary.hasAttachment;
    } catch {
      // Encrypted to a key not unlocked here: shown as encrypted.
    }
  }
}

export async function emails(jmap: Jmap, accountId: string, mailbox: string, text: string, limit: number): Promise<{ list: EmailSummary[]; total: number }> {
  const filter: Record<string, unknown> = { inMailbox: mailbox };
  if (text.trim()) filter.text = text.trim();
  const responses = await jmap.request(
    [MAIL],
    [
      ["Email/query", { accountId, filter, sort: [{ property: "receivedAt", isAscending: false }], limit, calculateTotal: true }, "q"],
      ["Email/get", { accountId, "#ids": { resultOf: "q", name: "Email/query", path: "/ids" }, properties: summaryProperties(jmap) }, "g"],
    ],
  );
  const query = responses.get("q")?.[0] as { total?: number } | undefined;
  const get = responses.get("g")?.[0] as { list: EmailSummary[] } | undefined;
  const list = get?.list ?? [];
  await openSummaries(list);
  return { list, total: query?.total ?? 0 };
}

export async function email(jmap: Jmap, accountId: string, id: string): Promise<Email | undefined> {
  const result = await jmap.call<{ list: Email[] }>([MAIL], "Email/get", {
    accountId,
    ids: [id],
    properties: [...summaryProperties(jmap), "blobId", "cc", "replyTo", "messageId", "references", "sentAt", "textBody", "htmlBody", "attachments", "bodyValues"],
    fetchTextBodyValues: true,
    fetchHTMLBodyValues: true,
    maxBodyValueBytes: 2_000_000,
  });
  const found = result.list[0];
  if (!found?.["kernoid:encrypted"]) return found;
  await openSummaries([found]);
  return decrypted(jmap, accountId, found);
}

interface Parsed {
  subject: string | null;
  from: Address[];
  to: Address[];
  cc: Address[];
  replyTo: Address[];
  sentAt: string | null;
  messageId: string | null;
  references: string[];
  text: string | null;
  html: string | null;
  attachments: { index: number; name: string | null; type: string; size: number; cid: string | null; inline: boolean }[];
}

/** An encrypted email read here: its message downloaded, decrypted and read into parts in this page – the text never
 * goes back to the server. Locked if the key is not unlocked. */
async function decrypted(jmap: Jmap, accountId: string, found: Email): Promise<Email> {
  const ring = await unlockedRing();
  const locked: Email = { ...found, textBody: [], htmlBody: [], attachments: [], bodyValues: {}, sealed: { locked: true, signed: false, verified: false } };
  if (!ring || !found.blobId) return locked;
  const response = await fetch(jmap.downloadPath(accountId, found.blobId, "message.eml", "message/rfc822"), { credentials: "same-origin" });
  if (!response.ok) return locked;
  const raw = new Uint8Array(await response.arrayBuffer());
  const senders = found.from?.length ? [...(await lookup(jmap, found.from.map((a) => a.email))).values()].flat() : [];
  let opened;
  try {
    opened = ring.decryptMessage(raw, senders);
  } catch {
    return locked;
  }
  const module = await import("@kernoid/e2e");
  const inner = opened.data;
  const parsed = JSON.parse(module.parseMessage(inner)) as Parsed;
  const bodyValues: Record<string, { value: string }> = {};
  const textBody: BodyPart[] = [];
  const htmlBody: BodyPart[] = [];
  if (parsed.text !== null) {
    bodyValues.text = { value: parsed.text };
    textBody.push({ partId: "text", blobId: null, type: "text/plain", name: null, size: parsed.text.length });
  }
  if (parsed.html !== null) {
    bodyValues.html = { value: parsed.html };
    htmlBody.push({ partId: "html", blobId: null, type: "text/html", name: null, size: parsed.html.length });
  } else if (parsed.text !== null) {
    htmlBody.push(...textBody);
  }
  const attachments = parsed.attachments.map((part) => {
    const content = module.messagePart(inner, part.index);
    const url = URL.createObjectURL(new Blob([content.slice().buffer], { type: part.type }));
    return { partId: null, blobId: null, type: part.type, name: part.name, size: part.size, url } satisfies BodyPart;
  });
  return {
    ...found,
    subject: parsed.subject,
    from: parsed.from.length ? parsed.from : found.from,
    to: parsed.to.length ? parsed.to : found.to,
    cc: parsed.cc,
    replyTo: parsed.replyTo,
    sentAt: parsed.sentAt,
    messageId: parsed.messageId ? [parsed.messageId] : found.messageId,
    references: parsed.references.length ? parsed.references : found.references,
    textBody,
    htmlBody,
    attachments,
    bodyValues,
    sealed: { locked: false, signed: opened.signed, verified: Boolean(opened.verifiedBy) },
  };
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
export function originalPath(accountId: string, email: Email): string | undefined {
  const part = email.htmlBody.find((entry) => entry.type === "text/html" && entry.blobId);
  if (!part?.blobId) return undefined;
  return `/jmap/view/${encodeURIComponent(accountId)}/${encodeURIComponent(part.blobId)}`;
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

export async function setKeyword(jmap: Jmap, accountId: string, id: string, keyword: string, on: boolean): Promise<void> {
  await jmap.set([MAIL], "Email", accountId, { update: { [id]: { [`keywords/${keyword}`]: on ? true : null } } });
}

export async function move(jmap: Jmap, accountId: string, id: string, to: string): Promise<void> {
  await jmap.set([MAIL], "Email", accountId, { update: { [id]: { mailboxIds: { [to]: true } } } });
}

export async function destroy(jmap: Jmap, accountId: string, id: string): Promise<void> {
  await jmap.set([MAIL], "Email", accountId, { destroy: [id] });
}

export async function upload(jmap: Jmap, accountId: string, file: File): Promise<Attachment> {
  const done = await jmap.upload(accountId, file);
  return { blobId: done.blobId, type: done.type || file.type || "application/octet-stream", name: file.name, size: done.size };
}

/** The identities of one mail account – or, without one, of the own account and every shared mailbox one may send as. */
export async function identities(jmap: Jmap, accountId?: string): Promise<Identity[]> {
  const accounts = accountId ? [accountId] : mailStores(jmap).map((store) => store.id);
  const lists = await Promise.all(
    accounts.map(async (account) => {
      const result = await jmap
        .call<{ list: Omit<Identity, "accountId">[] }>([MAIL, SUBMISSION], "Identity/get", { accountId: account })
        .catch(() => ({ list: [] }));
      return result.list.map((identity) => ({ ...identity, accountId: account }));
    }),
  );
  return lists.flat();
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
  /** The files attached – uploaded already to the sending account, or not yet: an end-to-end encrypted email carries
   * them inside, so they are uploaded only if it goes out plain. */
  files?: { file: File; attachment?: Attachment }[];
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

/** What was sent: where, and the submission – to take it back while it is held. */
export interface Sent {
  accountId: string;
  emailId: string;
  submissionId: string;
  /** Held, and may still be taken back. */
  pending: boolean;
}

/** Stores the message in the Drafts of the identity's account and submits it there – held for `holdSeconds` first
 * (RFC 8621, 7: HOLDFOR), so that it can be taken back until then. */
export async function send(jmap: Jmap, draft: Draft, holdSeconds = 0): Promise<Sent> {
  const accountId = draft.identity.accountId;
  const boxes = await mailboxes(jmap, accountId);
  const drafts = boxes.find((box) => box.role === "drafts");
  const sent = boxes.find((box) => box.role === "sent");
  if (!drafts) throw new Error("no Drafts mailbox");
  const recipients = await sealedTo(jmap, draft);
  if (recipients) return sendSealed(jmap, draft, recipients, drafts, sent, holdSeconds);
  const attachments = await Promise.all((draft.files ?? []).map((entry) => entry.attachment ?? upload(jmap, accountId, entry.file)));
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
  if (attachments.length) {
    email.attachments = attachments.map((file) => ({ blobId: file.blobId, type: file.type, name: file.name, disposition: "attachment" }));
  }
  if (draft.inReplyTo) email.inReplyTo = draft.inReplyTo;
  if (draft.references) email.references = draft.references;
  const update: Record<string, unknown> = { "keywords/$draft": null };
  if (sent) update.mailboxIds = { [sent.id]: true };
  const submission: Record<string, unknown> = { identityId: draft.identity.id, emailId: "#draft" };
  if (holdSeconds > 0) {
    // An envelope names its recipients too: everyone in To and Cc.
    submission.envelope = {
      mailFrom: { email: draft.identity.email, parameters: { HOLDFOR: String(holdSeconds) } },
      rcptTo: [...draft.to, ...draft.cc].map((address) => ({ email: address.email, parameters: null })),
    };
  }
  const responses = await jmap.request(
    [MAIL, SUBMISSION],
    [
      ["Email/set", { accountId, create: { draft: email } }, "e"],
      ["EmailSubmission/set", { accountId, create: { send: submission }, onSuccessUpdateEmail: { "#send": update } }, "s"],
    ],
  );
  for (const [, results] of responses) {
    for (const result of results) {
      const failed = (result.notCreated ?? {}) as Record<string, { type: string; description?: string }>;
      const first = Object.values(failed)[0];
      if (first) throw new Error(first.description ?? first.type);
    }
  }
  const created = (key: string, name: string) =>
    ((responses.get(key)?.[0]?.created ?? {}) as Record<string, { id: string; undoStatus?: string }>)[name];
  const stored = created("e", "draft");
  const submitted = created("s", "send");
  return { accountId, emailId: stored?.id ?? "", submissionId: submitted?.id ?? "", pending: submitted?.undoStatus === "pending" };
}

/** The fingerprints an email goes out end-to-end encrypted to – every recipient's key and the sender's own – or
 * nothing if it goes plain: the sender's key is not unlocked here, the identity is not the account's own, or a
 * recipient has no key (RFC 0006, 5.3). */
export async function sealedTo(jmap: Jmap, draft: Pick<Draft, "identity" | "to" | "cc">): Promise<string[] | undefined> {
  const ring = await unlockedRing();
  const own = e2e.unlocked;
  if (!ring || !own || draft.identity.accountId !== jmap.account(MAIL)) return undefined;
  if (!ring.addresses(own).some((address) => address.toLowerCase() === draft.identity.email.toLowerCase())) return undefined;
  const addresses = [...draft.to, ...draft.cc].map((address) => address.email);
  if (addresses.length === 0) return undefined;
  const keys = await lookup(jmap, addresses);
  if ([...keys.values()].some((list) => list.length === 0)) return undefined;
  return [...new Set([...[...keys.values()].flat(), own])];
}

/** A date as RFC 5322 writes it, in the browser's zone. */
function rfc5322Date(date: Date): string {
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const two = (n: number) => String(n).padStart(2, "0");
  const offset = -date.getTimezoneOffset();
  const zone = `${offset >= 0 ? "+" : "-"}${two(Math.floor(Math.abs(offset) / 60))}${two(Math.abs(offset) % 60)}`;
  return `${days[date.getDay()]}, ${two(date.getDate())} ${months[date.getMonth()]} ${date.getFullYear()} ${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())} ${zone}`;
}

/** Sends end-to-end encrypted: the message built, encrypted and signed in this page, uploaded as it is, imported
 * into Drafts with its summary encrypted to the sender, and submitted with an envelope – the server never sees text
 * or attachments (RFC 0006, 5.3). */
async function sendSealed(jmap: Jmap, draft: Draft, recipients: string[], drafts: Mailbox, sent: Mailbox | undefined, holdSeconds: number): Promise<Sent> {
  const ring = await unlockedRing();
  const own = e2e.unlocked;
  if (!ring || !own) throw new Error("the key is locked");
  const module = await import("@kernoid/e2e");
  const accountId = draft.identity.accountId;
  const domain = draft.identity.email.split("@")[1] ?? "localhost";
  const strip = (ids: string[] | null | undefined) => (ids ?? []).map((id) => id.replace(/^<|>$/g, ""));
  const attachments = await Promise.all(
    (draft.files ?? []).map(async ({ file }) => ({ name: file.name, type: file.type || "application/octet-stream", data: base64(new Uint8Array(await file.arrayBuffer())) })),
  );
  const raw = module.buildMessage(
    JSON.stringify({
      from: { name: draft.identity.name || null, email: draft.identity.email },
      to: draft.to,
      cc: draft.cc,
      subject: draft.subject,
      messageId: `${crypto.randomUUID()}@${domain}`,
      inReplyTo: strip(draft.inReplyTo),
      references: strip(draft.references),
      date: rfc5322Date(new Date()),
      text: draft.body,
      html: draft.html || null,
      attachments,
    }),
  );
  const encrypted = ring.encryptMessage(raw, recipients, own);
  const summary = ring.encryptedSummary(raw, [own]);
  const blob = await jmap.upload(accountId, new Blob([encrypted.slice().buffer], { type: "message/rfc822" }));
  const update: Record<string, unknown> = { "keywords/$draft": null };
  if (sent) update.mailboxIds = { [sent.id]: true };
  const mailFrom: Record<string, unknown> = { email: draft.identity.email, parameters: holdSeconds > 0 ? { HOLDFOR: String(holdSeconds) } : null };
  const responses = await jmap.request(
    [MAIL, SUBMISSION, OPENPGP],
    [
      [
        "Email/import",
        {
          accountId,
          emails: {
            draft: { blobId: blob.blobId, mailboxIds: { [drafts.id]: true }, keywords: { $draft: true, $seen: true }, "kernoid:encryptedSummary": base64(summary) },
          },
        },
        "e",
      ],
      [
        "EmailSubmission/set",
        {
          accountId,
          create: {
            send: {
              identityId: draft.identity.id,
              emailId: "#draft",
              envelope: { mailFrom, rcptTo: [...draft.to, ...draft.cc].map((address) => ({ email: address.email, parameters: null })) },
            },
          },
          onSuccessUpdateEmail: { "#send": update },
        },
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
  const created = (key: string, name: string) =>
    ((responses.get(key)?.[0]?.created ?? {}) as Record<string, { id: string; undoStatus?: string }>)[name];
  const submitted = created("s", "send");
  return { accountId, emailId: created("e", "draft")?.id ?? "", submissionId: submitted?.id ?? "", pending: submitted?.undoStatus === "pending" };
}

/** Takes back an email held before sending: it is not sent, and leaves Sent; the writing window opens again. */
export async function unsend(jmap: Jmap, sent: Sent): Promise<void> {
  await jmap.set([MAIL, SUBMISSION], "EmailSubmission", sent.accountId, { update: { [sent.submissionId]: { undoStatus: "canceled" } } });
  await jmap.set([MAIL], "Email", sent.accountId, { destroy: [sent.emailId] });
}

// Mailboxes of one's own (RFC 8621, 2.5): made, renamed, moved under another and destroyed.

export async function createMailbox(jmap: Jmap, accountId: string, name: string, parentId: string | null): Promise<void> {
  await jmap.set([MAIL], "Mailbox", accountId, { create: { box: { name, parentId } } });
}

export async function updateMailbox(jmap: Jmap, accountId: string, id: string, change: { name?: string; parentId?: string | null }): Promise<void> {
  await jmap.set([MAIL], "Mailbox", accountId, { update: { [id]: change } });
}

/** Destroys a mailbox; its emails go to the Trash first (they would be lost otherwise). */
export async function destroyMailbox(jmap: Jmap, accountId: string, box: Mailbox, trash: Mailbox | undefined): Promise<void> {
  if (trash && box.totalEmails > 0) await moveAll(jmap, accountId, box.id, trash.id);
  await jmap.set([MAIL], "Mailbox", accountId, { destroy: [box.id] }, { onDestroyRemoveEmails: !trash });
}

/** The ids of every email in a mailbox, page by page. */
async function idsIn(jmap: Jmap, accountId: string, mailbox: string): Promise<string[]> {
  const ids: string[] = [];
  for (;;) {
    const page = await jmap.call<{ ids: string[] }>([MAIL], "Email/query", { accountId, filter: { inMailbox: mailbox }, position: ids.length, limit: 500 });
    ids.push(...page.ids);
    if (page.ids.length < 500) return ids;
  }
}

/** Moves emails to another mailbox – out of every other. */
export async function moveMany(jmap: Jmap, accountId: string, ids: string[], to: string): Promise<void> {
  for (let start = 0; start < ids.length; start += 200) {
    const update = Object.fromEntries(ids.slice(start, start + 200).map((id) => [id, { mailboxIds: { [to]: true } }]));
    await jmap.set([MAIL], "Email", accountId, { update });
  }
}

async function moveAll(jmap: Jmap, accountId: string, from: string, to: string): Promise<void> {
  await moveMany(jmap, accountId, await idsIn(jmap, accountId, from), to);
}

/** Destroys every email in a mailbox (emptying the Trash). */
export async function emptyMailbox(jmap: Jmap, accountId: string, mailbox: string): Promise<void> {
  for (;;) {
    const ids = (await idsIn(jmap, accountId, mailbox)).slice(0, 500);
    if (ids.length === 0) return;
    await jmap.set([MAIL], "Email", accountId, { destroy: ids });
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
