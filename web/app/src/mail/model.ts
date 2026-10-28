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
  body: string;
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
    bodyValues: { body: { value: draft.body } },
    textBody: [{ partId: "body", type: "text/plain" }],
  };
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
