// SPDX-License-Identifier: MIT
// Contacts over JMAP (RFC 9610): address books and cards as JSContact.

import { putSealed, removeSealed, sealedEntries } from "../e2e/sealed.js";
import { CONTACTS, type Jmap } from "../jmap.js";

export interface AddressBook {
  id: string;
  name: string;
  isDefault: boolean;
  myRights: { mayWrite: boolean };
  accountId: string;
  shared: string | null;
  /** Encrypted (RFC 0006, 7): its contacts are encrypted entries only kernoid's apps read. */
  "kernoid:collectionKey"?: string | null;
}

export const encryptedBook = (book: Pick<AddressBook, "kernoid:collectionKey">): boolean => Boolean(book["kernoid:collectionKey"]);

export interface Card {
  id: string;
  addressBookIds: Record<string, boolean>;
  name?: { full?: string; components?: { kind: string; value: string }[] };
  emails?: Record<string, { address: string }>;
  phones?: Record<string, { number: string }>;
  organizations?: Record<string, { name?: string }>;
  notes?: Record<string, { note: string }>;
  accountId: string;
}

export function fullName(card: Card): string {
  if (card.name?.full) return card.name.full;
  const parts = card.name?.components?.map((part) => part.value).filter(Boolean) ?? [];
  return parts.join(" ") || Object.values(card.emails ?? {})[0]?.address || "";
}

export async function addressBooks(jmap: Jmap): Promise<AddressBook[]> {
  const out: AddressBook[] = [];
  for (const [accountId, account] of Object.entries(jmap.session.accounts)) {
    if (!account.accountCapabilities[CONTACTS]) continue;
    const result = await jmap.call<{ list: Omit<AddressBook, "accountId" | "shared">[] }>([CONTACTS], "AddressBook/get", { accountId });
    for (const book of result.list) out.push({ ...book, accountId, shared: account.isPersonal ? null : account.name });
  }
  return out;
}

/** Whether a decrypted contact holds `text` (the server cannot search it). */
function holds(card: Omit<Card, "id" | "accountId">, text: string): boolean {
  const needle = text.trim().toLowerCase();
  if (!needle) return true;
  const values = [card.name?.full ?? "", ...Object.values(card.emails ?? {}).map((e) => e.address), ...Object.values(card.phones ?? {}).map((p) => p.number)];
  return values.some((value) => value.toLowerCase().includes(needle));
}

export async function cards(jmap: Jmap, books: AddressBook[], text: string): Promise<Card[]> {
  const out: Card[] = [];
  for (const book of books.filter(encryptedBook)) {
    const { entries } = await sealedEntries<Omit<Card, "id" | "accountId">>(jmap, CONTACTS, book.accountId, book.id);
    for (const { id, value } of entries) {
      if (holds(value, text)) out.push({ ...value, id, addressBookIds: { [book.id]: true }, accountId: book.accountId });
    }
  }
  for (const accountId of [...new Set(books.filter((book) => !encryptedBook(book)).map((book) => book.accountId))]) {
    const filter: Record<string, unknown> = {};
    if (text.trim()) filter.text = text.trim();
    const responses = await jmap.request(
      [CONTACTS],
      [
        ["ContactCard/query", { accountId, filter }, "q"],
        ["ContactCard/get", { accountId, "#ids": { resultOf: "q", name: "ContactCard/query", path: "/ids" } }, "g"],
      ],
    );
    const get = responses.get("g")?.[0] as { list: Omit<Card, "accountId">[] } | undefined;
    out.push(...(get?.list ?? []).map((card) => ({ ...card, accountId })));
  }
  return out.sort((a, b) => fullName(a).localeCompare(fullName(b)));
}

export interface CardForm {
  book: AddressBook;
  name: string;
  email: string;
  phone: string;
  organization: string;
  note: string;
}

function object(form: CardForm): Record<string, unknown> {
  return {
    name: { full: form.name },
    emails: form.email ? { e1: { "@type": "EmailAddress", address: form.email } } : null,
    phones: form.phone ? { p1: { "@type": "Phone", number: form.phone } } : null,
    organizations: form.organization ? { o1: { "@type": "Organization", name: form.organization } } : null,
    notes: form.note ? { n1: { "@type": "Note", note: form.note } } : null,
  };
}

export async function create(jmap: Jmap, form: CardForm): Promise<void> {
  if (encryptedBook(form.book)) {
    await putSealed(jmap, CONTACTS, form.book.accountId, form.book.id, undefined, { "@type": "Card", version: "1.0", ...object(form) });
    return;
  }
  await jmap.set([CONTACTS], "ContactCard", form.book.accountId, {
    create: { c: { "@type": "Card", version: "1.0", ...object(form), addressBookIds: { [form.book.id]: true } } },
  });
}

export async function update(jmap: Jmap, card: Card, form: CardForm, books: AddressBook[] = []): Promise<void> {
  // Into or out of an encrypted address book: made anew there, removed here.
  const from = books.find((entry) => entry.accountId === card.accountId && card.addressBookIds[entry.id]);
  if (from && from.id !== form.book.id && (encryptedBook(from) || encryptedBook(form.book))) {
    await create(jmap, form);
    await remove(jmap, card, books);
    return;
  }
  if (encryptedBook(form.book)) {
    await putSealed(jmap, CONTACTS, form.book.accountId, form.book.id, card.id, { "@type": "Card", version: "1.0", ...object(form) });
    return;
  }
  await jmap.set([CONTACTS], "ContactCard", form.book.accountId, {
    update: { [card.id]: { ...object(form), addressBookIds: { [form.book.id]: true } } },
  });
}

export async function remove(jmap: Jmap, card: Card, books: AddressBook[] = []): Promise<void> {
  const book = books.find((entry) => entry.accountId === card.accountId && card.addressBookIds[entry.id]);
  if (book && encryptedBook(book)) {
    await removeSealed(jmap, CONTACTS, card.accountId, book.id, card.id);
    return;
  }
  await jmap.set([CONTACTS], "ContactCard", card.accountId, { destroy: [card.id] });
}
