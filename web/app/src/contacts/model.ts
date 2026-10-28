// SPDX-License-Identifier: MIT
// Contacts over JMAP (RFC 9610): address books and cards as JSContact.

import { CONTACTS, type Jmap } from "../jmap.js";

export interface AddressBook {
  id: string;
  name: string;
  isDefault: boolean;
  myRights: { mayWrite: boolean };
  accountId: string;
  shared: string | null;
}

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

export async function cards(jmap: Jmap, books: AddressBook[], text: string): Promise<Card[]> {
  const out: Card[] = [];
  for (const accountId of [...new Set(books.map((book) => book.accountId))]) {
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
  await jmap.set([CONTACTS], "ContactCard", form.book.accountId, {
    create: { c: { "@type": "Card", version: "1.0", ...object(form), addressBookIds: { [form.book.id]: true } } },
  });
}

export async function update(jmap: Jmap, card: Card, form: CardForm): Promise<void> {
  await jmap.set([CONTACTS], "ContactCard", form.book.accountId, {
    update: { [card.id]: { ...object(form), addressBookIds: { [form.book.id]: true } } },
  });
}

export async function remove(jmap: Jmap, card: Card): Promise<void> {
  await jmap.set([CONTACTS], "ContactCard", card.accountId, { destroy: [card.id] });
}
