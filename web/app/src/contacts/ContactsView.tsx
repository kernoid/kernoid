// SPDX-License-Identifier: MIT
// Contacts: the address books' cards, one shown, made and changed here.

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { Failure, changed, ok, touch, useJmap } from "../App.js";
import { t } from "../i18n.js";
import { type AddressBook, type Card, type CardForm, addressBooks, cards, create, fullName, remove, update } from "./model.js";

export function ContactsView(): JSX.Element {
  const jmap = useJmap();
  const [books] = createResource(() => changed("AddressBook"), () => addressBooks(jmap));
  const [search, setSearch] = createSignal("");
  const [query, setQuery] = createSignal("");
  const [list] = createResource(
    () => {
      const shown = ok(books);
      return shown ? { shown, text: query(), version: changed("ContactCard") } : undefined;
    },
    ({ shown, text }) => cards(jmap, shown, text),
  );
  const [open, setOpen] = createSignal<Card>();
  const [editing, setEditing] = createSignal<Card | "new">();

  const bookOf = (card: Card) => ok(books)?.find((book) => book.accountId === card.accountId && card.addressBookIds[book.id]);

  return (
    <div class="two">
      <section class="list">
        <div class="search row">
          <form
            class="grow"
            onSubmit={(event) => {
              event.preventDefault();
              setQuery(search());
            }}
          >
            <input type="search" placeholder={t("Search")} value={search()} onInput={(event) => setSearch(event.currentTarget.value)} />
          </form>
          <button type="button" class="primary" onClick={() => setEditing("new")}>
            {t("New")}
          </button>
        </div>
        <Failure error={books.error ?? list.error} />
        <Show when={ok(list)?.length === 0}>
          <p class="muted pad">{t("No contacts")}</p>
        </Show>
        <ul class="items">
          <For each={ok(list) ?? []}>
            {(card) => (
              <li>
                <button type="button" classList={{ active: open()?.id === card.id }} onClick={() => setOpen(card)}>
                  <span class="who">{fullName(card)}</span>
                  <span class="preview">{Object.values(card.emails ?? {})[0]?.address ?? ""}</span>
                </button>
              </li>
            )}
          </For>
        </ul>
      </section>
      <section class="read">
        <Show when={open()} fallback={<p class="muted pad">{t("Select a contact")}</p>}>
          {(card) => (
            <article>
              <div class="actions">
                <Show when={bookOf(card())?.myRights.mayWrite}>
                  <button type="button" onClick={() => setEditing(card())}>
                    {t("Edit")}
                  </button>
                  <button
                    type="button"
                    class="danger"
                    onClick={() => {
                      if (!window.confirm(t("Delete this?"))) return;
                      void remove(jmap, card()).then(() => {
                        setOpen(undefined);
                        touch("ContactCard");
                      });
                    }}
                  >
                    {t("Delete")}
                  </button>
                </Show>
              </div>
              <h2>{fullName(card())}</h2>
              <dl class="headers">
                <For each={Object.values(card().emails ?? {})}>
                  {(email) => (
                    <>
                      <dt>{t("Email")}</dt>
                      <dd>
                        <a href={`mailto:${email.address}`}>{email.address}</a>
                      </dd>
                    </>
                  )}
                </For>
                <For each={Object.values(card().phones ?? {})}>
                  {(phone) => (
                    <>
                      <dt>{t("Phone")}</dt>
                      <dd>
                        <a href={`tel:${phone.number}`}>{phone.number}</a>
                      </dd>
                    </>
                  )}
                </For>
                <For each={Object.values(card().organizations ?? {})}>
                  {(organization) => (
                    <>
                      <dt>{t("Organization")}</dt>
                      <dd>{organization.name}</dd>
                    </>
                  )}
                </For>
                <Show when={bookOf(card())}>
                  {(book) => (
                    <>
                      <dt>{t("Address books")}</dt>
                      <dd>{book().shared ? `${book().name} (${t("Shared by")} ${book().shared})` : book().name}</dd>
                    </>
                  )}
                </Show>
              </dl>
              <For each={Object.values(card().notes ?? {})}>{(note) => <pre class="body">{note.note}</pre>}</For>
            </article>
          )}
        </Show>
      </section>
      <Show when={editing()}>
        {(card) => (
          <CardDialog
            card={card() === "new" ? undefined : (card() as Card)}
            books={(ok(books) ?? []).filter((book) => book.myRights.mayWrite)}
            onClose={(saved) => {
              setEditing(undefined);
              setOpen(undefined);
              if (saved) touch("ContactCard");
            }}
          />
        )}
      </Show>
    </div>
  );
}

function CardDialog(props: { card: Card | undefined; books: AddressBook[]; onClose: (saved: boolean) => void }): JSX.Element {
  const jmap = useJmap();
  const card = props.card;
  const first = <T,>(record: Record<string, T> | undefined) => Object.values(record ?? {})[0];
  const initial = card ? props.books.find((book) => book.accountId === card.accountId && card.addressBookIds[book.id]) : props.books.find((book) => book.isDefault);
  const [book, setBook] = createSignal(initial ? `${initial.accountId}/${initial.id}` : "");
  const [name, setName] = createSignal(card ? fullName(card) : "");
  const [email, setEmail] = createSignal(first(card?.emails)?.address ?? "");
  const [phone, setPhone] = createSignal(first(card?.phones)?.number ?? "");
  const [organization, setOrganization] = createSignal(first(card?.organizations)?.name ?? "");
  const [note, setNote] = createSignal(first(card?.notes)?.note ?? "");
  const [error, setError] = createSignal<unknown>();

  const save = async (event: SubmitEvent) => {
    event.preventDefault();
    const [accountId, id] = book().split("/");
    const target = props.books.find((entry) => entry.accountId === accountId && entry.id === id);
    if (!target) return;
    const form: CardForm = { book: target, name: name(), email: email(), phone: phone(), organization: organization(), note: note() };
    try {
      if (card) await update(jmap, card, form);
      else await create(jmap, form);
      props.onClose(true);
    } catch (failure) {
      setError(failure);
    }
  };

  return (
    <div class="overlay" role="dialog" aria-modal="true" aria-label={t("New contact")}>
      <form class="dialog" onSubmit={(event) => void save(event)}>
        <label>
          <span>{t("Name")}</span>
          <input type="text" required value={name()} onInput={(event) => setName(event.currentTarget.value)} />
        </label>
        <label>
          <span>{t("Email")}</span>
          <input type="email" value={email()} onInput={(event) => setEmail(event.currentTarget.value)} />
        </label>
        <label>
          <span>{t("Phone")}</span>
          <input type="tel" value={phone()} onInput={(event) => setPhone(event.currentTarget.value)} />
        </label>
        <label>
          <span>{t("Organization")}</span>
          <input type="text" value={organization()} onInput={(event) => setOrganization(event.currentTarget.value)} />
        </label>
        <label>
          <span>{t("Address books")}</span>
          <select value={book()} onChange={(event) => setBook(event.currentTarget.value)}>
            <For each={props.books}>{(entry) => <option value={`${entry.accountId}/${entry.id}`}>{entry.shared ? `${entry.name} (${entry.shared})` : entry.name}</option>}</For>
          </select>
        </label>
        <label>
          <span>{t("Note")}</span>
          <textarea rows={3} value={note()} onInput={(event) => setNote(event.currentTarget.value)} />
        </label>
        <Failure error={error()} />
        <div class="actions end">
          <button type="button" class="quiet" onClick={() => props.onClose(false)}>
            {t("Cancel")}
          </button>
          <button type="submit" class="primary">
            {t("Save")}
          </button>
        </div>
      </form>
    </div>
  );
}
