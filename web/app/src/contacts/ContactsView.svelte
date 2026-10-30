<!-- SPDX-License-Identifier: MIT -->
<!-- Contacts: the address books' cards, one shown, made and changed here. -->
<script lang="ts">
  import { Pencil, Search, Trash2, UserPlus } from "@lucide/svelte";

  import Avatar from "../ui/Avatar.svelte";
  import { changed, resource, touch, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import CardDialog from "./CardDialog.svelte";
  import { type Card, addressBooks, cards, fullName, remove } from "./model.js";

  const jmap = useJmap();
  const books = resource(() => changed("AddressBook") + 1, () => addressBooks(jmap));
  let search = $state("");
  let query = $state("");
  const list = resource(
    () => (books.value ? { shown: books.value, text: query, version: changed("ContactCard") } : undefined),
    ({ shown, text }) => cards(jmap, shown, text),
  );
  let open = $state<Card>();
  let editing = $state<Card | "new">();

  const bookOf = (card: Card) =>
    books.value?.find((book) => book.accountId === card.accountId && card.addressBookIds[book.id]);

  function removeCard(card: Card): void {
    if (!window.confirm(t("Delete this?"))) return;
    void remove(jmap, card).then(() => {
      open = undefined;
      touch("ContactCard");
    });
  }
</script>

<div class="two">
  <section class="list">
    <div class="search row">
      <form
        class="grow"
        onsubmit={(event) => {
          event.preventDefault();
          query = search;
        }}
      >
        <Search size={16} />
        <input type="search" placeholder={t("Search")} aria-label={t("Search")} bind:value={search} />
      </form>
      <button type="button" class="primary icon" aria-label={t("New contact")} data-tip={t("New contact")} onclick={() => (editing = "new")}>
        <UserPlus size={18} />
      </button>
    </div>
    <Failure error={books.error ?? list.error} />
    {#if list.value?.length === 0}
      <p class="muted pad">{t("No contacts")}</p>
    {/if}
    <ul class="items">
      {#each list.value ?? [] as card (`${card.accountId}/${card.id}`)}
        <li>
          <button type="button" class:active={open?.id === card.id} onclick={() => (open = card)}>
            <Avatar name={fullName(card)} address={Object.values(card.emails ?? {})[0]?.address ?? ""} size={36} />
            <span class="text">
              <span class="who">{fullName(card)}</span>
              <span class="preview">{Object.values(card.emails ?? {})[0]?.address ?? ""}</span>
            </span>
          </button>
        </li>
      {/each}
    </ul>
  </section>
  <section class="read">
    {#if open}
      {@const card = open}
      {@const book = bookOf(card)}
      <article>
        <div class="actions">
          {#if book?.myRights.mayWrite}
            <button type="button" onclick={() => (editing = card)}><Pencil size={17} />{t("Edit")}</button>
            <button type="button" class="icon danger" aria-label={t("Delete")} data-tip={t("Delete")} onclick={() => removeCard(card)}>
              <Trash2 size={17} />
            </button>
          {/if}
        </div>
        <div class="sender contact-head">
          <Avatar name={fullName(card)} address={Object.values(card.emails ?? {})[0]?.address ?? ""} size={56} />
          <h2>{fullName(card)}</h2>
        </div>
        <dl class="headers">
          {#each Object.values(card.emails ?? {}) as email, index (index)}
            <dt>{t("Email")}</dt>
            <dd><a href={`mailto:${email.address}`}>{email.address}</a></dd>
          {/each}
          {#each Object.values(card.phones ?? {}) as phone, index (index)}
            <dt>{t("Phone")}</dt>
            <dd><a href={`tel:${phone.number}`}>{phone.number}</a></dd>
          {/each}
          {#each Object.values(card.organizations ?? {}) as organization, index (index)}
            <dt>{t("Organization")}</dt>
            <dd>{organization.name}</dd>
          {/each}
          {#if book}
            <dt>{t("Address books")}</dt>
            <dd>{book.shared ? `${book.name} (${t("Shared by")} ${book.shared})` : book.name}</dd>
          {/if}
        </dl>
        {#each Object.values(card.notes ?? {}) as note, index (index)}
          <pre class="body">{note.note}</pre>
        {/each}
      </article>
    {:else}
      <p class="muted pad">{t("Select a contact")}</p>
    {/if}
  </section>
  {#if editing}
    <CardDialog
      card={editing === "new" ? undefined : editing}
      books={(books.value ?? []).filter((book) => book.myRights.mayWrite)}
      onclose={(saved) => {
        editing = undefined;
        open = undefined;
        if (saved) touch("ContactCard");
      }}
    />
  {/if}
</div>
