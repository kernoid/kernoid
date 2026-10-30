<!-- SPDX-License-Identifier: MIT -->
<!-- A contact made or changed: name, email, phone, organisation, address book, note. -->
<script lang="ts">
  import { useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { type AddressBook, type Card, type CardForm, create, fullName, update } from "./model.js";

  let { card, books, onclose }: { card: Card | undefined; books: AddressBook[]; onclose: (saved: boolean) => void } =
    $props();

  const jmap = useJmap();
  const first = <T,>(record: Record<string, T> | undefined) => Object.values(record ?? {})[0];
  // svelte-ignore state_referenced_locally
  const initial = card
    ? books.find((entry) => entry.accountId === card.accountId && card.addressBookIds[entry.id])
    : books.find((entry) => entry.isDefault);
  let book = $state(initial ? `${initial.accountId}/${initial.id}` : "");
  // svelte-ignore state_referenced_locally
  let name = $state(card ? fullName(card) : "");
  // svelte-ignore state_referenced_locally
  let email = $state(first(card?.emails)?.address ?? "");
  // svelte-ignore state_referenced_locally
  let phone = $state(first(card?.phones)?.number ?? "");
  // svelte-ignore state_referenced_locally
  let organization = $state(first(card?.organizations)?.name ?? "");
  // svelte-ignore state_referenced_locally
  let note = $state(first(card?.notes)?.note ?? "");
  let error = $state<unknown>();

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const [accountId, id] = book.split("/");
    const target = books.find((entry) => entry.accountId === accountId && entry.id === id);
    if (!target) return;
    const form: CardForm = { book: target, name, email, phone, organization, note };
    try {
      if (card) await update(jmap, card, form, books);
      else await create(jmap, form);
      onclose(true);
    } catch (failure) {
      error = failure;
    }
  }
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={t("New contact")}>
  <form class="dialog" onsubmit={(event) => void save(event)}>
    <label>
      <span>{t("Name")}</span>
      <input type="text" required bind:value={name} />
    </label>
    <label>
      <span>{t("Email")}</span>
      <input type="email" bind:value={email} />
    </label>
    <label>
      <span>{t("Phone")}</span>
      <input type="tel" bind:value={phone} />
    </label>
    <label>
      <span>{t("Organization")}</span>
      <input type="text" bind:value={organization} />
    </label>
    <label>
      <span>{t("Address books")}</span>
      <select bind:value={book}>
        {#each books as entry (`${entry.accountId}/${entry.id}`)}
          <option value={`${entry.accountId}/${entry.id}`}>{entry.shared ? `${entry.name} (${entry.shared})` : entry.name}</option>
        {/each}
      </select>
    </label>
    <label>
      <span>{t("Note")}</span>
      <textarea rows={3} bind:value={note}></textarea>
    </label>
    <Failure {error} />
    <div class="actions end">
      <button type="button" class="quiet" onclick={() => onclose(false)}>{t("Cancel")}</button>
      <button type="submit" class="primary">{t("Save")}</button>
    </div>
  </form>
</div>
