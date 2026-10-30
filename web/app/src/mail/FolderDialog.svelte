<!-- SPDX-License-Identifier: MIT -->
<!-- A folder made, renamed or moved: its name and where it lies – at the top or beneath another folder (never
     beneath itself). -->
<script lang="ts">
  import Dialog from "../admin/ui/Dialog.svelte";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { type Mailbox, mailboxTree, within } from "./model.js";
  import { boxName } from "./names.js";

  let {
    title,
    boxes,
    box,
    parent = null,
    label,
    save,
    onclose,
  }: {
    title: string;
    boxes: Mailbox[];
    /** The folder changed; none when one is made. */
    box?: Mailbox | undefined;
    parent?: string | null;
    label: string;
    save: (name: string, parent: string | null) => Promise<void>;
    onclose: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let name = $state(box?.name ?? "");
  // svelte-ignore state_referenced_locally
  let where = $state(box ? (box.parentId ?? "") : (parent ?? ""));
  let busy = $state(false);
  let error = $state<unknown>();

  const places = $derived(mailboxTree(boxes).filter(({ box: other }) => !box || !within(boxes, other.id, box.id)));

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    error = undefined;
    try {
      await save(name.trim(), where || null);
      onclose();
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog {title} onClose={onclose}>
  <form onsubmit={submit}>
    <label>
      <span>{t("Name")}</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input bind:value={name} required autofocus />
    </label>
    <label>
      <span>{t("Inside")}</span>
      <select bind:value={where}>
        <option value="">{t("At the top")}</option>
        {#each places as { box: place, depth } (place.id)}
          <option value={place.id}>{" ".repeat(depth)}{boxName(place)}</option>
        {/each}
      </select>
    </label>
    <Failure {error} />
    <div class="actions end">
      <button type="button" onclick={onclose}>{t("Cancel")}</button>
      <button type="submit" class="primary" disabled={busy || !name.trim()}>{label}</button>
    </div>
  </form>
</Dialog>
