<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- The dialog of `ask` (ask.svelte.ts): a label, a field with the text, OK and Cancel; Enter answers, Escape or a
     click beside it cancels. -->
<script lang="ts">
  import Dialog from "../admin/ui/Dialog.svelte";
  import { t } from "../i18n.js";
  import { question } from "./ask.svelte.js";

  const asked = $derived(question());

  /** Into the field, its text chosen – `autofocus` does not reach a field that appears after the page loaded. */
  function focus(field: HTMLInputElement): void {
    queueMicrotask(() => {
      field.focus();
      field.select();
    });
  }
</script>

{#if asked}
  {#key asked}
    {@const current = asked}
    {@render form(current.label, current.value, current.answer)}
  {/key}
{/if}

{#snippet form(label: string, value: string, answer: (text: string | null) => void)}
  <Dialog title={label} onClose={() => answer(null)}>
    <!-- Escape answers here, so that a dialog beneath – the message being written – stays open. -->
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <form
      onkeydown={(event) => {
        if (event.key !== "Escape") return;
        event.stopPropagation();
        answer(null);
      }}
      onsubmit={(event) => {
        event.preventDefault();
        answer(String(new FormData(event.currentTarget).get("text") ?? ""));
      }}
    >
      <input name="text" class="answer" aria-label={label} {value} use:focus />
      <div class="actions end">
        <button type="button" onclick={() => answer(null)}>{t("Cancel")}</button>
        <button type="submit" class="primary">{t("OK")}</button>
      </div>
    </form>
  </Dialog>
{/snippet}

<style>
  .answer {
    width: 100%;
  }
</style>
