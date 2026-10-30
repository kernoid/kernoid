<!-- SPDX-License-Identifier: MIT -->
<!-- The toasts (toasts.svelte.ts), at the bottom of the window; read out by screen readers as they come. -->
<script lang="ts">
  import { CircleAlert, CircleCheck, X } from "@lucide/svelte";

  import { t } from "../i18n.js";
  import { dismiss, toasts } from "./toasts.svelte.js";

  let now = $state(Date.now());
  $effect(() => {
    const timer = setInterval(() => (now = Date.now()), 250);
    return () => clearInterval(timer);
  });
</script>

<div class="toasts" role="status" aria-live="polite">
  {#each toasts() as entry (entry.id)}
    <div class="toast" class:error={entry.kind === "error"}>
      {#if entry.kind === "error"}<CircleAlert size={18} />{:else}<CircleCheck size={18} />{/if}
      <span class="grow">{entry.text}</span>
      {#if entry.action}
        {@const action = entry.action}
        <button
          type="button"
          class="toast-action"
          onclick={() => {
            dismiss(entry.id);
            void action.run();
          }}
        >
          {action.label}
          <span class="muted small">{Math.max(0, Math.ceil((entry.until - now) / 1000))}</span>
        </button>
      {/if}
      <button type="button" class="icon quiet small" aria-label={t("Close")} onclick={() => dismiss(entry.id)}><X size={15} /></button>
    </div>
  {/each}
</div>
