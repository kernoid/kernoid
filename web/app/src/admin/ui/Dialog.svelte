<!-- SPDX-License-Identifier: MIT -->
<!-- A modal dialog; Escape or a click beside it closes it. -->
<script lang="ts">
  import type { Snippet } from "svelte";

  let { title, onClose, wide = false, children }: { title: string; onClose: () => void; wide?: boolean; children: Snippet } = $props();
</script>

<svelte:window onkeydown={(event) => event.key === "Escape" && onClose()} />
<!-- svelte-ignore a11y_click_events_have_key_events -->
<div class="overlay" role="dialog" aria-modal="true" aria-label={title} tabindex="-1" onclick={(event) => event.target === event.currentTarget && onClose()}>
  <div class="dialog" class:wide>
    <h2>{title}</h2>
    {@render children()}
  </div>
</div>
