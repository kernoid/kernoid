<!-- SPDX-License-Identifier: MIT -->
<!-- The current screen (screen.svelte.ts); each new one gets the focus on its first field, button or heading. -->
<script lang="ts">
  import { screen } from "./screen.svelte.js";

  const current = $derived(screen());

  function focus(element: HTMLElement): void {
    const first = (selector: string) => element.querySelector<HTMLElement>(selector);
    (first("input:not([type=hidden])") ?? first("button") ?? first("h1"))?.focus();
  }
</script>

{#if current}
  {#key current.turn}
    <div class="screen" {@attach focus}>
      <current.component {...current.props} />
    </div>
  {/key}
{:else}
  <p class="muted">Loading…</p>
{/if}
