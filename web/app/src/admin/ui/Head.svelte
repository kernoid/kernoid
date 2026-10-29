<!-- SPDX-License-Identifier: MIT -->
<!-- A page's heading with its buttons. -->
<script lang="ts">
  import type { Snippet } from "svelte";

  let { title, description, children }: { title: string; description?: string | undefined; children?: Snippet } = $props();
</script>

<div class="toolbar head">
  <h1 class="grow">{title}</h1>
  {@render children?.()}
</div>
{#if description}
  <p class="muted">{description}</p>
{/if}
