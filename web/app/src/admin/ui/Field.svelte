<!-- SPDX-License-Identifier: MIT -->
<!-- A labelled input; everything but the label and the hint goes to the input. -->
<script lang="ts">
  import type { HTMLInputAttributes } from "svelte/elements";

  let { label, hint, ...input }: { label: string; hint?: string | undefined } & HTMLInputAttributes = $props();
</script>

<label>
  <span>{label}</span>
  <input {...input} />
  {#if hint}
    <small class="muted">{hint}</small>
  {/if}
</label>
