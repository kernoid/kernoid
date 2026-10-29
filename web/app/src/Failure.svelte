<!-- SPDX-License-Identifier: MIT -->
<!-- A failure shown in place. -->
<script lang="ts">
  import { message } from "./app.svelte.js";

  let { error }: { error: unknown } = $props();
</script>

{#if error}
  <p class="error" role="alert">{message(error)}</p>
{/if}
