<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- A failure shown in place. -->
<script lang="ts">
  import { message } from "./app.svelte.js";

  let { error }: { error: unknown } = $props();
</script>

{#if error}
  <p class="error" role="alert">{message(error)}</p>
{/if}
