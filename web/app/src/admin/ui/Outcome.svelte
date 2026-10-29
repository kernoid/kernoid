<!-- SPDX-License-Identifier: MIT -->
<!-- How an action ended: its notice or its failure. -->
<script lang="ts">
  import Failure from "../../Failure.svelte";
  import type { Action } from "../ui.svelte.js";

  let { action }: { action: Action } = $props();
</script>

{#if action.notice}
  <p class="notice" role="status">{action.notice}</p>
{/if}
<Failure error={action.error} />
