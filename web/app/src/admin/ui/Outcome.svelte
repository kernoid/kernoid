<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
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
