<!-- SPDX-License-Identifier: MIT -->
<!-- A button that runs an action, showing its error next to it. -->
<script lang="ts">
  import { describe } from "../describe.js";
  import Message from "./Message.svelte";

  let { label, run, kind = "secondary" }: { label: string; run: () => Promise<void>; kind?: string } = $props();

  let busy = $state(false);
  let error = $state<string>();

  function click(): void {
    busy = true;
    error = undefined;
    run()
      .catch((failure: unknown) => (error = describe(failure)))
      .finally(() => (busy = false));
  }
</script>

<div class="action">
  <button type="button" class={kind} disabled={busy} onclick={click}>{label}</button>
  <span class="status">
    {#if error}
      <Message text={error} />
    {/if}
  </span>
</div>
