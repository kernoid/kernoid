<!-- SPDX-License-Identifier: MIT -->
<!-- A form whose submit handler gets the values; the button is disabled while it runs. -->
<script lang="ts">
  import type { Snippet } from "svelte";

  import { describe } from "../describe.js";
  import Message from "./Message.svelte";

  let {
    label,
    submit,
    children,
  }: { label: string; submit: (values: Record<string, string>) => Promise<void>; children: Snippet } = $props();

  let busy = $state(false);
  let error = $state<string>();

  function onsubmit(event: SubmitEvent): void {
    event.preventDefault();
    const values: Record<string, string> = {};
    for (const [key, value] of new FormData(event.currentTarget as HTMLFormElement)) values[key] = String(value);
    busy = true;
    error = undefined;
    submit(values)
      .catch((failure: unknown) => (error = describe(failure)))
      .finally(() => (busy = false));
  }
</script>

<form novalidate {onsubmit}>
  {@render children()}
  <div class="status">
    {#if error}
      <Message text={error} />
    {/if}
  </div>
  <button type="submit" class="primary" disabled={busy}>{label}</button>
</form>
