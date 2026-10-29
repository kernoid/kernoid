<!-- SPDX-License-Identifier: MIT -->
<!-- A labelled checkbox. -->
<script lang="ts">
  let { label, name, value = "on", checked = false, hint }: { label: string; name: string; value?: string; checked?: boolean; hint?: string | undefined } = $props();
</script>

<label class="inline">
  <input type="checkbox" {name} {value} {checked} />
  <span>
    {label}
    {#if hint}
      <small class="muted"> – {hint}</small>
    {/if}
  </span>
</label>
