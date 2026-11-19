<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- A labelled checkbox. -->
<script lang="ts">
  let {
    label,
    name,
    value = "on",
    checked = false,
    disabled = false,
    hint,
  }: { label: string; name: string; value?: string; checked?: boolean; disabled?: boolean; hint?: string | undefined } = $props();
</script>

<label class="inline">
  <input type="checkbox" {name} {value} {checked} {disabled} />
  <span>
    {label}
    {#if hint}
      <small class="muted"> – {hint}</small>
    {/if}
  </span>
</label>
