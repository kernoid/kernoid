<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- A labelled choice of [value, text] options. -->
<script lang="ts">
  let { label, name, value, options }: { label: string; name: string; value?: string | undefined; options: [string, string][] } = $props();
</script>

<label>
  <span>{label}</span>
  <select {name}>
    {#each options as [option, text] (option)}
      <option value={option} selected={option === value}>{text}</option>
    {/each}
  </select>
</label>
