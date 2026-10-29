<!-- SPDX-License-Identifier: MIT -->
<!-- A labelled text area. -->
<script lang="ts">
  let { label, name, value = "", hint, rows = 3 }: { label: string; name: string; value?: string; hint?: string | undefined; rows?: number } = $props();
</script>

<label>
  <span>{label}</span>
  <textarea {name} {rows} {value}></textarea>
  {#if hint}
    <small class="muted">{hint}</small>
  {/if}
</label>
