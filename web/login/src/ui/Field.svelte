<!-- SPDX-License-Identifier: MIT -->
<!-- A labelled input; everything but the label goes to the input. -->
<script lang="ts">
  import type { HTMLInputAttributes } from "svelte/elements";

  let { label, name, ...input }: { label: string; name: string } & HTMLInputAttributes = $props();
</script>

<label for={`f-${name}`}>
  <span>{label}</span>
  <input id={`f-${name}`} {name} {...input} />
</label>
