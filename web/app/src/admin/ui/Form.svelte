<!-- SPDX-License-Identifier: MIT -->
<!-- A form whose fields arrive by name, trimmed; checkboxes as "on" or missing. -->
<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    submit,
    class: className,
    children,
  }: { submit: (field: (name: string) => string, all: (name: string) => string[]) => void; class?: string; children: Snippet } = $props();
</script>

<form
  class={className}
  onsubmit={(event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    submit(
      (name) => String(data.get(name) ?? "").trim(),
      (name) => data.getAll(name).map((value) => String(value)),
    );
  }}
>
  {@render children()}
</form>
