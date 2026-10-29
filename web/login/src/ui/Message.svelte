<!-- SPDX-License-Identifier: MIT -->
<!-- A failure, or something to know. -->
<script lang="ts">
  let { text, kind = "error" }: { text: string; kind?: "error" | "info" } = $props();
</script>

<p class="message {kind}" role={kind === "error" ? "alert" : "status"}>{text}</p>
