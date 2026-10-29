<!-- SPDX-License-Identifier: MIT -->
<!-- The page frame: wordmark, heading, content. -->
<script lang="ts">
  import type { Snippet } from "svelte";

  let { title, children }: { title: string; children?: Snippet } = $props();

  /** Whether the page is light: as the web app chose (theme.ts), else as the system is. */
  function lightTheme(): boolean {
    const chosen = document.documentElement.getAttribute("data-theme");
    return chosen ? chosen === "light" : window.matchMedia("(prefers-color-scheme: light)").matches;
  }
</script>

<section class="card">
  <img src={`/login/kernoid-wordmark-flat-on-${lightTheme() ? "light" : "dark"}.svg`} alt="kernoid" class="wordmark" width="140" />
  <h1 tabindex="-1">{title}</h1>
  {@render children?.()}
</section>
