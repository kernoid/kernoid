<!-- SPDX-License-Identifier: MIT -->
<!-- A file shown in place (kind.ts). The browser loads the content from the download URL with the session's cookie;
     the server serves it with a policy that keeps it from running as a page (jmap.rs, download_response). Office
     documents and the rest: download. `url` saves the file; `inline` shows it in place (the server's `inline=1`). -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { kindOf, text } from "./kind.js";

  let {
    name,
    type,
    size,
    url,
    inline,
    onclose,
  }: { name: string; type: string | null | undefined; size: number | null; url: string; inline: string; onclose: () => void } =
    $props();

  // svelte-ignore state_referenced_locally
  const kind = kindOf(name, type);
  const content = loaded(() => (kind === "text" ? text(inline, size) : Promise.resolve("")));

  $effect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onclose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });
</script>

<!-- A click beside the sheet closes it; the keyboard closes it with Escape (the listener above). -->
<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<div
  class="overlay viewer"
  role="dialog"
  aria-modal="true"
  aria-label={name}
  tabindex="-1"
  onclick={(event) => event.target === event.currentTarget && onclose()}
>
  <div class="sheet">
    <header class="toolbar">
      <h2 class="grow">{name}</h2>
      {#if kind === "pdf"}
        <!-- Some browsers – on phones especially – show no PDF in a frame. -->
        <a class="button" href={inline} target="_blank" rel="noopener">{t("Open in a new tab")}</a>
      {/if}
      <a class="button" href={url} download={name}>{t("Download")}</a>
      <button type="button" onclick={() => onclose()}>{t("Close")}</button>
    </header>
    <div class="stage">
      {#if kind === "image"}
        <img src={inline} alt={name} />
      {:else if kind === "audio"}
        <!-- svelte-ignore a11y_autofocus -->
        <audio controls autoplay src={inline}></audio>
      {:else if kind === "video"}
        <!-- svelte-ignore a11y_media_has_caption -->
        <video controls autoplay src={inline}></video>
      {:else if kind === "pdf"}
        <iframe src={inline} title={name}></iframe>
      {:else if kind === "text"}
        <Failure error={content.error} />
        {#if content.value !== undefined && !content.loading}
          <pre class="text">{content.value}</pre>
        {:else}
          <p class="muted">{t("Loading")}</p>
        {/if}
      {:else}
        <p class="muted">{t("There is no preview for this file. Download it to open it.")}</p>
      {/if}
    </div>
  </div>
</div>
