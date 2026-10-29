<!-- SPDX-License-Identifier: MIT -->
<!-- For instance administrators: the queue of outgoing mail not yet delivered. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import { when } from "./ui.svelte.js";
  import Head from "./ui/Head.svelte";

  const queue = loaded(() => need(admin.GET("/v1/instance/mail-queue", { params: { query: { limit: 200 } } })));
</script>

<Head title={t("Mail queue")} description={t("Outgoing mail not yet delivered, newest first; kernoid tries again by itself.")}>
  <button type="button" onclick={() => void queue.refetch()}>{t("Refresh")}</button>
</Head>
<table class="nodes">
  <tbody>
    {#each queue.value ?? [] as entry (entry.message + entry.address)}
      <tr>
        <td class="name">
          {entry.address}
          {#if entry.last_error}
            <div class="small warn">{entry.last_error}</div>
          {/if}
        </td>
        <td class="small">{t(entry.status)}</td>
        <td class="small muted">{t("{count} tries", { count: entry.attempts })}</td>
        <td class="small muted">{t("next {date}", { date: when(entry.next_attempt_at) })}</td>
      </tr>
    {:else}
      <tr><td class="muted">{emptyText(queue, t("The queue is empty."))}</td></tr>
    {/each}
  </tbody>
</table>
