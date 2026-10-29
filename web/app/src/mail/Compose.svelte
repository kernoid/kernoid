<!-- SPDX-License-Identifier: MIT -->
<!-- Writing an email: from one of the account's identities, plain text, with attachments. -->
<script lang="ts" module>
  export interface ComposeStart {
    to: string;
    cc: string;
    subject: string;
    body: string;
    inReplyTo?: string[] | null;
    references?: string[] | null;
    /** Reply all: leave the own addresses out. */
    excludeOwn?: boolean;
  }
</script>

<script lang="ts">
  import { loaded, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { type Attachment, type Mailbox, identities, parseAddresses, send, upload } from "./model.js";

  let { start, mailboxes, onclose }: { start: ComposeStart; mailboxes: Mailbox[]; onclose: (sent: boolean) => void } =
    $props();

  const jmap = useJmap();
  const from = loaded(() => identities(jmap));
  // svelte-ignore state_referenced_locally
  let { to, cc, subject, body } = $state({ to: start.to, cc: start.cc, subject: start.subject, body: start.body });
  let identity = $state("");
  let busy = $state(false);
  let error = $state<unknown>();
  let files = $state<Attachment[]>([]);
  let uploading = $state(0);

  async function add(list: FileList | null): Promise<void> {
    for (const file of Array.from(list ?? [])) {
      uploading += 1;
      try {
        files = [...files, await upload(jmap, file)];
      } catch (failure) {
        error = failure;
      } finally {
        uploading -= 1;
      }
    }
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const list = from.value ?? [];
    const chosen = list.find((entry) => entry.id === identity) ?? list[0];
    if (!chosen) return;
    const own = new Set(list.map((entry) => entry.email.toLowerCase()));
    const keep = (text: string) =>
      parseAddresses(text).filter((address) => !start.excludeOwn || !own.has(address.email.toLowerCase()));
    busy = true;
    error = undefined;
    try {
      await send(
        jmap,
        {
          identity: chosen,
          attachments: files,
          to: keep(to),
          cc: keep(cc),
          subject,
          body,
          inReplyTo: start.inReplyTo ?? null,
          references: start.references ?? null,
        },
        mailboxes,
      );
      onclose(true);
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
    }
  }
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={t("Write")}>
  <form class="dialog compose" onsubmit={(event) => void submit(event)}>
    <label>
      <span>{t("From")}</span>
      <select bind:value={identity}>
        {#each from.value ?? [] as entry (entry.id)}
          <option value={entry.id}>{entry.name ? `${entry.name} <${entry.email}>` : entry.email}</option>
        {/each}
      </select>
    </label>
    <label>
      <span>{t("To")}</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input type="text" required bind:value={to} autofocus={!start.to} />
    </label>
    <label>
      <span>{t("Cc")}</span>
      <input type="text" bind:value={cc} />
    </label>
    <label>
      <span>{t("Subject")}</span>
      <input type="text" bind:value={subject} />
    </label>
    <!-- svelte-ignore a11y_autofocus -->
    <textarea rows={14} bind:value={body} autofocus={!!start.to} aria-label={t("Text")}></textarea>
    <div class="files">
      <label class="file">
        <input type="file" multiple onchange={(event) => void add(event.currentTarget.files)} />
        <span>{t("Attach files")}</span>
      </label>
      {#each files as file (file.blobId)}
        <span class="chip">
          {file.name} ({Math.ceil(file.size / 1024)} KB)
          <button
            type="button"
            class="quiet"
            aria-label={t("Remove")}
            onclick={() => (files = files.filter((entry) => entry !== file))}>×</button
          >
        </span>
      {/each}
      {#if uploading > 0}
        <span class="muted">{t("Uploading")}</span>
      {/if}
    </div>
    <Failure {error} />
    <div class="actions end">
      <button type="button" class="quiet" onclick={() => onclose(false)}>{t("Cancel")}</button>
      <button type="submit" class="primary" disabled={busy || uploading > 0 || !from.value}>
        {busy ? t("Sending") : t("Send")}
      </button>
    </div>
  </form>
</div>
