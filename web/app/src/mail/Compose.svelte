<!-- SPDX-License-Identifier: MIT -->
<!-- Writing an email: from one of the account's identities – the one chosen as default unless another is picked –,
     with formatting (Editor.svelte), the email answered or forwarded quoted beneath, and attachments. It goes out as
     HTML with the plain text alongside. -->
<script lang="ts" module>
  export interface ComposeStart {
    to: string;
    cc: string;
    subject: string;
    body: string;
    /** The email answered or forwarded, quoted beneath what is written. */
    quote?: { from: string; date: string; text: string; html?: string | undefined; forward?: string };
    inReplyTo?: string[] | null;
    references?: string[] | null;
    /** Reply all: leave the own addresses out. */
    excludeOwn?: boolean;
  }
</script>

<script lang="ts">
  import { Paperclip, Send, X } from "@lucide/svelte";

  import { loaded, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { formatSize } from "../files/model.js";
  import { locale, t } from "../i18n.js";
  import FileIcon from "../ui/FileIcon.svelte";
  import Editor from "./Editor.svelte";
  import { type Attachment, type Mailbox, identities, parseAddresses, send, upload } from "./model.js";

  let {
    start,
    mailboxes,
    defaultFrom = null,
    onclose,
  }: { start: ComposeStart; mailboxes: Mailbox[]; defaultFrom?: string | null; onclose: (sent: boolean) => void } = $props();

  const escape = (text: string) => text.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c);
  const paragraphs = (text: string) =>
    text
      .split(/\n{2,}/)
      .map((block) => `<p>${escape(block).replace(/\n/g, "<br>")}</p>`)
      .join("");

  /** What the editor starts with: the text given, then the quoted email. */
  function initial(): string {
    const quote = start.quote;
    const own = start.body ? paragraphs(start.body) : "<p></p>";
    if (!quote) return own;
    const date = new Date(quote.date).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
    const original = quote.html ?? paragraphs(quote.text);
    if (quote.forward !== undefined) {
      return `${own}<p>${escape(`---------- ${t("Forwarded message")} ----------`)}<br>${escape(`${t("From")}: ${quote.from}`)}<br>${escape(
        `${t("Date")}: ${date}`,
      )}<br>${escape(`${t("Subject")}: ${quote.forward}`)}</p>${original}`;
    }
    return `${own}<p>${escape(t("On {date}, {from} wrote:", { date, from: quote.from }))}</p><blockquote>${original}</blockquote>`;
  }

  const jmap = useJmap();
  const from = loaded(() => identities(jmap));
  // svelte-ignore state_referenced_locally
  let { to, cc, subject } = $state({ to: start.to, cc: start.cc, subject: start.subject });
  // svelte-ignore state_referenced_locally
  let showCc = $state(Boolean(start.cc));
  let html = $state("");
  let text = $state("");
  let identity = $state("");
  let busy = $state(false);
  let error = $state<unknown>();
  let files = $state<Attachment[]>([]);
  let uploading = $state(0);
  let dropping = $state(false);
  // svelte-ignore state_referenced_locally
  const content = initial();

  // The default sender, once the identities are known.
  $effect(() => {
    const list = from.value;
    if (!list || identity) return;
    identity = (list.find((entry) => defaultFrom && entry.email.toLowerCase() === defaultFrom.toLowerCase()) ?? list[0])?.id ?? "";
  });

  async function add(list: FileList | null | undefined): Promise<void> {
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
    const keep = (value: string) =>
      parseAddresses(value).filter((address) => !start.excludeOwn || !own.has(address.email.toLowerCase()));
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
          body: text,
          html,
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
  <form
    class="dialog wide compose"
    class:dropping
    onsubmit={(event) => void submit(event)}
    ondragover={(event) => {
      if (event.dataTransfer?.types.includes("Files")) {
        event.preventDefault();
        dropping = true;
      }
    }}
    ondragleave={() => (dropping = false)}
    ondrop={(event) => {
      if (!event.dataTransfer?.files.length) return;
      event.preventDefault();
      dropping = false;
      void add(event.dataTransfer.files);
    }}
  >
    <div class="compose-head">
      <h2>{subject.trim() || t("New message")}</h2>
      <button type="button" class="icon quiet" aria-label={t("Cancel")} data-tip={t("Cancel")} onclick={() => onclose(false)}>
        <X size={18} />
      </button>
    </div>
    <div class="fields">
      <label class="field-row">
        <span>{t("From")}</span>
        <select bind:value={identity}>
          {#each from.value ?? [] as entry (entry.id)}
            <option value={entry.id}>{entry.name ? `${entry.name} <${entry.email}>` : entry.email}</option>
          {/each}
        </select>
      </label>
      <div class="field-row">
        <label for="compose-to">{t("To")}</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input id="compose-to" type="text" required bind:value={to} autofocus={!start.to} />
        {#if !showCc}
          <button type="button" class="quiet small-button" onclick={() => (showCc = true)}>{t("Cc")}</button>
        {/if}
      </div>
      {#if showCc}
        <label class="field-row">
          <span>{t("Cc")}</span>
          <input type="text" bind:value={cc} />
        </label>
      {/if}
      <label class="field-row">
        <span>{t("Subject")}</span>
        <input type="text" bind:value={subject} />
      </label>
    </div>
    <Editor
      {content}
      autofocus={Boolean(start.to)}
      onchange={(nextHtml, nextText) => {
        html = nextHtml;
        text = nextText;
      }}
    />
    {#if files.length > 0 || uploading > 0}
      <ul class="attachments">
        {#each files as file (file.blobId)}
          <li class="attachment">
            <span class="quiet">
              <FileIcon name={file.name} type={file.type} size={22} />
              <span class="text">
                <span class="name">{file.name}</span>
                <span class="muted small">{formatSize(file.size, locale)}</span>
              </span>
            </span>
            <button
              type="button"
              class="icon quiet small"
              aria-label={t("Remove")}
              data-tip={t("Remove")}
              onclick={() => (files = files.filter((entry) => entry !== file))}
            >
              <X size={15} />
            </button>
          </li>
        {/each}
        {#if uploading > 0}
          <li class="muted small">{t("Uploading")}</li>
        {/if}
      </ul>
    {/if}
    <Failure {error} />
    <div class="compose-foot">
      <button type="submit" class="primary" disabled={busy || uploading > 0 || !from.value}>
        <Send size={17} />{busy ? t("Sending") : t("Send")}
      </button>
      <label class="button icon quiet" data-tip={t("Attach files")} aria-label={t("Attach files")}>
        <Paperclip size={18} />
        <input type="file" multiple hidden onchange={(event) => void add(event.currentTarget.files)} />
      </label>
      <span class="grow"></span>
      <span class="muted small">{t("Drop files here to attach them")}</span>
    </div>
  </form>
</div>
