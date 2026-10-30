<!-- SPDX-License-Identifier: MIT -->
<!-- Mail: the mailboxes (Folders.svelte), the emails of the one chosen, the one read, and writing. Emails are chosen one
     by one, with Ctrl or ⌘ more, with Shift a range – and dragged onto a folder to move them there. -->
<script lang="ts">
  import {
    ArrowLeft,
    Download,
    Flag,
    FolderInput,
    Forward,
    MailOpen,
    Paperclip,
    Reply,
    ReplyAll,
    Search,
    Settings,
    SquarePen,
    Trash2,
    X,
  } from "@lucide/svelte";

  import { admin, need } from "../admin/api.svelte.js";
  import { changed, loaded, resource, touch, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import Viewer from "../files/Viewer.svelte";
  import { kindOf } from "../files/kind.js";
  import { formatSize } from "../files/model.js";
  import { locale, t } from "../i18n.js";
  import { MAIL } from "../jmap.js";
  import Avatar from "../ui/Avatar.svelte";
  import FileIcon from "../ui/FileIcon.svelte";
  import type { ComposeStart } from "./Compose.svelte";
  import Folders, { EMAILS } from "./Folders.svelte";
  import { showHtml } from "./html.js";
  import {
    type BodyPart,
    type Email,
    type EmailSummary,
    bodyHtml,
    bodyText,
    destroy,
    email,
    emails,
    emptyMailbox,
    formatAddresses,
    mailboxTree,
    mailboxes,
    moveMany,
    originalPath,
    setKeyword,
  } from "./model.js";
  import { boxName } from "./names.js";

  function when(iso: string): string {
    const date = new Date(iso);
    const today = new Date();
    return date.toDateString() === today.toDateString()
      ? date.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" })
      : date.toLocaleDateString(locale, {
          day: "numeric",
          month: "short",
          ...(date.getFullYear() === today.getFullYear() ? {} : { year: "numeric" }),
        });
  }

  function sender(summary: EmailSummary): string {
    const from = summary.from?.[0];
    return from ? from.name || from.email : "";
  }

  function storedOriginal(): boolean {
    try {
      return localStorage.getItem("kernoid.mail.original") === "on";
    } catch {
      return false;
    }
  }

  const jmap = useJmap();
  const boxes = resource(() => [changed("Mailbox"), changed("Email")], () => mailboxes(jmap));
  const settings = loaded(() => need(admin.GET("/v1/account/mail-settings")).catch(() => undefined));
  let selected = $state<string>();
  let search = $state("");
  let query = $state("");
  let open = $state<string>();
  /** The emails chosen beyond the one open – for moving or deleting several at once. */
  let chosen = $state<string[]>([]);
  let anchor = $state<string>();
  // HTML emails readable (cleaned) or as their sender laid them out; kept per browser.
  let original = $state(storedOriginal());
  let composing = $state<ComposeStart>();
  let viewing = $state<BodyPart>();
  let error = $state<unknown>();

  function setOriginal(on: boolean): void {
    original = on;
    try {
      localStorage.setItem("kernoid.mail.original", on ? "on" : "off");
    } catch {
      // Not kept: readable next time.
    }
  }

  $effect(() => {
    const list = boxes.value;
    if (list && (!selected || !list.some((box) => box.id === selected))) {
      selected = list.find((box) => box.role === "inbox")?.id ?? list[0]?.id;
    }
  });

  const list = resource(
    () => (selected ? { box: selected, text: query, version: changed("Email") } : undefined),
    ({ box, text }) => emails(jmap, box, text, 100),
  );
  const message = resource(
    () => (open ? { id: open, version: changed("Email") } : undefined),
    ({ id }) => email(jmap, id),
  );

  // Reading marks as read.
  $effect(() => {
    const current = message.value;
    if (current && !current.keywords.$seen) {
      void setKeyword(jmap, current.id, "$seen", true).then(
        () => touch("Email"),
        (failure: unknown) => (error = failure),
      );
    }
  });

  function act(run: () => Promise<void>): void {
    error = undefined;
    run().then(
      () => touch("Email", "Mailbox"),
      (failure: unknown) => (error = failure),
    );
  }

  const here = $derived(boxes.value?.find((box) => box.id === selected));
  const trash = $derived(boxes.value?.find((box) => box.role === "trash"));
  const inTrash = $derived(here?.role === "trash");
  const trashDays = $derived(settings.value?.trash_retention_days ?? settings.value?.tenant_trash_retention_days ?? null);

  /** The emails acted on: those chosen, else the one open. */
  const acting = $derived(chosen.length > 0 ? chosen : open ? [open] : []);

  function remove(ids: string[]): void {
    act(async () => {
      if (!trash || inTrash) {
        if (inTrash && !window.confirm(t("Delete {count} emails for good?", { count: ids.length }))) return;
        for (const id of ids) await destroy(jmap, id);
      } else {
        await moveMany(jmap, ids, trash.id);
      }
      open = undefined;
      chosen = [];
    });
  }

  function moveTo(ids: string[], to: string): void {
    act(async () => {
      await moveMany(jmap, ids, to);
      open = undefined;
      chosen = [];
    });
  }

  function pick(summary: EmailSummary, event: MouseEvent): void {
    const ids = (list.value?.list ?? []).map((entry) => entry.id);
    if (event.shiftKey && (anchor ?? open)) {
      const from = ids.indexOf(anchor ?? open ?? "");
      const to = ids.indexOf(summary.id);
      chosen = ids.slice(Math.min(from, to), Math.max(from, to) + 1);
      return;
    }
    if (event.metaKey || event.ctrlKey) {
      const current = chosen.length > 0 ? chosen : open ? [open] : [];
      chosen = current.includes(summary.id) ? current.filter((id) => id !== summary.id) : [...current, summary.id];
      anchor = summary.id;
      return;
    }
    chosen = [];
    anchor = summary.id;
    open = summary.id;
  }

  function reply(current: Email, all: boolean): void {
    const to = current.replyTo?.length ? current.replyTo : (current.from ?? []);
    const cc = all ? [...(current.to ?? []), ...(current.cc ?? [])] : [];
    const subject = current.subject ?? "";
    composing = {
      to: formatAddresses(to),
      cc: formatAddresses(cc),
      subject: /^re:/i.test(subject) ? subject : `Re: ${subject}`,
      body: "",
      quote: { from: formatAddresses(current.from), date: current.sentAt ?? current.receivedAt, text: bodyText(current), html: bodyHtml(current) },
      inReplyTo: current.messageId,
      references: [...(current.references ?? []), ...(current.messageId ?? [])],
      excludeOwn: all,
    };
  }

  function forward(current: Email): void {
    composing = {
      to: "",
      cc: "",
      subject: `Fwd: ${current.subject ?? ""}`,
      body: "",
      quote: {
        from: formatAddresses(current.from),
        date: current.sentAt ?? current.receivedAt,
        text: bodyText(current),
        html: bodyHtml(current),
        forward: current.subject ?? "",
      },
    };
  }

  function choose(box: string): void {
    selected = box;
    open = undefined;
    chosen = [];
  }

  function attachmentUrl(part: BodyPart): string {
    return jmap.downloadPath(jmap.account(MAIL), part.blobId ?? "", part.name ?? "attachment", part.type);
  }

  const blank: ComposeStart = { to: "", cc: "", subject: "", body: "" };
  const places = $derived(mailboxTree(boxes.value ?? []));
</script>

<div class="three mail" class:reading={Boolean(open) || chosen.length > 0}>
  <aside class="side">
    <button type="button" class="primary wide" onclick={() => (composing = { ...blank })}>
      <SquarePen size={18} />{t("Write")}
    </button>
    <Folders
      boxes={boxes.value ?? []}
      {selected}
      onchoose={choose}
      onchanged={() => touch("Email", "Mailbox")}
      onerror={(failure) => (error = failure)}
    />
  </aside>
  <section class="list">
    <!-- On a phone the side is hidden: the mailbox and writing are here. -->
    <div class="narrow-only phone-bar">
      <select aria-label={t("Mailboxes")} value={selected ?? ""} onchange={(event) => choose(event.currentTarget.value)}>
        {#each places as { box, depth } (box.id)}
          <option value={box.id}>{" ".repeat(depth)}{boxName(box)}{box.unreadEmails > 0 ? ` (${box.unreadEmails})` : ""}</option>
        {/each}
      </select>
      <button type="button" class="primary icon" aria-label={t("Write")} onclick={() => (composing = { ...blank })}>
        <SquarePen size={18} />
      </button>
    </div>
    <form
      class="search"
      onsubmit={(event) => {
        event.preventDefault();
        query = search;
      }}
    >
      <Search size={16} />
      <input type="search" placeholder={t("Search")} aria-label={t("Search")} bind:value={search} oninput={() => search === "" && (query = "")} />
    </form>
    {#if inTrash && here}
      <div class="trash-note">
        <Trash2 size={16} />
        <span class="grow small">
          {trashDays
            ? t("Emails here are deleted for good after {days} days.", { days: trashDays })
            : t("Emails stay here until you delete them.")}
          <a href="#/account" data-tip={t("Change in your account")} aria-label={t("Change in your account")}><Settings size={13} /></a>
        </span>
        {#if here.totalEmails > 0}
          <button
            type="button"
            class="danger small-button"
            onclick={() =>
              window.confirm(t("Delete the {count} emails in {name} for good?", { count: here.totalEmails, name: boxName(here) })) &&
              act(async () => {
                await emptyMailbox(jmap, here.id);
                open = undefined;
              })}
          >
            {t("Empty")}
          </button>
        {/if}
      </div>
    {/if}
    <Failure error={list.error} />
    {#if list.value?.list.length === 0}
      <p class="muted pad empty">{inTrash ? t("The Trash is empty") : t("No messages")}</p>
    {/if}
    <ul class="items">
      {#each list.value?.list ?? [] as summary (summary.id)}
        {@const picked = chosen.includes(summary.id)}
        <li>
          <button
            type="button"
            aria-label={`${sender(summary)}: ${summary.subject || t("(no subject)")}`}
            class:active={open === summary.id && chosen.length === 0}
            class:picked
            class:unread={!summary.keywords.$seen}
            draggable="true"
            ondragstart={(event) => {
              const ids = picked ? chosen : [summary.id];
              event.dataTransfer?.setData(EMAILS, JSON.stringify(ids));
              event.dataTransfer?.setData("text/plain", ids.length === 1 ? summary.subject || "" : t("{count} emails", { count: ids.length }));
              if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
            }}
            onclick={(event) => pick(summary, event)}
          >
            <Avatar name={summary.from?.[0]?.name ?? ""} address={summary.from?.[0]?.email ?? ""} size={36} />
            <span class="text">
              <span class="line">
                <span class="who">{sender(summary)}</span>
                <span class="time">
                  {#if summary.hasAttachment}<Paperclip size={13} aria-label={t("Attachments")} />{/if}
                  {#if summary.keywords.$flagged}<Flag size={13} class="flag" aria-label={t("Flag")} />{/if}
                  {when(summary.receivedAt)}
                </span>
              </span>
              <span class="subject">{summary.subject || t("(no subject)")}</span>
              <span class="preview">{summary.preview}</span>
            </span>
          </button>
        </li>
      {/each}
    </ul>
  </section>
  <section class="read">
    <Failure error={error ?? message.error} />
    {#if chosen.length > 0}
      <div class="many">
        <h2>{t("{count} emails chosen", { count: chosen.length })}</h2>
        <p class="muted">{t("Drag them onto a folder, or:")}</p>
        <div class="actions">
          <FolderInput size={17} class="muted" aria-hidden="true" />
          <select
            aria-label={t("Move to")}
            onchange={(event) => {
              const to = event.currentTarget.value;
              if (to) moveTo(chosen, to);
            }}
          >
            <option value="">{t("Move to")}</option>
            {#each places.filter(({ box }) => box.id !== selected) as { box, depth } (box.id)}
              <option value={box.id}>{" ".repeat(depth)}{boxName(box)}</option>
            {/each}
          </select>
          <button type="button" class="danger" onclick={() => remove(chosen)}><Trash2 size={17} />{inTrash ? t("Delete for good") : t("Delete")}</button>
          <button type="button" class="quiet" onclick={() => (chosen = [])}><X size={17} />{t("Cancel")}</button>
        </div>
      </div>
    {:else if message.value}
      {@const current = message.value}
      {@const html = bodyHtml(current)}
      {@const path = originalPath(jmap, current)}
      <article>
        <div class="actions reading">
          <button type="button" class="icon quiet narrow-only" aria-label={t("Back")} onclick={() => (open = undefined)}><ArrowLeft size={18} /></button>
          <button type="button" onclick={() => reply(current, false)}><Reply size={17} />{t("Reply")}</button>
          <button type="button" class="icon" aria-label={t("Reply all")} data-tip={t("Reply all")} onclick={() => reply(current, true)}>
            <ReplyAll size={17} />
          </button>
          <button type="button" class="icon" aria-label={t("Forward")} data-tip={t("Forward")} onclick={() => forward(current)}>
            <Forward size={17} />
          </button>
          <span class="divider"></span>
          <button
            type="button"
            class="icon"
            class:on={current.keywords.$flagged}
            aria-label={current.keywords.$flagged ? t("Unflag") : t("Flag")}
            aria-pressed={Boolean(current.keywords.$flagged)}
            data-tip={current.keywords.$flagged ? t("Unflag") : t("Flag")}
            onclick={() => act(() => setKeyword(jmap, current.id, "$flagged", !current.keywords.$flagged))}
          >
            <Flag size={17} />
          </button>
          <button
            type="button"
            class="icon"
            aria-label={t("Mark unread")}
            data-tip={t("Mark unread")}
            onclick={() =>
              act(async () => {
                await setKeyword(jmap, current.id, "$seen", false);
                open = undefined;
              })}
          >
            <MailOpen size={17} />
          </button>
          <FolderInput size={17} class="muted" aria-hidden="true" />
          <select
            aria-label={t("Move to")}
            onchange={(event) => {
              const to = event.currentTarget.value;
              if (to) moveTo([current.id], to);
            }}
          >
            <option value="">{t("Move to")}</option>
            {#each places.filter(({ box }) => !current.mailboxIds[box.id]) as { box, depth } (box.id)}
              <option value={box.id}>{" ".repeat(depth)}{boxName(box)}</option>
            {/each}
          </select>
          <button
            type="button"
            class="icon danger"
            aria-label={inTrash ? t("Delete for good") : t("Delete")}
            data-tip={inTrash ? t("Delete for good") : t("Delete")}
            onclick={() => remove([current.id])}
          >
            <Trash2 size={17} />
          </button>
        </div>
        <h2 class="subject-line">{current.subject || t("(no subject)")}</h2>
        <div class="sender">
          <Avatar name={current.from?.[0]?.name ?? ""} address={current.from?.[0]?.email ?? ""} size={42} />
          <div>
            <strong>{current.from?.[0]?.name || current.from?.[0]?.email}</strong>
            {#if current.from?.[0]?.name}<span class="muted small">&lt;{current.from[0].email}&gt;</span>{/if}
            <div class="muted small">{new Date(current.sentAt ?? current.receivedAt).toLocaleString(locale)}</div>
          </div>
        </div>
        <dl class="headers">
          <dt>{t("To")}</dt>
          <dd>{formatAddresses(current.to)}</dd>
          {#if current.cc?.length}
            <dt>{t("Cc")}</dt>
            <dd>{formatAddresses(current.cc)}</dd>
          {/if}
        </dl>
        {#if current.attachments.length > 0}
          <ul class="attachments">
            {#each current.attachments as part, index (index)}
              {@const name = part.name ?? part.type}
              {@const viewable = kindOf(name, part.type) !== "other"}
              <li class="attachment">
                <button
                  type="button"
                  class="quiet"
                  data-tip={viewable ? t("Show") : t("Download")}
                  onclick={() => {
                    if (viewable) viewing = part;
                    else window.location.assign(attachmentUrl(part));
                  }}
                >
                  <FileIcon {name} type={part.type} size={22} />
                  <span class="text">
                    <span class="name">{name}</span>
                    <span class="muted small">{formatSize(part.size, locale)}</span>
                  </span>
                </button>
                <a class="button icon quiet small" href={attachmentUrl(part)} download={name} aria-label={t("Download")} data-tip={t("Download")}>
                  <Download size={16} />
                </a>
              </li>
            {/each}
          </ul>
        {/if}
        {#if html}
          {#if path}
            <div class="segmented view-switch" role="group" aria-label={t("View")}>
              <button type="button" class:active={!original} aria-pressed={!original} onclick={() => setOriginal(false)}>
                {t("Readable")}
              </button>
              <button type="button" class:active={original} aria-pressed={original} onclick={() => setOriginal(true)}>
                {t("Original")}
              </button>
            </div>
          {/if}
          {#if original && path}
            <iframe
              class="body original"
              src={path}
              title={current.subject ?? t("(no subject)")}
              sandbox="allow-popups allow-popups-to-escape-sandbox"
              referrerpolicy="no-referrer"
            ></iframe>
            <p class="muted small">
              {t("Images from elsewhere are not loaded, so the sender does not learn that you read it.")}
            </p>
          {:else}
            <div class="body html" {@attach (element) => showHtml(element, html)}></div>
          {/if}
        {:else}
          <pre class="body">{bodyText(current)}</pre>
        {/if}
      </article>
    {:else}
      <div class="nothing">
        <MailOpen size={48} />
        <p class="muted">{t("Select a message")}</p>
      </div>
    {/if}
  </section>
  {#if composing}
    <!-- Writing (with its editor) loads when first needed: most visits only read. -->
    {#await import("./Compose.svelte") then { default: Compose }}
      <Compose
        start={composing}
        mailboxes={boxes.value ?? []}
        defaultFrom={settings.value?.default_from ?? null}
        onclose={(sent) => {
          composing = undefined;
          if (sent) touch("Email", "Mailbox");
        }}
      />
    {/await}
  {/if}
  {#if viewing}
    {@const url = attachmentUrl(viewing)}
    <Viewer
      name={viewing.name ?? viewing.type}
      type={viewing.type}
      size={viewing.size}
      {url}
      inline={`${url}${url.includes("?") ? "&" : "?"}inline=1`}
      onclose={() => (viewing = undefined)}
    />
  {/if}
</div>
