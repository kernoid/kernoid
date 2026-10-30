<!-- SPDX-License-Identifier: MIT -->
<!-- Mail: the mailboxes, the emails of the one chosen, the one read, and writing. -->
<script lang="ts">
  import {
    Archive,
    FileText,
    Flag,
    Folder,
    FolderInput,
    Forward,
    Inbox,
    MailOpen,
    Paperclip,
    Reply,
    ReplyAll,
    Search,
    Send,
    ShieldAlert,
    SquarePen,
    Trash2,
  } from "@lucide/svelte";

  import { changed, resource, touch, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import { MAIL } from "../jmap.js";
  import Compose, { type ComposeStart } from "./Compose.svelte";
  import Avatar from "../ui/Avatar.svelte";
  import { showHtml } from "./html.js";
  import {
    type Email,
    type EmailSummary,
    type Mailbox,
    bodyHtml,
    bodyText,
    destroy,
    email,
    emails,
    formatAddresses,
    mailboxes,
    move,
    originalPath,
    setKeyword,
  } from "./model.js";

  const ROLE_NAMES: Record<string, string> = {
    inbox: "Inbox",
    drafts: "Drafts",
    sent: "Sent",
    archive: "Archive",
    junk: "Junk",
    trash: "Trash",
  };

  const ROLE_ICONS: Record<string, typeof Inbox> = {
    inbox: Inbox,
    drafts: FileText,
    sent: Send,
    archive: Archive,
    junk: ShieldAlert,
    trash: Trash2,
  };

  function boxName(box: Mailbox): string {
    return box.role ? t(ROLE_NAMES[box.role] ?? box.name) : box.name;
  }

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
  let selected = $state<string>();
  let search = $state("");
  let query = $state("");
  let open = $state<string>();
  // HTML emails readable (cleaned) or as their sender laid them out; kept per browser.
  let original = $state(storedOriginal());
  let composing = $state<ComposeStart>();
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
    if (list && !selected) selected = list.find((box) => box.role === "inbox")?.id ?? list[0]?.id;
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
      () => {
        touch("Email", "Mailbox");
      },
      (failure: unknown) => (error = failure),
    );
  }

  const trash = $derived(boxes.value?.find((box) => box.role === "trash"));

  function remove(current: Email): void {
    act(async () => {
      if (!trash || current.mailboxIds[trash.id]) await destroy(jmap, current.id);
      else await move(jmap, current.id, trash.id);
      open = undefined;
    });
  }

  function reply(current: Email, all: boolean): void {
    const to = current.replyTo?.length ? current.replyTo : (current.from ?? []);
    const cc = all ? [...(current.to ?? []), ...(current.cc ?? [])] : [];
    const subject = current.subject ?? "";
    composing = {
      to: formatAddresses(to),
      cc: formatAddresses(cc),
      subject: /^re:/i.test(subject) ? subject : `Re: ${subject}`,
      body: `\n\n> ${bodyText(current).split("\n").join("\n> ")}`,
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
      body: `\n\n---------- ${t("Forward")} ----------\n${t("From")}: ${formatAddresses(current.from)}\n${t("Subject")}: ${current.subject ?? ""}\n\n${bodyText(current)}`,
    };
  }

  function choose(box: string): void {
    selected = box;
    open = undefined;
  }

  const blank: ComposeStart = { to: "", cc: "", subject: "", body: "" };
</script>

<div class="three">
  <aside class="side">
    <button type="button" class="primary wide" onclick={() => (composing = { ...blank })}>
      <SquarePen size={18} />{t("Write")}
    </button>
    <ul class="boxes">
      {#each boxes.value ?? [] as box (box.id)}
        {@const Icon = (box.role && ROLE_ICONS[box.role]) || Folder}
        <li>
          <button
            type="button"
            aria-label={box.unreadEmails > 0 ? `${boxName(box)} (${box.unreadEmails})` : boxName(box)}
            class:active={selected === box.id}
            onclick={() => choose(box.id)}
          >
            <Icon size={18} />
            <span class="label">{boxName(box)}</span>
            {#if box.unreadEmails > 0}
              <span class="count">{box.unreadEmails}</span>
            {/if}
          </button>
        </li>
      {/each}
    </ul>
  </aside>
  <section class="list">
    <!-- On a phone the side is hidden: the mailbox and writing are here. -->
    <div class="narrow-only phone-bar">
      <select aria-label={t("Mailboxes")} value={selected ?? ""} onchange={(event) => choose(event.currentTarget.value)}>
        {#each boxes.value ?? [] as box (box.id)}
          <option value={box.id}>{boxName(box)}{box.unreadEmails > 0 ? ` (${box.unreadEmails})` : ""}</option>
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
      <input type="search" placeholder={t("Search")} aria-label={t("Search")} bind:value={search} />
    </form>
    <Failure error={list.error} />
    {#if list.value?.list.length === 0}
      <p class="muted pad">{t("No messages")}</p>
    {/if}
    <ul class="items">
      {#each list.value?.list ?? [] as summary (summary.id)}
        <li>
          <button
            type="button"
            aria-label={`${sender(summary)}: ${summary.subject || t("(no subject)")}`}
            class:active={open === summary.id}
            class:unread={!summary.keywords.$seen}
            onclick={() => (open = summary.id)}
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
    {#if message.value}
      {@const current = message.value}
      {@const html = bodyHtml(current)}
      {@const path = originalPath(jmap, current)}
      <article>
        <div class="actions reading">
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
              if (to) act(() => move(jmap, current.id, to).then(() => (open = undefined)));
            }}
          >
            <option value="">{t("Move to")}</option>
            {#each (boxes.value ?? []).filter((box) => !current.mailboxIds[box.id]) as box (box.id)}
              <option value={box.id}>{boxName(box)}</option>
            {/each}
          </select>
          <button type="button" class="icon danger" aria-label={t("Delete")} data-tip={t("Delete")} onclick={() => remove(current)}>
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
        {#if current.attachments.length > 0}
          <h3>{t("Attachments")}</h3>
          <ul class="attachments">
            {#each current.attachments as part, index (index)}
              <li>
                <a
                  href={jmap.downloadPath(jmap.account(MAIL), part.blobId ?? "", part.name ?? "attachment", part.type)}
                  download={part.name ?? "attachment"}
                >
                  {part.name ?? part.type} ({Math.ceil(part.size / 1024)} KB)
                </a>
              </li>
            {/each}
          </ul>
        {/if}
      </article>
    {:else}
      <p class="muted pad">{t("Select a message")}</p>
    {/if}
  </section>
  {#if composing}
    <Compose
      start={composing}
      mailboxes={boxes.value ?? []}
      onclose={(sent) => {
        composing = undefined;
        if (sent) touch("Email", "Mailbox");
      }}
    />
  {/if}
</div>
