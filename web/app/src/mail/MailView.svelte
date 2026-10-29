<!-- SPDX-License-Identifier: MIT -->
<!-- Mail: the mailboxes, the emails of the one chosen, the one read, and writing. -->
<script lang="ts">
  import { changed, resource, touch, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import { MAIL } from "../jmap.js";
  import Compose, { type ComposeStart } from "./Compose.svelte";
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
    <button type="button" class="primary wide" onclick={() => (composing = { ...blank })}>{t("Write")}</button>
    <ul class="boxes">
      {#each boxes.value ?? [] as box (box.id)}
        <li>
          <button
            type="button"
            aria-label={box.unreadEmails > 0 ? `${boxName(box)} (${box.unreadEmails})` : boxName(box)}
            class:active={selected === box.id}
            onclick={() => choose(box.id)}
          >
            <span>{boxName(box)}</span>
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
      <button type="button" class="primary" onclick={() => (composing = { ...blank })}>{t("Write")}</button>
    </div>
    <form
      class="search"
      onsubmit={(event) => {
        event.preventDefault();
        query = search;
      }}
    >
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
            <span class="line">
              <span class="who">{sender(summary)}</span>
              <span class="time">{when(summary.receivedAt)}</span>
            </span>
            <span class="subject">
              {#if summary.keywords.$flagged}
                <span class="flag" aria-label={t("Flag")}>● </span>
              {/if}
              {summary.subject || t("(no subject)")}
            </span>
            <span class="preview">{summary.preview}</span>
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
        <div class="actions">
          <button type="button" onclick={() => reply(current, false)}>{t("Reply")}</button>
          <button type="button" onclick={() => reply(current, true)}>{t("Reply all")}</button>
          <button type="button" onclick={() => forward(current)}>{t("Forward")}</button>
          <button
            type="button"
            onclick={() => act(() => setKeyword(jmap, current.id, "$flagged", !current.keywords.$flagged))}
          >
            {current.keywords.$flagged ? t("Unflag") : t("Flag")}
          </button>
          <button
            type="button"
            onclick={() =>
              act(async () => {
                await setKeyword(jmap, current.id, "$seen", false);
                open = undefined;
              })}
          >
            {t("Mark unread")}
          </button>
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
          <button type="button" class="danger" onclick={() => remove(current)}>{t("Delete")}</button>
        </div>
        <h2>{current.subject || t("(no subject)")}</h2>
        <dl class="headers">
          <dt>{t("From")}</dt>
          <dd>{formatAddresses(current.from)}</dd>
          <dt>{t("To")}</dt>
          <dd>{formatAddresses(current.to)}</dd>
          {#if current.cc?.length}
            <dt>{t("Cc")}</dt>
            <dd>{formatAddresses(current.cc)}</dd>
          {/if}
          <dt></dt>
          <dd class="muted">{new Date(current.sentAt ?? current.receivedAt).toLocaleString(locale)}</dd>
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
