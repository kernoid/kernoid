// SPDX-License-Identifier: MIT
// Mail: the mailboxes, the emails of the one chosen, the one read, and writing.

import { For, type JSX, Show, createEffect, createResource, createSignal, on } from "solid-js";

import { Failure, changed, ok, touch, useJmap } from "../App.js";
import { locale, t } from "../i18n.js";
import { MAIL } from "../jmap.js";
import { Compose, type ComposeStart } from "./Compose.js";
import { showHtml } from "./html.js";
import {
  type Email,
  type EmailSummary,
  type Mailbox,
  bodyHtml,
  originalPath,
  bodyText,
  destroy,
  email,
  emails,
  formatAddresses,
  mailboxes,
  move,
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
    : date.toLocaleDateString(locale, { day: "numeric", month: "short", year: date.getFullYear() === today.getFullYear() ? undefined : "numeric" });
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

export function MailView(): JSX.Element {
  const jmap = useJmap();
  const [boxes, { refetch: refetchBoxes }] = createResource(() => [changed("Mailbox"), changed("Email")], () => mailboxes(jmap));
  const [selected, setSelected] = createSignal<string>();
  const [search, setSearch] = createSignal("");
  const [query, setQuery] = createSignal("");
  const [open, setOpen] = createSignal<string>();
  // HTML emails readable (cleaned) or as their sender laid them out; kept per browser.
  const [original, setOriginalSignal] = createSignal(storedOriginal());
  const setOriginal = (on: boolean) => {
    setOriginalSignal(on);
    try {
      localStorage.setItem("kernoid.mail.original", on ? "on" : "off");
    } catch {
      // Not kept: readable next time.
    }
  };
  const [composing, setComposing] = createSignal<ComposeStart>();
  const [error, setError] = createSignal<unknown>();

  createEffect(() => {
    const list = ok(boxes);
    if (list && !selected()) setSelected(list.find((box) => box.role === "inbox")?.id ?? list[0]?.id);
  });

  const [list] = createResource(
    () => {
      const box = selected();
      return box ? { box, text: query(), version: changed("Email") } : undefined;
    },
    ({ box, text }) => emails(jmap, box, text, 100),
  );
  const [message] = createResource(
    () => {
      const id = open();
      return id ? { id, version: changed("Email") } : undefined;
    },
    ({ id }) => email(jmap, id),
  );

  // Reading marks as read.
  createEffect(
    on(() => ok(message), (current) => {
      if (current && !current.keywords.$seen) {
        void setKeyword(jmap, current.id, "$seen", true).then(() => touch("Email"), setError);
      }
    }),
  );

  const act = (run: () => Promise<void>) => () => {
    setError(undefined);
    run().then(
      () => {
        touch("Email", "Mailbox");
        void refetchBoxes();
      },
      setError,
    );
  };

  const trash = () => ok(boxes)?.find((box) => box.role === "trash");
  const remove = (current: Email) =>
    act(async () => {
      const bin = trash();
      if (!bin || current.mailboxIds[bin.id]) await destroy(jmap, current.id);
      else await move(jmap, current.id, bin.id);
      setOpen(undefined);
    });

  const reply = (current: Email, all: boolean) => {
    const to = current.replyTo?.length ? current.replyTo : (current.from ?? []);
    const cc = all ? [...(current.to ?? []), ...(current.cc ?? [])] : [];
    const subject = current.subject ?? "";
    setComposing({
      to: formatAddresses(to),
      cc: formatAddresses(cc),
      subject: /^re:/i.test(subject) ? subject : `Re: ${subject}`,
      body: `\n\n> ${bodyText(current).split("\n").join("\n> ")}`,
      inReplyTo: current.messageId,
      references: [...(current.references ?? []), ...(current.messageId ?? [])],
      excludeOwn: all,
    });
  };

  const forward = (current: Email) =>
    setComposing({
      to: "",
      cc: "",
      subject: `Fwd: ${current.subject ?? ""}`,
      body: `\n\n---------- ${t("Forward")} ----------\n${t("From")}: ${formatAddresses(current.from)}\n${t("Subject")}: ${current.subject ?? ""}\n\n${bodyText(current)}`,
    });

  return (
    <div class="three">
      <aside class="side">
        <button type="button" class="primary wide" onClick={() => setComposing({ to: "", cc: "", subject: "", body: "" })}>
          {t("Write")}
        </button>
        <ul class="boxes">
          <For each={ok(boxes) ?? []}>
            {(box) => (
              <li>
                <button
                  type="button"
                  aria-label={box.unreadEmails > 0 ? `${boxName(box)} (${box.unreadEmails})` : boxName(box)}
                  classList={{ active: selected() === box.id }}
                  onClick={() => {
                    setSelected(box.id);
                    setOpen(undefined);
                  }}
                >
                  <span>{boxName(box)}</span>
                  <Show when={box.unreadEmails > 0}>
                    <span class="count">{box.unreadEmails}</span>
                  </Show>
                </button>
              </li>
            )}
          </For>
        </ul>
      </aside>
      <section class="list">
        {/* On a phone the side is hidden: the mailbox and writing are here. */}
        <div class="narrow-only phone-bar">
          <select
            aria-label={t("Mailboxes")}
            value={selected() ?? ""}
            onChange={(event) => {
              setSelected(event.currentTarget.value);
              setOpen(undefined);
            }}
          >
            <For each={ok(boxes) ?? []}>
              {(box) => (
                <option value={box.id}>
                  {boxName(box)}
                  {box.unreadEmails > 0 ? ` (${box.unreadEmails})` : ""}
                </option>
              )}
            </For>
          </select>
          <button type="button" class="primary" onClick={() => setComposing({ to: "", cc: "", subject: "", body: "" })}>
            {t("Write")}
          </button>
        </div>
        <form
          class="search"
          onSubmit={(event) => {
            event.preventDefault();
            setQuery(search());
          }}
        >
          <input type="search" placeholder={t("Search")} value={search()} onInput={(event) => setSearch(event.currentTarget.value)} />
        </form>
        <Failure error={list.error} />
        <Show when={ok(list)?.list.length === 0}>
          <p class="muted pad">{t("No messages")}</p>
        </Show>
        <ul class="items">
          <For each={ok(list)?.list ?? []}>
            {(summary) => (
              <li>
                <button
                  type="button"
                  aria-label={`${sender(summary)}: ${summary.subject || t("(no subject)")}`}
                  classList={{ active: open() === summary.id, unread: !summary.keywords.$seen }}
                  onClick={() => setOpen(summary.id)}
                >
                  <span class="line">
                    <span class="who">{sender(summary)}</span>
                    <span class="time">{when(summary.receivedAt)}</span>
                  </span>
                  <span class="subject">
                    <Show when={summary.keywords.$flagged}>
                      <span class="flag" aria-label={t("Flag")}>
                        ●{" "}
                      </span>
                    </Show>
                    {summary.subject || t("(no subject)")}
                  </span>
                  <span class="preview">{summary.preview}</span>
                </button>
              </li>
            )}
          </For>
        </ul>
      </section>
      <section class="read">
        <Failure error={error() ?? message.error} />
        <Show when={ok(message)} fallback={<p class="muted pad">{t("Select a message")}</p>}>
          {(current) => (
            <article>
              <div class="actions">
                <button type="button" onClick={() => reply(current(), false)}>
                  {t("Reply")}
                </button>
                <button type="button" onClick={() => reply(current(), true)}>
                  {t("Reply all")}
                </button>
                <button type="button" onClick={() => forward(current())}>
                  {t("Forward")}
                </button>
                <button type="button" onClick={act(() => setKeyword(jmap, current().id, "$flagged", !current().keywords.$flagged))}>
                  {current().keywords.$flagged ? t("Unflag") : t("Flag")}
                </button>
                <button
                  type="button"
                  onClick={act(async () => {
                    await setKeyword(jmap, current().id, "$seen", false);
                    setOpen(undefined);
                  })}
                >
                  {t("Mark unread")}
                </button>
                <select
                  aria-label={t("Move to")}
                  onChange={(event) => {
                    const to = event.currentTarget.value;
                    if (to) act(() => move(jmap, current().id, to).then(() => setOpen(undefined)))();
                  }}
                >
                  <option value="">{t("Move to")}</option>
                  <For each={(ok(boxes) ?? []).filter((box) => !current().mailboxIds[box.id])}>
                    {(box) => <option value={box.id}>{boxName(box)}</option>}
                  </For>
                </select>
                <button type="button" class="danger" onClick={remove(current())}>
                  {t("Delete")}
                </button>
              </div>
              <h2>{current().subject || t("(no subject)")}</h2>
              <dl class="headers">
                <dt>{t("From")}</dt>
                <dd>{formatAddresses(current().from)}</dd>
                <dt>{t("To")}</dt>
                <dd>{formatAddresses(current().to)}</dd>
                <Show when={current().cc?.length}>
                  <dt>{t("Cc")}</dt>
                  <dd>{formatAddresses(current().cc)}</dd>
                </Show>
                <dt />
                <dd class="muted">{new Date(current().sentAt ?? current().receivedAt).toLocaleString(locale)}</dd>
              </dl>
              <Show when={bodyHtml(current())} keyed fallback={<pre class="body">{bodyText(current())}</pre>}>
                {(html) => (
                  <>
                    <Show when={originalPath(jmap, current())}>
                      <div class="segmented view-switch" role="group" aria-label={t("View")}>
                        <button type="button" classList={{ active: !original() }} aria-pressed={!original()} onClick={() => setOriginal(false)}>
                          {t("Readable")}
                        </button>
                        <button type="button" classList={{ active: original() }} aria-pressed={original()} onClick={() => setOriginal(true)}>
                          {t("Original")}
                        </button>
                      </div>
                    </Show>
                    <Show
                      when={original() && originalPath(jmap, current())}
                      keyed
                      fallback={<div class="body html" ref={(element) => queueMicrotask(() => showHtml(element, html))} />}
                    >
                      {(path) => (
                        <>
                          <iframe
                            class="body original"
                            src={path}
                            title={current().subject ?? t("(no subject)")}
                            sandbox="allow-popups allow-popups-to-escape-sandbox"
                            referrerpolicy="no-referrer"
                          />
                          <p class="muted small">{t("Images from elsewhere are not loaded, so the sender does not learn that you read it.")}</p>
                        </>
                      )}
                    </Show>
                  </>
                )}
              </Show>
              <Show when={current().attachments.length > 0}>
                <h3>{t("Attachments")}</h3>
                <ul class="attachments">
                  <For each={current().attachments}>
                    {(part) => (
                      <li>
                        <a
                          href={jmap.downloadPath(jmap.account(MAIL), part.blobId ?? "", part.name ?? "attachment", part.type)}
                          download={part.name ?? "attachment"}
                        >
                          {part.name ?? part.type} ({Math.ceil(part.size / 1024)} KB)
                        </a>
                      </li>
                    )}
                  </For>
                </ul>
              </Show>
            </article>
          )}
        </Show>
      </section>
      <Show when={composing()}>
        {(start) => (
          <Compose
            start={start()}
            mailboxes={ok(boxes) ?? []}
            onClose={(sent) => {
              setComposing(undefined);
              if (sent) touch("Email", "Mailbox");
            }}
          />
        )}
      </Show>
    </div>
  );
}
