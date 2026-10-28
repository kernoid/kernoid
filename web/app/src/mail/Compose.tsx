// SPDX-License-Identifier: MIT
// Writing an email: from one of the account's identities, plain text.

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { Failure, ok, useJmap } from "../App.js";
import { t } from "../i18n.js";
import { type Attachment, type Mailbox, identities, parseAddresses, send, upload } from "./model.js";

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

export function Compose(props: { start: ComposeStart; mailboxes: Mailbox[]; onClose: (sent: boolean) => void }): JSX.Element {
  const jmap = useJmap();
  const [from] = createResource(() => identities(jmap));
  const [identity, setIdentity] = createSignal<string>();
  const [to, setTo] = createSignal(props.start.to);
  const [cc, setCc] = createSignal(props.start.cc);
  const [subject, setSubject] = createSignal(props.start.subject);
  const [body, setBody] = createSignal(props.start.body);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const [files, setFiles] = createSignal<Attachment[]>([]);
  const [uploading, setUploading] = createSignal(0);

  const add = async (list: FileList | null) => {
    for (const file of Array.from(list ?? [])) {
      setUploading((count) => count + 1);
      try {
        const done = await upload(jmap, file);
        setFiles((current) => [...current, done]);
      } catch (failure) {
        setError(failure);
      } finally {
        setUploading((count) => count - 1);
      }
    }
  };

  const submit = async (event: SubmitEvent) => {
    event.preventDefault();
    const list = ok(from) ?? [];
    const chosen = list.find((entry) => entry.id === identity()) ?? list[0];
    if (!chosen) return;
    const own = new Set(list.map((entry) => entry.email.toLowerCase()));
    const keep = (text: string) =>
      parseAddresses(text).filter((address) => !props.start.excludeOwn || !own.has(address.email.toLowerCase()));
    setBusy(true);
    setError(undefined);
    try {
      await send(
        jmap,
        {
          identity: chosen,
          attachments: files(),
          to: keep(to()),
          cc: keep(cc()),
          subject: subject(),
          body: body(),
          inReplyTo: props.start.inReplyTo ?? null,
          references: props.start.references ?? null,
        },
        props.mailboxes,
      );
      props.onClose(true);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="overlay" role="dialog" aria-modal="true" aria-label={t("Write")}>
      <form class="dialog compose" onSubmit={(event) => void submit(event)}>
        <label>
          <span>{t("From")}</span>
          <select value={identity() ?? ""} onChange={(event) => setIdentity(event.currentTarget.value)}>
            <For each={ok(from) ?? []}>
              {(entry) => <option value={entry.id}>{entry.name ? `${entry.name} <${entry.email}>` : entry.email}</option>}
            </For>
          </select>
        </label>
        <label>
          <span>{t("To")}</span>
          <input type="text" required value={to()} onInput={(event) => setTo(event.currentTarget.value)} autofocus={!props.start.to} />
        </label>
        <label>
          <span>{t("Cc")}</span>
          <input type="text" value={cc()} onInput={(event) => setCc(event.currentTarget.value)} />
        </label>
        <label>
          <span>{t("Subject")}</span>
          <input type="text" value={subject()} onInput={(event) => setSubject(event.currentTarget.value)} />
        </label>
        <textarea rows={14} value={body()} onInput={(event) => setBody(event.currentTarget.value)} autofocus={!!props.start.to} />
        <div class="files">
          <label class="file">
            <input type="file" multiple onChange={(event) => void add(event.currentTarget.files)} />
            <span>{t("Attach files")}</span>
          </label>
          <For each={files()}>
            {(file) => (
              <span class="chip">
                {file.name} ({Math.ceil(file.size / 1024)} KB)
                <button type="button" class="quiet" aria-label={t("Remove")} onClick={() => setFiles((current) => current.filter((entry) => entry !== file))}>
                  ×
                </button>
              </span>
            )}
          </For>
          <Show when={uploading() > 0}>
            <span class="muted">{t("Uploading")}</span>
          </Show>
        </div>
        <Failure error={error()} />
        <div class="actions end">
          <button type="button" class="quiet" onClick={() => props.onClose(false)}>
            {t("Cancel")}
          </button>
          <button type="submit" class="primary" disabled={busy() || uploading() > 0 || !ok(from)}>
            <Show when={busy()} fallback={t("Send")}>
              {t("Sending")}
            </Show>
          </button>
        </div>
      </form>
    </div>
  );
}
