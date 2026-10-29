// SPDX-License-Identifier: MIT
// An account's mailboxes: each saved as an mbox file (with its keywords), and messages of an mbox file stored in one –
// up to 2 MiB here; larger files go with the CLI (`kernoid mail import-mbox`).

import { For, type JSX } from "solid-js";

import { t } from "../i18n.js";
import { type MailOverviewView, seg, send } from "./api.js";
import { Outcome, useAction } from "./ui.js";

const MAX_IMPORT = 2 * 1024 * 1024;

export function MailTransfer(props: { base: string; mail: MailOverviewView; onImported: () => void }): JSX.Element {
  const action = useAction();
  let file: HTMLInputElement | undefined;
  let target: HTMLSelectElement | undefined;

  const save = (mailbox: { id: string; name: string }) =>
    void action.run(async () => {
      const response = await send("GET", `${props.base}/mail/mailboxes/${seg(mailbox.id)}/mbox`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `${mailbox.name.replace(/[\\/:*?"<>|]/g, "_")}.mbox`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    });

  const load = () =>
    void action.run(async () => {
      const chosen = file?.files?.[0];
      if (!chosen || !target) return;
      if (chosen.size > MAX_IMPORT) throw new Error(t("Larger than 2 MiB: import it with the CLI (kernoid mail import-mbox)."));
      const response = await send("POST", `${props.base}/mail/mailboxes/${seg(target.value)}/mbox`, { type: "application/mbox", content: chosen });
      const done = (await response.json()) as { imported: number; failed: number };
      if (file) file.value = "";
      props.onImported();
      action.say(done.failed > 0 ? t("{imported} imported, {failed} not readable.", done) : t("{imported} imported.", done));
    });

  return (
    <section>
      <h2>{t("Mailboxes")}</h2>
      <Outcome action={action} />
      <ul class="rows">
        <For each={props.mail.mailboxes}>
          {(mailbox) => (
            <li>
              <span class="grow">
                {mailbox.name} <small class="muted">· {t("{count} emails", { count: mailbox.total_emails })}</small>
              </span>
              <button type="button" class="quiet" disabled={action.busy()} onClick={() => save(mailbox)}>
                {t("Save as mbox")}
              </button>
            </li>
          )}
        </For>
      </ul>
      <div class="row">
        <select ref={target} aria-label={t("Import into")}>
          <For each={props.mail.mailboxes}>{(mailbox) => <option value={mailbox.id}>{mailbox.name}</option>}</For>
        </select>
        <input ref={file} type="file" accept=".mbox,application/mbox,text/plain" aria-label={t("mbox file")} />
        <button type="button" disabled={action.busy()} onClick={load}>
          {t("Import")}
        </button>
      </div>
    </section>
  );
}
