<!-- SPDX-License-Identifier: MIT -->
<!-- An account's mailboxes: each saved as an mbox file (with its keywords), and messages of an mbox file stored in one –
     up to 2 MiB here; larger files go with the CLI (`kernoid mail import-mbox`). -->
<script lang="ts">
  import { t } from "../i18n.js";
  import { type MailOverviewView, type Schema, send } from "./api.svelte.js";
  import Outcome from "./ui/Outcome.svelte";
  import { Action } from "./ui.svelte.js";

  const MAX_IMPORT = 2 * 1024 * 1024;

  let { account, mail, onImported }: { account: string; mail: MailOverviewView; onImported: () => void } = $props();

  const action = new Action();
  let file = $state<HTMLInputElement>();
  let target = $state<HTMLSelectElement>();

  // The mbox routes take and give mbox, not JSON: `send` with the path built here.
  const mbox = (mailbox: string) => `/v1/accounts/${encodeURIComponent(account)}/mail/mailboxes/${encodeURIComponent(mailbox)}/mbox`;

  const save = (mailbox: { id: string; name: string }) =>
    void action.run(async () => {
      const response = await send("GET", mbox(mailbox.id));
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
      const response = await send("POST", mbox(target.value), { type: "application/mbox", content: chosen });
      const done = (await response.json()) as Schema<"MboxImportView">;
      if (file) file.value = "";
      onImported();
      action.say(done.failed > 0 ? t("{imported} imported, {failed} not readable.", done) : t("{imported} imported.", done));
    });
</script>

<section>
  <h2>{t("Mailboxes")}</h2>
  <Outcome {action} />
  <ul class="rows">
    {#each mail.mailboxes as mailbox (mailbox.id)}
      <li>
        <span class="grow">
          {mailbox.name} <small class="muted">· {t("{count} emails", { count: mailbox.total_emails })}</small>
        </span>
        <button type="button" class="quiet" disabled={action.busy} onclick={() => save(mailbox)}>{t("Save as mbox")}</button>
      </li>
    {/each}
  </ul>
  <div class="row">
    <select bind:this={target} aria-label={t("Import into")}>
      {#each mail.mailboxes as mailbox (mailbox.id)}
        <option value={mailbox.id}>{mailbox.name}</option>
      {/each}
    </select>
    <input bind:this={file} type="file" accept=".mbox,application/mbox,text/plain" aria-label={t("mbox file")} />
    <button type="button" disabled={action.busy} onclick={load}>{t("Import")}</button>
  </div>
</section>
