<!-- SPDX-License-Identifier: MIT -->
<!-- Links to a file or folder for people without an account: made with an expiry and a password if wanted, shown once
     when made (kernoid keeps only a hash), removed when no longer wanted. -->
<script lang="ts">
  import { emptyText, loaded, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import { type FileNode, type LinkMode, createLink, isDirectory, linkMode, links, removeLink } from "./model.js";

  let { account, node, onclose }: { account: string; node: FileNode; onclose: () => void } = $props();

  const jmap = useJmap();
  const list = loaded(() => links(jmap, account, node));
  let made = $state<string>();
  let error = $state<unknown>();
  let busy = $state(false);

  async function run(work: () => Promise<void>): Promise<void> {
    busy = true;
    error = undefined;
    try {
      await work();
      await list.refetch();
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
    }
  }

  function make(event: SubmitEvent): void {
    event.preventDefault();
    const target = event.currentTarget as HTMLFormElement;
    const form = new FormData(target);
    const date = String(form.get("expires") ?? "");
    const password = String(form.get("password") ?? "");
    const mode = (String(form.get("mode") ?? "view") as LinkMode) || "view";
    // The link works through the whole day chosen.
    const expires = date ? new Date(`${date}T23:59:59`).toISOString() : null;
    void run(async () => {
      made = await createLink(jmap, account, node, mode, expires, password || null);
      target.reset();
    });
  }

  const when = (date: string) => new Date(date).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
  // People may add files through a link to a folder the user may add to.
  const adds = $derived(isDirectory(node) && (node.myRights?.mayAddChildren ?? false));
  const modeLabel = (mode: LinkMode) =>
    ({ view: t("View and download"), add: t("View, download and add files"), drop: t("Only add files (drop box)") })[mode];
  const modes: LinkMode[] = ["view", "add", "drop"];
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={t("Links")}>
  <div class="dialog">
    <h2>{t("Links")} „{node.name}“</h2>
    <p class="muted small">
      {adds
        ? t("Anyone with a link can view and download what it leads to, or add files to it – without an account.")
        : t("Anyone with a link can view and download what it leads to – without an account.")}
    </p>
    {#if made}
      {@const url = made}
      <div class="notice">
        <p>{t("The new link – copy it now; it is not shown again:")}</p>
        <div class="row">
          <input class="grow" readonly value={url} aria-label={t("Link")} onfocus={(event) => event.currentTarget.select()} />
          <button type="button" onclick={() => void navigator.clipboard?.writeText(url)}>{t("Copy")}</button>
        </div>
      </div>
    {/if}
    <table class="nodes">
      <tbody>
        {#each list.value ?? [] as link (link.id)}
          <tr>
            <td class="small">
              {modeLabel(linkMode(link))}
              <div class="muted">
                {t("made {date}", { date: when(link.created) })} ·
                {link.expires ? t("valid until {date}", { date: when(link.expires) }) : t("no expiry")}
                {link.hasPassword ? ` · ${t("with password")}` : ""}
              </div>
            </td>
            <td class="end">
              <button
                type="button"
                class="quiet danger"
                disabled={busy}
                onclick={() => void run(() => removeLink(jmap, account, link))}>{t("Remove")}</button
              >
            </td>
          </tr>
        {:else}
          <tr><td class="muted">{emptyText(list, t("No links yet."))}</td></tr>
        {/each}
      </tbody>
    </table>
    <form onsubmit={make}>
      <h3>{t("New link")}</h3>
      {#if adds}
        <label>
          <span>{t("People can")}</span>
          <select name="mode">
            {#each modes as mode (mode)}
              <option value={mode}>{modeLabel(mode)}</option>
            {/each}
          </select>
        </label>
      {/if}
      <label>
        <span>{t("Valid until (optional)")}</span>
        <input type="date" name="expires" min={new Date().toISOString().slice(0, 10)} />
      </label>
      <label>
        <span>{t("Password (optional)")}</span>
        <input type="password" name="password" autocomplete="new-password" />
      </label>
      <Failure error={error ?? list.error} />
      <div class="actions end">
        <button type="button" class="quiet" onclick={() => onclose()}>{t("Close")}</button>
        <button type="submit" class="primary" disabled={busy}>{t("Make a link")}</button>
      </div>
    </form>
  </div>
</div>
