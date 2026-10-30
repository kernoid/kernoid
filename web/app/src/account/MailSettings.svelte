<!-- SPDX-License-Identifier: MIT -->
<!-- The mail store's settings: the address new emails come from, and how long the Trash keeps emails before they are
     deleted for good – the tenant's days unless one chooses one's own. -->
<script lang="ts">
  import { admin, need } from "../admin/api.svelte.js";
  import { loaded, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { MAIL } from "../jmap.js";
  import { identities } from "../mail/model.js";

  const jmap = useJmap();
  const available = Boolean(jmap.session.primaryAccounts[MAIL]);
  const settings = loaded(() => (available ? need(admin.GET("/v1/account/mail-settings")) : Promise.resolve(undefined)));
  // Only the account's own addresses (and its groups'): a shared mailbox is chosen when writing.
  const from = loaded(() => (available ? identities(jmap, jmap.account(MAIL)) : Promise.resolve([])));
  let error = $state<unknown>();
  let saved = $state(false);

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const data = new FormData(event.currentTarget as HTMLFormElement);
    const days = String(data.get("days") ?? "").trim();
    error = undefined;
    saved = false;
    try {
      await need(
        admin.PUT("/v1/account/mail-settings", {
          body: {
            default_from: String(data.get("from") ?? "") || null,
            trash_retention_days: data.get("own") === "on" && days ? Number(days) : null,
            undo_send_seconds: Number(data.get("undo") ?? 0),
          },
        }),
      );
      saved = true;
      await settings.refetch();
    } catch (failure) {
      error = failure;
    }
  }

  let own = $state<boolean>();
  const ownDays = $derived(own ?? settings.value?.trash_retention_days != null);
</script>

{#if available && settings.value}
  {@const current = settings.value}
  <section>
    <h2>{t("Writing and the Trash")}</h2>
    <form class="stack" onsubmit={save}>
      <label>
        <span>{t("Send from")}</span>
        <select name="from" value={current.default_from ?? ""}>
          <option value="">{t("My address")}</option>
          {#each from.value ?? [] as entry (entry.id)}
            <option value={entry.email}>{entry.name ? `${entry.name} <${entry.email}>` : entry.email}</option>
          {/each}
        </select>
        <small class="muted">{t("New emails come from it; you can pick another when writing.")}</small>
      </label>
      <label>
        <span>{t("Undo sending")}</span>
        <select name="undo" value={String(current.undo_send_seconds)}>
          <option value="0">{t("Off")}</option>
          <option value="5">{t("{seconds} seconds", { seconds: 5 })}</option>
          <option value="10">{t("{seconds} seconds", { seconds: 10 })}</option>
        </select>
        <small class="muted">{t("A sent email waits this long and can be taken back until then.")}</small>
      </label>
      <fieldset class="choice">
        <legend class="muted small">{t("Keep emails in the Trash")}</legend>
        <label class="inline">
          <input type="radio" name="own" value="off" checked={!ownDays} onchange={() => (own = false)} />
          <span>
            {current.tenant_trash_retention_days
              ? t("As the organisation sets it ({days} days)", { days: current.tenant_trash_retention_days })
              : t("As the organisation sets it (until deleted)")}
          </span>
        </label>
        <label class="inline">
          <input type="radio" name="own" value="on" checked={ownDays} onchange={() => (own = true)} />
          <span>{t("For")}</span>
          <input
            class="days"
            type="number"
            name="days"
            min="1"
            max="3650"
            value={current.trash_retention_days ?? current.tenant_trash_retention_days ?? 30}
            disabled={!ownDays}
            aria-label={t("Days")}
          />
          <span>{t("days")}</span>
        </label>
      </fieldset>
      <div class="actions">
        <button type="submit" class="primary">{t("Save")}</button>
        {#if saved}<span class="muted">{t("Saved.")}</span>{/if}
      </div>
    </form>
    <Failure {error} />
  </section>
{/if}
