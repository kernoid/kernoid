<!-- SPDX-License-Identifier: MIT -->
<!-- For instance administrators: the keys that sign the instance's tokens. -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import { Action, when } from "./ui.svelte.js";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";

  const action = new Action();
  const keys = loaded(() => need(admin.GET("/v1/instance/signing-keys")));

  async function change(work: () => Promise<unknown>, done?: string): Promise<boolean> {
    const succeeded = await action.run(work, done);
    if (succeeded) await keys.refetch();
    return succeeded;
  }
</script>

<Head title={t("Signing keys")} description={t("The keys that sign the instance's tokens. kernoid rotates them by itself; here they can be rotated at once.")}>
  <button
    type="button"
    class="primary"
    disabled={action.busy}
    onclick={() => void change(() => need(admin.POST("/v1/instance/signing-keys")), t("A new key is made; it is published before it signs."))}
  >
    {t("New key")}
  </button>
</Head>
<Outcome {action} />
<table class="nodes">
  <tbody>
    {#each keys.value ?? [] as key (key.kid)}
      <tr>
        <td class="name">
          <code>{key.kid}</code>
          <div class="small muted">
            {key.algorithm} · {t("made {date}", { date: when(key.created_at) })}
          </div>
        </td>
        <td class="small">
          {t(key.state)} <span class="muted">{t("since {date}", { date: when(key.state_since) })}</span>
        </td>
        <td class="end">
          {#if key.state === "initial"}
            <button
              type="button"
              class="quiet"
              disabled={action.busy}
              onclick={() => void change(() => need(admin.POST("/v1/instance/signing-keys/{kid}/activate", { params: { path: { kid: key.kid } } })))}
            >
              {t("Sign with it now")}
            </button>
          {/if}
          {#if key.state !== "active"}
            <button
              type="button"
              class="quiet danger"
              disabled={action.busy}
              onclick={() =>
                window.confirm(t("Delete this key? Tokens it signed are no longer valid.")) &&
                void change(() => need(admin.DELETE("/v1/instance/signing-keys/{kid}", { params: { path: { kid: key.kid } } })))}
            >
              {t("Delete")}
            </button>
          {/if}
        </td>
      </tr>
    {/each}
  </tbody>
</table>
