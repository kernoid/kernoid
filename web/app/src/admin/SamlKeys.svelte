<!-- SPDX-License-Identifier: MIT -->
<!-- For instance administrators: the keys that sign SAML requests and decrypt assertions. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import { Action, when } from "./ui.svelte.js";
  import Outcome from "./ui/Outcome.svelte";

  const action = new Action();
  const keys = loaded(() => need(admin.GET("/v1/instance/saml-keys")));

  async function change(work: () => Promise<unknown>, done?: string): Promise<boolean> {
    const succeeded = await action.run(work, done);
    if (succeeded) await keys.refetch();
    return succeeded;
  }
</script>

<section>
  <div class="toolbar">
    <h2 class="grow">{t("SAML keys")}</h2>
    <button
      type="button"
      disabled={action.busy}
      onclick={() =>
        void change(() => need(admin.POST("/v1/instance/saml-keys")), t("A new SAML key is in the metadata now. Once the providers have taken it in, sign with it."))}
    >
      {t("New key")}
    </button>
  </div>
  <p class="muted small">{t("kernoid's key for SAML providers: it signs requests and decrypts assertions. A new key is in the metadata beside the old one until it signs.")}</p>
  <Outcome {action} />
  <table class="nodes">
    <tbody>
      {#each keys.value ?? [] as key (key.id)}
        <tr>
          <td class="name">
            <code class="small">{key.fingerprint.match(/.{2}/g)?.join(":")}</code>
            <div class="small muted">{t("made {date}", { date: when(key.created_at) })}</div>
          </td>
          <td class="small">
            {t(key.state)} <span class="muted">{t("since {date}", { date: when(key.state_since) })}</span>
          </td>
          <td class="end">
            {#if key.state === "next"}
              <button
                type="button"
                class="quiet"
                disabled={action.busy}
                onclick={() => void change(() => need(admin.POST("/v1/instance/saml-keys/{id}/activate", { params: { path: { id: key.id } } })))}
              >
                {t("Sign with it now")}
              </button>
            {/if}
          </td>
        </tr>
      {:else}
        <tr><td class="muted">{emptyText(keys, t("No SAML key yet; one is made at the first SAML login."))}</td></tr>
      {/each}
    </tbody>
  </table>
</section>
