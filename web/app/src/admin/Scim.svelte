<!-- SPDX-License-Identifier: MIT -->
<!-- SCIM tokens, with which a directory creates and removes the tenant's accounts. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import { Action, when } from "./ui.svelte.js";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import Secret from "./ui/Secret.svelte";

  const action = new Action();
  const tokens = loaded(() => need(admin.GET("/v1/scim-tokens")));
  let made = $state<{ endpoint: string; token: string }>();
</script>

<Head title={t("Provisioning (SCIM)")} description={t("A directory (e.g. Entra ID, Okta) creates, changes and deactivates the tenant's accounts over SCIM 2.0 with a token.")} />
<Outcome {action} />
{#if made}
  <p>
    {t("Endpoint")}: <code>{made.endpoint}</code>
  </p>
  <Secret label={t("Token:")} value={made.token} onDone={() => (made = undefined)} />
{/if}
<ul class="rows">
  {#each tokens.value ?? [] as token (token.id)}
    <li>
      <span class="grow">
        {token.name} <small class="muted">– {t("last used {date}", { date: when(token.last_used_at) })}</small>
      </span>
      <button
        type="button"
        class="quiet danger"
        disabled={action.busy}
        onclick={() =>
          window.confirm(t("Revoke the token {name}?", { name: token.name })) &&
          void action
            .run(() => need(admin.DELETE("/v1/scim-tokens/{id}", { params: { path: { id: token.id } } })))
            .then(() => tokens.refetch())}>{t("Revoke")}</button
      >
    </li>
  {:else}
    <li class="muted">{emptyText(tokens, t("No tokens yet."))}</li>
  {/each}
</ul>
<Form
  class="row"
  submit={(field) =>
    void action.run(async () => {
      made = await need(admin.POST("/v1/scim-tokens", { body: { name: field("name") } }));
      await tokens.refetch();
    })}
>
  <input name="name" required placeholder={t("e.g. Entra ID")} aria-label={t("Name")} />
  <button type="submit" disabled={action.busy}>{t("Make a token")}</button>
</Form>
