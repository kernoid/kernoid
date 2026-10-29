<!-- SPDX-License-Identifier: MIT -->
<!-- For instance administrators: the instance's tenants – creating, renaming, deactivating them, and managing one. -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need, setTenant } from "./api.svelte.js";
  import { Action, go } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";

  const action = new Action();
  const tenants = loaded(() => need(admin.GET("/v1/instance/tenants")));
  let creating = $state(false);

  async function change(work: () => Promise<unknown>, done?: string): Promise<boolean> {
    const succeeded = await action.run(work, done);
    if (succeeded) await tenants.refetch();
    return succeeded;
  }
</script>

<Head title={t("Tenants")} description={t("Organisations on this instance, each with its own domains, accounts and settings.")}>
  <button type="button" class="primary" onclick={() => (creating = true)}>{t("New tenant")}</button>
</Head>
<Outcome {action} />
<table class="nodes">
  <tbody>
    {#each tenants.value ?? [] as entry (entry.id)}
      <tr>
        <td class="name">
          {entry.name}
          <div class="small muted">{entry.id}</div>
        </td>
        <td class="small">
          {#if !entry.active}
            <span class="warn">{t("inactive")}</span>
          {/if}
        </td>
        <td class="end">
          <button
            type="button"
            class="quiet"
            onclick={() => {
              setTenant(entry.id);
              go("settings");
            }}
          >
            {t("Manage")}
          </button>
          <button
            type="button"
            class="quiet"
            disabled={action.busy}
            onclick={() => {
              const name = window.prompt(t("New name"), entry.name)?.trim();
              if (name) void change(() => need(admin.PATCH("/v1/instance/tenants/{id}", { params: { path: { id: entry.id } }, body: { name } })));
            }}
          >
            {t("Rename")}
          </button>
          <button
            type="button"
            class="quiet"
            class:danger={entry.active}
            disabled={action.busy}
            onclick={() =>
              (!entry.active || window.confirm(t("Deactivate {name}? Its accounts can no longer log in.", { name: entry.name }))) &&
              void change(() => need(admin.PATCH("/v1/instance/tenants/{id}", { params: { path: { id: entry.id } }, body: { active: !entry.active } })))}
          >
            {entry.active ? t("Deactivate") : t("Reactivate")}
          </button>
        </td>
      </tr>
    {/each}
  </tbody>
</table>
{#if creating}
  <Dialog title={t("New tenant")} onClose={() => (creating = false)}>
    <Form
      submit={(field) =>
        void change(() => need(admin.POST("/v1/instance/tenants", { body: { name: field("name") } })), t("The tenant is created.")).then(
          (succeeded) => succeeded && (creating = false),
        )}
    >
      <Field label={t("Name")} name="name" required />
      <Buttons busy={action.busy} onCancel={() => (creating = false)} label={t("Create")} />
    </Form>
  </Dialog>
{/if}
