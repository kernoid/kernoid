<!-- SPDX-License-Identifier: MIT -->
<!-- The tenant's projects, and the projects other tenants have granted to it. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type GrantView, admin, need } from "./api.svelte.js";
  import { Action, go } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";

  const action = new Action();
  const projects = loaded(() => need(admin.GET("/v1/projects")));
  const granted = loaded(() => need(admin.GET("/v1/granted-projects")).catch((): GrantView[] => []));
  let creating = $state(false);
</script>

<Head title={t("Projects")} description={t("A project holds applications and the roles they know; kernoid puts the roles a person holds into their tokens.")}>
  <button type="button" class="primary" onclick={() => (creating = true)}>{t("New project")}</button>
</Head>
<Outcome {action} />
<table class="nodes">
  <tbody>
    {#each projects.value ?? [] as project (project.id)}
      <tr>
        <td class="name">
          <button type="button" class="quiet file" onclick={() => go("projects", project.id)}>{project.name}</button>
        </td>
        <td class="small muted">{t("{count} roles", { count: project.roles.length })}</td>
      </tr>
    {:else}
      <tr><td class="muted">{emptyText(projects, t("No projects yet."))}</td></tr>
    {/each}
  </tbody>
</table>
{#if (granted.value ?? []).length > 0}
  <section>
    <h2>{t("Projects of other tenants")}</h2>
    <ul class="rows">
      {#each granted.value ?? [] as grant (`${grant.project}/${grant.tenant}`)}
        <li>
          <span class="grow">
            {grant.project_name} <span class="muted small">· {grant.tenant_name} · {grant.roles.join(", ")}</span>
          </span>
        </li>
      {/each}
    </ul>
  </section>
{/if}
{#if creating}
  <Dialog title={t("New project")} onClose={() => (creating = false)}>
    <Form
      submit={(field) =>
        void action.run(async () => {
          const made = await need(admin.POST("/v1/projects", { body: { name: field("name") } }));
          go("projects", made.id);
        })}
    >
      <Field label={t("Name")} name="name" required />
      <Buttons busy={action.busy} onCancel={() => (creating = false)} label={t("Create")} />
    </Form>
  </Dialog>
{/if}
