<!-- SPDX-License-Identifier: MIT -->
<!-- One project: its settings, its roles, who holds which role, and the other tenants it is granted to. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type GrantView, type TenantSummary, admin, need } from "./api.svelte.js";
  import { Action, go, principal, useDirectory } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Check from "./ui/Check.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import PrincipalSelect from "./ui/PrincipalSelect.svelte";
  import Select from "./ui/Select.svelte";

  let { id }: { id: string } = $props();

  const directory = useDirectory();
  const action = new Action();
  // svelte-ignore state_referenced_locally
  const path = { path: { id } };
  const project = loaded(() => need(admin.GET("/v1/projects/{id}", { params: path })));
  const authorizations = loaded(() => need(admin.GET("/v1/projects/{id}/authorizations", { params: path })));
  const grants = loaded(() => need(admin.GET("/v1/projects/{id}/grants", { params: path })).catch((): GrantView[] => []));
  const tenants = loaded(() => need(admin.GET("/v1/instance/tenants")).catch((): TenantSummary[] => []));
  let dialog = $state<"role" | "authorize" | "grant">();

  async function change(work: () => Promise<unknown>, after: () => unknown, done?: string): Promise<void> {
    if (await action.run(work, done)) await after();
  }
</script>

{#if project.value}
  {@const me = project.value}
  <p>
    <button type="button" class="quiet" onclick={() => go("projects")}>← {t("Projects")}</button>
  </p>
  <Head title={me.name} description={me.id}>
    <button
      type="button"
      class="danger"
      disabled={action.busy}
      onclick={() =>
        window.confirm(t("Delete the project {name}?", { name: me.name })) &&
        void change(
          () => need(admin.DELETE("/v1/projects/{id}", { params: path })),
          () => go("projects"),
        )}>{t("Delete")}</button
    >
  </Head>
  <Outcome {action} />
  <section>
    <Form
      class="stack"
      submit={(field, all) =>
        void change(
          () =>
            need(
              admin.PATCH("/v1/projects/{id}", {
                params: path,
                body: { name: field("name"), role_assertion: all("assertion").length > 0, role_check: all("check").length > 0 },
              }),
            ),
          () => project.refetch(),
          t("Saved."),
        )}
    >
      <Field label={t("Name")} name="name" required value={me.name} />
      <Check label={t("Roles in the ID token")} name="assertion" checked={me.role_assertion} hint={t("claim urn:kernoid:project:roles")} />
      <Check label={t("Only people with a role may log in")} name="check" checked={me.role_check} />
      <Buttons busy={action.busy} />
    </Form>
  </section>

  <section>
    <div class="toolbar">
      <h2 class="grow">{t("Roles")}</h2>
      <button type="button" onclick={() => (dialog = "role")}>{t("New role")}</button>
    </div>
    <ul class="rows">
      {#each me.roles as role (role.key)}
        <li>
          <span class="grow">
            <code>{role.key}</code>
            {role.display_name}
            {#if role.group}
              <span class="muted small"> · {role.group}</span>
            {/if}
          </span>
          <button
            type="button"
            class="quiet danger"
            disabled={action.busy}
            onclick={() =>
              void change(
                () => need(admin.DELETE("/v1/projects/{id}/roles/{key}", { params: { path: { id, key: role.key } } })),
                () => project.refetch(),
              )}>{t("Remove")}</button
          >
        </li>
      {:else}
        <li class="muted">{t("No roles yet.")}</li>
      {/each}
    </ul>
  </section>

  <section>
    <div class="toolbar">
      <h2 class="grow">{t("Who holds which role")}</h2>
      <button type="button" disabled={me.roles.length === 0} onclick={() => (dialog = "authorize")}>{t("Authorize")}</button>
    </div>
    <ul class="rows">
      {#each authorizations.value ?? [] as entry (`${entry.role}/${entry.principal_kind}/${entry.principal_id}/${entry.tenant}`)}
        <li>
          <span class="grow">
            {directory.name(entry.principal_kind, entry.principal_id)} <code>{entry.role}</code>
          </span>
          <button
            type="button"
            class="quiet danger"
            disabled={action.busy}
            onclick={() =>
              void change(
                () =>
                  need(
                    admin.DELETE("/v1/projects/{id}/authorizations/{role}/{kind}/{principal}", {
                      params: { path: { id, role: entry.role, kind: entry.principal_kind, principal: entry.principal_id } },
                    }),
                  ),
                () => authorizations.refetch(),
              )}>{t("Remove")}</button
          >
        </li>
      {:else}
        <li class="muted">{emptyText(authorizations, t("Nobody yet."))}</li>
      {/each}
    </ul>
  </section>

  <section>
    <div class="toolbar">
      <h2 class="grow">{t("Other tenants")}</h2>
      <button type="button" disabled={me.roles.length === 0} onclick={() => (dialog = "grant")}>{t("Grant to a tenant")}</button>
    </div>
    <ul class="rows">
      {#each grants.value ?? [] as grant (grant.tenant)}
        <li>
          <span class="grow">
            {grant.tenant_name} <span class="muted small">· {grant.roles.join(", ")}</span>
          </span>
          <button
            type="button"
            class="quiet danger"
            disabled={action.busy}
            onclick={() =>
              void change(
                () => need(admin.DELETE("/v1/projects/{id}/grants/{tenant}", { params: { path: { id, tenant: grant.tenant } } })),
                () => grants.refetch(),
              )}>{t("Remove")}</button
          >
        </li>
      {:else}
        <li class="muted">{emptyText(grants, t("No other tenant uses it."))}</li>
      {/each}
    </ul>
  </section>

  {#if dialog === "role"}
    <Dialog title={t("New role")} onClose={() => (dialog = undefined)}>
      <Form
        submit={(field) =>
          void change(
            () =>
              need(
                admin.PUT("/v1/projects/{id}/roles/{key}", {
                  params: { path: { id, key: field("key") } },
                  body: { display_name: field("name"), group: field("group") || null },
                }),
              ),
            () => ((dialog = undefined), project.refetch()),
          )}
      >
        <Field label={t("Key")} name="key" required hint={t("what applications see, e.g. editor")} />
        <Field label={t("Name")} name="name" required />
        <Field label={t("Group (optional)")} name="group" />
        <Buttons busy={action.busy} onCancel={() => (dialog = undefined)} />
      </Form>
    </Dialog>
  {:else if dialog === "authorize"}
    <Dialog title={t("Authorize")} onClose={() => (dialog = undefined)}>
      <Form
        submit={(field) => {
          const [kind, who] = principal(field("who"));
          void change(
            () =>
              need(
                admin.PUT("/v1/projects/{id}/authorizations/{role}/{kind}/{principal}", {
                  params: { path: { id, role: field("role"), kind, principal: who } },
                }),
              ),
            () => ((dialog = undefined), authorizations.refetch()),
          );
        }}
      >
        <PrincipalSelect name="who" label={t("Who")} />
        <Select label={t("Role")} name="role" options={me.roles.map((role): [string, string] => [role.key, `${role.key} – ${role.display_name}`])} />
        <Buttons busy={action.busy} onCancel={() => (dialog = undefined)} label={t("Authorize")} />
      </Form>
    </Dialog>
  {:else if dialog === "grant"}
    <Dialog title={t("Grant to a tenant")} onClose={() => (dialog = undefined)}>
      <Form
        submit={(field, all) =>
          void change(
            () =>
              need(
                admin.PUT("/v1/projects/{id}/grants/{tenant}", {
                  params: { path: { id, tenant: field("tenant") } },
                  body: { roles: all("role") },
                }),
              ),
            () => ((dialog = undefined), grants.refetch()),
          )}
      >
        {#if (tenants.value ?? []).length > 0}
          <Select label={t("Tenant")} name="tenant" options={(tenants.value ?? []).map((entry): [string, string] => [entry.id, entry.name])} />
        {:else}
          <Field label={t("Tenant id")} name="tenant" required />
        {/if}
        <fieldset class="permissions">
          <legend>{t("Roles it may hand out")}</legend>
          {#each me.roles as role (role.key)}
            <label class="inline">
              <input type="checkbox" name="role" value={role.key} />
              <span>{role.key}</span>
            </label>
          {/each}
        </fieldset>
        <Buttons busy={action.busy} onCancel={() => (dialog = undefined)} label={t("Grant")} />
      </Form>
    </Dialog>
  {/if}
{:else}
  <p class="muted">{t("Loading")}</p>
{/if}
