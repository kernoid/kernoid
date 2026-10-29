<!-- SPDX-License-Identifier: MIT -->
<!-- Roles and who holds them – of the tenant (`/v1/roles`) or of the instance (`/v1/instance/roles`). Built-in roles
     are fixed; a tenant or instance defines its own from the permissions kernoid knows (role.rs). -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type Schema, admin, need } from "./api.svelte.js";
  import { Action, principal, useDirectory } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import PrincipalSelect from "./ui/PrincipalSelect.svelte";
  import Select from "./ui/Select.svelte";

  const TENANT_PERMISSIONS = [
    "directory.read",
    "tenant.manage",
    "domains.manage",
    "policies.manage",
    "accounts.manage",
    "groups.manage",
    "roles.manage",
    "projects.manage",
    "applications.manage",
    "authorizations.manage",
    "identity_providers.manage",
    "provisioning.manage",
  ];
  const INSTANCE_PERMISSIONS = ["instance.read", "instance.manage", "tenants.manage", "instance_roles.manage"];

  // `base` names the API ("/v1/roles" or "/v1/instance/roles"); the typed calls below pick it by `instance`.
  let { title, instance = false }: { base: string; title: string; instance?: boolean } = $props();

  const directory = useDirectory();
  const action = new Action();
  const view = loaded(
    (): Promise<Schema<"RolesView"> | Schema<"InstanceRolesView">> =>
      instance ? need(admin.GET("/v1/instance/roles")) : need(admin.GET("/v1/roles")),
  );
  /** The roles alike for both: instance roles also hold permissions in every tenant. */
  const roles = $derived(
    (view.value?.roles ?? []).map((role): Schema<"InstanceRoleView"> => ({ tenant_permissions: [], ...role })),
  );
  let defining = $state(false);
  let assigning = $state(false);
  const permissions = $derived(instance ? INSTANCE_PERMISSIONS : TENANT_PERMISSIONS);

  async function change(work: () => Promise<unknown>, done?: string): Promise<boolean> {
    const succeeded = await action.run(work, done);
    if (succeeded) await view.refetch();
    return succeeded;
  }

  const define = (role: string, granted: string[]) => {
    const params = { path: { role } };
    const body = { permissions: granted };
    return instance ? need(admin.PUT("/v1/instance/roles/{role}", { params, body })) : need(admin.PUT("/v1/roles/{role}", { params, body }));
  };
  const remove = (role: string) => {
    const params = { path: { role } };
    return instance ? need(admin.DELETE("/v1/instance/roles/{role}", { params })) : need(admin.DELETE("/v1/roles/{role}", { params }));
  };
  const assign = (role: string, kind: string, id: string) => {
    const params = { path: { role, kind, id } };
    return instance
      ? need(admin.PUT("/v1/instance/roles/{role}/{kind}/{id}", { params }))
      : need(admin.PUT("/v1/roles/{role}/{kind}/{id}", { params }));
  };
  const unassign = (role: string, kind: string, id: string) => {
    const params = { path: { role, kind, id } };
    return instance
      ? need(admin.DELETE("/v1/instance/roles/{role}/{kind}/{id}", { params }))
      : need(admin.DELETE("/v1/roles/{role}/{kind}/{id}", { params }));
  };
</script>

<Head {title}>
  <button type="button" class="primary" onclick={() => (assigning = true)}>{t("Assign a role")}</button>
  <button type="button" onclick={() => (defining = true)}>{t("New role")}</button>
</Head>
<Outcome {action} />
{#each roles as role (role.name)}
  {@const holders = (view.value?.assignments ?? []).filter((entry) => entry.role === role.name)}
  <section>
    <div class="toolbar">
      <h2 class="grow">
        {role.name}
        {#if role.builtin}<span class="muted small">{t("built in")}</span>{/if}
      </h2>
      {#if !role.builtin}
        <button
          type="button"
          class="quiet danger"
          disabled={action.busy}
          onclick={() => window.confirm(t("Delete the role {name}?", { name: role.name })) && void change(() => remove(role.name))}
          >{t("Delete")}</button
        >
      {/if}
    </div>
    <p class="small muted">
      {[...role.permissions, ...role.tenant_permissions.map((permission) => `${permission} (${t("every tenant")})`)].join(" · ") || t("no permissions")}
    </p>
    <ul class="rows">
      {#each holders as holder (`${holder.principal_kind}:${holder.principal_id}`)}
        <li>
          <span class="grow">
            {directory.name(holder.principal_kind, holder.principal_id)}
            <span class="muted small"> · {holder.principal_kind === "group" ? t("Group") : t("Account")}</span>
          </span>
          <button
            type="button"
            class="quiet danger"
            disabled={action.busy}
            onclick={() => void change(() => unassign(role.name, holder.principal_kind, holder.principal_id))}>{t("Remove")}</button
          >
        </li>
      {:else}
        <li class="muted">{t("Nobody holds it.")}</li>
      {/each}
    </ul>
  </section>
{/each}

{#if assigning}
  <Dialog title={t("Assign a role")} onClose={() => (assigning = false)}>
    <Form
      submit={(field) => {
        const [kind, id] = principal(field("who"));
        void change(() => assign(field("role"), kind, id), t("The role is assigned.")).then((succeeded) => succeeded && (assigning = false));
      }}
    >
      <Select label={t("Role")} name="role" options={roles.map((role): [string, string] => [role.name, role.name])} />
      <PrincipalSelect name="who" label={t("To")} />
      <Buttons busy={action.busy} onCancel={() => (assigning = false)} label={t("Assign")} />
    </Form>
  </Dialog>
{/if}
{#if defining}
  <Dialog title={t("New role")} onClose={() => (defining = false)}>
    <Form
      submit={(field, all) =>
        void change(() => define(field("name"), all("permission")), t("The role is saved.")).then((succeeded) => succeeded && (defining = false))}
    >
      <Field label={t("Name")} name="name" required pattern="[a-z][a-z0-9_]*" hint={t("lower case, e.g. helpdesk")} />
      <fieldset class="permissions">
        <legend>{t("Permissions")}</legend>
        {#each permissions as permission (permission)}
          <label class="inline">
            <input type="checkbox" name="permission" value={permission} />
            <span>{permission}</span>
          </label>
        {/each}
      </fieldset>
      <Buttons busy={action.busy} onCancel={() => (defining = false)} />
    </Form>
  </Dialog>
{/if}
