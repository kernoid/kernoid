// SPDX-License-Identifier: MIT
// Roles and who holds them – of the tenant (`/v1/roles`) or of the instance (`/v1/instance/roles`). Built-in roles
// are fixed; a tenant or instance defines its own from the permissions kernoid knows (role.rs).

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { ok } from "../App.js";
import { t } from "../i18n.js";
import { PrincipalSelect, principal, useDirectory } from "./AdminView.js";
import { type RolesView, api, seg } from "./api.js";
import { Buttons, Dialog, Field, Form, Head, Outcome, Select, useAction } from "./ui.js";

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

export function Roles(props: { base: string; title: string; instance?: boolean }): JSX.Element {
  const directory = useDirectory();
  const action = useAction();
  const [view, { refetch }] = createResource(() => api<RolesView>("GET", props.base));
  const [defining, setDefining] = createSignal(false);
  const [assigning, setAssigning] = createSignal(false);
  const permissions = () => (props.instance ? INSTANCE_PERMISSIONS : TENANT_PERMISSIONS);
  const change = async (work: () => Promise<unknown>, done?: string) => {
    const succeeded = await action.run(work, done);
    if (succeeded) await refetch();
    return succeeded;
  };

  return (
    <>
      <Head title={props.title}>
        <button type="button" class="primary" onClick={() => setAssigning(true)}>
          {t("Assign a role")}
        </button>
        <button type="button" onClick={() => setDefining(true)}>
          {t("New role")}
        </button>
      </Head>
      <Outcome action={action} />
      <For each={ok(view)?.roles ?? []}>
        {(role) => {
          const holders = () => (ok(view)?.assignments ?? []).filter((entry) => entry.role === role.name);
          return (
            <section>
              <div class="toolbar">
                <h2 class="grow">
                  {role.name} <Show when={role.builtin}><span class="muted small">{t("built in")}</span></Show>
                </h2>
                <Show when={!role.builtin}>
                  <button
                    type="button"
                    class="quiet danger"
                    disabled={action.busy()}
                    onClick={() => window.confirm(t("Delete the role {name}?", { name: role.name })) && void change(() => api("DELETE", `${props.base}/${seg(role.name)}`))}
                  >
                    {t("Delete")}
                  </button>
                </Show>
              </div>
              <p class="small muted">{[...role.permissions, ...(role.tenant_permissions ?? []).map((permission) => `${permission} (${t("every tenant")})`)].join(" · ") || t("no permissions")}</p>
              <ul class="rows">
                <For each={holders()} fallback={<li class="muted">{t("Nobody holds it.")}</li>}>
                  {(holder) => (
                    <li>
                      <span class="grow">
                        {directory.name(holder.principal_kind, holder.principal_id)}
                        <span class="muted small"> · {holder.principal_kind === "group" ? t("Group") : t("Account")}</span>
                      </span>
                      <button
                        type="button"
                        class="quiet danger"
                        disabled={action.busy()}
                        onClick={() => void change(() => api("DELETE", `${props.base}/${seg(role.name)}/${seg(holder.principal_kind)}/${seg(holder.principal_id)}`))}
                      >
                        {t("Remove")}
                      </button>
                    </li>
                  )}
                </For>
              </ul>
            </section>
          );
        }}
      </For>

      <Show when={assigning()}>
        <Dialog title={t("Assign a role")} onClose={() => setAssigning(false)}>
          <Form
            submit={(field) => {
              const [kind, id] = principal(field("who"));
              void change(() => api("PUT", `${props.base}/${seg(field("role"))}/${seg(kind)}/${seg(id)}`), t("The role is assigned.")).then((succeeded) => succeeded && setAssigning(false));
            }}
          >
            <Select label={t("Role")} name="role" options={(ok(view)?.roles ?? []).map((role) => [role.name, role.name])} />
            <PrincipalSelect name="who" label={t("To")} />
            <Buttons busy={action.busy()} onCancel={() => setAssigning(false)} label={t("Assign")} />
          </Form>
        </Dialog>
      </Show>
      <Show when={defining()}>
        <Dialog title={t("New role")} onClose={() => setDefining(false)}>
          <Form
            submit={(field, all) =>
              void change(() => api("PUT", `${props.base}/${seg(field("name"))}`, { permissions: all("permission") }), t("The role is saved.")).then((succeeded) => succeeded && setDefining(false))
            }
          >
            <Field label={t("Name")} name="name" required pattern="[a-z][a-z0-9_]*" hint={t("lower case, e.g. helpdesk")} />
            <fieldset class="permissions">
              <legend>{t("Permissions")}</legend>
              <For each={permissions()}>
                {(permission) => (
                  <label class="inline">
                    <input type="checkbox" name="permission" value={permission} />
                    <span>{permission}</span>
                  </label>
                )}
              </For>
            </fieldset>
            <Buttons busy={action.busy()} onCancel={() => setDefining(false)} />
          </Form>
        </Dialog>
      </Show>
    </>
  );
}
