// SPDX-License-Identifier: MIT
// Projects (as in Zitadel): roles of one's own applications, who holds them (authorizations), and which other tenants
// may use the project (grants) – and the applications that log people in with kernoid (OpenID Connect clients).

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { emptyText, ok } from "../App.js";
import { t } from "../i18n.js";
import { PrincipalSelect, go, principal, useDirectory } from "./AdminView.js";
import { type ApplicationView, type AuthorizationView, type ProjectGrantView, type ProjectView, type TenantSummary, api, seg } from "./api.js";
import { Area, Buttons, Check, Dialog, Field, Form, Head, Outcome, Secret, Select, lines, toList, useAction } from "./ui.js";

export function Projects(props: { id: string | undefined }): JSX.Element {
  return (
    <Show when={props.id} fallback={<ProjectList />}>
      {(id) => <Project id={id()} />}
    </Show>
  );
}

function ProjectList(): JSX.Element {
  const action = useAction();
  const [projects] = createResource(() => api<ProjectView[]>("GET", "/v1/projects"));
  const [granted] = createResource(() => api<ProjectGrantView[]>("GET", "/v1/granted-projects").catch(() => []));
  const [creating, setCreating] = createSignal(false);
  return (
    <>
      <Head title={t("Projects")} description={t("A project holds applications and the roles they know; kernoid puts the roles a person holds into their tokens.")}>
        <button type="button" class="primary" onClick={() => setCreating(true)}>
          {t("New project")}
        </button>
      </Head>
      <Outcome action={action} />
      <table class="nodes">
        <tbody>
          <For each={ok(projects) ?? []} fallback={<tr><td class="muted">{emptyText(projects, t("No projects yet."))}</td></tr>}>
            {(project) => (
              <tr>
                <td class="name">
                  <button type="button" class="quiet file" onClick={() => go("projects", project.id)}>
                    {project.name}
                  </button>
                </td>
                <td class="small muted">{t("{count} roles", { count: project.roles.length })}</td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
      <Show when={(ok(granted) ?? []).length > 0}>
        <section>
          <h2>{t("Projects of other tenants")}</h2>
          <ul class="rows">
            <For each={ok(granted) ?? []}>
              {(grant) => (
                <li>
                  <span class="grow">
                    {grant.project_name} <span class="muted small">· {grant.tenant_name} · {grant.roles.join(", ")}</span>
                  </span>
                </li>
              )}
            </For>
          </ul>
        </section>
      </Show>
      <Show when={creating()}>
        <Dialog title={t("New project")} onClose={() => setCreating(false)}>
          <Form
            submit={(field) =>
              void action.run(async () => {
                const made = await api<{ id: string }>("POST", "/v1/projects", { name: field("name") });
                go("projects", made.id);
              })
            }
          >
            <Field label={t("Name")} name="name" required />
            <Buttons busy={action.busy()} onCancel={() => setCreating(false)} label={t("Create")} />
          </Form>
        </Dialog>
      </Show>
    </>
  );
}

function Project(props: { id: string }): JSX.Element {
  const directory = useDirectory();
  const action = useAction();
  const base = `/v1/projects/${seg(props.id)}`;
  const [project, { refetch }] = createResource(() => api<ProjectView>("GET", base));
  const [authorizations, { refetch: refetchAuthorizations }] = createResource(() => api<AuthorizationView[]>("GET", `${base}/authorizations`));
  const [grants, { refetch: refetchGrants }] = createResource(() => api<ProjectGrantView[]>("GET", `${base}/grants`).catch(() => []));
  const [tenants] = createResource(() => api<TenantSummary[]>("GET", "/v1/instance/tenants").catch(() => []));
  const [dialog, setDialog] = createSignal<"role" | "authorize" | "grant">();
  const change = async (work: () => Promise<unknown>, after: () => unknown, done?: string) => {
    if (await action.run(work, done)) await after();
  };

  return (
    <Show when={ok(project)} fallback={<p class="muted">{t("Loading")}</p>}>
      {(me) => (
        <>
          <p>
            <button type="button" class="quiet" onClick={() => go("projects")}>
              ← {t("Projects")}
            </button>
          </p>
          <Head title={me().name} description={me().id}>
            <button
              type="button"
              class="danger"
              disabled={action.busy()}
              onClick={() => window.confirm(t("Delete the project {name}?", { name: me().name })) && void change(() => api("DELETE", base), () => go("projects"))}
            >
              {t("Delete")}
            </button>
          </Head>
          <Outcome action={action} />
          <section>
            <Form
              class="stack"
              submit={(field, all) =>
                void change(
                  () => api("PATCH", base, { name: field("name"), role_assertion: all("assertion").length > 0, role_check: all("check").length > 0 }),
                  refetch,
                  t("Saved."),
                )
              }
            >
              <Field label={t("Name")} name="name" required value={me().name} />
              <Check label={t("Roles in the ID token")} name="assertion" checked={me().role_assertion} hint={t("claim urn:kernoid:project:roles")} />
              <Check label={t("Only people with a role may log in")} name="check" checked={me().role_check} />
              <Buttons busy={action.busy()} />
            </Form>
          </section>

          <section>
            <div class="toolbar">
              <h2 class="grow">{t("Roles")}</h2>
              <button type="button" onClick={() => setDialog("role")}>
                {t("New role")}
              </button>
            </div>
            <ul class="rows">
              <For each={me().roles} fallback={<li class="muted">{t("No roles yet.")}</li>}>
                {(role) => (
                  <li>
                    <span class="grow">
                      <code>{role.key}</code> {role.display_name}
                      <Show when={role.group}>
                        <span class="muted small"> · {role.group}</span>
                      </Show>
                    </span>
                    <button type="button" class="quiet danger" disabled={action.busy()} onClick={() => void change(() => api("DELETE", `${base}/roles/${seg(role.key)}`), refetch)}>
                      {t("Remove")}
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </section>

          <section>
            <div class="toolbar">
              <h2 class="grow">{t("Who holds which role")}</h2>
              <button type="button" disabled={me().roles.length === 0} onClick={() => setDialog("authorize")}>
                {t("Authorize")}
              </button>
            </div>
            <ul class="rows">
              <For each={ok(authorizations) ?? []} fallback={<li class="muted">{emptyText(authorizations, t("Nobody yet."))}</li>}>
                {(entry) => (
                  <li>
                    <span class="grow">
                      {directory.name(entry.principal_kind, entry.principal_id)} <code>{entry.role}</code>
                    </span>
                    <button
                      type="button"
                      class="quiet danger"
                      disabled={action.busy()}
                      onClick={() => void change(() => api("DELETE", `${base}/authorizations/${seg(entry.role)}/${seg(entry.principal_kind)}/${seg(entry.principal_id)}`), refetchAuthorizations)}
                    >
                      {t("Remove")}
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </section>

          <section>
            <div class="toolbar">
              <h2 class="grow">{t("Other tenants")}</h2>
              <button type="button" disabled={me().roles.length === 0} onClick={() => setDialog("grant")}>
                {t("Grant to a tenant")}
              </button>
            </div>
            <ul class="rows">
              <For each={ok(grants) ?? []} fallback={<li class="muted">{emptyText(grants, t("No other tenant uses it."))}</li>}>
                {(grant) => (
                  <li>
                    <span class="grow">
                      {grant.tenant_name} <span class="muted small">· {grant.roles.join(", ")}</span>
                    </span>
                    <button type="button" class="quiet danger" disabled={action.busy()} onClick={() => void change(() => api("DELETE", `${base}/grants/${seg(grant.tenant)}`), refetchGrants)}>
                      {t("Remove")}
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </section>

          <Show when={dialog() === "role"}>
            <Dialog title={t("New role")} onClose={() => setDialog(undefined)}>
              <Form
                submit={(field) =>
                  void change(() => api("PUT", `${base}/roles/${seg(field("key"))}`, { display_name: field("name"), group: field("group") || null }), () => (setDialog(undefined), refetch()))
                }
              >
                <Field label={t("Key")} name="key" required hint={t("what applications see, e.g. editor")} />
                <Field label={t("Name")} name="name" required />
                <Field label={t("Group (optional)")} name="group" />
                <Buttons busy={action.busy()} onCancel={() => setDialog(undefined)} />
              </Form>
            </Dialog>
          </Show>
          <Show when={dialog() === "authorize"}>
            <Dialog title={t("Authorize")} onClose={() => setDialog(undefined)}>
              <Form
                submit={(field) => {
                  const [kind, id] = principal(field("who"));
                  void change(() => api("PUT", `${base}/authorizations/${seg(field("role"))}/${seg(kind)}/${seg(id)}`), () => (setDialog(undefined), refetchAuthorizations()));
                }}
              >
                <PrincipalSelect name="who" label={t("Who")} />
                <Select label={t("Role")} name="role" options={me().roles.map((role) => [role.key, `${role.key} – ${role.display_name}`])} />
                <Buttons busy={action.busy()} onCancel={() => setDialog(undefined)} label={t("Authorize")} />
              </Form>
            </Dialog>
          </Show>
          <Show when={dialog() === "grant"}>
            <Dialog title={t("Grant to a tenant")} onClose={() => setDialog(undefined)}>
              <Form submit={(field, all) => void change(() => api("PUT", `${base}/grants/${seg(field("tenant"))}`, { roles: all("role") }), () => (setDialog(undefined), refetchGrants()))}>
                <Show when={(ok(tenants) ?? []).length > 0} fallback={<Field label={t("Tenant id")} name="tenant" required />}>
                  <Select label={t("Tenant")} name="tenant" options={(ok(tenants) ?? []).map((entry) => [entry.id, entry.name])} />
                </Show>
                <fieldset class="permissions">
                  <legend>{t("Roles it may hand out")}</legend>
                  <For each={me().roles}>
                    {(role) => (
                      <label class="inline">
                        <input type="checkbox" name="role" value={role.key} />
                        <span>{role.key}</span>
                      </label>
                    )}
                  </For>
                </fieldset>
                <Buttons busy={action.busy()} onCancel={() => setDialog(undefined)} label={t("Grant")} />
              </Form>
            </Dialog>
          </Show>
        </>
      )}
    </Show>
  );
}

export function Applications(): JSX.Element {
  const action = useAction();
  const [applications, { refetch }] = createResource(() => api<ApplicationView[]>("GET", "/v1/applications"));
  const [projects] = createResource(() => api<ProjectView[]>("GET", "/v1/projects").catch(() => []));
  const [creating, setCreating] = createSignal(false);
  const [editing, setEditing] = createSignal<ApplicationView>();
  const [secret, setSecret] = createSignal<{ id: string; value: string }>();
  const projectName = (id: string | null | undefined) => ok(projects)?.find((project) => project.id === id)?.name ?? id ?? "–";
  const projectOptions = () => (ok(projects) ?? []).map((project) => [project.id, project.name] as [string, string]);

  return (
    <>
      <Head title={t("Applications")} description={t("Programs and websites that log people in with kernoid (OpenID Connect).")}>
        <button type="button" class="primary" disabled={projectOptions().length === 0} onClick={() => setCreating(true)}>
          {t("New application")}
        </button>
      </Head>
      <Show when={ok(projects)?.length === 0}>
        <p class="muted">{t("Create a project first: applications belong to one.")}</p>
      </Show>
      <Outcome action={action} />
      <Show when={secret()}>{(made) => <Secret label={t("Client secret of {id}:", { id: made().id })} value={made().value} onDone={() => setSecret(undefined)} />}</Show>
      <table class="nodes">
        <tbody>
          <For each={ok(applications) ?? []} fallback={<tr><td class="muted">{emptyText(applications, t("No applications yet."))}</td></tr>}>
            {(app) => (
              <tr>
                <td class="name">
                  <button type="button" class="quiet file" onClick={() => setEditing(app)}>
                    {app.name}
                  </button>
                  <div class="small muted">
                    <code>{app.id}</code> · {app.kind === "confidential" ? t("confidential") : t("public")} · {projectName(app.project)}
                  </div>
                </td>
                <td class="small">{app.active ? "" : <span class="warn">{t("inactive")}</span>}</td>
              </tr>
            )}
          </For>
        </tbody>
      </table>

      <Show when={creating()}>
        <Dialog title={t("New application")} onClose={() => setCreating(false)}>
          <Form
            submit={(field) =>
              void action.run(async () => {
                const made = await api<{ id: string; client_secret?: string | null }>("POST", "/v1/applications", {
                  name: field("name"),
                  kind: field("kind"),
                  project: field("project"),
                  redirect_uris: toList(field("redirect")),
                  post_logout_redirect_uris: toList(field("logout")),
                });
                if (made.client_secret) setSecret({ id: made.id, value: made.client_secret });
                setCreating(false);
                await refetch();
              })
            }
          >
            <Field label={t("Name")} name="name" required />
            <Select label={t("Project")} name="project" options={projectOptions()} />
            <Select
              label={t("Kind")}
              name="kind"
              value="confidential"
              options={[
                ["confidential", t("confidential – a server keeps a secret")],
                ["public", t("public – a browser or phone app, with PKCE")],
              ]}
            />
            <Area label={t("Redirect URIs")} name="redirect" hint={t("one per line")} />
            <Area label={t("After logout")} name="logout" hint={t("one per line")} />
            <Buttons busy={action.busy()} onCancel={() => setCreating(false)} label={t("Create")} />
          </Form>
        </Dialog>
      </Show>
      <Show when={editing()}>
        {(app) => (
          <Dialog title={app().name} onClose={() => setEditing(undefined)} wide>
            <Form
              submit={(field, all) => {
                const id = seg(app().id);
                void action.run(async () => {
                  await api("PATCH", `/v1/applications/${id}`, {
                    name: field("name"),
                    active: all("active").length > 0,
                    project: field("project"),
                    redirect_uris: toList(field("redirect")),
                    post_logout_redirect_uris: toList(field("logout")),
                  });
                  await api("PUT", `/v1/applications/${id}/options`, {
                    access_token_format: field("format"),
                    consent_required: all("consent").length > 0,
                    offline_access: all("offline").length > 0,
                    backchannel_logout_uri: field("backchannel") || null,
                    frontchannel_logout_uri: field("frontchannel") || null,
                  });
                  await api("PUT", `/v1/applications/${id}/policy`, { mfa_required: all("mfa").length > 0 });
                  setEditing(undefined);
                  await refetch();
                }, t("Saved."));
              }}
            >
              <p class="small muted">
                {t("Client id")}: <code>{app().id}</code>
              </p>
              <Field label={t("Name")} name="name" required value={app().name} />
              <Check label={t("Active")} name="active" checked={app().active} />
              <Select label={t("Project")} name="project" value={app().project ?? ""} options={projectOptions()} />
              <Area label={t("Redirect URIs")} name="redirect" value={lines(app().redirect_uris)} hint={t("one per line")} />
              <Area label={t("After logout")} name="logout" value={lines(app().post_logout_redirect_uris)} hint={t("one per line")} />
              <Select
                label={t("Access tokens")}
                name="format"
                value={app().options.access_token_format ?? "opaque"}
                options={[
                  ["opaque", t("opaque – checked by introspection")],
                  ["jwt", t("JWT – checked with the signing keys")],
                ]}
              />
              <Check label={t("Ask for consent")} name="consent" checked={app().options.consent_required ?? false} />
              <Check label={t("May stay logged in (offline_access)")} name="offline" checked={app().options.offline_access ?? false} />
              <Check label={t("Needs a second factor")} name="mfa" checked={app().mfa_required} />
              <Field label={t("Back-channel logout URI")} name="backchannel" value={app().options.backchannel_logout_uri ?? ""} />
              <Field label={t("Front-channel logout URI")} name="frontchannel" value={app().options.frontchannel_logout_uri ?? ""} />
              <div class="actions">
                <Show when={app().kind === "confidential"}>
                  <button
                    type="button"
                    disabled={action.busy()}
                    onClick={() =>
                      window.confirm(t("Make a new client secret? The old one stops working.")) &&
                      void action.run(async () => {
                        const made = await api<{ client_secret: string }>("POST", `/v1/applications/${seg(app().id)}/secret`);
                        setSecret({ id: app().id, value: made.client_secret });
                        setEditing(undefined);
                      })
                    }
                  >
                    {t("New client secret")}
                  </button>
                </Show>
              </div>
              <Buttons busy={action.busy()} onCancel={() => setEditing(undefined)} />
            </Form>
          </Dialog>
        )}
      </Show>
    </>
  );
}
