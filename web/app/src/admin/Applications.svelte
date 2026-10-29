<!-- SPDX-License-Identifier: MIT -->
<!-- The applications that log people in with kernoid (OpenID Connect clients), each in a project. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type ApplicationView, type ProjectView, admin, need } from "./api.svelte.js";
  import { Action, lines, toList } from "./ui.svelte.js";
  import Area from "./ui/Area.svelte";
  import Buttons from "./ui/Buttons.svelte";
  import Check from "./ui/Check.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import Secret from "./ui/Secret.svelte";
  import Select from "./ui/Select.svelte";

  const action = new Action();
  const applications = loaded(() => need(admin.GET("/v1/applications")));
  const projects = loaded(() => need(admin.GET("/v1/projects")).catch((): ProjectView[] => []));
  let creating = $state(false);
  let editing = $state<ApplicationView>();
  let secret = $state<{ id: string; value: string }>();
  const projectName = (id: string | null | undefined) => projects.value?.find((project) => project.id === id)?.name ?? id ?? "–";
  const projectOptions = $derived((projects.value ?? []).map((project): [string, string] => [project.id, project.name]));
</script>

<Head title={t("Applications")} description={t("Programs and websites that log people in with kernoid (OpenID Connect).")}>
  <button type="button" class="primary" disabled={projectOptions.length === 0} onclick={() => (creating = true)}>{t("New application")}</button>
</Head>
{#if projects.value?.length === 0}
  <p class="muted">{t("Create a project first: applications belong to one.")}</p>
{/if}
<Outcome {action} />
{#if secret}
  <Secret label={t("Client secret of {id}:", { id: secret.id })} value={secret.value} onDone={() => (secret = undefined)} />
{/if}
<table class="nodes">
  <tbody>
    {#each applications.value ?? [] as app (app.id)}
      <tr>
        <td class="name">
          <button type="button" class="quiet file" onclick={() => (editing = app)}>{app.name}</button>
          <div class="small muted">
            <code>{app.id}</code> · {app.kind === "confidential" ? t("confidential") : t("public")} · {projectName(app.project)}
          </div>
        </td>
        <td class="small">
          {#if !app.active}<span class="warn">{t("inactive")}</span>{/if}
        </td>
      </tr>
    {:else}
      <tr><td class="muted">{emptyText(applications, t("No applications yet."))}</td></tr>
    {/each}
  </tbody>
</table>

{#if creating}
  <Dialog title={t("New application")} onClose={() => (creating = false)}>
    <Form
      submit={(field) =>
        void action.run(async () => {
          const made = await need(
            admin.POST("/v1/applications", {
              body: {
                name: field("name"),
                kind: field("kind"),
                project: field("project"),
                redirect_uris: toList(field("redirect")),
                post_logout_redirect_uris: toList(field("logout")),
              },
            }),
          );
          if (made.client_secret) secret = { id: made.id, value: made.client_secret };
          creating = false;
          await applications.refetch();
        })}
    >
      <Field label={t("Name")} name="name" required />
      <Select label={t("Project")} name="project" options={projectOptions} />
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
      <Buttons busy={action.busy} onCancel={() => (creating = false)} label={t("Create")} />
    </Form>
  </Dialog>
{/if}
{#if editing}
  {@const app = editing}
  <Dialog title={app.name} onClose={() => (editing = undefined)} wide>
    <Form
      submit={(field, all) => {
        const id = app.id;
        void action.run(async () => {
          const params = { path: { id } };
          await need(
            admin.PATCH("/v1/applications/{id}", {
              params,
              body: {
                name: field("name"),
                active: all("active").length > 0,
                project: field("project"),
                redirect_uris: toList(field("redirect")),
                post_logout_redirect_uris: toList(field("logout")),
              },
            }),
          );
          await need(
            admin.PUT("/v1/applications/{id}/options", {
              params,
              body: {
                access_token_format: field("format"),
                consent_required: all("consent").length > 0,
                offline_access: all("offline").length > 0,
                backchannel_logout_uri: field("backchannel") || null,
                frontchannel_logout_uri: field("frontchannel") || null,
              },
            }),
          );
          await need(admin.PUT("/v1/applications/{id}/policy", { params, body: { mfa_required: all("mfa").length > 0 } }));
          editing = undefined;
          await applications.refetch();
        }, t("Saved."));
      }}
    >
      <p class="small muted">
        {t("Client id")}: <code>{app.id}</code>
      </p>
      <Field label={t("Name")} name="name" required value={app.name} />
      <Check label={t("Active")} name="active" checked={app.active} />
      <Select label={t("Project")} name="project" value={app.project ?? ""} options={projectOptions} />
      <Area label={t("Redirect URIs")} name="redirect" value={lines(app.redirect_uris)} hint={t("one per line")} />
      <Area label={t("After logout")} name="logout" value={lines(app.post_logout_redirect_uris)} hint={t("one per line")} />
      <Select
        label={t("Access tokens")}
        name="format"
        value={app.options.access_token_format ?? "opaque"}
        options={[
          ["opaque", t("opaque – checked by introspection")],
          ["jwt", t("JWT – checked with the signing keys")],
        ]}
      />
      <Check label={t("Ask for consent")} name="consent" checked={app.options.consent_required ?? false} />
      <Check label={t("May stay logged in (offline_access)")} name="offline" checked={app.options.offline_access ?? false} />
      <Check label={t("Needs a second factor")} name="mfa" checked={app.mfa_required} />
      <Field label={t("Back-channel logout URI")} name="backchannel" value={app.options.backchannel_logout_uri ?? ""} />
      <Field label={t("Front-channel logout URI")} name="frontchannel" value={app.options.frontchannel_logout_uri ?? ""} />
      <div class="actions">
        {#if app.kind === "confidential"}
          <button
            type="button"
            disabled={action.busy}
            onclick={() => {
              const id = app.id;
              if (!window.confirm(t("Make a new client secret? The old one stops working."))) return;
              void action.run(async () => {
                const made = await need(admin.POST("/v1/applications/{id}/secret", { params: { path: { id } } }));
                secret = { id, value: made.client_secret };
                editing = undefined;
              });
            }}>{t("New client secret")}</button
          >
        {/if}
      </div>
      <Buttons busy={action.busy} onCancel={() => (editing = undefined)} />
    </Form>
  </Dialog>
{/if}
