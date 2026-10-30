<!-- SPDX-License-Identifier: MIT -->
<!-- The tenant's settings: name, second factor, how accounts log in, registration, who gets which service, quotas and
     how long the trash and junk keep mail, and the modules the tenant uses. -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import { Action, bytes, parseBytes, toList } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Check from "./ui/Check.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import Select from "./ui/Select.svelte";
  import EndToEnd from "./EndToEnd.svelte";

  const action = new Action();
  const tenant = loaded(() => need(admin.GET("/v1/tenant")));
  const login = loaded(() => need(admin.GET("/v1/tenant/login-policy")));
  const registration = loaded(() => need(admin.GET("/v1/tenant/registration")));
  const services = loaded(() => need(admin.GET("/v1/tenant/service-policies")));
  const mailQuota = loaded(() => need(admin.GET("/v1/tenant/mail-quota")));
  const filesQuota = loaded(() => need(admin.GET("/v1/tenant/files-quota")));
  const retention = loaded(() => need(admin.GET("/v1/tenant/mail-retention")));
  const modules = loaded(() => need(admin.GET("/v1/tenant/modules")));
  const filesRetention = loaded(() => need(admin.GET("/v1/tenant/files-retention")));
  const language = loaded(() => need(admin.GET("/v1/tenant/language")));
  const days = (text: string) => (text ? Number.parseInt(text, 10) : null);

  function moduleName(name: string): string {
    if (name === "clamav") return t("Virus scan (ClamAV)");
    if (name === "jitsi") return t("Video meetings (Jitsi)");
    return name;
  }

  function moduleHint(name: string): string {
    if (name === "clamav") return t("uploads, files and mail are checked for malware before they are kept");
    if (name === "jitsi") return t("meetings with a link in invitations; the organizer is moderator");
    return "";
  }
</script>

<Head title={t("Settings")} description={tenant.value ? `${tenant.value.name} · ${tenant.value.id}` : undefined} />
<Outcome {action} />

{#if tenant.value}
  {@const view = tenant.value}
  <section>
    <h2>{t("Tenant")}</h2>
    <Form
      class="stack"
      submit={(field, all) =>
        void action.run(async () => {
          await need(admin.PATCH("/v1/tenant", { body: { name: field("name") } }));
          await need(admin.PUT("/v1/tenant/policy", { body: { mfa_required: all("mfa").length > 0 } }));
          await tenant.refetch();
        }, t("Saved."))}
    >
      <Field label={t("Name")} name="name" required value={view.name} />
      <Check
        label={t("Everyone needs a second factor")}
        name="mfa"
        checked={view.mfa_required}
        hint={t("a passkey or an authenticator app; {days} days to set one up", { days: view.mfa_grace_days })}
      />
      <Buttons busy={action.busy} />
    </Form>
  </section>
{/if}

{#if language.ready}
  <section>
    <h2>{t("Language of emails from kernoid")}</h2>
    <Form
      class="stack"
      submit={(field) => void action.run(() => need(admin.PUT("/v1/tenant/language", { body: { language: field("language") || null } })), t("Saved."))}
    >
      <Select
        label={t("Invitations and notices, for accounts that chose none")}
        name="language"
        value={language.value?.language ?? ""}
        options={[
          ["", t("English (default)")],
          ["de", "Deutsch"],
        ]}
      />
      <Buttons busy={action.busy} />
    </Form>
  </section>
{/if}

<EndToEnd />

{#if login.value}
  {@const policy = login.value}
  <section>
    <h2>{t("Logging in")}</h2>
    <Form
      class="stack"
      submit={(_, all) =>
        void action.run(
          () => need(admin.PUT("/v1/tenant/login-policy", { body: { usernames: all("usernames").length > 0, email_login: all("email").length > 0 } })),
          t("Saved."),
        )}
    >
      <Check label={t("Usernames")} name="usernames" checked={policy.usernames} hint={t("accounts may also log in with a username")} />
      <Check label={t("Contact address")} name="email" checked={policy.email_login} hint={t("accounts may also log in with their verified contact address")} />
      <Buttons busy={action.busy} />
    </Form>
  </section>
{/if}

{#if registration.value}
  {@const view = registration.value}
  <section>
    <h2>{t("Registration")}</h2>
    <Form
      class="stack"
      submit={(field, all) =>
        void action.run(
          () => need(admin.PUT("/v1/tenant/registration", { body: { allowed: all("allowed").length > 0, domains: toList(field("domains")) } })),
          t("Saved."),
        )}
    >
      <Check label={t("People may register")} name="allowed" checked={view.allowed} />
      <Field
        label={t("Domains for own addresses")}
        name="domains"
        value={view.domains.join(", ")}
        hint={t("comma-separated; empty for accounts without an address of the tenant")}
      />
      <Buttons busy={action.busy} />
    </Form>
  </section>
{/if}

<section>
  <h2>{t("Services")}</h2>
  <p class="muted">{t("Who gets mail or files when an account is created, and whether an administrator approves it first.")}</p>
  {#each services.value ?? [] as policy (policy.service)}
    <Form
      class="row"
      submit={(field, all) =>
        void action.run(
          () =>
            need(
              admin.PUT("/v1/tenant/service-policies/{service}", {
                params: { path: { service: policy.service ?? "" } },
                body: { assign: field("assign"), approval: all("approval").length > 0 },
              }),
            ),
          t("Saved."),
        )}
    >
      <strong class="label">{policy.service === "files" ? t("Files") : t("Mail")}</strong>
      <Select
        label=""
        name="assign"
        value={policy.assign}
        options={[
          ["none", t("nobody")],
          ["native", t("accounts with an address of the tenant")],
          ["all", t("every account")],
        ]}
      />
      <Check label={t("after approval")} name="approval" checked={policy.approval} />
      <button type="submit" disabled={action.busy}>{t("Save")}</button>
    </Form>
  {/each}
</section>

{#if (modules.value ?? []).length > 0}
  <section>
    <h2>{t("Modules")}</h2>
    <p class="muted">{t("Connections to outside services the installation offers; each tenant decides whether it uses them.")}</p>
    <Form
      class="stack"
      submit={(_, all) =>
        void action.run(async () => {
          const on = all("module");
          for (const module of modules.value ?? []) {
            if (on.includes(module.name) !== module.enabled) {
              await need(admin.PUT("/v1/tenant/modules/{module}", { params: { path: { module: module.name } }, body: { enabled: on.includes(module.name) } }));
            }
          }
        }, t("Saved."))}
    >
      {#each modules.value ?? [] as module (module.name)}
        <Check label={moduleName(module.name)} name="module" value={module.name} checked={module.enabled} hint={moduleHint(module.name)} />
      {/each}
      <Buttons busy={action.busy} />
    </Form>
  </section>
{/if}

<section>
  <h2>{t("Quotas")}</h2>
  <p class="muted">{t("The default for accounts without a quota of their own. Empty: no limit.")}</p>
  <Form
    class="stack"
    submit={(field) =>
      void action.run(async () => {
        await need(admin.PUT("/v1/tenant/mail-quota", { body: { bytes: parseBytes(field("mail")) } }));
        await need(admin.PUT("/v1/tenant/files-quota", { body: { bytes: parseBytes(field("files")) } }));
      }, t("Saved."))}
  >
    <Field label={t("Mail")} name="mail" placeholder={t("no limit")} value={mailQuota.value?.bytes != null ? bytes(mailQuota.value.bytes) : ""} />
    <Field label={t("Files")} name="files" placeholder={t("no limit")} value={filesQuota.value?.bytes != null ? bytes(filesQuota.value.bytes) : ""} />
    <Buttons busy={action.busy} />
  </Form>
</section>

<section>
  <h2>{t("Retention")}</h2>
  <Form
    class="stack"
    submit={(field) =>
      void action.run(async () => {
        await need(admin.PUT("/v1/tenant/mail-retention", { body: { trash_days: days(field("trash")), junk_days: days(field("junk")) } }));
        await need(admin.PUT("/v1/tenant/files-retention", { body: { trash_days: days(field("files-trash")) } }));
      }, t("Saved."))}
  >
    <Field label={t("Days mail stays in the trash")} name="trash" type="number" min="1" placeholder={t("for ever")} value={retention.value?.trash_days ?? ""} />
    <Field label={t("Days mail stays in junk")} name="junk" type="number" min="1" placeholder={t("for ever")} value={retention.value?.junk_days ?? ""} />
    <Field label={t("Days files stay in the trash")} name="files-trash" type="number" min="1" placeholder={t("for ever")} value={filesRetention.value?.trash_days ?? ""} />
    <Buttons busy={action.busy} />
  </Form>
</section>
