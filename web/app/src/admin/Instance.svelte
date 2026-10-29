<!-- SPDX-License-Identifier: MIT -->
<!-- For instance administrators: the instance (name, domains, login UI, passkeys, where people register). Creating
     instances and the main key stay with the operator's CLI. -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type TenantSummary, admin, need } from "./api.svelte.js";
  import { Action } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import Select from "./ui/Select.svelte";

  const action = new Action();
  const details = loaded(() => need(admin.GET("/v1/instance/details")));
  const tenants = loaded(() => need(admin.GET("/v1/instance/tenants")).catch((): TenantSummary[] => []));
  const registrationOptions = $derived<[string, string][]>([["", t("nowhere")], ...(tenants.value ?? []).map((entry): [string, string] => [entry.id, entry.name])]);

  async function change(work: () => Promise<unknown>): Promise<void> {
    if (await action.run(work, t("Saved."))) await details.refetch();
  }
</script>

{#if details.value && !details.error}
  {@const me = details.value}
  <Head title={t("Instance")} description={me.id} />
  <Outcome {action} />
  <section>
    <Form class="row" submit={(field) => void change(() => need(admin.PATCH("/v1/instance", { body: { name: field("name") } })))}>
      <input name="name" required value={me.name} aria-label={t("Name")} />
      <button type="submit" disabled={action.busy}>{t("Rename")}</button>
    </Form>
  </section>
  <section>
    <h2>{t("Domains")}</h2>
    <p class="muted">{t("The hosts the instance answers at. The primary one is the issuer of its tokens.")}</p>
    <ul class="rows">
      {#each me.domains as domain (domain)}
        <li>
          <span class="grow">
            {domain}
            {#if domain === me.primary_domain}
              <span class="muted small"> · {t("primary")}</span>
            {/if}
          </span>
          {#if domain !== me.primary_domain}
            <button type="button" class="quiet" disabled={action.busy} onclick={() => void change(() => need(admin.PUT("/v1/instance/primary-domain", { body: { domain } })))}>
              {t("Make primary")}
            </button>
            <button
              type="button"
              class="quiet danger"
              disabled={action.busy}
              onclick={() =>
                window.confirm(t("Remove {domain}?", { domain })) &&
                void change(() => need(admin.DELETE("/v1/instance/domains/{domain}", { params: { path: { domain } } })))}
            >
              {t("Remove")}
            </button>
          {/if}
        </li>
      {/each}
    </ul>
    <Form class="row" submit={(field) => void change(() => need(admin.PUT("/v1/instance/domains/{domain}", { params: { path: { domain: field("domain") } } })))}>
      <input name="domain" required placeholder="login.example.org" aria-label={t("Domain")} />
      <button type="submit" disabled={action.busy}>{t("Add")}</button>
    </Form>
  </section>
  <section>
    <h2>{t("Logging in")}</h2>
    <Form
      class="stack"
      submit={(field) =>
        void change(async () => {
          await need(admin.PUT("/v1/instance/login-ui", { body: { url: field("login_ui") || null } }));
          await need(admin.PUT("/v1/instance/passkey-rp-id", { body: { rp_id: field("rp_id") } }));
          await need(admin.PUT("/v1/instance/registration-tenant", { body: { tenant: field("registration") || null } }));
        })}
    >
      <Field label={t("Login UI of one's own")} name="login_ui" value={me.login_ui_url ?? ""} placeholder={t("kernoid's own")} hint={t("a URL where kernoid sends auth requests instead")} />
      <Field label={t("Passkey relying party")} name="rp_id" required value={me.passkey_rp_id} hint={t("changing it makes existing passkeys unusable")} />
      <Select label={t("Where people without an address register")} name="registration" options={registrationOptions} />
      <Buttons busy={action.busy} />
    </Form>
  </section>
{:else}
  <p class="muted">{t("Loading")}</p>
{/if}
