<!-- SPDX-License-Identifier: MIT -->
<!-- Identity providers: logging in with another OpenID Connect or SAML 2.0 provider (an organisation's directory, or
     "continue with …"), for the tenant or the whole instance. SCIM tokens are in Scim.svelte. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type ProviderView, type Schema, admin, need } from "./api.svelte.js";
  import { Action, lines, toList } from "./ui.svelte.js";
  import Area from "./ui/Area.svelte";
  import Buttons from "./ui/Buttons.svelte";
  import Check from "./ui/Check.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";

  const action = new Action();
  const providers = loaded(() => need(admin.GET("/v1/identity-providers")));
  let editing = $state<ProviderView | "oidc" | "saml">();
  const existing = $derived(typeof editing === "object" ? editing : undefined);
  const saml = $derived(existing ? existing.kind === "saml" : editing === "saml");

  async function change(work: () => Promise<unknown>, done?: string): Promise<void> {
    if (await action.run(work, done)) await providers.refetch();
  }

  function save(field: (name: string) => string, all: (name: string) => string[]): void {
    const target = existing;
    const common = {
      name: field("name"),
      issuer: field("issuer"),
      domains: toList(field("domains")),
      auto_create: all("auto_create").length > 0,
      auto_link: all("auto_link").length > 0,
      register: all("register").length > 0,
      sync_profile: all("sync_profile").length > 0,
    };
    const specific: Pick<Schema<"NewProvider">, "saml" | "client_id" | "scopes"> = saml
      ? {
          saml: {
            sso_url: field("sso_url"),
            slo_url: field("slo_url") || null,
            certificates: field("certificates") ? field("certificates").split(/\n(?=-----BEGIN)/) : [],
            sign_requests: all("sign_requests").length > 0,
            email_attribute: field("email_attribute") || null,
            name_attribute: field("name_attribute") || null,
          },
        }
      : { client_id: field("client_id"), scopes: toList(field("scopes")) };
    const secret = field("client_secret");
    void change(async () => {
      if (target) {
        const params = { path: { id: target.id } };
        await need(admin.PATCH("/v1/identity-providers/{id}", { params, body: { ...common, ...specific, active: all("active").length > 0 } }));
        if (secret) await need(admin.PUT("/v1/identity-providers/{id}/secret", { params, body: { client_secret: secret } }));
      } else {
        await need(
          admin.POST("/v1/identity-providers", {
            body: { ...common, ...specific, client_secret: secret || null, instance_wide: all("instance_wide").length > 0 },
          }),
        );
      }
      editing = undefined;
    }, t("Saved."));
  }
</script>

<Head title={t("Identity providers")} description={t("Log in with another provider: an organisation's directory over OpenID Connect or SAML 2.0, chosen by the address's domain, or offered to everyone.")}>
  <button type="button" class="primary" onclick={() => (editing = "oidc")}>{t("New OpenID Connect provider")}</button>
  <button type="button" onclick={() => (editing = "saml")}>{t("New SAML provider")}</button>
</Head>
<Outcome {action} />
<table class="nodes">
  <tbody>
    {#each providers.value ?? [] as provider (provider.id)}
      <tr>
        <td class="name">
          <button type="button" class="quiet file" onclick={() => (editing = provider)}>{provider.name}</button>
          <div class="small muted">
            {provider.kind.toUpperCase()} · {provider.issuer}{provider.domains.length ? ` · ${provider.domains.join(", ")}` : ""}{provider.instance_wide ? ` · ${t("whole instance")}` : ""}
          </div>
        </td>
        <td class="small">
          {#if !provider.active}<span class="warn">{t("inactive")}</span>{/if}
        </td>
        <td class="end">
          <button
            type="button"
            class="quiet"
            disabled={action.busy}
            onclick={() =>
              void change(
                () => need(admin.POST("/v1/identity-providers/{id}/check", { params: { path: { id: provider.id } } })),
                t("The provider answers as expected."),
              )}>{t("Check")}</button
          >
          <button
            type="button"
            class="quiet danger"
            disabled={action.busy}
            onclick={() =>
              window.confirm(t("Delete the provider {name}?", { name: provider.name })) &&
              void change(() => need(admin.DELETE("/v1/identity-providers/{id}", { params: { path: { id: provider.id } } })))}
            >{t("Delete")}</button
          >
        </td>
      </tr>
    {:else}
      <tr><td class="muted">{emptyText(providers, t("No providers yet."))}</td></tr>
    {/each}
  </tbody>
</table>
{#if editing}
  <Dialog title={existing?.name ?? (saml ? t("New SAML provider") : t("New OpenID Connect provider"))} onClose={() => (editing = undefined)} wide>
    {#if existing}
      <dl class="headers small">
        <dt>{t("Redirect URI")}</dt>
        <dd><code>{existing.redirect_uri}</code></dd>
        {#if existing.sp_entity_id}
          <dt>{t("SP entity id")}</dt>
          <dd><code>{existing.sp_entity_id}</code></dd>
        {/if}
      </dl>
    {/if}
    <Form submit={save}>
      <Field label={t("Name")} name="name" required value={existing?.name ?? ""} hint={t("shown as “Continue with …”")} />
      <Field
        label={saml ? t("Entity id of the provider") : t("Issuer")}
        name="issuer"
        required
        value={existing?.issuer ?? ""}
        placeholder={saml ? "https://idp.example.org/saml" : "https://accounts.example.org"}
      />
      {#if saml}
        <Field label={t("Single sign-on URL")} name="sso_url" required value={existing?.saml?.sso_url ?? ""} />
        <Field label={t("Single logout URL")} name="slo_url" value={existing?.saml?.slo_url ?? ""} />
        <Area label={t("Signing certificates (PEM)")} name="certificates" rows={5} value={lines(existing?.saml?.certificates)} />
        <Check label={t("Sign requests")} name="sign_requests" checked={existing?.saml?.sign_requests ?? true} />
        <Field label={t("Attribute with the email address")} name="email_attribute" value={existing?.saml?.email_attribute ?? ""} />
        <Field label={t("Attribute with the name")} name="name_attribute" value={existing?.saml?.name_attribute ?? ""} />
      {:else}
        <Field label={t("Client id")} name="client_id" required value={existing?.client_id ?? ""} />
        <Field label={t("Client secret")} name="client_secret" type="password" placeholder={existing?.has_secret ? t("unchanged") : ""} />
        <Field label={t("Scopes")} name="scopes" value={(existing?.scopes ?? ["openid", "email", "profile"]).join(" ")} />
      {/if}
      <Field label={t("Domains")} name="domains" value={(existing?.domains ?? []).join(", ")} hint={t("addresses on these domains log in there; empty: offered to everyone")} />
      <Check label={t("Create accounts on first login")} name="auto_create" checked={existing?.auto_create ?? false} />
      <Check label={t("Link to an account with the same address")} name="auto_link" checked={existing?.auto_link ?? false} />
      <Check label={t("Registering with it (“Sign up with …”)")} name="register" checked={existing?.register ?? false} />
      <Check label={t("Take the name from the provider at each login")} name="sync_profile" checked={existing?.sync_profile ?? false} />
      {#if existing}
        <Check label={t("Active")} name="active" checked={existing.active} />
      {:else}
        <Check label={t("For the whole instance")} name="instance_wide" hint={t("instance administrators only")} />
      {/if}
      <Buttons busy={action.busy} onCancel={() => (editing = undefined)} />
    </Form>
  </Dialog>
{/if}
