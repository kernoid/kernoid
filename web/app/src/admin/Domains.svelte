<!-- SPDX-License-Identifier: MIT -->
<!-- The tenant's domains: adding one (with the TXT record that proves it), checking it, removing it – and the DNS
     records mail needs (MX, SPF, DKIM, DMARC), with what DNS answers today; a domain's DKIM keys can be changed. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type DomainView, type Schema, admin, need } from "./api.svelte.js";
  import { Action } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";

  const action = new Action();
  const tenant = loaded(() => need(admin.GET("/v1/tenant")));
  const dns = loaded(() => need(admin.GET("/v1/tenant/mail-dns")).catch((): Schema<"MailDnsView">[] => []));
  let adding = $state(false);
  let added = $state<DomainView>();

  const verify = (domain: string) =>
    void action.run(async () => {
      await need(admin.POST("/v1/tenant/domains/{domain}/verify", { params: { path: { domain } }, body: {} }));
      await tenant.refetch();
      await dns.refetch();
    }, t("{domain} is verified.", { domain }));
  const rotate = (domain: string, algorithm: "rsa" | "ed25519") =>
    void action.run(async () => {
      await need(admin.POST("/v1/tenant/domains/{domain}/dkim-rotate", { params: { path: { domain } }, body: { algorithm } }));
      await dns.refetch();
    }, t("A new key waits: publish its DKIM record, listed below as missing. It signs once DNS shows it, and the old key stops."));
  const remove = (domain: string) => {
    if (!window.confirm(t("Remove {domain}? Addresses on it stop working.", { domain }))) return;
    void action.run(async () => {
      await need(admin.DELETE("/v1/tenant/domains/{domain}", { params: { path: { domain } } }));
      await tenant.refetch();
    });
  };
</script>

<Head title={t("Domains")} description={t("The domains of the tenant's addresses. A domain is used once DNS proves it is the tenant's.")}>
  <button type="button" class="primary" onclick={() => (adding = true)}>{t("Add a domain")}</button>
</Head>
<Outcome {action} />
<table class="nodes">
  <tbody>
    {#each tenant.value?.domains ?? [] as domain (domain.domain)}
      <tr>
        <td class="name">
          <strong>{domain.domain}</strong>
          {#if !domain.verified && domain.record}
            {@const record = domain.record}
            <div class="small muted">
              {t("Publish:")} <code>{`${record.name} ${record.kind} "${record.value}"`}</code>
            </div>
          {/if}
        </td>
        <td>
          {#if domain.verified}
            <span class="ok">{t("verified")}</span>
          {:else}
            <span class="warn">{t("not verified")}</span>
          {/if}
        </td>
        <td class="end">
          {#if !domain.verified}
            <button type="button" class="quiet" disabled={action.busy} onclick={() => verify(domain.domain)}>{t("Check")}</button>
          {/if}
          <button type="button" class="quiet danger" disabled={action.busy} onclick={() => remove(domain.domain)}>{t("Remove")}</button>
        </td>
      </tr>
    {:else}
      <tr><td class="muted">{emptyText(tenant, t("No domains yet."))}</td></tr>
    {/each}
  </tbody>
</table>

<section>
  <div class="toolbar">
    <h2 class="grow">{t("DNS records for mail")}</h2>
    <button type="button" class="quiet" onclick={() => void dns.refetch()}>{t("Check again")}</button>
  </div>
  {#each dns.value ?? [] as entry (entry.domain)}
    <div class="toolbar">
      <h3 class="grow">{entry.domain}</h3>
      <button type="button" class="quiet" disabled={action.busy} onclick={() => rotate(entry.domain, "rsa")}>{t("New RSA key")}</button>
      <button type="button" class="quiet" disabled={action.busy} onclick={() => rotate(entry.domain, "ed25519")}>{t("New Ed25519 key")}</button>
    </div>
    <table class="nodes records">
      <tbody>
        {#each entry.records as record, index (index)}
          <tr>
            <td>{record.kind}</td>
            <td class={record.status === "ok" ? "ok" : "warn"}>{t(record.status)}</td>
            <td class="name">
              <code>{`${record.name} ${record.record_type}`}</code>
              <div>
                <code class="small">{record.expected}</code>
              </div>
              {#if record.status !== "ok" && record.found.length > 0}
                <div class="small muted">
                  {t("found:")} {record.found.join(" · ")}
                </div>
              {/if}
            </td>
            <td class="end">
              <button type="button" class="quiet" onclick={() => void navigator.clipboard?.writeText(record.expected)}>{t("Copy")}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="muted">{emptyText(dns, t("No verified domain, or kernoid handles no mail here."))}</p>
  {/each}
</section>

{#if adding}
  <Dialog title={t("Add a domain")} onClose={() => (adding = false)}>
    <Form
      submit={(field) =>
        void action.run(async () => {
          added = await need(admin.POST("/v1/tenant/domains", { body: { domain: field("domain") } }));
          adding = false;
          await tenant.refetch();
        })}
    >
      <Field label={t("Domain")} name="domain" required placeholder="example.org" />
      <Buttons busy={action.busy} onCancel={() => (adding = false)} label={t("Add")} />
    </Form>
  </Dialog>
{/if}
{#if added?.record}
  {@const record = added.record}
  <Dialog title={t("Prove the domain")} onClose={() => (added = undefined)}>
    <p>{t("Publish this record in the domain's DNS, then check the domain:")}</p>
    <p>
      <code>{`${record.name} ${record.kind} "${record.value}"`}</code>
    </p>
    <div class="actions end">
      <button type="button" class="primary" onclick={() => (added = undefined)}>{t("Done")}</button>
    </div>
  </Dialog>
{/if}
