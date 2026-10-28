// SPDX-License-Identifier: MIT
// The tenant's domains: adding one (with the TXT record that proves it), checking it, removing it – and the DNS
// records mail needs (MX, SPF, DKIM, DMARC), with what DNS answers today.

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { ok } from "../App.js";
import { t } from "../i18n.js";
import { type DomainView, type RecordCheckView, type TenantView, api, seg } from "./api.js";
import { Buttons, Dialog, Field, Form, Head, Outcome, useAction } from "./ui.js";

export function Domains(): JSX.Element {
  const action = useAction();
  const [tenant, { refetch }] = createResource(() => api<TenantView>("GET", "/v1/tenant"));
  const [dns, { refetch: recheck }] = createResource(() => api<{ domain: string; records: RecordCheckView[] }[]>("GET", "/v1/tenant/mail-dns").catch(() => []));
  const [adding, setAdding] = createSignal(false);
  const [added, setAdded] = createSignal<DomainView>();

  const verify = (domain: string) =>
    void action.run(async () => {
      await api("POST", `/v1/tenant/domains/${seg(domain)}/verify`, {});
      await refetch();
      await recheck();
    }, t("{domain} is verified.", { domain }));
  const remove = (domain: string) => {
    if (!window.confirm(t("Remove {domain}? Addresses on it stop working.", { domain }))) return;
    void action.run(async () => {
      await api("DELETE", `/v1/tenant/domains/${seg(domain)}`);
      await refetch();
    });
  };

  return (
    <>
      <Head title={t("Domains")} description={t("The domains of the tenant's addresses. A domain is used once DNS proves it is the tenant's.")}>
        <button type="button" class="primary" onClick={() => setAdding(true)}>
          {t("Add a domain")}
        </button>
      </Head>
      <Outcome action={action} />
      <table class="nodes">
        <tbody>
          <For each={ok(tenant)?.domains ?? []} fallback={<tr><td class="muted">{t("No domains yet.")}</td></tr>}>
            {(domain) => (
              <tr>
                <td class="name">
                  <strong>{domain.domain}</strong>
                  <Show when={!domain.verified && domain.record}>
                    {(record) => (
                      <div class="small muted">
                        {t("Publish:")} <code>{`${record().name} ${record().kind} "${record().value}"`}</code>
                      </div>
                    )}
                  </Show>
                </td>
                <td>{domain.verified ? <span class="ok">{t("verified")}</span> : <span class="warn">{t("not verified")}</span>}</td>
                <td class="end">
                  <Show when={!domain.verified}>
                    <button type="button" class="quiet" disabled={action.busy()} onClick={() => verify(domain.domain)}>
                      {t("Check")}
                    </button>
                  </Show>
                  <button type="button" class="quiet danger" disabled={action.busy()} onClick={() => remove(domain.domain)}>
                    {t("Remove")}
                  </button>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>

      <section>
        <div class="toolbar">
          <h2 class="grow">{t("DNS records for mail")}</h2>
          <button type="button" class="quiet" onClick={() => void recheck()}>
            {t("Check again")}
          </button>
        </div>
        <For each={ok(dns) ?? []} fallback={<p class="muted">{t("No verified domain, or kernoid handles no mail here.")}</p>}>
          {(entry) => (
            <>
              <h3>{entry.domain}</h3>
              <table class="nodes records">
                <tbody>
                  <For each={entry.records}>
                    {(record) => (
                      <tr>
                        <td>{record.kind}</td>
                        <td class={record.status === "ok" ? "ok" : "warn"}>{t(record.status)}</td>
                        <td class="name">
                          <code>{`${record.name} ${record.record_type}`}</code>
                          <div>
                            <code class="small">{record.expected}</code>
                          </div>
                          <Show when={record.status !== "ok" && record.found.length > 0}>
                            <div class="small muted">
                              {t("found:")} {record.found.join(" · ")}
                            </div>
                          </Show>
                        </td>
                        <td class="end">
                          <button type="button" class="quiet" onClick={() => void navigator.clipboard?.writeText(record.expected)}>
                            {t("Copy")}
                          </button>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </>
          )}
        </For>
      </section>

      <Show when={adding()}>
        <Dialog title={t("Add a domain")} onClose={() => setAdding(false)}>
          <Form
            submit={(field) =>
              void action.run(async () => {
                setAdded(await api<DomainView>("POST", "/v1/tenant/domains", { domain: field("domain") }));
                setAdding(false);
                await refetch();
              })
            }
          >
            <Field label={t("Domain")} name="domain" required placeholder="example.org" />
            <Buttons busy={action.busy()} onCancel={() => setAdding(false)} label={t("Add")} />
          </Form>
        </Dialog>
      </Show>
      <Show when={added()?.record}>
        {(record) => (
          <Dialog title={t("Prove the domain")} onClose={() => setAdded(undefined)}>
            <p>{t("Publish this record in the domain's DNS, then check the domain:")}</p>
            <p>
              <code>{`${record().name} ${record().kind} "${record().value}"`}</code>
            </p>
            <div class="actions end">
              <button type="button" class="primary" onClick={() => setAdded(undefined)}>
                {t("Done")}
              </button>
            </div>
          </Dialog>
        )}
      </Show>
    </>
  );
}
