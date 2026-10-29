// SPDX-License-Identifier: MIT
// For instance administrators: the instance (name, domains, login UI, passkeys, where people register), its tenants,
// the keys that sign tokens and SAML requests, and the queue of outgoing mail. Creating instances and the main key stay with the
// operator's CLI.

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { emptyText, ok } from "../App.js";
import { t } from "../i18n.js";
import { setTenant } from "./api.js";
import { type InstanceDetails, type QueuedView, type SamlKeyView, type SigningKeyView, type TenantSummary, api, seg } from "./api.js";
import { go } from "./AdminView.js";
import { Buttons, Dialog, Field, Form, Head, Outcome, Select, useAction, when } from "./ui.js";

export function Instance(): JSX.Element {
  const action = useAction();
  const [details, { refetch }] = createResource(() => api<InstanceDetails>("GET", "/v1/instance/details"));
  const [tenants] = createResource(() => api<TenantSummary[]>("GET", "/v1/instance/tenants").catch(() => []));
  const change = async (work: () => Promise<unknown>) => {
    if (await action.run(work, t("Saved."))) await refetch();
  };

  return (
    <Show when={ok(details)} fallback={<p class="muted">{t("Loading")}</p>}>
      {(me) => (
        <>
          <Head title={t("Instance")} description={me().id} />
          <Outcome action={action} />
          <section>
            <Form class="row" submit={(field) => void change(() => api("PATCH", "/v1/instance", { name: field("name") }))}>
              <input name="name" required value={me().name} aria-label={t("Name")} />
              <button type="submit" disabled={action.busy()}>
                {t("Rename")}
              </button>
            </Form>
          </section>
          <section>
            <h2>{t("Domains")}</h2>
            <p class="muted">{t("The hosts the instance answers at. The primary one is the issuer of its tokens.")}</p>
            <ul class="rows">
              <For each={me().domains}>
                {(domain) => (
                  <li>
                    <span class="grow">
                      {domain}
                      <Show when={domain === me().primary_domain}>
                        <span class="muted small"> · {t("primary")}</span>
                      </Show>
                    </span>
                    <Show when={domain !== me().primary_domain}>
                      <button type="button" class="quiet" disabled={action.busy()} onClick={() => void change(() => api("PUT", "/v1/instance/primary-domain", { domain }))}>
                        {t("Make primary")}
                      </button>
                      <button
                        type="button"
                        class="quiet danger"
                        disabled={action.busy()}
                        onClick={() => window.confirm(t("Remove {domain}?", { domain })) && void change(() => api("DELETE", `/v1/instance/domains/${seg(domain)}`))}
                      >
                        {t("Remove")}
                      </button>
                    </Show>
                  </li>
                )}
              </For>
            </ul>
            <Form class="row" submit={(field) => void change(() => api("PUT", `/v1/instance/domains/${seg(field("domain"))}`))}>
              <input name="domain" required placeholder="login.example.org" aria-label={t("Domain")} />
              <button type="submit" disabled={action.busy()}>
                {t("Add")}
              </button>
            </Form>
          </section>
          <section>
            <h2>{t("Logging in")}</h2>
            <Form
              class="stack"
              submit={(field) =>
                void change(async () => {
                  await api("PUT", "/v1/instance/login-ui", { url: field("login_ui") || null });
                  await api("PUT", "/v1/instance/passkey-rp-id", { rp_id: field("rp_id") });
                  await api("PUT", "/v1/instance/registration-tenant", { tenant: field("registration") || null });
                })
              }
            >
              <Field label={t("Login UI of one's own")} name="login_ui" value={me().login_ui_url ?? ""} placeholder={t("kernoid's own")} hint={t("a URL where kernoid sends auth requests instead")} />
              <Field label={t("Passkey relying party")} name="rp_id" required value={me().passkey_rp_id} hint={t("changing it makes existing passkeys unusable")} />
              <Select
                label={t("Where people without an address register")}
                name="registration"
                options={[["", t("nowhere")], ...((ok(tenants) ?? []).map((entry) => [entry.id, entry.name]) as [string, string][])]}
              />
              <Buttons busy={action.busy()} />
            </Form>
          </section>
        </>
      )}
    </Show>
  );
}

export function Tenants(): JSX.Element {
  const action = useAction();
  const [tenants, { refetch }] = createResource(() => api<TenantSummary[]>("GET", "/v1/instance/tenants"));
  const [creating, setCreating] = createSignal(false);
  const change = async (work: () => Promise<unknown>, done?: string) => {
    const succeeded = await action.run(work, done);
    if (succeeded) await refetch();
    return succeeded;
  };
  return (
    <>
      <Head title={t("Tenants")} description={t("Organisations on this instance, each with its own domains, accounts and settings.")}>
        <button type="button" class="primary" onClick={() => setCreating(true)}>
          {t("New tenant")}
        </button>
      </Head>
      <Outcome action={action} />
      <table class="nodes">
        <tbody>
          <For each={ok(tenants) ?? []}>
            {(entry) => (
              <tr>
                <td class="name">
                  {entry.name}
                  <div class="small muted">{entry.id}</div>
                </td>
                <td class="small">{entry.active ? "" : <span class="warn">{t("inactive")}</span>}</td>
                <td class="end">
                  <button
                    type="button"
                    class="quiet"
                    onClick={() => {
                      setTenant(entry.id);
                      go("settings");
                    }}
                  >
                    {t("Manage")}
                  </button>
                  <button
                    type="button"
                    class="quiet"
                    disabled={action.busy()}
                    onClick={() => {
                      const name = window.prompt(t("New name"), entry.name)?.trim();
                      if (name) void change(() => api("PATCH", `/v1/instance/tenants/${seg(entry.id)}`, { name }));
                    }}
                  >
                    {t("Rename")}
                  </button>
                  <button
                    type="button"
                    class="quiet"
                    classList={{ danger: entry.active }}
                    disabled={action.busy()}
                    onClick={() =>
                      (!entry.active || window.confirm(t("Deactivate {name}? Its accounts can no longer log in.", { name: entry.name }))) &&
                      void change(() => api("PATCH", `/v1/instance/tenants/${seg(entry.id)}`, { active: !entry.active }))
                    }
                  >
                    {entry.active ? t("Deactivate") : t("Reactivate")}
                  </button>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
      <Show when={creating()}>
        <Dialog title={t("New tenant")} onClose={() => setCreating(false)}>
          <Form submit={(field) => void change(() => api("POST", "/v1/instance/tenants", { name: field("name") }), t("The tenant is created.")).then((succeeded) => succeeded && setCreating(false))}>
            <Field label={t("Name")} name="name" required />
            <Buttons busy={action.busy()} onCancel={() => setCreating(false)} label={t("Create")} />
          </Form>
        </Dialog>
      </Show>
    </>
  );
}

export function SigningKeys(): JSX.Element {
  const action = useAction();
  const [keys, { refetch }] = createResource(() => api<SigningKeyView[]>("GET", "/v1/instance/signing-keys"));
  const change = async (work: () => Promise<unknown>, done?: string) => {
    const succeeded = await action.run(work, done);
    if (succeeded) await refetch();
    return succeeded;
  };
  return (
    <>
      <Head title={t("Signing keys")} description={t("The keys that sign the instance's tokens. kernoid rotates them by itself; here they can be rotated at once.")}>
        <button type="button" class="primary" disabled={action.busy()} onClick={() => void change(() => api("POST", "/v1/instance/signing-keys"), t("A new key is made; it is published before it signs."))}>
          {t("New key")}
        </button>
      </Head>
      <Outcome action={action} />
      <table class="nodes">
        <tbody>
          <For each={ok(keys) ?? []}>
            {(key) => (
              <tr>
                <td class="name">
                  <code>{key.kid}</code>
                  <div class="small muted">
                    {key.algorithm} · {t("made {date}", { date: when(key.created_at) })}
                  </div>
                </td>
                <td class="small">
                  {t(key.state)} <span class="muted">{t("since {date}", { date: when(key.state_since) })}</span>
                </td>
                <td class="end">
                  <Show when={key.state === "initial"}>
                    <button type="button" class="quiet" disabled={action.busy()} onClick={() => void change(() => api("POST", `/v1/instance/signing-keys/${seg(key.kid)}/activate`))}>
                      {t("Sign with it now")}
                    </button>
                  </Show>
                  <Show when={key.state !== "active"}>
                    <button
                      type="button"
                      class="quiet danger"
                      disabled={action.busy()}
                      onClick={() => window.confirm(t("Delete this key? Tokens it signed are no longer valid.")) && void change(() => api("DELETE", `/v1/instance/signing-keys/${seg(key.kid)}`))}
                    >
                      {t("Delete")}
                    </button>
                  </Show>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </>
  );
}

export function SamlKeys(): JSX.Element {
  const action = useAction();
  const [keys, { refetch }] = createResource(() => api<SamlKeyView[]>("GET", "/v1/instance/saml-keys"));
  const change = async (work: () => Promise<unknown>, done?: string) => {
    const succeeded = await action.run(work, done);
    if (succeeded) await refetch();
    return succeeded;
  };
  return (
    <section>
      <div class="toolbar">
        <h2 class="grow">{t("SAML keys")}</h2>
        <button type="button" disabled={action.busy()} onClick={() => void change(() => api("POST", "/v1/instance/saml-keys"), t("A new SAML key is in the metadata now. Once the providers have taken it in, sign with it."))}>
          {t("New key")}
        </button>
      </div>
      <p class="muted small">{t("kernoid's key for SAML providers: it signs requests and decrypts assertions. A new key is in the metadata beside the old one until it signs.")}</p>
      <Outcome action={action} />
      <table class="nodes">
        <tbody>
          <For each={ok(keys) ?? []} fallback={<tr><td class="muted">{emptyText(keys, t("No SAML key yet; one is made at the first SAML login."))}</td></tr>}>
            {(key) => (
              <tr>
                <td class="name">
                  <code class="small">{key.fingerprint.match(/.{2}/g)?.join(":")}</code>
                  <div class="small muted">{t("made {date}", { date: when(key.created_at) })}</div>
                </td>
                <td class="small">
                  {t(key.state)} <span class="muted">{t("since {date}", { date: when(key.state_since) })}</span>
                </td>
                <td class="end">
                  <Show when={key.state === "next"}>
                    <button type="button" class="quiet" disabled={action.busy()} onClick={() => void change(() => api("POST", `/v1/instance/saml-keys/${seg(key.id)}/activate`))}>
                      {t("Sign with it now")}
                    </button>
                  </Show>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </section>
  );
}

export function MailQueue(): JSX.Element {
  const [queue, { refetch }] = createResource(() => api<QueuedView[]>("GET", "/v1/instance/mail-queue?limit=200"));
  return (
    <>
      <Head title={t("Mail queue")} description={t("Outgoing mail not yet delivered, newest first; kernoid tries again by itself.")}>
        <button type="button" onClick={() => void refetch()}>
          {t("Refresh")}
        </button>
      </Head>
      <table class="nodes">
        <tbody>
          <For each={ok(queue) ?? []} fallback={<tr><td class="muted">{emptyText(queue, t("The queue is empty."))}</td></tr>}>
            {(entry) => (
              <tr>
                <td class="name">
                  {entry.address}
                  <Show when={entry.last_error}>
                    <div class="small warn">{entry.last_error}</div>
                  </Show>
                </td>
                <td class="small">{t(entry.status)}</td>
                <td class="small muted">{t("{count} tries", { count: entry.attempts })}</td>
                <td class="small muted">{t("next {date}", { date: when(entry.next_attempt_at) })}</td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </>
  );
}
