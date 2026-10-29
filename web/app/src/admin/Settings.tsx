// SPDX-License-Identifier: MIT
// The tenant's settings: name, second factor, how accounts log in, registration, who gets which service, quotas and
// how long the trash and junk keep mail, and the modules the tenant uses.

import { For, type JSX, Show, createResource } from "solid-js";

import { ok } from "../App.js";
import { t } from "../i18n.js";
import { type ServicePolicyView, type TenantView, api, seg } from "./api.js";
import { Buttons, Check, Field, Form, Head, Outcome, Select, bytes, parseBytes, toList, useAction } from "./ui.js";

export function Settings(): JSX.Element {
  const action = useAction();
  const [tenant, { refetch }] = createResource(() => api<TenantView>("GET", "/v1/tenant"));
  const [login] = createResource(() => api<{ email_login: boolean; usernames: boolean }>("GET", "/v1/tenant/login-policy"));
  const [registration] = createResource(() => api<{ allowed: boolean; domains: string[] }>("GET", "/v1/tenant/registration"));
  const [services] = createResource(() => api<ServicePolicyView[]>("GET", "/v1/tenant/service-policies"));
  const [mailQuota] = createResource(() => api<{ bytes?: number | null }>("GET", "/v1/tenant/mail-quota"));
  const [filesQuota] = createResource(() => api<{ bytes?: number | null }>("GET", "/v1/tenant/files-quota"));
  const [retention] = createResource(() => api<{ trash_days?: number | null; junk_days?: number | null }>("GET", "/v1/tenant/mail-retention"));
  const [modules] = createResource(() => api<{ name: string; enabled: boolean }[]>("GET", "/v1/tenant/modules"));
  const [filesRetention] = createResource(() => api<{ trash_days?: number | null }>("GET", "/v1/tenant/files-retention"));
  const days = (text: string) => (text ? Number.parseInt(text, 10) : null);

  return (
    <>
      <Head title={t("Settings")} description={ok(tenant) ? `${ok(tenant)?.name} · ${ok(tenant)?.id}` : undefined} />
      <Outcome action={action} />

      <Show when={ok(tenant)}>
        {(view) => (
          <section>
            <h2>{t("Tenant")}</h2>
            <Form
              class="stack"
              submit={(field, all) =>
                void action.run(async () => {
                  await api("PATCH", "/v1/tenant", { name: field("name") });
                  await api("PUT", "/v1/tenant/policy", { mfa_required: all("mfa").length > 0 });
                  await refetch();
                }, t("Saved."))
              }
            >
              <Field label={t("Name")} name="name" required value={view().name} />
              <Check label={t("Everyone needs a second factor")} name="mfa" checked={view().mfa_required} hint={t("a passkey or an authenticator app; {days} days to set one up", { days: view().mfa_grace_days })} />
              <Buttons busy={action.busy()} />
            </Form>
          </section>
        )}
      </Show>

      <Show when={ok(login)}>
        {(policy) => (
          <section>
            <h2>{t("Logging in")}</h2>
            <Form
              class="stack"
              submit={(_, all) =>
                void action.run(() => api("PUT", "/v1/tenant/login-policy", { usernames: all("usernames").length > 0, email_login: all("email").length > 0 }), t("Saved."))
              }
            >
              <Check label={t("Usernames")} name="usernames" checked={policy().usernames} hint={t("accounts may also log in with a username")} />
              <Check label={t("Contact address")} name="email" checked={policy().email_login} hint={t("accounts may also log in with their verified contact address")} />
              <Buttons busy={action.busy()} />
            </Form>
          </section>
        )}
      </Show>

      <Show when={ok(registration)}>
        {(view) => (
          <section>
            <h2>{t("Registration")}</h2>
            <Form
              class="stack"
              submit={(field, all) =>
                void action.run(() => api("PUT", "/v1/tenant/registration", { allowed: all("allowed").length > 0, domains: toList(field("domains")) }), t("Saved."))
              }
            >
              <Check label={t("People may register")} name="allowed" checked={view().allowed} />
              <Field label={t("Domains for own addresses")} name="domains" value={view().domains.join(", ")} hint={t("comma-separated; empty for accounts without an address of the tenant")} />
              <Buttons busy={action.busy()} />
            </Form>
          </section>
        )}
      </Show>

      <section>
        <h2>{t("Services")}</h2>
        <p class="muted">{t("Who gets mail or files when an account is created, and whether an administrator approves it first.")}</p>
        <For each={ok(services) ?? []}>
          {(policy) => (
            <Form
              class="row"
              submit={(field, all) =>
                void action.run(
                  () => api("PUT", `/v1/tenant/service-policies/${seg(policy.service ?? "")}`, { assign: field("assign"), approval: all("approval").length > 0 }),
                  t("Saved."),
                )
              }
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
              <button type="submit" disabled={action.busy()}>
                {t("Save")}
              </button>
            </Form>
          )}
        </For>
      </section>

      <Show when={(ok(modules) ?? []).length > 0}>
        <section>
          <h2>{t("Modules")}</h2>
          <p class="muted">{t("Connections to outside services the installation offers; each tenant decides whether it uses them.")}</p>
          <Form
            class="stack"
            submit={(_, all) =>
              void action.run(async () => {
                const on = all("module");
                for (const module of ok(modules) ?? []) {
                  if (on.includes(module.name) !== module.enabled) {
                    await api("PUT", `/v1/tenant/modules/${seg(module.name)}`, { enabled: on.includes(module.name) });
                  }
                }
              }, t("Saved."))
            }
          >
            <For each={ok(modules) ?? []}>
              {(module) => <Check label={moduleName(module.name)} name="module" value={module.name} checked={module.enabled} hint={moduleHint(module.name)} />}
            </For>
            <Buttons busy={action.busy()} />
          </Form>
        </section>
      </Show>

      <section>
        <h2>{t("Quotas")}</h2>
        <p class="muted">{t("The default for accounts without a quota of their own. Empty: no limit.")}</p>
        <Form
          class="stack"
          submit={(field) =>
            void action.run(async () => {
              await api("PUT", "/v1/tenant/mail-quota", { bytes: parseBytes(field("mail")) });
              await api("PUT", "/v1/tenant/files-quota", { bytes: parseBytes(field("files")) });
            }, t("Saved."))
          }
        >
          <Field label={t("Mail")} name="mail" placeholder={t("no limit")} value={ok(mailQuota)?.bytes != null ? bytes(ok(mailQuota)?.bytes) : ""} />
          <Field label={t("Files")} name="files" placeholder={t("no limit")} value={ok(filesQuota)?.bytes != null ? bytes(ok(filesQuota)?.bytes) : ""} />
          <Buttons busy={action.busy()} />
        </Form>
      </section>

      <section>
        <h2>{t("Retention")}</h2>
        <Form
          class="stack"
          submit={(field) =>
            void action.run(async () => {
              await api("PUT", "/v1/tenant/mail-retention", { trash_days: days(field("trash")), junk_days: days(field("junk")) });
              await api("PUT", "/v1/tenant/files-retention", { trash_days: days(field("files-trash")) });
            }, t("Saved."))
          }
        >
          <Field label={t("Days mail stays in the trash")} name="trash" type="number" min="1" placeholder={t("for ever")} value={ok(retention)?.trash_days ?? ""} />
          <Field label={t("Days mail stays in junk")} name="junk" type="number" min="1" placeholder={t("for ever")} value={ok(retention)?.junk_days ?? ""} />
          <Field label={t("Days files stay in the trash")} name="files-trash" type="number" min="1" placeholder={t("for ever")} value={ok(filesRetention)?.trash_days ?? ""} />
          <Buttons busy={action.busy()} />
        </Form>
      </section>
    </>
  );
}

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
