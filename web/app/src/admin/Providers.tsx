// SPDX-License-Identifier: MIT
// Identity providers: logging in with another OpenID Connect or SAML 2.0 provider (an organisation's directory, or
// "continue with …"), for the tenant or the whole instance – and SCIM tokens, with which a directory creates and
// removes the tenant's accounts.

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { emptyText, ok } from "../App.js";
import { t } from "../i18n.js";
import { type ProviderView, type ScimTokenView, api, seg } from "./api.js";
import { Area, Buttons, Check, Dialog, Field, Form, Head, Outcome, Secret, lines, toList, useAction, when } from "./ui.js";

export function Providers(): JSX.Element {
  const action = useAction();
  const [providers, { refetch }] = createResource(() => api<ProviderView[]>("GET", "/v1/identity-providers"));
  const [editing, setEditing] = createSignal<ProviderView | "oidc" | "saml">();
  const change = async (work: () => Promise<unknown>, done?: string) => {
    if (await action.run(work, done)) await refetch();
  };

  return (
    <>
      <Head title={t("Identity providers")} description={t("Log in with another provider: an organisation's directory over OpenID Connect or SAML 2.0, chosen by the address's domain, or offered to everyone.")}>
        <button type="button" class="primary" onClick={() => setEditing("oidc")}>
          {t("New OpenID Connect provider")}
        </button>
        <button type="button" onClick={() => setEditing("saml")}>
          {t("New SAML provider")}
        </button>
      </Head>
      <Outcome action={action} />
      <table class="nodes">
        <tbody>
          <For each={ok(providers) ?? []} fallback={<tr><td class="muted">{emptyText(providers, t("No providers yet."))}</td></tr>}>
            {(provider) => (
              <tr>
                <td class="name">
                  <button type="button" class="quiet file" onClick={() => setEditing(provider)}>
                    {provider.name}
                  </button>
                  <div class="small muted">
                    {provider.kind.toUpperCase()} · {provider.issuer}
                    {provider.domains.length ? ` · ${provider.domains.join(", ")}` : ""}
                    {provider.instance_wide ? ` · ${t("whole instance")}` : ""}
                  </div>
                </td>
                <td class="small">{provider.active ? "" : <span class="warn">{t("inactive")}</span>}</td>
                <td class="end">
                  <button type="button" class="quiet" disabled={action.busy()} onClick={() => void change(() => api("POST", `/v1/identity-providers/${seg(provider.id)}/check`), t("The provider answers as expected."))}>
                    {t("Check")}
                  </button>
                  <button
                    type="button"
                    class="quiet danger"
                    disabled={action.busy()}
                    onClick={() => window.confirm(t("Delete the provider {name}?", { name: provider.name })) && void change(() => api("DELETE", `/v1/identity-providers/${seg(provider.id)}`))}
                  >
                    {t("Delete")}
                  </button>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
      <Show when={editing()}>
        {(target) => {
          const existing = typeof target() === "string" ? undefined : (target() as ProviderView);
          const saml = existing ? existing.kind === "saml" : target() === "saml";
          return (
            <Dialog title={existing?.name ?? (saml ? t("New SAML provider") : t("New OpenID Connect provider"))} onClose={() => setEditing(undefined)} wide>
              <Show when={existing}>
                {(view) => (
                  <dl class="headers small">
                    <dt>{t("Redirect URI")}</dt>
                    <dd>
                      <code>{view().redirect_uri}</code>
                    </dd>
                    <Show when={view().sp_entity_id}>
                      <dt>{t("SP entity id")}</dt>
                      <dd>
                        <code>{view().sp_entity_id}</code>
                      </dd>
                    </Show>
                  </dl>
                )}
              </Show>
              <Form
                submit={(field, all) => {
                  const body: Record<string, unknown> = {
                    name: field("name"),
                    issuer: field("issuer"),
                    domains: toList(field("domains")),
                    auto_create: all("auto_create").length > 0,
                    auto_link: all("auto_link").length > 0,
                    register: all("register").length > 0,
                    sync_profile: all("sync_profile").length > 0,
                  };
                  if (saml) {
                    body.saml = {
                      sso_url: field("sso_url"),
                      slo_url: field("slo_url") || null,
                      certificates: field("certificates") ? field("certificates").split(/\n(?=-----BEGIN)/) : [],
                      sign_requests: all("sign_requests").length > 0,
                      email_attribute: field("email_attribute") || null,
                      name_attribute: field("name_attribute") || null,
                    };
                  } else {
                    body.client_id = field("client_id");
                    body.scopes = toList(field("scopes"));
                  }
                  const secret = field("client_secret");
                  void change(async () => {
                    if (existing) {
                      await api("PATCH", `/v1/identity-providers/${seg(existing.id)}`, { ...body, active: all("active").length > 0 });
                      if (secret) await api("PUT", `/v1/identity-providers/${seg(existing.id)}/secret`, { client_secret: secret });
                    } else {
                      await api("POST", "/v1/identity-providers", { ...body, client_secret: secret || null, instance_wide: all("instance_wide").length > 0 });
                    }
                    setEditing(undefined);
                  }, t("Saved."));
                }}
              >
                <Field label={t("Name")} name="name" required value={existing?.name ?? ""} hint={t("shown as “Continue with …”")} />
                <Field label={saml ? t("Entity id of the provider") : t("Issuer")} name="issuer" required value={existing?.issuer ?? ""} placeholder={saml ? "https://idp.example.org/saml" : "https://accounts.example.org"} />
                <Show
                  when={saml}
                  fallback={
                    <>
                      <Field label={t("Client id")} name="client_id" required value={existing?.client_id ?? ""} />
                      <Field label={t("Client secret")} name="client_secret" type="password" placeholder={existing?.has_secret ? t("unchanged") : ""} />
                      <Field label={t("Scopes")} name="scopes" value={(existing?.scopes ?? ["openid", "email", "profile"]).join(" ")} />
                    </>
                  }
                >
                  <Field label={t("Single sign-on URL")} name="sso_url" required value={existing?.saml?.sso_url ?? ""} />
                  <Field label={t("Single logout URL")} name="slo_url" value={existing?.saml?.slo_url ?? ""} />
                  <Area label={t("Signing certificates (PEM)")} name="certificates" rows={5} value={lines(existing?.saml?.certificates)} />
                  <Check label={t("Sign requests")} name="sign_requests" checked={existing?.saml?.sign_requests ?? true} />
                  <Field label={t("Attribute with the email address")} name="email_attribute" value={existing?.saml?.email_attribute ?? ""} />
                  <Field label={t("Attribute with the name")} name="name_attribute" value={existing?.saml?.name_attribute ?? ""} />
                </Show>
                <Field label={t("Domains")} name="domains" value={(existing?.domains ?? []).join(", ")} hint={t("addresses on these domains log in there; empty: offered to everyone")} />
                <Check label={t("Create accounts on first login")} name="auto_create" checked={existing?.auto_create ?? false} />
                <Check label={t("Link to an account with the same address")} name="auto_link" checked={existing?.auto_link ?? false} />
                <Check label={t("Registering with it (“Sign up with …”)")} name="register" checked={existing?.register ?? false} />
                <Check label={t("Take the name from the provider at each login")} name="sync_profile" checked={existing?.sync_profile ?? false} />
                <Show when={existing} fallback={<Check label={t("For the whole instance")} name="instance_wide" hint={t("instance administrators only")} />}>
                  <Check label={t("Active")} name="active" checked={existing?.active ?? true} />
                </Show>
                <Buttons busy={action.busy()} onCancel={() => setEditing(undefined)} />
              </Form>
            </Dialog>
          );
        }}
      </Show>
    </>
  );
}

export function Scim(): JSX.Element {
  const action = useAction();
  const [tokens, { refetch }] = createResource(() => api<ScimTokenView[]>("GET", "/v1/scim-tokens"));
  const [made, setMade] = createSignal<{ endpoint: string; token: string }>();
  return (
    <>
      <Head title={t("Provisioning (SCIM)")} description={t("A directory (e.g. Entra ID, Okta) creates, changes and deactivates the tenant's accounts over SCIM 2.0 with a token.")} />
      <Outcome action={action} />
      <Show when={made()}>
        {(view) => (
          <>
            <p>
              {t("Endpoint")}: <code>{view().endpoint}</code>
            </p>
            <Secret label={t("Token:")} value={view().token} onDone={() => setMade(undefined)} />
          </>
        )}
      </Show>
      <ul class="rows">
        <For each={ok(tokens) ?? []} fallback={<li class="muted">{emptyText(tokens, t("No tokens yet."))}</li>}>
          {(token) => (
            <li>
              <span class="grow">
                {token.name} <small class="muted">– {t("last used {date}", { date: when(token.last_used_at) })}</small>
              </span>
              <button
                type="button"
                class="quiet danger"
                disabled={action.busy()}
                onClick={() => window.confirm(t("Revoke the token {name}?", { name: token.name })) && void action.run(() => api("DELETE", `/v1/scim-tokens/${seg(token.id)}`)).then(() => refetch())}
              >
                {t("Revoke")}
              </button>
            </li>
          )}
        </For>
      </ul>
      <Form
        class="row"
        submit={(field) =>
          void action.run(async () => {
            setMade(await api<{ endpoint: string; token: string }>("POST", "/v1/scim-tokens", { name: field("name") }));
            await refetch();
          })
        }
      >
        <input name="name" required placeholder={t("e.g. Entra ID")} aria-label={t("Name")} />
        <button type="submit" disabled={action.busy()}>
          {t("Make a token")}
        </button>
      </Form>
    </>
  );
}
