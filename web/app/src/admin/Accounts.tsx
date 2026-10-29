// SPDX-License-Identifier: MIT
// The tenant's accounts: people with an address of the tenant, external accounts (logins only), shared mailboxes –
// and one account in detail: name, state, addresses, logins, password and second factors, services, quotas, who may
// use its mail and files, sessions, applications and linked providers.

import { For, type JSX, Match, Show, Switch, createMemo, createResource, createSignal } from "solid-js";

import { ok } from "../App.js";
import { t } from "../i18n.js";
import { PrincipalSelect, go, principal, useDirectory } from "./AdminView.js";
import {
  type AccountDetails,
  type ConsentView,
  type FilesOverviewView,
  type GrantView,
  type LinkView,
  type MailOverviewView,
  type ServiceView,
  type SessionSummaryView,
  api,
  seg,
} from "./api.js";
import { Buttons, Check, Dialog, Field, Form, Head, Outcome, Select, bytes, parseBytes, useAction, when } from "./ui.js";
import { MailTransfer } from "./MailTransfer.js";
import { SieveScripts } from "./Sieve.js";

export function Accounts(props: { id: string | undefined }): JSX.Element {
  return (
    <Show when={props.id} fallback={<AccountList />}>
      {(id) => <Account id={id()} />}
    </Show>
  );
}

function kindOf(account: AccountDetails): string {
  if (account.shared) return t("Shared mailbox");
  return account.native ? t("Person") : t("External");
}

function AccountList(): JSX.Element {
  const directory = useDirectory();
  const action = useAction();
  const [search, setSearch] = createSignal("");
  const [creating, setCreating] = createSignal<"person" | "external" | "shared">();
  const shown = createMemo(() => {
    const text = search().trim().toLowerCase();
    return directory
      .accounts()
      .filter((account) => !text || `${account.display_name} ${account.address}`.toLowerCase().includes(text))
      .sort((a, b) => a.display_name.localeCompare(b.display_name));
  });
  const create = (path: string, body: unknown) =>
    void action.run(async () => {
      const made = await api<{ id: string }>("POST", path, body);
      setCreating(undefined);
      directory.reload();
      go("accounts", made.id);
    });

  return (
    <>
      <Head title={t("Accounts")}>
        <button type="button" class="primary" onClick={() => setCreating("person")}>
          {t("New account")}
        </button>
        <button type="button" onClick={() => setCreating("shared")}>
          {t("New shared mailbox")}
        </button>
        <button type="button" onClick={() => setCreating("external")}>
          {t("New external account")}
        </button>
      </Head>
      <Outcome action={action} />
      <input type="search" class="filter" placeholder={t("Search")} value={search()} onInput={(event) => setSearch(event.currentTarget.value)} />
      <table class="nodes">
        <tbody>
          <For each={shown()} fallback={<tr><td class="muted">{t("No accounts.")}</td></tr>}>
            {(account) => (
              <tr>
                <td class="name">
                  <button type="button" class="quiet file" onClick={() => go("accounts", account.id)}>
                    {account.display_name}
                  </button>
                  <div class="small muted">{account.address}</div>
                </td>
                <td class="muted small">{kindOf(account)}</td>
                <td class="small">{account.active ? "" : <span class="warn">{t("inactive")}</span>}</td>
              </tr>
            )}
          </For>
        </tbody>
      </table>

      <Switch>
        <Match when={creating() === "person"}>
          <Dialog title={t("New account")} onClose={() => setCreating(undefined)}>
            <Form submit={(field) => create("/v1/accounts", { address: field("address"), display_name: field("name"), password: field("password") || null })}>
              <Field label={t("Address")} name="address" type="email" required placeholder="name@example.org" hint={t("on a verified domain of the tenant; it is also the login name")} />
              <Field label={t("Name")} name="name" required />
              <Field label={t("Password")} name="password" type="password" autocomplete="new-password" minlength="12" hint={t("optional; at least 12 characters")} />
              <Buttons busy={action.busy()} onCancel={() => setCreating(undefined)} label={t("Create")} />
            </Form>
          </Dialog>
        </Match>
        <Match when={creating() === "shared"}>
          <Dialog title={t("New shared mailbox")} onClose={() => setCreating(undefined)}>
            <p class="muted">{t("An address such as info@ or support@ that people use through access you grant; nobody logs in as it.")}</p>
            <Form submit={(field) => create("/v1/shared-mailboxes", { address: field("address"), display_name: field("name") })}>
              <Field label={t("Address")} name="address" type="email" required placeholder="info@example.org" />
              <Field label={t("Name")} name="name" required />
              <Buttons busy={action.busy()} onCancel={() => setCreating(undefined)} label={t("Create")} />
            </Form>
          </Dialog>
        </Match>
        <Match when={creating() === "external"}>
          <Dialog title={t("New external account")} onClose={() => setCreating(undefined)}>
            <p class="muted">{t("For logins only – and files, if granted: no address of the tenant, no mailbox.")}</p>
            <Form submit={(field) => create("/v1/external-accounts", { display_name: field("name"), email: field("email") || null, username: field("username") || null })}>
              <Field label={t("Name")} name="name" required />
              <Field label={t("Contact address")} name="email" type="email" />
              <Field label={t("Username")} name="username" />
              <Buttons busy={action.busy()} onCancel={() => setCreating(undefined)} label={t("Create")} />
            </Form>
          </Dialog>
        </Match>
      </Switch>
    </>
  );
}

const MAIL_LEVELS: [string, string][] = [
  ["lrs", "read"],
  ["lrswite", "work in it"],
  ["lrswitekxa", "everything, also share"],
];
const FILE_LEVELS: [string, string][] = [
  ["r", "view"],
  ["rnadw", "edit"],
  ["randws", "edit and share"],
];

function Account(props: { id: string }): JSX.Element {
  const directory = useDirectory();
  const action = useAction();
  const base = `/v1/accounts/${seg(props.id)}`;
  const [account, { refetch }] = createResource(() => api<AccountDetails>("GET", base));
  const [services, { refetch: refetchServices }] = createResource(() => api<ServiceView[]>("GET", `${base}/services`).catch(() => []));
  const [mail, { refetch: refetchMail }] = createResource(() => api<MailOverviewView>("GET", `${base}/mail`).catch(() => undefined));
  const [files, { refetch: refetchFiles }] = createResource(() => api<FilesOverviewView>("GET", `${base}/files`).catch(() => undefined));
  const [mailAccess, { refetch: refetchMailAccess }] = createResource(() => api<GrantView[]>("GET", `${base}/mail/access`).catch(() => []));
  const [fileAccess, { refetch: refetchFileAccess }] = createResource(() => api<GrantView[]>("GET", `${base}/files/access`).catch(() => []));
  const [sessions, { refetch: refetchSessions }] = createResource(() => api<SessionSummaryView[]>("GET", `${base}/sessions`).catch(() => []));
  const [consents, { refetch: refetchConsents }] = createResource(() => api<ConsentView[]>("GET", `${base}/consents`).catch(() => []));
  const [links, { refetch: refetchLinks }] = createResource(() => api<LinkView[]>("GET", `${base}/links`).catch(() => []));
  const [addresses, { refetch: refetchAddresses }] = createResource(() => api<{ address: string; primary: boolean }[]>("GET", `${base}/addresses`).catch(() => []));
  const [dialog, setDialog] = createSignal<"mail-grant" | "file-grant" | "password">();
  const change = async (work: () => Promise<unknown>, done: string, after: () => unknown) => {
    if (await action.run(work, done)) await after();
  };

  return (
    <Show when={ok(account)} fallback={<p class="muted">{t("Loading")}</p>}>
      {(me) => (
        <>
          <p>
            <button type="button" class="quiet" onClick={() => go("accounts")}>
              ← {t("Accounts")}
            </button>
          </p>
          <Head title={me().display_name} description={`${me().address} · ${kindOf(me())} · ${me().id}`}>
            <button type="button" onClick={() => go("audit", `account:${me().id}`)}>
              {t("History")}
            </button>
            <button
              type="button"
              classList={{ danger: me().active }}
              disabled={action.busy()}
              onClick={() =>
                void change(() => api("PATCH", base, { active: !me().active }), me().active ? t("The account is deactivated.") : t("The account is active again."), () => {
                  void refetch();
                  directory.reload();
                })
              }
            >
              {me().active ? t("Deactivate") : t("Reactivate")}
            </button>
          </Head>
          <Outcome action={action} />

          <section>
            <h2>{t("Name and addresses")}</h2>
            <Form class="row" submit={(field) => void change(() => api("PATCH", base, { display_name: field("name") }), t("Saved."), () => (void refetch(), directory.reload()))}>
              <input name="name" required value={me().display_name} aria-label={t("Name")} />
              <button type="submit" disabled={action.busy()}>
                {t("Rename")}
              </button>
            </Form>
            <Show when={(ok(addresses) ?? []).length > 0}>
              <ul class="rows">
                <For each={ok(addresses) ?? []}>
                  {(entry) => (
                    <li>
                      <span class="grow">
                        {entry.address}
                        <Show when={entry.primary}>
                          <span class="muted small"> · {t("primary, the login name")}</span>
                        </Show>
                      </span>
                      <Show when={!entry.primary}>
                        <button
                          type="button"
                          class="quiet"
                          disabled={action.busy()}
                          onClick={() => void change(() => api("PATCH", base, { primary_address: entry.address }), t("Saved."), () => (void refetch(), void refetchAddresses(), directory.reload()))}
                        >
                          {t("Make primary")}
                        </button>
                        <button
                          type="button"
                          class="quiet danger"
                          disabled={action.busy()}
                          onClick={() => void change(() => api("DELETE", `${base}/aliases/${seg(entry.address)}`), t("The alias is removed."), refetchAddresses)}
                        >
                          {t("Remove")}
                        </button>
                      </Show>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
            <Show when={me().native}>
              <Form
                class="row"
                submit={(field) => void change(() => api("PUT", `${base}/aliases/${seg(field("alias"))}`), t("The alias is added."), refetchAddresses)}
              >
                <input name="alias" type="email" required placeholder={t("Alias, e.g. office@example.org")} aria-label={t("Alias")} />
                <button type="submit" disabled={action.busy()}>
                  {t("Add alias")}
                </button>
              </Form>
            </Show>
          </section>

          <Show when={!me().shared}>
            <section>
              <h2>{t("Logging in")}</h2>
              <Form class="row" submit={(field) => void change(() => api("PUT", `${base}/username`, { username: field("username") || null }), t("Saved."), () => undefined)}>
                <input name="username" placeholder={t("Username (empty removes it)")} aria-label={t("Username")} />
                <button type="submit" disabled={action.busy()}>
                  {t("Set username")}
                </button>
              </Form>
              <Form
                class="row"
                submit={(field, all) => void change(() => api("PUT", `${base}/contact`, { email: field("email") || null, verified: all("verified").length > 0 }), t("Saved."), () => undefined)}
              >
                <input name="email" type="email" placeholder={t("Contact address (empty removes it)")} aria-label={t("Contact address")} />
                <label class="inline">
                  <input type="checkbox" name="verified" />
                  <span>{t("verified")}</span>
                </label>
                <button type="submit" disabled={action.busy()}>
                  {t("Set contact address")}
                </button>
              </Form>
              <div class="actions">
                <button type="button" onClick={() => setDialog("password")}>
                  {t("Set a password")}
                </button>
                <button
                  type="button"
                  class="danger"
                  disabled={action.busy()}
                  onClick={() =>
                    window.confirm(t("Remove all second factors, recovery codes and app passwords of this account?")) &&
                    void change(() => api("DELETE", `${base}/second-factors`), t("The second factors are removed."), () => undefined)
                  }
                >
                  {t("Reset second factors")}
                </button>
              </div>
            </section>
          </Show>

          <section>
            <h2>{t("Services")}</h2>
            <table class="nodes">
              <tbody>
                <For each={["mail", "files"]}>
                  {(service) => {
                    const state = () => ok(services)?.find((entry) => entry.service === service)?.state ?? "off";
                    return (
                      <tr>
                        <td class="name">{service === "mail" ? t("Mail") : t("Files")}</td>
                        <td class="small">{t(state())}</td>
                        <td class="end">
                          <Show
                            when={state() === "on"}
                            fallback={
                              <button type="button" disabled={action.busy()} onClick={() => void change(() => api("PUT", `${base}/services/${service}`), t("Saved."), refetchServices)}>
                                {state() === "requested" ? t("Approve") : t("Switch on")}
                              </button>
                            }
                          >
                            <button type="button" class="quiet danger" disabled={action.busy()} onClick={() => void change(() => api("DELETE", `${base}/services/${service}`), t("Saved."), refetchServices)}>
                              {t("Switch off")}
                            </button>
                          </Show>
                        </td>
                      </tr>
                    );
                  }}
                </For>
              </tbody>
            </table>
          </section>

          <section>
            <h2>{t("Quotas")}</h2>
            <Form
              class="stack"
              submit={(field) =>
                void change(
                  async () => {
                    if (ok(mail)) await api("PUT", `${base}/mail/quota`, { bytes: parseBytes(field("mail")) });
                    if (ok(files)) await api("PUT", `${base}/files/quota`, { bytes: parseBytes(field("files")) });
                  },
                  t("Saved."),
                  () => (void refetchMail(), void refetchFiles()),
                )
              }
            >
              <Show when={ok(mail)}>
                {(view) => (
                  <Field
                    label={t("Mail – {used} used of {limit}", { used: bytes(view().used_bytes), limit: bytes(view().effective_quota) })}
                    name="mail"
                    placeholder={t("the tenant's default")}
                    value={view().quota != null ? bytes(view().quota) : ""}
                  />
                )}
              </Show>
              <Show when={ok(files)}>
                {(view) => (
                  <Field
                    label={t("Files – {used} used of {limit}", { used: bytes(view().used_bytes), limit: bytes(view().effective_quota) })}
                    name="files"
                    placeholder={t("the tenant's default")}
                    value={view().quota != null ? bytes(view().quota) : ""}
                  />
                )}
              </Show>
              <Buttons busy={action.busy()} />
            </Form>
          </section>

          <Show when={ok(mail)}>
            <section>
              <div class="toolbar">
                <h2 class="grow">{t("Access to the mail")}</h2>
                <button type="button" onClick={() => setDialog("mail-grant")}>
                  {t("Grant access")}
                </button>
              </div>
              <Grants
                grants={ok(mailAccess) ?? []}
                where={(grant) => (grant.mailbox ? (ok(mail)?.mailboxes.find((box) => box.id === grant.mailbox)?.name ?? grant.mailbox) : t("all mailboxes"))}
                extra={(grant) => (grant.send_as ? t("may send as") : "")}
                busy={action.busy()}
                remove={(grant) =>
                  void change(
                    () =>
                      api(
                        "DELETE",
                        `${base}/mail/access?grantee_kind=${seg(grant.grantee_kind)}&grantee_id=${seg(grant.grantee_id)}${grant.mailbox ? `&mailbox=${seg(grant.mailbox)}` : ""}`,
                      ),
                    t("The access is removed."),
                    refetchMailAccess,
                  )
                }
              />
            </section>
          </Show>

          <Show when={ok(files)}>
            <section>
              <div class="toolbar">
                <h2 class="grow">{t("Access to the files")}</h2>
                <button type="button" onClick={() => setDialog("file-grant")}>
                  {t("Grant access")}
                </button>
              </div>
              <Grants
                grants={ok(fileAccess) ?? []}
                where={(grant) => (grant.node ? t("a folder") : t("all files"))}
                busy={action.busy()}
                remove={(grant) =>
                  void change(
                    () =>
                      api(
                        "DELETE",
                        `${base}/files/access?grantee_kind=${seg(grant.grantee_kind)}&grantee_id=${seg(grant.grantee_id)}${grant.node ? `&node=${seg(grant.node)}` : ""}`,
                      ),
                    t("The access is removed."),
                    refetchFileAccess,
                  )
                }
              />
            </section>
          </Show>

          <Show when={ok(mail)}>
            {(overview) => (
              <>
                <MailTransfer base={base} mail={overview()} onImported={() => void refetchMail()} />
                <SieveScripts base={base} />
              </>
            )}
          </Show>

          <Show when={!me().shared}>
            <section>
              <h2>{t("Sessions")}</h2>
              <ul class="rows">
                <For each={ok(sessions) ?? []} fallback={<li class="muted">{t("No sessions.")}</li>}>
                  {(entry) => (
                    <li>
                      <span class="grow">
                        {(entry.user_agent ?? t("Unknown device")).slice(0, 60)}
                        <small class="muted">
                          {" "}
                          – {when(entry.created_at)}
                          {entry.client_address ? `, ${entry.client_address}` : ""}
                        </small>
                      </span>
                      <button type="button" class="quiet danger" disabled={action.busy()} onClick={() => void change(() => api("DELETE", `${base}/sessions/${seg(entry.id)}`), t("The session has ended."), refetchSessions)}>
                        {t("End")}
                      </button>
                    </li>
                  )}
                </For>
              </ul>
            </section>

            <section>
              <h2>{t("Applications")}</h2>
              <ul class="rows">
                <For each={ok(consents) ?? []} fallback={<li class="muted">{t("None.")}</li>}>
                  {(consent) => (
                    <li>
                      <span class="grow">
                        {consent.application_name} <small class="muted">– {when(consent.granted_at)}</small>
                      </span>
                      <button type="button" class="quiet danger" disabled={action.busy()} onClick={() => void change(() => api("DELETE", `${base}/consents/${seg(consent.application)}`), t("Withdrawn."), refetchConsents)}>
                        {t("Withdraw")}
                      </button>
                    </li>
                  )}
                </For>
              </ul>
            </section>

            <section>
              <h2>{t("Linked providers")}</h2>
              <ul class="rows">
                <For each={ok(links) ?? []} fallback={<li class="muted">{t("None.")}</li>}>
                  {(link) => (
                    <li>
                      <span class="grow">
                        {link.identity_provider} <small class="muted">– {link.subject}</small>
                      </span>
                      <button
                        type="button"
                        class="quiet danger"
                        disabled={action.busy()}
                        onClick={() => void change(() => api("DELETE", `${base}/links/${seg(link.identity_provider)}/${seg(link.subject)}`), t("The link is removed."), refetchLinks)}
                      >
                        {t("Remove")}
                      </button>
                    </li>
                  )}
                </For>
              </ul>
            </section>
          </Show>

          <Switch>
            <Match when={dialog() === "password"}>
              <Dialog title={t("Set a password")} onClose={() => setDialog(undefined)}>
                <Form submit={(field) => void change(() => api("PUT", `${base}/password`, { password: field("password") }), t("The password is set."), () => setDialog(undefined))}>
                  <Field label={t("New password")} name="password" type="password" autocomplete="new-password" required minlength="12" />
                  <Buttons busy={action.busy()} onCancel={() => setDialog(undefined)} />
                </Form>
              </Dialog>
            </Match>
            <Match when={dialog() === "mail-grant"}>
              <Dialog title={t("Grant access to the mail")} onClose={() => setDialog(undefined)}>
                <Form
                  submit={(field, all) => {
                    const [kind, id] = principal(field("who"));
                    void change(
                      () => api("PUT", `${base}/mail/access`, { grantee_kind: kind, grantee_id: id, rights: field("rights"), mailbox: field("mailbox") || null, send_as: all("send_as").length > 0 }),
                      t("Access granted."),
                      () => (setDialog(undefined), void refetchMailAccess()),
                    );
                  }}
                >
                  <PrincipalSelect name="who" label={t("Who")} />
                  <Select label={t("May")} name="rights" value="lrswite" options={MAIL_LEVELS.map(([rights, label]) => [rights, t(label)])} />
                  <Select label={t("Where")} name="mailbox" options={[["", t("all mailboxes")], ...((ok(mail)?.mailboxes ?? []).map((box) => [box.id, box.name]) as [string, string][])]} />
                  <Check label={t("may send as this address")} name="send_as" hint={t("all mailboxes only")} />
                  <Buttons busy={action.busy()} onCancel={() => setDialog(undefined)} label={t("Grant")} />
                </Form>
              </Dialog>
            </Match>
            <Match when={dialog() === "file-grant"}>
              <Dialog title={t("Grant access to the files")} onClose={() => setDialog(undefined)}>
                <p class="muted">{t("For all files of the account. Single folders are shared in Files.")}</p>
                <Form
                  submit={(field) => {
                    const [kind, id] = principal(field("who"));
                    void change(() => api("PUT", `${base}/files/access`, { grantee_kind: kind, grantee_id: id, rights: field("rights") }), t("Access granted."), () => (setDialog(undefined), void refetchFileAccess()));
                  }}
                >
                  <PrincipalSelect name="who" label={t("Who")} />
                  <Select label={t("May")} name="rights" value="rnadw" options={FILE_LEVELS.map(([rights, label]) => [rights, t(label)])} />
                  <Buttons busy={action.busy()} onCancel={() => setDialog(undefined)} label={t("Grant")} />
                </Form>
              </Dialog>
            </Match>
          </Switch>
        </>
      )}
    </Show>
  );
}

/** Grants with whom, where, how much – and a way to remove each. */
export function Grants(props: { grants: GrantView[]; where: (grant: GrantView) => string; extra?: (grant: GrantView) => string; busy: boolean; remove: (grant: GrantView) => void }): JSX.Element {
  const directory = useDirectory();
  return (
    <table class="nodes">
      <tbody>
        <For each={props.grants} fallback={<tr><td class="muted">{t("Nobody else has access.")}</td></tr>}>
          {(grant) => (
            <tr>
              <td class="name">
                {grant.grantee_name ?? directory.name(grant.grantee_kind, grant.grantee_id)}
                <span class="muted small"> · {grant.grantee_kind === "group" ? t("Group") : t("Account")}</span>
              </td>
              <td class="small">{props.where(grant)}</td>
              <td class="small">
                <code>{grant.rights}</code> {props.extra?.(grant)}
              </td>
              <td class="end">
                <button type="button" class="quiet danger" disabled={props.busy} onClick={() => props.remove(grant)}>
                  {t("Remove")}
                </button>
              </td>
            </tr>
          )}
        </For>
      </tbody>
    </table>
  );
}
