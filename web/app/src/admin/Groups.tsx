// SPDX-License-Identifier: MIT
// Groups: members (accounts of the tenant), and addresses – a group with an address is a distribution list. Groups
// receive roles, access to mail and files, and team folders.

import { For, type JSX, Show, createSignal } from "solid-js";

import { t } from "../i18n.js";
import { useDirectory } from "./AdminView.js";
import { type GroupView, api, seg } from "./api.js";
import { Buttons, Dialog, Field, Form, Head, Outcome, useAction } from "./ui.js";

export function Groups(): JSX.Element {
  const directory = useDirectory();
  const action = useAction();
  const [creating, setCreating] = createSignal(false);
  const change = async (work: () => Promise<unknown>, done?: string) => {
    if (await action.run(work, done)) directory.reload();
  };

  return (
    <>
      <Head title={t("Groups")} description={t("Groups gather accounts: for roles, access and team folders – and, with an address, as a distribution list.")}>
        <button type="button" class="primary" onClick={() => setCreating(true)}>
          {t("New group")}
        </button>
      </Head>
      <Outcome action={action} />
      <For each={[...directory.groups()].sort((a, b) => a.name.localeCompare(b.name))} fallback={<p class="muted">{t("No groups yet.")}</p>}>
        {(group) => <Group group={group} busy={action.busy()} change={change} />}
      </For>
      <Show when={creating()}>
        <Dialog title={t("New group")} onClose={() => setCreating(false)}>
          <Form
            submit={(field) =>
              void change(async () => {
                await api("POST", "/v1/groups", { name: field("name") });
                setCreating(false);
              })
            }
          >
            <Field label={t("Name")} name="name" required />
            <Buttons busy={action.busy()} onCancel={() => setCreating(false)} label={t("Create")} />
          </Form>
        </Dialog>
      </Show>
    </>
  );
}

function Group(props: { group: GroupView; busy: boolean; change: (work: () => Promise<unknown>, done?: string) => Promise<void> }): JSX.Element {
  const directory = useDirectory();
  const base = `/v1/groups/${seg(props.group.id)}`;
  const outside = () => directory.accounts().filter((account) => !props.group.members.includes(account.id));
  return (
    <section>
      <div class="toolbar">
        <h2 class="grow">{props.group.name}</h2>
        <button
          type="button"
          class="quiet"
          disabled={props.busy}
          onClick={() => {
            const name = window.prompt(t("New name"), props.group.name)?.trim();
            if (name) void props.change(() => api("PATCH", base, { name }));
          }}
        >
          {t("Rename")}
        </button>
        <button
          type="button"
          class="quiet danger"
          disabled={props.busy}
          onClick={() => window.confirm(t("Delete the group {name}?", { name: props.group.name })) && void props.change(() => api("DELETE", base))}
        >
          {t("Delete")}
        </button>
      </div>
      <div class="pair">
        <div>
          <h3>{t("Members")}</h3>
          <ul class="rows">
            <For each={props.group.members} fallback={<li class="muted">{t("No members.")}</li>}>
              {(member) => (
                <li>
                  <span class="grow">{directory.name("account", member)}</span>
                  <button type="button" class="quiet danger" disabled={props.busy} onClick={() => void props.change(() => api("DELETE", `${base}/members/${seg(member)}`))}>
                    {t("Remove")}
                  </button>
                </li>
              )}
            </For>
          </ul>
          <Form class="row" submit={(field) => field("account") && void props.change(() => api("PUT", `${base}/members/${seg(field("account"))}`))}>
            <select name="account" aria-label={t("Account")}>
              <For each={outside()}>{(account) => <option value={account.id}>{`${account.display_name} <${account.address}>`}</option>}</For>
            </select>
            <button type="submit" disabled={props.busy || outside().length === 0}>
              {t("Add")}
            </button>
          </Form>
        </div>
        <div>
          <h3>{t("Addresses")}</h3>
          <ul class="rows">
            <For each={props.group.addresses} fallback={<li class="muted">{t("No address – not a distribution list.")}</li>}>
              {(address) => (
                <li>
                  <span class="grow">{address}</span>
                  <button type="button" class="quiet danger" disabled={props.busy} onClick={() => void props.change(() => api("DELETE", `${base}/addresses/${seg(address)}`))}>
                    {t("Remove")}
                  </button>
                </li>
              )}
            </For>
          </ul>
          <Form class="row" submit={(field) => void props.change(() => api("PUT", `${base}/addresses/${seg(field("address"))}`))}>
            <input name="address" type="email" required placeholder="team@example.org" aria-label={t("Address")} />
            <button type="submit" disabled={props.busy}>
              {t("Add")}
            </button>
          </Form>
        </div>
      </div>
    </section>
  );
}
