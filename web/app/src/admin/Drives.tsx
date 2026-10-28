// SPDX-License-Identifier: MIT
// Team folders (drives, RFC 0005): file stores that belong to the tenant, not to a person. Administrators create them
// and decide who may do what in them; people find them in Files.

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { ok } from "../App.js";
import { t } from "../i18n.js";
import { PrincipalSelect, principal } from "./AdminView.js";
import { Grants } from "./Accounts.js";
import { type DriveView, type FilesOverviewView, type GrantView, api, seg } from "./api.js";
import { Buttons, Dialog, Field, Form, Head, Outcome, Select, bytes, parseBytes, useAction } from "./ui.js";

const LEVELS: [string, string][] = [
  ["r", "view"],
  ["rnadw", "edit"],
  ["randws", "edit and share"],
];

export function Drives(): JSX.Element {
  const action = useAction();
  const [drives, { refetch }] = createResource(() => api<DriveView[]>("GET", "/v1/drives"));
  const [creating, setCreating] = createSignal(false);

  return (
    <>
      <Head
        title={t("Team folders")}
        description={t("Folders that belong to the tenant, not to a person – like a shared drive. Who may use them is decided here; people find them in Files.")}
      >
        <button type="button" class="primary" onClick={() => setCreating(true)}>
          {t("New team folder")}
        </button>
      </Head>
      <Outcome action={action} />
      <For each={ok(drives) ?? []} fallback={<p class="muted">{t("No team folders yet.")}</p>}>
        {(drive) => <Drive drive={drive} />}
      </For>
      <Show when={creating()}>
        <Dialog title={t("New team folder")} onClose={() => setCreating(false)}>
          <Form
            submit={(field) => {
              const who = field("who");
              const rights = field("rights");
              void action.run(async () => {
                const made = await api<{ id: string }>("POST", "/v1/drives", { name: field("name") });
                if (who) {
                  const [kind, id] = principal(who);
                  await api("PUT", `/v1/accounts/${seg(made.id)}/files/access`, { grantee_kind: kind, grantee_id: id, rights });
                }
                setCreating(false);
                await refetch();
              }, t("The team folder is created."));
            }}
          >
            <Field label={t("Name")} name="name" required placeholder={t("e.g. Board, Projects, Office")} />
            <PrincipalSelect name="who" label={t("First access for (e.g. a group)")} optional />
            <Select label={t("May")} name="rights" value="rnadw" options={LEVELS.map(([rights, label]) => [rights, t(label)])} />
            <Buttons busy={action.busy()} onCancel={() => setCreating(false)} label={t("Create")} />
          </Form>
        </Dialog>
      </Show>
    </>
  );
}

function Drive(props: { drive: DriveView }): JSX.Element {
  const action = useAction();
  const base = `/v1/accounts/${seg(props.drive.id)}`;
  const [grants, { refetch }] = createResource(() => api<GrantView[]>("GET", `${base}/files/access`));
  const [overview, { refetch: refetchOverview }] = createResource(() => api<FilesOverviewView>("GET", `${base}/files`).catch(() => undefined));
  const [granting, setGranting] = createSignal(false);
  return (
    <section>
      <div class="toolbar">
        <h2 class="grow">{props.drive.name}</h2>
        <span class="muted small">{ok(overview) ? t("{used} of {limit}", { used: bytes(ok(overview)?.used_bytes), limit: bytes(ok(overview)?.effective_quota) }) : ""}</span>
        <button
          type="button"
          class="quiet"
          disabled={action.busy()}
          onClick={() => {
            const text = window.prompt(t("Quota (e.g. 50 GB; empty: the tenant's default)"), ok(overview)?.quota != null ? bytes(ok(overview)?.quota) : "");
            if (text !== null) void action.run(() => api("PUT", `${base}/files/quota`, { bytes: parseBytes(text) }), t("Saved.")).then(() => refetchOverview());
          }}
        >
          {t("Quota")}
        </button>
        <button type="button" onClick={() => setGranting(true)}>
          {t("Grant access")}
        </button>
      </div>
      <Outcome action={action} />
      <Grants
        grants={ok(grants) ?? []}
        where={(grant) => (grant.node ? t("a folder") : t("everything"))}
        busy={action.busy()}
        remove={(grant) =>
          void action
            .run(() => api("DELETE", `${base}/files/access?grantee_kind=${seg(grant.grantee_kind)}&grantee_id=${seg(grant.grantee_id)}${grant.node ? `&node=${seg(grant.node)}` : ""}`))
            .then(() => refetch())
        }
      />
      <Show when={granting()}>
        <Dialog title={t("Access to {name}", { name: props.drive.name })} onClose={() => setGranting(false)}>
          <Form
            submit={(field) => {
              const [kind, id] = principal(field("who"));
              void action.run(() => api("PUT", `${base}/files/access`, { grantee_kind: kind, grantee_id: id, rights: field("rights") })).then((done) => {
                if (done) {
                  setGranting(false);
                  void refetch();
                }
              });
            }}
          >
            <PrincipalSelect name="who" label={t("Who")} />
            <Select label={t("May")} name="rights" value="rnadw" options={LEVELS.map(([rights, label]) => [rights, t(label)])} />
            <Buttons busy={action.busy()} onCancel={() => setGranting(false)} label={t("Grant")} />
          </Form>
        </Dialog>
      </Show>
    </section>
  );
}
