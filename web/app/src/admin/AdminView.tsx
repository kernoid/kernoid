// SPDX-License-Identifier: MIT
// Administration, as a section of the app (#/admin/<page>/<id>): the tenant's settings, domains, accounts, groups,
// team folders, roles, projects and applications, identity providers and provisioning – and, for instance
// administrators, the instance, its tenants, roles, signing keys and mail queue. Pages appear as the account's
// permissions allow; kernoid checks them again on every request. Instance administrators pick the tenant they work on.

import { For, type JSX, Match, Show, Switch, createContext, createResource, createSignal, onCleanup, useContext } from "solid-js";

import { ok } from "../App.js";
import { t } from "../i18n.js";
import { Accounts } from "./Accounts.js";
import { type AccountDetails, type GroupView, type TenantSummary, api, setTenant, tenant } from "./api.js";
import { Audit } from "./Audit.js";
import { Domains } from "./Domains.js";
import { Drives } from "./Drives.js";
import { Groups } from "./Groups.js";
import { Instance, MailQueue, SamlKeys, SigningKeys, Tenants } from "./Instance.js";
import { Applications, Projects } from "./Projects.js";
import { Providers, Scim } from "./Providers.js";
import { Roles } from "./Roles.js";
import { Settings } from "./Settings.js";

export interface Access {
  /** The account's permissions in the tenant worked on (role.rs). */
  permissions: string[];
  /** Whether it administers the instance. */
  instance: boolean;
}

/** What the logged-in account may administer; nothing for most. */
export async function adminAccess(): Promise<Access> {
  const [permissions, instance] = await Promise.all([
    api<{ permissions: string[] }>("GET", "/v1/tenant/permissions").then((view) => view.permissions).catch(() => []),
    api("GET", "/v1/instance/details").then(() => true).catch(() => false),
  ]);
  return { permissions, instance };
}

/** The tenant's accounts and groups, for names and choosers on every page. */
interface Directory {
  accounts: () => AccountDetails[];
  groups: () => GroupView[];
  reload: () => void;
  name: (kind: string, id: string) => string;
}

const DirectoryContext = createContext<Directory>();

export function useDirectory(): Directory {
  const directory = useContext(DirectoryContext);
  if (!directory) throw new Error("no directory");
  return directory;
}

type Page =
  | "settings"
  | "domains"
  | "accounts"
  | "groups"
  | "drives"
  | "roles"
  | "projects"
  | "applications"
  | "providers"
  | "scim"
  | "audit"
  | "instance"
  | "tenants"
  | "instance-roles"
  | "signing-keys"
  | "mail-queue";

const TENANT_PAGES: [Page, string, string][] = [
  ["settings", "Settings", "tenant.manage"],
  ["domains", "Domains", "domains.manage"],
  ["accounts", "Accounts", "accounts.manage"],
  ["groups", "Groups", "groups.manage"],
  ["drives", "Team folders", "accounts.manage"],
  ["roles", "Roles", "roles.manage"],
  ["projects", "Projects", "projects.manage"],
  ["applications", "Applications", "applications.manage"],
  ["providers", "Identity providers", "identity_providers.manage"],
  ["scim", "Provisioning (SCIM)", "provisioning.manage"],
  ["audit", "Audit log", "directory.read"],
];
const INSTANCE_PAGES: [Page, string][] = [
  ["instance", "Instance"],
  ["tenants", "Tenants"],
  ["instance-roles", "Instance roles"],
  ["signing-keys", "Signing keys"],
  ["mail-queue", "Mail queue"],
];

function route(): { page: string; id: string | undefined } {
  const [, page = "", id] = window.location.hash.replace(/^#\/?/, "").split("/");
  return { page, id: id ? decodeURIComponent(id) : undefined };
}

export function go(page: string, id?: string): void {
  window.location.hash = `#/admin/${page}${id ? `/${encodeURIComponent(id)}` : ""}`;
}

export function AdminView(): JSX.Element {
  const [hash, setHash] = createSignal(route());
  const onHash = () => setHash(route());
  window.addEventListener("hashchange", onHash);
  onCleanup(() => window.removeEventListener("hashchange", onHash));

  const [access, { refetch: refetchAccess }] = createResource(() => tenant() ?? "own", () => adminAccess());
  const [tenants] = createResource(
    () => ok(access)?.instance,
    (instance) => (instance ? api<TenantSummary[]>("GET", "/v1/instance/tenants") : Promise.resolve([] as TenantSummary[])),
  );
  const [accounts, { refetch: refetchAccounts }] = createResource(() => tenant() ?? "own", () => api<AccountDetails[]>("GET", "/v1/accounts").catch(() => []), { initialValue: [] });
  const [groups, { refetch: refetchGroups }] = createResource(() => tenant() ?? "own", () => api<GroupView[]>("GET", "/v1/groups").catch(() => []), { initialValue: [] });
  const directory: Directory = {
    accounts: () => (ok(accounts) ?? []).filter((account) => !account.drive),
    groups: () => ok(groups) ?? [],
    reload: () => {
      void refetchAccounts();
      void refetchGroups();
    },
    name: (kind, id) => {
      if (kind === "group") return directory.groups().find((group) => group.id === id)?.name ?? id;
      // Drives too, which the account lists leave out: they have a name but no address.
      const account = (ok(accounts) ?? []).find((entry) => entry.id === id);
      return account?.address || account?.display_name || id;
    },
  };

  const may = (permission: string) => ok(access)?.permissions.includes(permission) ?? false;
  const tenantPages = () => TENANT_PAGES.filter(([, , permission]) => may(permission));
  const instancePages = () => (ok(access)?.instance ? INSTANCE_PAGES : []);
  const page = (): Page | undefined => {
    const wanted = hash().page as Page;
    const allowed = [...tenantPages().map(([name]) => name), ...instancePages().map(([name]) => name)];
    return allowed.includes(wanted) ? wanted : allowed[0];
  };

  return (
    <DirectoryContext.Provider value={directory}>
      <div class="two admin-shell">
        <nav class="side" aria-label={t("Administration")}>
          <Show when={(ok(tenants) ?? []).length > 1}>
            <label class="tenant-pick">
              <span class="muted small">{t("Tenant")}</span>
              <select
                onChange={(event) => {
                  setTenant(event.currentTarget.value || undefined);
                  void refetchAccess();
                }}
              >
                <option value="">{t("My tenant")}</option>
                <For each={ok(tenants) ?? []}>{(entry) => <option value={entry.id} selected={tenant() === entry.id}>{entry.name}</option>}</For>
              </select>
            </label>
          </Show>
          <Show when={tenantPages().length > 0}>
            <h3 class="muted small">{t("Tenant")}</h3>
            <ul class="boxes">
              <For each={tenantPages()}>
                {([name, label]) => (
                  <li>
                    <button type="button" classList={{ active: page() === name }} onClick={() => go(name)}>
                      {t(label)}
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </Show>
          <Show when={instancePages().length > 0}>
            <h3 class="muted small">{t("Instance")}</h3>
            <ul class="boxes">
              <For each={instancePages()}>
                {([name, label]) => (
                  <li>
                    <button type="button" classList={{ active: page() === name }} onClick={() => go(name)}>
                      {t(label)}
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </nav>
        <main class="page admin">
          <Show when={ok(access)} fallback={<p class="muted">{t("Loading")}</p>}>
            <Show when={page()} fallback={<p class="muted">{t("You may not administer anything here.")}</p>}>
              <Switch>
                <Match when={page() === "settings"}>
                  <Settings />
                </Match>
                <Match when={page() === "domains"}>
                  <Domains />
                </Match>
                <Match when={page() === "accounts"}>
                  <Accounts id={hash().id} />
                </Match>
                <Match when={page() === "groups"}>
                  <Groups />
                </Match>
                <Match when={page() === "drives"}>
                  <Drives />
                </Match>
                <Match when={page() === "roles"}>
                  <Roles base="/v1/roles" title={t("Roles")} />
                </Match>
                <Match when={page() === "projects"}>
                  <Projects id={hash().id} />
                </Match>
                <Match when={page() === "applications"}>
                  <Applications />
                </Match>
                <Match when={page() === "providers"}>
                  <Providers />
                </Match>
                <Match when={page() === "scim"}>
                  <Scim />
                </Match>
                <Match when={page() === "audit"}>
                  <Audit object={hash().id} instance={ok(access)?.instance ?? false} />
                </Match>
                <Match when={page() === "instance"}>
                  <Instance />
                </Match>
                <Match when={page() === "tenants"}>
                  <Tenants />
                </Match>
                <Match when={page() === "instance-roles"}>
                  <Roles base="/v1/instance/roles" title={t("Instance roles")} instance />
                </Match>
                <Match when={page() === "signing-keys"}>
                  <SigningKeys />
                  <SamlKeys />
                </Match>
                <Match when={page() === "mail-queue"}>
                  <MailQueue />
                </Match>
              </Switch>
            </Show>
          </Show>
        </main>
      </div>
    </DirectoryContext.Provider>
  );
}

/** Choosing an account or a group of the tenant: `account:<id>` or `group:<id>`. */
export function PrincipalSelect(props: { name: string; label: string; groups?: boolean; optional?: boolean }): JSX.Element {
  const directory = useDirectory();
  return (
    <label>
      <span>{props.label}</span>
      <select name={props.name} required={!props.optional}>
        <option value="">{props.optional ? t("nobody yet") : t("Choose …")}</option>
        <optgroup label={t("Accounts")}>
          <For each={directory.accounts()}>{(account) => <option value={`account:${account.id}`}>{`${account.display_name} <${account.address}>`}</option>}</For>
        </optgroup>
        <Show when={props.groups !== false}>
          <optgroup label={t("Groups")}>
            <For each={directory.groups()}>{(group) => <option value={`group:${group.id}`}>{group.name}</option>}</For>
          </optgroup>
        </Show>
      </select>
    </label>
  );
}

/** `account:<id>` → ["account", id]. */
export function principal(value: string): [string, string] {
  const at = value.indexOf(":");
  return [value.slice(0, at), value.slice(at + 1)];
}
