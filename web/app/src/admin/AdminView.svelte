<!-- SPDX-License-Identifier: MIT -->
<!-- Administration, as a section of the app (#/admin/<page>/<id>): the tenant's settings, domains, accounts, groups,
     team folders, roles, projects and applications, identity providers and provisioning – and, for instance
     administrators, the instance, its tenants, roles, signing keys and mail queue. Pages appear as the account's
     permissions allow; kernoid checks them again on every request. Instance administrators pick the tenant they
     work on. -->
<script lang="ts">
  import {
    AppWindow,
    Building,
    Building2,
    FileKey,
    Fingerprint,
    FolderKanban,
    Globe,
    KeyRound,
    Mails,
    RefreshCw,
    ScrollText,
    Server,
    Settings as SettingsIcon,
    ShieldCheck,
    Users,
    UsersRound,
  } from "@lucide/svelte";

  import { resource } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { adminAccess } from "./access.js";
  import { type AccountDetails, type GroupView, type TenantSummary, admin, need, setTenant, tenant } from "./api.svelte.js";
  import { type Directory, go, provideDirectory } from "./ui.svelte.js";
  import Accounts from "./Accounts.svelte";
  import Applications from "./Applications.svelte";
  import Audit from "./Audit.svelte";
  import Domains from "./Domains.svelte";
  import Drives from "./Drives.svelte";
  import Groups from "./Groups.svelte";
  import Instance from "./Instance.svelte";
  import MailQueue from "./MailQueue.svelte";
  import Projects from "./Projects.svelte";
  import Providers from "./Providers.svelte";
  import Roles from "./Roles.svelte";
  import SamlKeys from "./SamlKeys.svelte";
  import Scim from "./Scim.svelte";
  import Settings from "./Settings.svelte";
  import SigningKeys from "./SigningKeys.svelte";
  import Tenants from "./Tenants.svelte";

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
  const ICONS: Record<Page, typeof Globe> = {
    settings: SettingsIcon,
    domains: Globe,
    accounts: Users,
    groups: UsersRound,
    drives: Building2,
    roles: KeyRound,
    projects: FolderKanban,
    applications: AppWindow,
    providers: Fingerprint,
    scim: RefreshCw,
    audit: ScrollText,
    instance: Server,
    tenants: Building,
    "instance-roles": ShieldCheck,
    "signing-keys": FileKey,
    "mail-queue": Mails,
  };

  function route(): { page: string; id: string | undefined } {
    const [, page = "", id] = window.location.hash.replace(/^#\/?/, "").split("/");
    return { page, id: id ? decodeURIComponent(id) : undefined };
  }

  let hash = $state(route());

  const worked = () => tenant() ?? "own";
  const access = resource(worked, () => adminAccess());
  const tenants = resource(
    () => access.value?.instance,
    () => need(admin.GET("/v1/instance/tenants")),
    [] as TenantSummary[],
  );
  const accounts = resource(worked, () => need(admin.GET("/v1/accounts")).catch((): AccountDetails[] => []), []);
  const groups = resource(worked, () => need(admin.GET("/v1/groups")).catch((): GroupView[] => []), []);

  provideDirectory({
    get accounts() {
      return (accounts.value ?? []).filter((account) => !account.drive);
    },
    get groups() {
      return groups.value ?? [];
    },
    get loading() {
      return accounts.loading || groups.loading;
    },
    reload() {
      void accounts.refetch();
      void groups.refetch();
    },
    name(kind, id) {
      if (kind === "group") return (groups.value ?? []).find((group) => group.id === id)?.name ?? id;
      // Drives too, which the account lists leave out: they have a name but no address.
      const account = (accounts.value ?? []).find((entry) => entry.id === id);
      return account?.address || account?.display_name || id;
    },
  } satisfies Directory);

  const may = (permission: string) => access.value?.permissions.includes(permission) ?? false;
  const tenantPages = $derived(TENANT_PAGES.filter(([, , permission]) => may(permission)));
  const instancePages = $derived(access.value?.instance ? INSTANCE_PAGES : []);
  const page = $derived.by((): Page | undefined => {
    const wanted = hash.page as Page;
    const allowed = [...tenantPages.map(([name]) => name), ...instancePages.map(([name]) => name)];
    return allowed.includes(wanted) ? wanted : allowed[0];
  });

  let side = $state<HTMLElement>();
  // On a phone the pages are one row that scrolls: keep the open one in sight.
  $effect(() => {
    if (!page) return;
    queueMicrotask(() => side?.querySelector(".active")?.scrollIntoView({ block: "nearest", inline: "nearest" }));
  });
</script>

<svelte:window onhashchange={() => (hash = route())} />

<div class="two admin-shell">
  <nav class="side" bind:this={side} aria-label={t("Administration")}>
    {#if (tenants.value ?? []).length > 1}
      <label class="tenant-pick">
        <span class="muted small">{t("Tenant")}</span>
        <select value={tenant() ?? ""} onchange={(event) => setTenant(event.currentTarget.value || undefined)}>
          <option value="">{t("My tenant")}</option>
          {#each tenants.value ?? [] as entry (entry.id)}
            <option value={entry.id}>{entry.name}</option>
          {/each}
        </select>
      </label>
    {/if}
    {#if tenantPages.length > 0}
      <h3 class="muted small">{t("Tenant")}</h3>
      <ul class="boxes">
        {#each tenantPages as [name, label] (name)}
          {@const Icon = ICONS[name]}
          <li>
            <button type="button" class:active={page === name} onclick={() => go(name)}>
              <Icon size={17} /><span class="label">{t(label)}</span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
    {#if instancePages.length > 0}
      <h3 class="muted small">{t("Instance")}</h3>
      <ul class="boxes">
        {#each instancePages as [name, label] (name)}
          {@const Icon = ICONS[name]}
          <li>
            <button type="button" class:active={page === name} onclick={() => go(name)}>
              <Icon size={17} /><span class="label">{t(label)}</span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </nav>
  <main class="page admin">
    {#if !access.value}
      <p class="muted">{t("Loading")}</p>
    {:else if !page}
      <p class="muted">{t("You may not administer anything here.")}</p>
    {:else}
      {#key `${worked()}/${page}`}
        {#if page === "settings"}
          <Settings />
        {:else if page === "domains"}
          <Domains />
        {:else if page === "accounts"}
          <Accounts id={hash.id} />
        {:else if page === "groups"}
          <Groups />
        {:else if page === "drives"}
          <Drives />
        {:else if page === "roles"}
          <Roles base="/v1/roles" title={t("Roles")} />
        {:else if page === "projects"}
          <Projects id={hash.id} />
        {:else if page === "applications"}
          <Applications />
        {:else if page === "providers"}
          <Providers />
        {:else if page === "scim"}
          <Scim />
        {:else if page === "audit"}
          <Audit object={hash.id} instance={access.value.instance} />
        {:else if page === "instance"}
          <Instance />
        {:else if page === "tenants"}
          <Tenants />
        {:else if page === "instance-roles"}
          <Roles base="/v1/instance/roles" title={t("Instance roles")} instance />
        {:else if page === "signing-keys"}
          <SigningKeys />
          <SamlKeys />
        {:else if page === "mail-queue"}
          <MailQueue />
        {/if}
      {/key}
    {/if}
  </main>
</div>
