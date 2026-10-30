<!-- SPDX-License-Identifier: MIT -->
<!-- The frame: navigation between mail, calendar, contacts and files (by the URL's fragment) – those the account has –,
     the account (#/account), the administration (#/admin), and the views. -->
<script lang="ts">
  import { LoginClient } from "@kernoid/sdk";
  import { CalendarDays, Contact, FolderOpen, Mail, Monitor, Moon, Shield, Sun } from "@lucide/svelte";

  import { loaded, message, provideJmap } from "./app.svelte.js";
  import { avatarOfAccount, loadAvatars } from "./avatars.svelte.js";
  import { t } from "./i18n.js";
  import { FILENODE, type Jmap, MAIL } from "./jmap.js";
  import MailNotifications from "./mail/MailNotifications.svelte";
  import MailView from "./mail/MailView.svelte";
  import CalendarView from "./calendar/CalendarView.svelte";
  import ContactsView from "./contacts/ContactsView.svelte";
  import FilesView from "./files/FilesView.svelte";
  import AccountView from "./account/AccountView.svelte";
  import AdminView from "./admin/AdminView.svelte";
  import { type Theme, setTheme, theme } from "./theme.svelte.js";
  import Toasts from "./ui/Toasts.svelte";
  import Tooltip from "./ui/Tooltip.svelte";
  import UserMenu from "./ui/UserMenu.svelte";

  type Section = "mail" | "calendar" | "contacts" | "files" | "account" | "admin";

  let { jmap, admin }: { jmap: Jmap; admin: boolean } = $props();
  // svelte-ignore state_referenced_locally
  provideJmap(jmap);

  let hash = $state(window.location.hash);
  let sectionBar = $state<HTMLElement>();

  $effect(() => {
    const onHash = () => (hash = window.location.hash);
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  });

  const available = $derived.by((): Section[] => {
    const primary = jmap.session.primaryAccounts;
    const out: Section[] = [];
    if (primary[MAIL]) out.push("mail", "calendar", "contacts");
    // Files also for someone with no store of their own who reaches a drive or someone's shared folders.
    const accounts = Object.values(jmap.session.accounts);
    if (primary[FILENODE] || accounts.some((account) => account.accountCapabilities[FILENODE])) out.push("files");
    return out;
  });

  /** The section the URL names, if the account has it; else the first it has. */
  const current = $derived.by((): Section => {
    const name = hash.replace(/^#\/?/, "").split("/")[0] as Section;
    if (name === "account" || name === "admin") return name;
    return available.includes(name) ? name : (available[0] ?? "account");
  });

  // On a phone the sections are a row that scrolls: keep the open one in sight.
  $effect(() => {
    void current;
    queueMicrotask(() => sectionBar?.querySelector(".active")?.scrollIntoView({ block: "nearest", inline: "nearest" }));
  });

  const login = new LoginClient({ cookies: true });
  async function logout(): Promise<void> {
    const next = await login.logout().catch(() => null);
    window.location.assign(next ?? "/login/account");
  }

  const me = loaded(() => login.session());
  void loadAvatars();

  const links: [Section, string, typeof Mail][] = [
    ["mail", "Mail", Mail],
    ["calendar", "Calendar", CalendarDays],
    ["contacts", "Contacts", Contact],
    ["files", "Files", FolderOpen],
  ];
  const themes: [Theme, string, typeof Sun][] = [
    ["light", "Light", Sun],
    ["dark", "Dark", Moon],
    ["system", "System", Monitor],
  ];
</script>
<div class="shell">
  <header class="bar">
    <a class="brand" href="#/" aria-label="kernoid">kern<b>0</b><i>id</i></a>
    <nav class="sections" bind:this={sectionBar} aria-label={t("Sections")}>
      {#each links as [name, label, Icon] (name)}
        {#if available.includes(name)}
          <a href={`#/${name}`} class:active={current === name} aria-current={current === name ? "page" : undefined}>
            <Icon size={18} />
            <span>{t(label)}</span>
          </a>
        {/if}
      {/each}
      {#if admin}
        <a href="#/admin" class:active={current === "admin"} aria-current={current === "admin" ? "page" : undefined}>
          <Shield size={18} />
          <span>{t("Administration")}</span>
        </a>
      {/if}
    </nav>
    <div class="bar-end">
      <div class="segmented icons theme-switch" role="group" aria-label={t("Theme")}>
        {#each themes as [value, label, Icon] (value)}
          <button
            type="button"
            class:active={theme() === value}
            aria-pressed={theme() === value}
            aria-label={t(label)}
            data-tip={t(label)}
            onclick={() => setTheme(value)}
          >
            <Icon size={16} />
          </button>
        {/each}
      </div>
      <UserMenu
        name={me.value?.account.display_name ?? jmap.session.username}
        address={me.value?.account.address ?? jmap.session.username}
        avatar={avatarOfAccount(me.value?.account.id)}
        {admin}
        onlogout={() => void logout()}
      />
    </div>
  </header>
  {#if available.includes("mail")}
    <MailNotifications />
  {/if}
  <svelte:boundary>
    {#key current}
      {#if current === "mail"}
        <MailView />
      {:else if current === "calendar"}
        <CalendarView />
      {:else if current === "contacts"}
        <ContactsView />
      {:else if current === "files"}
        <FilesView />
      {:else if current === "account"}
        <AccountView />
      {:else}
        <AdminView />
      {/if}
    {/key}
    {#snippet failed(error, reset)}
      <main class="center">
        <h1>{t("Something went wrong")}</h1>
        <p class="muted">{message(error)}</p>
        <button type="button" onclick={reset}>{t("Try again")}</button>
      </main>
    {/snippet}
  </svelte:boundary>
  <Tooltip />
  <Toasts />
</div>
