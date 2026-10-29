<!-- SPDX-License-Identifier: MIT -->
<!-- The frame: navigation between mail, calendar, contacts and files (by the URL's fragment) – those the account has –,
     the account (#/account), the administration (#/admin), and the views. -->
<script lang="ts">
  import { LoginClient } from "@kernoid/sdk";

  import { message, provideJmap } from "./app.svelte.js";
  import { t } from "./i18n.js";
  import { FILENODE, type Jmap, MAIL } from "./jmap.js";
  import MailNotifications from "./mail/MailNotifications.svelte";
  import MailView from "./mail/MailView.svelte";
  import CalendarView from "./calendar/CalendarView.svelte";
  import ContactsView from "./contacts/ContactsView.svelte";
  import FilesView from "./files/FilesView.svelte";
  import AccountView from "./account/AccountView.svelte";
  import AdminView from "./admin/AdminView.svelte";
  import { THEMES, setTheme, theme } from "./theme.svelte.js";

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

  function nextTheme(): void {
    setTheme(THEMES[(THEMES.indexOf(theme()) + 1) % THEMES.length] ?? "system");
  }

  const links: [Section, string][] = [
    ["mail", "Mail"],
    ["calendar", "Calendar"],
    ["contacts", "Contacts"],
    ["files", "Files"],
  ];
</script>
<div class="shell">
  <header class="bar">
    <span class="brand" aria-label="kernoid">kern<b>0</b><i>id</i></span>
    <nav bind:this={sectionBar}>
      {#each links as [name, label] (name)}
        {#if available.includes(name)}
          <a href={`#/${name}`} class:active={current === name}>{t(label)}</a>
        {/if}
      {/each}
      {#if admin}
        <a href="#/admin" class:active={current === "admin"}>{t("Administration")}</a>
      {/if}
    </nav>
    <span class="who">
      <button type="button" class="quiet" title={t("Theme")} onclick={nextTheme}>
        {t(theme() === "system" ? "System" : theme() === "light" ? "Light" : "Dark")}
      </button>
      <a href="#/account" class:active={current === "account"}>{jmap.session.username}</a>
      <button type="button" class="quiet" onclick={() => void logout()}>{t("Log out")}</button>
    </span>
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
</div>
