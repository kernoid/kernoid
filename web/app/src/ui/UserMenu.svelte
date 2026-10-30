<!-- SPDX-License-Identifier: MIT -->
<!-- The account's menu behind its avatar: who is logged in, the account, the administration, appearance (theme and
     density) and logging out. Escape or a click elsewhere closes it. -->
<script lang="ts">
  import { LogOut, Monitor, Moon, Rows3, Rows4, Shield, Sun, UserRound } from "@lucide/svelte";

  import { type Density, density, setDensity } from "../density.svelte.js";
  import { t } from "../i18n.js";
  import { type Theme, setTheme, theme } from "../theme.svelte.js";
  import Avatar from "./Avatar.svelte";

  let {
    name,
    address,
    avatar,
    admin,
    onlogout,
  }: { name: string; address: string; avatar?: string | undefined; admin: boolean; onlogout: () => void } = $props();

  let open = $state(false);
  let root = $state<HTMLElement>();

  const themes: [Theme, string, typeof Sun][] = [
    ["light", "Light", Sun],
    ["dark", "Dark", Moon],
    ["system", "System", Monitor],
  ];
  const densities: [Density, string, typeof Sun][] = [
    ["comfortable", "Comfortable", Rows3],
    ["compact", "Compact", Rows4],
  ];
</script>

<svelte:window
  onpointerdown={(event) => open && root && !root.contains(event.target as Node) && (open = false)}
  onkeydown={(event) => event.key === "Escape" && (open = false)}
  onhashchange={() => (open = false)}
/>

<div class="user-menu" bind:this={root}>
  <button
    type="button"
    class="avatar-button"
    aria-haspopup="menu"
    aria-expanded={open}
    aria-label={t("Account menu")}
    data-tip={address}
    onclick={() => (open = !open)}
  >
    <Avatar {name} {address} src={avatar} size={32} />
  </button>
  {#if open}
    <div class="menu" role="menu">
      <div class="menu-who">
        <Avatar {name} {address} src={avatar} size={44} />
        <span>
          <strong>{name}</strong>
          <small class="muted">{address}</small>
        </span>
      </div>
      <a role="menuitem" href="#/account"><UserRound size={18} />{t("Your account")}</a>
      {#if admin}
        <a role="menuitem" href="#/admin"><Shield size={18} />{t("Administration")}</a>
      {/if}
      <div class="menu-group" role="group" aria-label={t("Theme")}>
        <span class="muted small">{t("Theme")}</span>
        <div class="segmented icons">
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
      </div>
      <div class="menu-group" role="group" aria-label={t("Density")}>
        <span class="muted small">{t("Density")}</span>
        <div class="segmented icons">
          {#each densities as [value, label, Icon] (value)}
            <button
              type="button"
              class:active={density() === value}
              aria-pressed={density() === value}
              aria-label={t(label)}
              data-tip={t(label)}
              onclick={() => setDensity(value)}
            >
              <Icon size={16} />
            </button>
          {/each}
        </div>
      </div>
      <button type="button" role="menuitem" class="menu-item" onclick={onlogout}><LogOut size={18} />{t("Log out")}</button>
    </div>
  {/if}
</div>
