<!-- SPDX-License-Identifier: MIT -->
<!-- Choosing an account or a group of the tenant: `account:<id>` or `group:<id>`. -->
<script lang="ts">
  import { t } from "../../i18n.js";
  import { useDirectory } from "../ui.svelte.js";

  let { name, label, groups = true, optional = false }: { name: string; label: string; groups?: boolean; optional?: boolean } = $props();

  const directory = useDirectory();
</script>

<label>
  <span>{label}</span>
  <select {name} required={!optional}>
    <option value="">{optional ? t("nobody yet") : t("Choose …")}</option>
    <optgroup label={t("Accounts")}>
      {#each directory.accounts as account (account.id)}
        <option value={`account:${account.id}`}>{`${account.display_name} <${account.address}>`}</option>
      {/each}
    </optgroup>
    {#if groups}
      <optgroup label={t("Groups")}>
        {#each directory.groups as group (group.id)}
          <option value={`group:${group.id}`}>{group.name}</option>
        {/each}
      </optgroup>
    {/if}
  </select>
</label>
