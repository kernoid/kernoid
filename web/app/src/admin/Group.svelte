<!-- SPDX-License-Identifier: MIT -->
<!-- One group on the groups page: renaming and deleting it, its members, its addresses and whether members may send
     as the group. -->
<script lang="ts">
  import { t } from "../i18n.js";
  import { type GroupView, admin, need } from "./api.svelte.js";
  import Form from "./ui/Form.svelte";
  import { useDirectory } from "./ui.svelte.js";

  let { group, busy, change }: { group: GroupView; busy: boolean; change: (work: () => Promise<unknown>, done?: string) => Promise<void> } = $props();

  const directory = useDirectory();
  const id = $derived({ id: group.id });
  const outside = $derived(directory.accounts.filter((account) => !group.members.includes(account.id)));
</script>

<section>
  <div class="toolbar">
    <h2 class="grow">{group.name}</h2>
    <button
      type="button"
      class="quiet"
      disabled={busy}
      onclick={() => {
        const name = window.prompt(t("New name"), group.name)?.trim();
        if (name) void change(() => need(admin.PATCH("/v1/groups/{id}", { params: { path: id }, body: { name } })));
      }}
    >
      {t("Rename")}
    </button>
    <button
      type="button"
      class="quiet danger"
      disabled={busy}
      onclick={() =>
        window.confirm(t("Delete the group {name}?", { name: group.name })) && void change(() => need(admin.DELETE("/v1/groups/{id}", { params: { path: id } })))}
    >
      {t("Delete")}
    </button>
  </div>
  <div class="pair">
    <div>
      <h3>{t("Members")}</h3>
      <ul class="rows">
        {#each group.members as member (member)}
          <li>
            <span class="grow">{directory.name("account", member)}</span>
            <button
              type="button"
              class="quiet danger"
              disabled={busy}
              onclick={() => void change(() => need(admin.DELETE("/v1/groups/{id}/members/{account}", { params: { path: { ...id, account: member } } })))}
            >
              {t("Remove")}
            </button>
          </li>
        {:else}
          <li class="muted">{t("No members.")}</li>
        {/each}
      </ul>
      <Form
        class="row"
        submit={(field) =>
          field("account") && void change(() => need(admin.PUT("/v1/groups/{id}/members/{account}", { params: { path: { ...id, account: field("account") } } })))}
      >
        <select name="account" aria-label={t("Account")}>
          {#each outside as account (account.id)}
            <option value={account.id}>{`${account.display_name} <${account.address}>`}</option>
          {/each}
        </select>
        <button type="submit" disabled={busy || outside.length === 0}>{t("Add")}</button>
      </Form>
    </div>
    <div>
      <h3>{t("Addresses")}</h3>
      <ul class="rows">
        {#each group.addresses as address (address)}
          <li>
            <span class="grow">{address}</span>
            <button
              type="button"
              class="quiet danger"
              disabled={busy}
              onclick={() => void change(() => need(admin.DELETE("/v1/groups/{id}/addresses/{address}", { params: { path: { ...id, address } } })))}
            >
              {t("Remove")}
            </button>
          </li>
        {:else}
          <li class="muted">{t("No address – not a distribution list.")}</li>
        {/each}
      </ul>
      <Form
        class="row"
        submit={(field) => void change(() => need(admin.PUT("/v1/groups/{id}/addresses/{address}", { params: { path: { ...id, address: field("address") } } })))}
      >
        <input name="address" type="email" required placeholder="team@example.org" aria-label={t("Address")} />
        <button type="submit" disabled={busy}>{t("Add")}</button>
      </Form>
      {#if group.addresses.length > 0}
        <label class="inline">
          <input
            type="checkbox"
            checked={group.members_send_as}
            disabled={busy}
            onchange={(event) => {
              const enabled = event.currentTarget.checked;
              void change(() => need(admin.PUT("/v1/groups/{id}/send-as", { params: { path: id }, body: { enabled } })));
            }}
          />
          <span>{t("Members may send as the group")}</span>
        </label>
      {/if}
    </div>
  </div>
</section>
