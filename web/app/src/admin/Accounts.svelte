<!-- SPDX-License-Identifier: MIT -->
<!-- The tenant's accounts: people with an address of the tenant, external accounts (logins only), shared mailboxes –
     and one account in detail (Account.svelte): name, state, addresses, logins, password and second factors, services,
     quotas, who may use its mail and files, sessions, applications and linked providers. -->
<script lang="ts">
  import { UserPlus } from "@lucide/svelte";

  import { avatarOfAccount } from "../avatars.svelte.js";
  import { t } from "../i18n.js";
  import Avatar from "../ui/Avatar.svelte";
  import Account, { kindOf } from "./Account.svelte";
  import { admin, need } from "./api.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import { Action, go, useDirectory } from "./ui.svelte.js";

  let { id }: { id: string | undefined } = $props();

  const directory = useDirectory();
  const action = new Action();
  let search = $state("");
  let creating = $state<"person" | "external" | "shared">();
  const shown = $derived.by(() => {
    const text = search.trim().toLowerCase();
    return directory.accounts
      .filter((account) => !text || `${account.display_name} ${account.address}`.toLowerCase().includes(text))
      .sort((a, b) => a.display_name.localeCompare(b.display_name));
  });
  const create = (made: () => Promise<{ id: string }>) =>
    void action.run(async () => {
      const { id: created } = await made();
      creating = undefined;
      directory.reload();
      go("accounts", created);
    });
</script>

{#if id}
  {#key id}
    <Account {id} />
  {/key}
{:else}
  <Head title={t("Accounts")}>
    <button type="button" class="primary" onclick={() => (creating = "person")}><UserPlus size={17} />{t("New account")}</button>
    <button type="button" onclick={() => (creating = "shared")}>{t("New shared mailbox")}</button>
    <button type="button" onclick={() => (creating = "external")}>{t("New external account")}</button>
  </Head>
  <Outcome {action} />
  <input type="search" class="filter" placeholder={t("Search")} bind:value={search} />
  <table class="nodes">
    <tbody>
      {#each shown as account (account.id)}
        <tr>
          <td class="name">
            <button type="button" class="quiet person" onclick={() => go("accounts", account.id)}>
              <Avatar name={account.display_name} address={account.address} src={avatarOfAccount(account.id)} size={34} />
              <span>
                <span class="who">{account.display_name}</span>
                <span class="small muted">{account.address}</span>
              </span>
            </button>
          </td>
          <td class="muted small">{kindOf(account)}</td>
          <td class="small">
            {#if !account.active}<span class="warn">{t("inactive")}</span>{/if}
          </td>
        </tr>
      {:else}
        <tr><td class="muted">{directory.loading ? t("Loading") : t("No accounts.")}</td></tr>
      {/each}
    </tbody>
  </table>

  {#if creating === "person"}
    <Dialog title={t("New account")} onClose={() => (creating = undefined)}>
      <Form
        submit={(field) =>
          create(() =>
            need(admin.POST("/v1/accounts", { body: { address: field("address"), display_name: field("name"), password: field("password") || null } })),
          )}
      >
        <Field
          label={t("Address")}
          name="address"
          type="email"
          required
          placeholder="name@example.org"
          hint={t("on a verified domain of the tenant; it is also the login name")}
        />
        <Field label={t("Name")} name="name" required />
        <Field
          label={t("Password")}
          name="password"
          type="password"
          autocomplete="new-password"
          minlength={12}
          hint={t("optional; at least 12 characters")}
        />
        <Buttons busy={action.busy} onCancel={() => (creating = undefined)} label={t("Create")} />
      </Form>
    </Dialog>
  {:else if creating === "shared"}
    <Dialog title={t("New shared mailbox")} onClose={() => (creating = undefined)}>
      <p class="muted">{t("An address such as info@ or support@ that people use through access you grant; nobody logs in as it.")}</p>
      <Form
        submit={(field) =>
          create(() => need(admin.POST("/v1/shared-mailboxes", { body: { address: field("address"), display_name: field("name") } })))}
      >
        <Field label={t("Address")} name="address" type="email" required placeholder="info@example.org" />
        <Field label={t("Name")} name="name" required />
        <Buttons busy={action.busy} onCancel={() => (creating = undefined)} label={t("Create")} />
      </Form>
    </Dialog>
  {:else if creating === "external"}
    <Dialog title={t("New external account")} onClose={() => (creating = undefined)}>
      <p class="muted">{t("For logins only – and files, if granted: no address of the tenant, no mailbox.")}</p>
      <Form
        submit={(field) =>
          create(() =>
            need(
              admin.POST("/v1/external-accounts", {
                body: { display_name: field("name"), email: field("email") || null, username: field("username") || null },
              }),
            ),
          )}
      >
        <Field label={t("Name")} name="name" required />
        <Field label={t("Contact address")} name="email" type="email" />
        <Field label={t("Username")} name="username" />
        <Buttons busy={action.busy} onCancel={() => (creating = undefined)} label={t("Create")} />
      </Form>
    </Dialog>
  {/if}
{/if}
