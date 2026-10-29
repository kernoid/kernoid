<!-- SPDX-License-Identifier: MIT -->
<!-- Registering (RFC 0003): a name, an email address and a password – where the instance offers it, an address of
     one's own on one of its domains (a mailbox) or a username – then the code kernoid sends (ConfirmEmail.svelte). -->
<script lang="ts">
  import type { RegistrationOptions } from "@kernoid/sdk";

  import { t } from "../i18n.js";
  import { show } from "../screen.svelte.js";
  import { client } from "../session.js";
  import Action from "../ui/Action.svelte";
  import Card from "../ui/Card.svelte";
  import Field from "../ui/Field.svelte";
  import Form from "../ui/Form.svelte";
  import Message from "../ui/Message.svelte";
  import ConfirmEmail from "./ConfirmEmail.svelte";

  let {
    options,
    providers,
    done,
  }: { options: RegistrationOptions; providers: { id: string; name: string }[]; done: () => Promise<void> } = $props();

  const possible = $derived(options.by_email && (options.open || options.domains.length > 0));

  async function register(values: Record<string, string>): Promise<void> {
    const nativeAddress = values.local ? `${values.local.trim()}@${values.domain ?? options.domains[0]}` : undefined;
    const email = (values.email ?? "").trim();
    const password = values.password ?? "";
    const id = await client.register({
      email,
      password,
      displayName: (values.name ?? "").trim(),
      ...(nativeAddress ? { nativeAddress } : {}),
      ...(values.username ? { username: values.username.trim() } : {}),
    });
    show(ConfirmEmail, { id, email, password, done });
  }
</script>

<Card title={t("Create an account")}>
  {#if possible}
    <Form label={t("Continue")} submit={register}>
      <Field label={t("Name")} name="name" autocomplete="name" required />
      <Field label={t("Email address")} name="email" type="email" autocomplete="email" required />
      <Field label={t("Password")} name="password" type="password" autocomplete="new-password" required minlength={12} />
      {#if options.domains.length > 0}
        <!-- An address of one's own – a mailbox; optional where people may register without one. -->
        <label for="f-local">
          <span>{options.open ? t("Your own address (optional)") : t("Your own address")}</span>
          <div class="address">
            <input id="f-local" name="local" autocomplete="off" required={!options.open} />
            {#if options.domains.length === 1}
              <div class="suffix">@{options.domains[0]}</div>
            {:else}
              <select name="domain">
                {#each options.domains as name (name)}
                  <option value={name}>@{name}</option>
                {/each}
              </select>
            {/if}
          </div>
        </label>
      {/if}
      {#if options.usernames}
        <Field label={t("Username (optional)")} name="username" autocomplete="username" />
      {/if}
    </Form>
    {#if providers.length > 0}
      <p class="or">{t("or")}</p>
    {/if}
  {:else if providers.length === 0}
    <Message text={t("Registering is not possible here.")} kind="info" />
  {/if}
  {#each providers as provider (provider.id)}
    <Action
      label={t("Continue with {provider}", { provider: provider.name })}
      run={async () => window.location.assign(await client.startIdpLogin(provider.id))}
    />
  {/each}
  <Action label={t("Back to logging in")} run={async () => window.location.assign("/login/account")} kind="link" />
</Card>
