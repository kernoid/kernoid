<!-- SPDX-License-Identifier: MIT -->
<!-- Logging in: the address first – which may belong to an identity provider – then the password (Password.svelte);
     or a passkey alone, also from the address field's autofill. Then "sign in with …" for the instance's open
     providers, and registering where it is possible. -->
<script lang="ts">
  import type { RegistrationOptions } from "@kernoid/sdk";

  import { type LoginOptions, offerPasskeys, stopAutofill } from "../factors.js";
  import { t } from "../i18n.js";
  import { show } from "../screen.svelte.js";
  import { client } from "../session.js";
  import Action from "../ui/Action.svelte";
  import Card from "../ui/Card.svelte";
  import Field from "../ui/Field.svelte";
  import Form from "../ui/Form.svelte";
  import Message from "../ui/Message.svelte";
  import Password from "./Password.svelte";

  let { done, options = {} }: { done: () => Promise<void>; options?: LoginOptions } = $props();

  let failure = $state<string>();
  let providers = $state<{ id: string; name: string }[]>([]);
  let registration = $state<RegistrationOptions>();
  const registers = $derived(Boolean(registration?.by_email && (registration.open || registration.domains.length > 0)));

  $effect(() => {
    void offerPasskeys(done, (text) => (failure = text));
    void Promise.all([client.loginProviders().catch(() => []), client.registrationOptions().catch(() => undefined)]).then(([found, offered]) => {
      providers = found;
      registration = offered;
    });
    return stopAutofill;
  });

  async function next({ address = "" }: Record<string, string>): Promise<void> {
    stopAutofill();
    const trimmed = address.trim();
    const found = await client.loginOptions(trimmed);
    if (found.identity_provider) {
      const start = { loginHint: trimmed, ...(options.authRequest ? { authRequest: options.authRequest } : {}) };
      window.location.assign(await client.startIdpLogin(found.identity_provider.id, start));
      return;
    }
    show(Password, { address: trimmed, done, options });
  }
</script>

<Card title={t("Log in")}>
  {#if options.notice}
    <Message text={options.notice} kind="info" />
  {/if}
  <Form label={t("Continue")} submit={next}>
    <Field label={t("Email address or username")} name="address" autocomplete="username webauthn" required value={options.address} spellcheck="false" />
  </Form>
  <div class="status">
    {#if failure}
      <Message text={failure} />
    {/if}
  </div>
  <p class="or">{t("or")}</p>
  <Action
    label={t("Log in with a passkey")}
    run={async () => {
      stopAutofill();
      await client.loginWithPasskey();
      await done();
    }}
  />
  {#if providers.length > 0 || registers}
    <div class="others">
      {#each providers as provider (provider.id)}
        <Action
          label={t("Continue with {provider}", { provider: provider.name })}
          run={async () => {
            stopAutofill();
            window.location.assign(await client.startIdpLogin(provider.id, options.authRequest ? { authRequest: options.authRequest } : {}));
          }}
        />
      {/each}
      {#if registers}
        <p class="muted"><a href="/login/register">{t("Create an account")}</a></p>
      {/if}
    </div>
  {/if}
  {#if options.cancel}
    <Action label={t("Cancel")} run={options.cancel} kind="link" />
  {/if}
</Card>
