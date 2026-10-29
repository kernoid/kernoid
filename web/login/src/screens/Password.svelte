<!-- SPDX-License-Identifier: MIT -->
<!-- The password for an address. -->
<script lang="ts">
  import type { LoginOptions } from "../factors.js";
  import { t } from "../i18n.js";
  import { show } from "../screen.svelte.js";
  import { client, deviceToken, rememberDevice } from "../session.js";
  import Action from "../ui/Action.svelte";
  import Card from "../ui/Card.svelte";
  import Field from "../ui/Field.svelte";
  import Form from "../ui/Form.svelte";
  import Login from "./Login.svelte";

  let { address, done, options = {} }: { address: string; done: () => Promise<void>; options?: LoginOptions } = $props();

  async function login({ password = "" }: Record<string, string>): Promise<void> {
    const session = await client.login(address, password, undefined, deviceToken(address));
    rememberDevice(address, session.device_token);
    await done();
  }
</script>

<Card title={t("Log in")}>
  <p class="muted">{address}</p>
  <Form label={t("Log in")} submit={login}>
    <input type="hidden" name="address" value={address} autocomplete="username" />
    <Field label={t("Password")} name="password" type="password" autocomplete="current-password" required />
  </Form>
  <Action label={t("Use another address")} run={async () => show(Login, { done, options: { ...options, address } })} />
</Card>
