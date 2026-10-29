<!-- SPDX-License-Identifier: MIT -->
<!-- Asking for a second factor the account has: a code from the authenticator app, a passkey, or a recovery code. -->
<script lang="ts">
  import type { SecondFactors } from "@kernoid/sdk";

  import { t } from "../i18n.js";
  import { show } from "../screen.svelte.js";
  import { client } from "../session.js";
  import Action from "../ui/Action.svelte";
  import Card from "../ui/Card.svelte";
  import Field from "../ui/Field.svelte";
  import Form from "../ui/Form.svelte";
  import Message from "../ui/Message.svelte";
  import Recovery from "./Recovery.svelte";

  let { factors, done, back }: { factors: SecondFactors; done: () => Promise<void>; back: () => Promise<void> } = $props();
</script>

<Card title={t("Confirm it is you")}>
  <Message text={t("This login needs a second factor.")} kind="info" />
  {#if factors.totp}
    <Form
      label={t("Continue")}
      submit={async ({ code = "" }) => {
        await client.checkTotp(code.replace(/\s/g, ""));
        await done();
      }}
    >
      <Field label={t("Code from your authenticator app")} name="code" inputmode="numeric" autocomplete="one-time-code" pattern={"[0-9]{6}"} required />
    </Form>
  {/if}
  {#if factors.passkeys > 0}
    <Action
      label={t("Use a passkey")}
      kind={factors.totp ? "secondary" : "primary"}
      run={async () => {
        await client.checkPasskey();
        await done();
      }}
    />
  {/if}
  {#if factors.recovery_codes_left > 0}
    <Action label={t("Use a recovery code")} kind="link" run={async () => show(Recovery, { done, back })} />
  {/if}
</Card>
