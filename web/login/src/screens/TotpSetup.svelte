<!-- SPDX-License-Identifier: MIT -->
<!-- A TOTP secret to scan or type in, confirmed with a first code. -->
<script lang="ts">
  import type { TotpSetup } from "@kernoid/sdk";

  import { t } from "../i18n.js";
  import { client } from "../session.js";
  import Card from "../ui/Card.svelte";
  import Field from "../ui/Field.svelte";
  import Form from "../ui/Form.svelte";

  let { setup, done }: { setup: TotpSetup; done: () => Promise<void> } = $props();
</script>

<Card title={t("Authenticator app")}>
  <p>{t("Scan this code with your authenticator app, open the link on this device, or type in the key:")}</p>
  <img src={setup.qr_code} alt={t("QR code for the authenticator app")} class="qr" width="200" height="200" />
  <p><a href={setup.uri} class="button secondary">{t("Open in authenticator app")}</a></p>
  <p class="secret" aria-label={t("Key")}>{setup.secret.replace(/(.{4})/g, "$1 ").trim()}</p>
  <Form
    label={t("Confirm")}
    submit={async ({ code = "" }) => {
      await client.confirmTotp(code.replace(/\s/g, ""));
      await done();
    }}
  >
    <Field label={t("Code shown by the app")} name="code" inputmode="numeric" autocomplete="one-time-code" pattern={"[0-9]{6}"} required />
  </Form>
</Card>
