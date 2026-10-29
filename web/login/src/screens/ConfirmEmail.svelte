<!-- SPDX-License-Identifier: MIT -->
<!-- The code kernoid sent to the address given when registering; then the new account logs in. -->
<script lang="ts">
  import { t } from "../i18n.js";
  import { client } from "../session.js";
  import Card from "../ui/Card.svelte";
  import Field from "../ui/Field.svelte";
  import Form from "../ui/Form.svelte";
  import Message from "../ui/Message.svelte";

  let { id, email, password, done }: { id: string; email: string; password: string; done: () => Promise<void> } = $props();
</script>

<Card title={t("Confirm your email address")}>
  <Message text={t("We sent a code to {email}.", { email })} kind="info" />
  <Form
    label={t("Create the account")}
    submit={async ({ code = "" }) => {
      await client.confirmRegistration(id, code.replace(/\s/g, ""));
      await client.login(email, password);
      await done();
    }}
  >
    <Field label={t("Code")} name="code" inputmode="numeric" autocomplete="one-time-code" pattern={"[0-9]{8}"} required />
  </Form>
</Card>
