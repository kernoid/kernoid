<!-- SPDX-License-Identifier: MIT -->
<!-- A recovery code instead of a second factor. -->
<script lang="ts">
  import { t } from "../i18n.js";
  import { client } from "../session.js";
  import Action from "../ui/Action.svelte";
  import Card from "../ui/Card.svelte";
  import Field from "../ui/Field.svelte";
  import Form from "../ui/Form.svelte";

  let { done, back }: { done: () => Promise<void>; back: () => Promise<void> } = $props();
</script>

<Card title={t("Use a recovery code")}>
  <Form
    label={t("Continue")}
    submit={async ({ code = "" }) => {
      await client.checkRecoveryCode(code.trim());
      await done();
    }}
  >
    <Field label={t("Recovery code")} name="code" autocomplete="off" required spellcheck="false" />
  </Form>
  <Action label={t("Back")} run={back} kind="link" />
</Card>
