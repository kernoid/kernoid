<!-- SPDX-License-Identifier: MIT -->
<!-- New recovery codes, shown once. -->
<script lang="ts">
  import { t } from "../i18n.js";
  import Action from "../ui/Action.svelte";
  import Card from "../ui/Card.svelte";

  let { codes, done }: { codes: string[]; done: () => Promise<void> } = $props();
</script>

<Card title={t("Recovery codes")}>
  <p>{t("If you lose your devices, each of these codes lets you log in once. Keep them somewhere safe – they are shown only now.")}</p>
  <ol class="codes">
    {#each codes as code (code)}
      <li>{code}</li>
    {/each}
  </ol>
  <Action label={t("I have saved them")} run={done} kind="primary" />
</Card>
