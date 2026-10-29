<!-- SPDX-License-Identifier: MIT -->
<!-- Groups: members (accounts of the tenant), and addresses – a group with an address is a distribution list. Groups
     receive roles, access to mail and files, and team folders. -->
<script lang="ts">
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import Group from "./Group.svelte";
  import { Action, useDirectory } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";

  const directory = useDirectory();
  const action = new Action();
  let creating = $state(false);
  const sorted = $derived([...directory.groups].sort((a, b) => a.name.localeCompare(b.name)));

  async function change(work: () => Promise<unknown>, done?: string): Promise<void> {
    if (await action.run(work, done)) directory.reload();
  }
</script>

<Head title={t("Groups")} description={t("Groups gather accounts: for roles, access and team folders – and, with an address, as a distribution list.")}>
  <button type="button" class="primary" onclick={() => (creating = true)}>{t("New group")}</button>
</Head>
<Outcome {action} />
{#each sorted as group (group.id)}
  <Group {group} busy={action.busy} {change} />
{:else}
  <p class="muted">{directory.loading ? t("Loading") : t("No groups yet.")}</p>
{/each}
{#if creating}
  <Dialog title={t("New group")} onClose={() => (creating = false)}>
    <Form
      submit={(field) =>
        void change(async () => {
          await need(admin.POST("/v1/groups", { body: { name: field("name") } }));
          creating = false;
        })}
    >
      <Field label={t("Name")} name="name" required />
      <Buttons busy={action.busy} onCancel={() => (creating = false)} label={t("Create")} />
    </Form>
  </Dialog>
{/if}
