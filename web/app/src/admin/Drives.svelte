<!-- SPDX-License-Identifier: MIT -->
<!-- Team folders (drives, RFC 0005): file stores that belong to the tenant, not to a person. Administrators create them
     and decide who may do what in them; people find them in Files. -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import Drive from "./Drive.svelte";
  import { FILE_LEVELS as LEVELS } from "./Grants.svelte";
  import Buttons from "./ui/Buttons.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import PrincipalSelect from "./ui/PrincipalSelect.svelte";
  import Select from "./ui/Select.svelte";
  import { Action, principal } from "./ui.svelte.js";

  const action = new Action();
  const drives = loaded(() => need(admin.GET("/v1/drives")));
  const list = $derived(drives.error ? [] : (drives.value ?? []));
  let creating = $state(false);
</script>

<Head
  title={t("Team folders")}
  description={t("Folders that belong to the tenant, not to a person – like a shared drive. Who may use them is decided here; people find them in Files.")}
>
  <button type="button" class="primary" onclick={() => (creating = true)}>{t("New team folder")}</button>
</Head>
<Outcome {action} />
{#each list as drive (drive.id)}
  <Drive {drive} />
{:else}
  <p class="muted">{emptyText(drives, t("No team folders yet."))}</p>
{/each}
{#if creating}
  <Dialog title={t("New team folder")} onClose={() => (creating = false)}>
    <Form
      submit={(field) => {
        const who = field("who");
        const rights = field("rights");
        void action.run(async () => {
          const made = await need(admin.POST("/v1/drives", { body: { name: field("name") } }));
          if (who) {
            const [kind, id] = principal(who);
            await need(
              admin.PUT("/v1/accounts/{id}/files/access", {
                params: { path: { id: made.id } },
                body: { grantee_kind: kind, grantee_id: id, rights },
              }),
            );
          }
          creating = false;
          await drives.refetch();
        }, t("The team folder is created."));
      }}
    >
      <Field label={t("Name")} name="name" required placeholder={t("e.g. Board, Projects, Office")} />
      <PrincipalSelect name="who" label={t("First access for (e.g. a group)")} optional />
      <Select label={t("May")} name="rights" value="rnadw" options={LEVELS.map(([rights, label]) => [rights, t(label)])} />
      <Buttons busy={action.busy} onCancel={() => (creating = false)} label={t("Create")} />
    </Form>
  </Dialog>
{/if}
