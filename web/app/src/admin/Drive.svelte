<!-- SPDX-License-Identifier: MIT -->
<!-- One team folder: its usage and quota, who may do what in it, and granting access. -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type DriveView, type FilesOverviewView, admin, need } from "./api.svelte.js";
  import Grants, { FILE_LEVELS as LEVELS } from "./Grants.svelte";
  import Buttons from "./ui/Buttons.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import Form from "./ui/Form.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import PrincipalSelect from "./ui/PrincipalSelect.svelte";
  import Select from "./ui/Select.svelte";
  import { Action, bytes, parseBytes, principal } from "./ui.svelte.js";

  let { drive }: { drive: DriveView } = $props();

  const action = new Action();
  const id = () => drive.id;
  const grants = loaded(() => need(admin.GET("/v1/accounts/{id}/files/access", { params: { path: { id: id() } } })));
  const overview = loaded(() =>
    need(admin.GET("/v1/accounts/{id}/files", { params: { path: { id: id() } } })).catch((): FilesOverviewView | undefined => undefined),
  );
  const shown = $derived(overview.error ? undefined : overview.value);
  let granting = $state(false);
</script>

<section>
  <div class="toolbar">
    <h2 class="grow">{drive.name}</h2>
    <span class="muted small">{shown ? t("{used} of {limit}", { used: bytes(shown.used_bytes), limit: bytes(shown.effective_quota) }) : ""}</span>
    <button
      type="button"
      class="quiet"
      disabled={action.busy}
      onclick={() => {
        const text = window.prompt(t("Quota (e.g. 50 GB; empty: the tenant's default)"), shown?.quota != null ? bytes(shown.quota) : "");
        if (text !== null)
          void action
            .run(
              () => need(admin.PUT("/v1/accounts/{id}/files/quota", { params: { path: { id: id() } }, body: { bytes: parseBytes(text) } })),
              t("Saved."),
            )
            .then(() => overview.refetch());
      }}
    >
      {t("Quota")}
    </button>
    <button type="button" onclick={() => (granting = true)}>{t("Grant access")}</button>
  </div>
  <Outcome {action} />
  <Grants
    grants={grants.error ? [] : (grants.value ?? [])}
    where={(grant) => (grant.node ? t("a folder") : t("everything"))}
    busy={action.busy}
    remove={(grant) =>
      void action
        .run(() =>
          need(
            admin.DELETE("/v1/accounts/{id}/files/access", {
              params: {
                path: { id: id() },
                query: { grantee_kind: grant.grantee_kind, grantee_id: grant.grantee_id, node: grant.node ?? null },
              },
            }),
          ),
        )
        .then(() => grants.refetch())}
  />
  {#if granting}
    <Dialog title={t("Access to {name}", { name: drive.name })} onClose={() => (granting = false)}>
      <Form
        submit={(field) => {
          const [kind, grantee] = principal(field("who"));
          void action
            .run(() =>
              need(
                admin.PUT("/v1/accounts/{id}/files/access", {
                  params: { path: { id: id() } },
                  body: { grantee_kind: kind, grantee_id: grantee, rights: field("rights") },
                }),
              ),
            )
            .then((done) => {
              if (done) {
                granting = false;
                void grants.refetch();
              }
            });
        }}
      >
        <PrincipalSelect name="who" label={t("Who")} />
        <Select label={t("May")} name="rights" value="rnadw" options={LEVELS.map(([rights, label]) => [rights, t(label)])} />
        <Buttons busy={action.busy} onCancel={() => (granting = false)} label={t("Grant")} />
      </Form>
    </Dialog>
  {/if}
</section>
