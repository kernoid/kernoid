<!-- SPDX-License-Identifier: MIT -->
<!-- An account's Sieve scripts (RFC 5228): which runs when mail arrives, each to read, change, switch on or remove –
     kernoid checks that a script compiles before it keeps it. The vacation response is the account's own (account page). -->
<script lang="ts">
  import { emptyText, loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type Schema, admin, need } from "./api.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Check from "./ui/Check.svelte";
  import Field from "./ui/Field.svelte";
  import Form from "./ui/Form.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import { Action } from "./ui.svelte.js";

  type Script = Schema<"SieveScriptView">;

  const EXAMPLE = `require ["fileinto"];
if header :contains "list-id" "newsletter" {
  fileinto "Newsletter";
}`;

  let { account }: { account: string } = $props();

  const action = new Action();
  const scripts = loaded(() =>
    need(admin.GET("/v1/accounts/{id}/mail/sieve", { params: { path: { id: account } } })).catch((): Script[] => []),
  );
  // The script being written: a new one, or one of the list by its name.
  let editing = $state<Script>();
  const list = $derived(scripts.error ? [] : (scripts.value ?? []));
  const run = (work: () => Promise<unknown>, done: string) =>
    void action.run(work, done).then((worked) => {
      if (worked) void scripts.refetch();
    });
</script>

<section>
  <h2>{t("Filters (Sieve)")}</h2>
  <p class="muted">{t("What happens to mail when it arrives: one script runs at a time.")}</p>
  <Outcome {action} />
  <ul class="rows">
    {#each list as script (script.name)}
      <li>
        <span class="grow">
          <code>{script.name}</code>
          {#if script.active}
            <span class="badge">{t("runs")}</span>
          {/if}
        </span>
        <button type="button" class="quiet" onclick={() => (editing = script)}>{t("Edit")}</button>
        <button
          type="button"
          class="quiet"
          disabled={action.busy}
          onclick={() =>
            run(
              () =>
                need(
                  admin.PUT("/v1/accounts/{id}/mail/sieve-active", {
                    params: { path: { id: account } },
                    body: { name: script.active ? null : script.name },
                  }),
                ),
              script.active ? t("No script runs.") : t("The script runs."),
            )}
        >
          {script.active ? t("Stop") : t("Run")}
        </button>
        <button
          type="button"
          class="quiet danger"
          disabled={action.busy}
          onclick={() =>
            window.confirm(t("Delete this?")) &&
            run(
              () => need(admin.DELETE("/v1/accounts/{id}/mail/sieve/{name}", { params: { path: { id: account, name: script.name } } })),
              t("Deleted."),
            )}
        >
          {t("Delete")}
        </button>
      </li>
    {:else}
      <li class="muted">{emptyText(scripts, t("No scripts."))}</li>
    {/each}
  </ul>
  {#if editing}
    {#key editing}
      <Form
        class="stack"
        submit={(field, all) =>
          void action
            .run(
              () =>
                need(
                  admin.PUT("/v1/accounts/{id}/mail/sieve/{name}", {
                    params: { path: { id: account, name: field("name") } },
                    body: { content: field("content"), activate: all("activate").length > 0 },
                  }),
                ),
              t("Saved."),
            )
            .then((worked) => {
              if (worked) {
                editing = undefined;
                void scripts.refetch();
              }
            })}
      >
        <Field label={t("Name")} name="name" required value={editing.name} readonly={editing.name !== ""} pattern="[^/]+" />
        <label>
          <span>{t("Script")}</span>
          <textarea name="content" class="code" rows={12} spellcheck="false" value={editing.content}></textarea>
        </label>
        <Check label={t("Run this script")} name="activate" checked={editing.active} />
        <Buttons busy={action.busy} onCancel={() => (editing = undefined)} />
      </Form>
    {/key}
  {:else}
    <button type="button" onclick={() => (editing = { name: "", content: EXAMPLE, active: false })}>{t("New script")}</button>
  {/if}
</section>
