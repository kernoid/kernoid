<!-- SPDX-License-Identifier: MIT -->
<!-- The audit log: what happened in the tenant – or the instance – and who did it, newest first, from kernoid's events.
     `#/admin/audit/<type>:<id>` shows one object's history (an account's, a group's …). -->
<script lang="ts">
  import { message, resource } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { type Schema, admin, need } from "./api.svelte.js";
  import { Action, useDirectory, when } from "./ui.svelte.js";
  import Head from "./ui/Head.svelte";
  import Outcome from "./ui/Outcome.svelte";

  type Entry = Schema<"AuditEntryView">;

  const TYPES = ["account", "group", "tenant", "session", "project", "authorization", "application", "identity_provider", "instance", "signing_keys"];
  const PAGE = 50;

  let { object: initial, instance }: { object: string | undefined; instance: boolean } = $props();

  const directory = useDirectory();
  const action = new Action();
  let scope = $state<"tenant" | "instance">("tenant");
  // svelte-ignore state_referenced_locally
  let type = $state(initial?.split(":")[0] ?? "");
  // svelte-ignore state_referenced_locally
  let object = $state(initial?.split(":").slice(1).join(":") ?? "");
  let older = $state<Entry[]>([]);
  let more = $state(true);
  let open = $state<number>();

  function query(before?: number): Promise<Entry[]> {
    return need(
      admin.GET("/v1/audit", {
        params: {
          query: {
            scope,
            limit: PAGE,
            ...(type ? { aggregate_type: type } : {}),
            ...(type && object ? { aggregate_id: object } : {}),
            ...(before !== undefined ? { before } : {}),
          },
        },
      }),
    );
  }
  const first = resource(
    () => ({ scope, type, object }),
    async () => {
      older = [];
      const page = await query();
      more = page.length === PAGE;
      return page;
    },
  );
  const entries = $derived([...(first.error ? [] : (first.value ?? [])), ...older]);
  const loadOlder = () =>
    void action.run(async () => {
      const last = entries.at(-1);
      const page = await query(last?.position);
      older = [...older, ...page];
      more = page.length === PAGE;
    });

  /** Whose: an account's address, a group's name – else the id. */
  const subject = (entry: Entry) =>
    entry.aggregate_type === "account" || entry.aggregate_type === "group" ? directory.name(entry.aggregate_type, entry.aggregate_id) : entry.aggregate_id;
  /** `account:<id>` as the account's address; `system`, `operator` and the like as they are. */
  const who = (creator: string) => (creator.startsWith("account:") ? directory.name("account", creator.slice("account:".length)) : creator);
</script>

<Head title={t("Audit log")} description={t("What happened and who did it – from kernoid's events, newest first. Passwords and other secrets never appear here.")} />
<div class="row filters">
  {#if instance}
    <select aria-label={t("Scope")} onchange={(event) => (scope = event.currentTarget.value as "tenant" | "instance")}>
      <option value="tenant">{t("Tenant")}</option>
      <option value="instance">{t("Instance")}</option>
    </select>
  {/if}
  <select
    aria-label={t("Kind")}
    onchange={(event) => {
      type = event.currentTarget.value;
      object = "";
    }}
  >
    <option value="">{t("everything")}</option>
    {#each TYPES as name (name)}
      <option value={name} selected={type === name}>{name}</option>
    {/each}
  </select>
  {#if object}
    <span class="chip">
      {type === "account" || type === "group" ? directory.name(type, object) : object}
      <button type="button" class="quiet" aria-label={t("Remove")} onclick={() => (object = "")}>×</button>
    </span>
  {/if}
</div>
<Outcome {action} />
{#if first.error}
  <p class="error">{message(first.error)}</p>
{/if}
<table class="nodes audit">
  <tbody>
    {#each entries as entry (entry.position)}
      <tr>
        <td class="small muted nowrap">{when(entry.created_at)}</td>
        <td class="name">
          <button type="button" class="quiet file" onclick={() => (open = open === entry.position ? undefined : entry.position)}>
            <code>{entry.event_type}</code>
          </button>
          <div class="small muted">
            {entry.aggregate_type} ·
            <button
              type="button"
              class="quiet link"
              onclick={() => {
                type = entry.aggregate_type;
                object = entry.aggregate_id;
              }}
            >
              {subject(entry)}
            </button>
          </div>
        </td>
        <td class="small">{who(entry.creator)}</td>
      </tr>
      {#if open === entry.position}
        <tr>
          <td colspan="3">
            <pre class="payload">{JSON.stringify(entry.payload, null, 2)}</pre>
          </td>
        </tr>
      {/if}
    {:else}
      <tr><td class="muted">{first.loading ? t("Loading") : t("Nothing here")}</td></tr>
    {/each}
  </tbody>
</table>
{#if more && entries.length > 0}
  <div class="actions">
    <button type="button" disabled={action.busy} onclick={loadOlder}>{t("Load older")}</button>
  </div>
{/if}
