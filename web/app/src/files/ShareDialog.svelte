<!-- SPDX-License-Identifier: MIT -->
<!-- With whom a folder is shared, and at which level: read, edit, or full (which may share on). -->
<script lang="ts">
  import { resource, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { type FileNode, LEVELS, type Principal, type Rights, findPrincipals, level, principals, share } from "./model.js";

  type Level = keyof typeof LEVELS;

  let { account, node, onclose }: { account: string; node: FileNode; onclose: (saved: boolean) => void } = $props();

  const jmap = useJmap();
  let entries = $state<{ principal: Principal; level: Level }[]>([]);
  let search = $state("");
  let error = $state<unknown>();

  $effect(() => {
    const current = node.shareWith ?? {};
    void principals(jmap, Object.keys(current))
      .then(
        (known) =>
          (entries = known.map((principal) => ({ principal, level: level(current[principal.id] ?? LEVELS.read) }))),
      )
      .catch((failure: unknown) => (error = failure));
  });
  const found = resource(
    () => search.trim(),
    (text) => (text.length >= 2 ? findPrincipals(jmap, text) : Promise.resolve([] as Principal[])),
  );

  function add(principal: Principal): void {
    if (!entries.some((entry) => entry.principal.id === principal.id)) entries = [...entries, { principal, level: "read" }];
    search = "";
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const shareWith: Record<string, Rights> = {};
    for (const entry of entries) shareWith[entry.principal.id] = LEVELS[entry.level];
    try {
      await share(jmap, account, node, shareWith);
      onclose(true);
    } catch (failure) {
      error = failure;
    }
  }
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={t("Share")}>
  <form class="dialog" onsubmit={(event) => void save(event)}>
    <h2>{t("Share")} „{node.name}“</h2>
    <ul class="items shares">
      {#each entries as entry, index (entry.principal.id)}
        <li class="row">
          <span class="grow">
            {entry.principal.name}
            <span class="muted small"> {entry.principal.type === "group" ? t("Group") : (entry.principal.email ?? "")}</span>
          </span>
          <select bind:value={entries[index]!.level} aria-label={t("Share")}>
            <option value="read">{t("Can view")}</option>
            <option value="edit">{t("Can edit")}</option>
            <option value="full">{t("Can edit and share")}</option>
          </select>
          <button
            type="button"
            class="quiet danger"
            onclick={() => (entries = entries.filter((_, at) => at !== index))}>{t("Remove")}</button
          >
        </li>
      {/each}
    </ul>
    <label>
      <span>{t("Add people or groups")}</span>
      <input type="search" bind:value={search} placeholder={t("Name or address")} />
    </label>
    <ul class="items">
      {#each (found.value ?? []).filter((principal) => !entries.some((entry) => entry.principal.id === principal.id)) as principal (principal.id)}
        <li>
          <button type="button" onclick={() => add(principal)}>
            <span class="who">{principal.name}</span>
            <span class="preview">{principal.type === "group" ? t("Group") : (principal.email ?? "")}</span>
          </button>
        </li>
      {/each}
    </ul>
    <Failure {error} />
    <div class="actions end">
      <button type="button" class="quiet" onclick={() => onclose(false)}>{t("Cancel")}</button>
      <button type="submit" class="primary">{t("Save")}</button>
    </div>
  </form>
</div>
