<!-- SPDX-License-Identifier: MIT -->
<!-- Copies or moves a node to a folder of another store the user may add to – or moves it within its own. -->
<script lang="ts">
  import { emptyText, resource, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import { type FileNode, children, copyTo, isDirectory, move, sortNodes, stores } from "./model.js";

  let {
    account,
    node,
    mayMove,
    onclose,
  }: { account: string; node: FileNode; mayMove: boolean; onclose: (done: boolean) => void } = $props();

  const jmap = useJmap();
  const targets = stores(jmap);
  // svelte-ignore state_referenced_locally
  let target = $state(account);
  // The folders from the top of the target down to where the copy goes.
  let trail = $state<FileNode[]>([]);
  let moveIt = $state(false);
  let error = $state<unknown>();
  let busy = $state(false);
  const parent = $derived(trail[trail.length - 1]?.id ?? null);
  const sameStore = $derived(target === account);
  const folders = resource(
    () => ({ account: target, parent }),
    ({ account: store, parent: folder }) =>
      children(jmap, store, folder).then((nodes) =>
        sortNodes(
          nodes.filter((entry) => isDirectory(entry) && !entry.role && entry.id !== node.id),
          locale,
        ),
      ),
  );
  const storeOf = (id: string) => targets.find((entry) => entry.id === id);
  const mayAddHere = $derived.by(() => {
    const folder = trail[trail.length - 1];
    return folder ? (folder.myRights?.mayAddChildren ?? false) : (storeOf(target)?.mayCreateTopLevel ?? false);
  });

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    error = undefined;
    try {
      if (sameStore) await move(jmap, account, node, parent);
      else await copyTo(jmap, account, target, node, parent, moveIt);
      onclose(true);
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
    }
  }
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={t("Copy or move")}>
  <form class="dialog" onsubmit={(event) => void submit(event)}>
    <h2>„{node.name}“</h2>
    <label>
      <span>{t("Copy to")}</span>
      <select bind:value={target} onchange={() => (trail = [])}>
        {#each targets as entry (entry.id)}
          <option value={entry.id}>{entry.kind === "own" ? t("My files") : entry.name}</option>
        {/each}
      </select>
    </label>
    <div class="crumbs">
      <button type="button" class="quiet" onclick={() => (trail = [])}>
        {storeOf(target)?.kind === "own" ? t("My files") : storeOf(target)?.name}
      </button>
      {#each trail as folder, index (folder.id)}
        /
        <button type="button" class="quiet" onclick={() => (trail = trail.slice(0, index + 1))}>{folder.name}</button>
      {/each}
    </div>
    <ul class="folders">
      {#each folders.value ?? [] as folder (folder.id)}
        <li>
          <button type="button" class="quiet" onclick={() => (trail = [...trail, folder])}>📁 {folder.name}</button>
        </li>
      {:else}
        <li class="muted small">{emptyText(folders, t("No folders here"))}</li>
      {/each}
    </ul>
    {#if sameStore}
      <p class="muted small">{t("Within the same store it is moved.")}</p>
    {:else}
      <label class="inline">
        <input type="checkbox" bind:checked={moveIt} disabled={!mayMove} />
        <span>{t("Move instead of copy (removed here)")}</span>
      </label>
    {/if}
    <Failure error={error ?? folders.error} />
    <div class="actions end">
      <button type="button" onclick={() => onclose(false)}>{t("Cancel")}</button>
      <button type="submit" class="primary" disabled={busy || !mayAddHere || (sameStore && !mayMove)}>
        {sameStore || moveIt ? t("Move here") : t("Copy here")}
      </button>
    </div>
  </form>
</div>
