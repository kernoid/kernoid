<!-- SPDX-License-Identifier: MIT -->
<!-- A file's current content and its earlier versions, each to download; an earlier one can become current again. -->
<script lang="ts">
  import { loaded, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import { type FileNode, downloadPath, formatSize, restore, versions } from "./model.js";

  let {
    account,
    node,
    mayRestore,
    onclose,
  }: { account: string; node: FileNode; mayRestore: boolean; onclose: (restored: boolean) => void } = $props();

  const jmap = useJmap();
  const list = loaded(() => versions(jmap, account, node));
  let error = $state<unknown>();
  const when = (date: string) => new Date(date).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={t("Versions")}>
  <div class="dialog">
    <h2>{t("Versions")} „{node.name}“</h2>
    <table class="nodes">
      <tbody>
        {#each list.value ?? [] as version (version.id)}
          <tr>
            <td class="name">
              <a href={downloadPath(jmap, account, version.blobId, node.name, node.mediaType)} download={node.name}>
                {when(version.modified)}
              </a>
              {#if version.isCurrent}
                <span class="muted small"> · {t("Current")}</span>
              {/if}
            </td>
            <td class="muted small">{formatSize(version.size, locale)}</td>
            <td class="end">
              {#if !version.isCurrent && mayRestore}
                <button
                  type="button"
                  class="quiet"
                  onclick={() =>
                    void restore(jmap, account, node, version)
                      .then(() => onclose(true))
                      .catch((failure: unknown) => (error = failure))}
                >
                  {t("Restore")}
                </button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <Failure error={error ?? list.error} />
    <div class="actions end">
      <button type="button" class="primary" onclick={() => onclose(false)}>{t("Close")}</button>
    </div>
  </div>
</div>
