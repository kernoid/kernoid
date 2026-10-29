<!-- SPDX-License-Identifier: MIT -->
<!-- Grants with whom, where, how much – and a way to remove each. -->
<script lang="ts" module>
  /** What every grant has: mail grants add a mailbox and "send as", file grants a folder. */
  export interface Grant {
    grantee_kind: string;
    grantee_id: string;
    grantee_name?: string | null;
    rights: string;
  }

  /** The levels of access to mail and to files an administrator grants: rights and what they mean. */
  export const MAIL_LEVELS: [string, string][] = [
    ["lrs", "read"],
    ["lrswite", "work in it"],
    ["lrswitekxa", "everything, also share"],
  ];
  export const FILE_LEVELS: [string, string][] = [
    ["r", "view"],
    ["rnadw", "edit"],
    ["randws", "edit and share"],
  ];
</script>

<script lang="ts" generics="G extends Grant">
  import { t } from "../i18n.js";
  import { useDirectory } from "./ui.svelte.js";

  let {
    grants,
    where,
    extra,
    busy,
    remove,
  }: { grants: G[]; where: (grant: G) => string; extra?: ((grant: G) => string) | undefined; busy: boolean; remove: (grant: G) => void } = $props();

  const directory = useDirectory();
</script>

<table class="nodes">
  <tbody>
    {#each grants as grant (`${grant.grantee_kind}:${grant.grantee_id}:${where(grant)}`)}
      <tr>
        <td class="name">
          {grant.grantee_name ?? directory.name(grant.grantee_kind, grant.grantee_id)}
          <span class="muted small"> · {grant.grantee_kind === "group" ? t("Group") : t("Account")}</span>
        </td>
        <td class="small">{where(grant)}</td>
        <td class="small">
          <code>{grant.rights}</code>
          {extra?.(grant)}
        </td>
        <td class="end">
          <button type="button" class="quiet danger" disabled={busy} onclick={() => remove(grant)}>{t("Remove")}</button>
        </td>
      </tr>
    {:else}
      <tr><td class="muted">{t("Nobody else has access.")}</td></tr>
    {/each}
  </tbody>
</table>
