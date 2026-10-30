<!-- SPDX-License-Identifier: MIT -->
<!-- The mailboxes as a tree: choose one; make, rename, move and delete folders of one's own; empty Junk and Trash.
     Emails dragged from the list – and folders dragged within the tree – are dropped onto a folder to move them there,
     a folder also onto "Folders" to move it to the top. -->
<script lang="ts" module>
  /** What the list puts into a drag: the ids of the emails dragged. */
  export const EMAILS = "application/x-kernoid-emails";
  /** What the tree puts into a drag: the id of the folder dragged. */
  export const FOLDER = "application/x-kernoid-mailbox";
</script>

<script lang="ts">
  import { Ellipsis, FolderInput, FolderPlus, Pencil, Plus, Trash2 } from "@lucide/svelte";

  import { useJmap } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import FolderDialog from "./FolderDialog.svelte";
  import {
    type Mailbox,
    createMailbox,
    destroyMailbox,
    emptyMailbox,
    mailboxTree,
    moveMany,
    updateMailbox,
    within,
  } from "./model.js";
  import { boxIcon, boxName } from "./names.js";

  let {
    boxes,
    selected,
    onchoose,
    onchanged,
    onerror,
  }: {
    boxes: Mailbox[];
    selected: string | undefined;
    onchoose: (id: string) => void;
    onchanged: () => void;
    onerror: (failure: unknown) => void;
  } = $props();

  const jmap = useJmap();
  const tree = $derived(mailboxTree(boxes));
  const trash = $derived(boxes.find((box) => box.role === "trash"));

  let menu = $state<string>();
  let over = $state<string | null>();
  let dialog = $state<{ kind: "new"; parent: string | null } | { kind: "rename" | "move"; box: Mailbox }>();

  function act(run: () => Promise<void>): void {
    menu = undefined;
    run().then(onchanged, onerror);
  }

  function remove(box: Mailbox): void {
    const text =
      box.totalEmails > 0
        ? t("Delete the folder {name}? Its {count} emails go to the Trash.", { name: box.name, count: box.totalEmails })
        : t("Delete the folder {name}?", { name: box.name });
    if (window.confirm(text)) act(() => destroyMailbox(jmap, box, trash));
  }

  function empty(box: Mailbox): void {
    const text = t("Delete the {count} emails in {name} for good?", { count: box.totalEmails, name: boxName(box) });
    if (window.confirm(text)) act(() => emptyMailbox(jmap, box.id));
  }

  /** What may be dropped where: emails onto any folder but the one shown; a folder onto one not beneath itself. */
  function accepts(event: DragEvent, target: string | null): boolean {
    const types = event.dataTransfer?.types ?? [];
    if (types.includes(EMAILS)) return target !== null && target !== selected;
    if (types.includes(FOLDER)) return true;
    return false;
  }

  function drop(event: DragEvent, target: string | null): void {
    event.preventDefault();
    over = undefined;
    const data = event.dataTransfer;
    if (!data) return;
    const emails = data.getData(EMAILS);
    const folder = data.getData(FOLDER);
    if (emails && target) {
      act(() => moveMany(jmap, JSON.parse(emails) as string[], target));
    } else if (folder && folder !== target && !within(boxes, target, folder)) {
      act(() => updateMailbox(jmap, folder, { parentId: target }));
    }
  }
</script>

<svelte:window onpointerdown={(event) => menu && !(event.target as Element).closest(".folder-menu, .folder-more") && (menu = undefined)} />

<div class="folders-head" class:over={over === null} role="group" aria-label={t("Folders")}
  ondragover={(event) => {
    if (event.dataTransfer?.types.includes(FOLDER)) {
      event.preventDefault();
      over = null;
    }
  }}
  ondragleave={() => over === null && (over = undefined)}
  ondrop={(event) => drop(event, null)}
>
  <span class="muted small">{t("Folders")}</span>
  <button type="button" class="icon quiet small" aria-label={t("New folder")} data-tip={t("New folder")} onclick={() => (dialog = { kind: "new", parent: null })}>
    <Plus size={16} />
  </button>
</div>
<ul class="boxes tree">
  {#each tree as { box, depth } (box.id)}
    {@const Icon = boxIcon(box)}
    {@const own = !box.role}
    <li
      class:over={over === box.id}
      class:trash={box.role === "trash"}
      class:junk={box.role === "junk"}
      ondragover={(event) => {
        if (accepts(event, box.id)) {
          event.preventDefault();
          over = box.id;
        }
      }}
      ondragleave={() => over === box.id && (over = undefined)}
      ondrop={(event) => drop(event, box.id)}
    >
      <button
        type="button"
        class:active={selected === box.id}
        style:padding-left={`${10 + depth * 16}px`}
        aria-label={box.unreadEmails > 0 ? `${boxName(box)} (${box.unreadEmails})` : boxName(box)}
        draggable={own}
        ondragstart={(event) => {
          event.dataTransfer?.setData(FOLDER, box.id);
          if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
        }}
        onclick={() => onchoose(box.id)}
      >
        <Icon size={18} />
        <span class="label">{boxName(box)}</span>
        {#if box.role === "trash" || box.role === "junk"}
          {#if box.totalEmails > 0}<span class="muted small">{box.totalEmails}</span>{/if}
        {:else if box.unreadEmails > 0}
          <span class="count">{box.unreadEmails}</span>
        {/if}
      </button>
      {#if own || ((box.role === "trash" || box.role === "junk") && box.totalEmails > 0)}
        <button
          type="button"
          class="icon quiet small folder-more"
          aria-label={t("More for {name}", { name: boxName(box) })}
          aria-haspopup="menu"
          aria-expanded={menu === box.id}
          onclick={() => (menu = menu === box.id ? undefined : box.id)}
        >
          <Ellipsis size={16} />
        </button>
      {/if}
      {#if menu === box.id}
        <div class="menu folder-menu" role="menu">
          {#if own}
            <button type="button" role="menuitem" class="menu-item" onclick={() => ((menu = undefined), (dialog = { kind: "new", parent: box.id }))}>
              <FolderPlus size={17} />{t("New subfolder")}
            </button>
            <button type="button" role="menuitem" class="menu-item" onclick={() => ((menu = undefined), (dialog = { kind: "rename", box }))}>
              <Pencil size={17} />{t("Rename")}
            </button>
            <button type="button" role="menuitem" class="menu-item" onclick={() => ((menu = undefined), (dialog = { kind: "move", box }))}>
              <FolderInput size={17} />{t("Move")}
            </button>
            <button type="button" role="menuitem" class="menu-item danger" onclick={() => remove(box)}>
              <Trash2 size={17} />{t("Delete")}
            </button>
          {:else}
            <button type="button" role="menuitem" class="menu-item danger" onclick={() => empty(box)}>
              <Trash2 size={17} />{box.role === "trash" ? t("Empty the Trash") : t("Empty Junk")}
            </button>
          {/if}
        </div>
      {/if}
    </li>
  {/each}
</ul>

{#if dialog?.kind === "new"}
  <FolderDialog
    title={t("New folder")}
    {boxes}
    parent={dialog.parent}
    label={t("Create")}
    save={(name, parent) => createMailbox(jmap, name, parent).then(onchanged)}
    onclose={() => (dialog = undefined)}
  />
{:else if dialog}
  {@const box = dialog.box}
  <FolderDialog
    title={dialog.kind === "rename" ? t("Rename folder") : t("Move folder")}
    {boxes}
    {box}
    label={t("Save")}
    save={(name, parent) => updateMailbox(jmap, box.id, { name, parentId: parent }).then(onchanged)}
    onclose={() => (dialog = undefined)}
  />
{/if}
