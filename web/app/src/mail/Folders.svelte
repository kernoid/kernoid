<!-- SPDX-License-Identifier: MIT -->
<!-- The mailboxes of one mail account – one's own, or a shared mailbox – as a tree: choose one; make, rename, move and
     delete folders; empty Junk and Trash.
     Emails dragged from the list – and folders dragged within the tree – are dropped onto a folder to move them there,
     a folder also onto "Folders" to move it to the top. -->
<script lang="ts" module>
  /** What the list puts into a drag: the account and the ids of the emails dragged (`{ account, ids }`). */
  export const EMAILS = "application/x-kernoid-emails";
  /** What the tree puts into a drag: the account and the id of the folder dragged (`account/id`). */
  export const FOLDER = "application/x-kernoid-mailbox";
</script>

<script lang="ts">
  import { Ellipsis, FolderInput, FolderPlus, Pencil, Plus, Trash2, UserRound, UsersRound } from "@lucide/svelte";

  import Dialog from "../admin/ui/Dialog.svelte";

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
    account,
    title,
    address,
    shared = false,
    onrename,
    boxes,
    selected,
    onchoose,
    onchanged,
    onerror,
  }: {
    account: string;
    /** The name the user gave the mailbox, or its address. */
    title: string;
    address: string;
    shared?: boolean;
    /** Gives the mailbox a name of the user's own; empty shows the address again. */
    onrename: (name: string) => Promise<void>;
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
  let naming = $state<string>();
  let namingError = $state<unknown>();

  function act(run: () => Promise<void>): void {
    menu = undefined;
    run().then(onchanged, onerror);
  }

  function remove(box: Mailbox): void {
    const text =
      box.totalEmails > 0
        ? t("Delete the folder {name}? Its {count} emails go to the Trash.", { name: box.name, count: box.totalEmails })
        : t("Delete the folder {name}?", { name: box.name });
    if (window.confirm(text)) act(() => destroyMailbox(jmap, account, box, trash));
  }

  function empty(box: Mailbox): void {
    const text = t("Delete the {count} emails in {name} for good?", { count: box.totalEmails, name: boxName(box) });
    if (window.confirm(text)) act(() => emptyMailbox(jmap, account, box.id));
  }

  /** What may be dropped where: emails onto any folder but the one shown; a folder onto one not beneath itself.
   * Only within this account – the drag's account is known on the drop alone, which then checks it. */
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
    const [from, folder] = data.getData(FOLDER).split("/");
    if (emails && target) {
      const dragged = JSON.parse(emails) as { account: string; ids: string[] };
      if (dragged.account !== account) return onerror(new Error(t("Emails move only within one mailbox.")));
      act(() => moveMany(jmap, account, dragged.ids, target));
    } else if (folder && from === account && folder !== target && !within(boxes, target, folder)) {
      act(() => updateMailbox(jmap, account, folder, { parentId: target }));
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
  <span class="store-name" data-tip={address}>
    {#if shared}<UsersRound size={14} />{:else}<UserRound size={14} />{/if}
    <span class="lines">
      <span class="name">{title}</span>
      <span class="tag" class:shared>{shared ? t("Shared") : t("Private")}</span>
    </span>
  </span>
  <span class="store-tools">
    <button type="button" class="icon quiet small" aria-label={t("Name the mailbox")} data-tip={t("Name the mailbox")} onclick={() => (naming = title === address ? "" : title)}>
      <Pencil size={14} />
    </button>
    <button type="button" class="icon quiet small" aria-label={t("New folder")} data-tip={t("New folder")} onclick={() => (dialog = { kind: "new", parent: null })}>
      <Plus size={16} />
    </button>
  </span>
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
          event.dataTransfer?.setData(FOLDER, `${account}/${box.id}`);
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
    save={(name, parent) => createMailbox(jmap, account, name, parent).then(onchanged)}
    onclose={() => (dialog = undefined)}
  />
{:else if dialog}
  {@const box = dialog.box}
  <FolderDialog
    title={dialog.kind === "rename" ? t("Rename folder") : t("Move folder")}
    {boxes}
    {box}
    label={t("Save")}
    save={(name, parent) => updateMailbox(jmap, account, box.id, { name, parentId: parent }).then(onchanged)}
    onclose={() => (dialog = undefined)}
  />
{/if}

{#if naming !== undefined}
  <Dialog title={t("Name the mailbox")} onClose={() => (naming = undefined)}>
    <form
      onsubmit={async (event) => {
        event.preventDefault();
        namingError = undefined;
        try {
          await onrename(naming ?? "");
          naming = undefined;
        } catch (failure) {
          namingError = failure;
        }
      }}
    >
      <label>
        <span>{t("Name")}</span>
        <!-- svelte-ignore a11y_autofocus -->
        <input bind:value={naming} maxlength="64" placeholder={address} autofocus />
        <small class="muted">{t("Only you see it. Empty shows the address {address}.", { address })}</small>
      </label>
      {#if namingError}<p class="error">{namingError instanceof Error ? namingError.message : String(namingError)}</p>{/if}
      <div class="actions end">
        <button type="button" onclick={() => (naming = undefined)}>{t("Cancel")}</button>
        <button type="submit" class="primary">{t("Save")}</button>
      </div>
    </form>
  </Dialog>
{/if}
