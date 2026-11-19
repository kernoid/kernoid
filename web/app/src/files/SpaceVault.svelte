<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- A vault on a space (RFC 0010, 5): what lies in it lives in the space, end to end encrypted, and is shown from the
     worker's copy (spaces.ts) – the file store only knows the vault's directory. Directories one below the other with
     the way up, uploading, new folders, renaming, moving to another directory of the vault, the vault's own trash,
     removing for good. Files are decrypted here: images, audio, video and text are shown (from `blob:` URLs, never in
     a frame), everything else is saved. -->
<script lang="ts">
  import { ArrowLeft, Folder, FolderInput, FolderLock, FolderPlus, Pencil, RefreshCw, Trash2, Undo2, Upload } from "@lucide/svelte";

  import { touch, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import FileIcon from "../ui/FileIcon.svelte";
  import { kindOf } from "./kind.js";
  import { type FileNode, formatSize } from "./model.js";
  import * as spaces from "./spaces.js";
  import Viewer from "./Viewer.svelte";

  let { account, vault, onclose }: { account: string; vault: FileNode; onclose: () => void } = $props();

  const jmap = useJmap();
  /** The directories from the vault's top down to the one shown. */
  let path = $state<{ id: string; name: string }[]>([]);
  const here = $derived(path.at(-1)?.id ?? null);
  let entered = $state<boolean | undefined>();
  let name = $state<string | undefined>();
  let entries = $state<spaces.Entry[] | undefined>();
  let showTrash = $state(false);
  let busy = $state(false);
  let error = $state<unknown>();
  let uploads = $state<string[]>([]);
  let moving = $state<{ entry: spaces.Entry; targets: { id: string | null; path: string }[] }>();
  let viewing = $state<{ entry: spaces.Entry; url: string; body: Uint8Array }>();

  async function load(): Promise<void> {
    entries = await spaces.list(jmap, vault, here);
  }

  async function enter(): Promise<void> {
    error = undefined;
    try {
      // svelte-ignore state_referenced_locally
      entered = await spaces.enter(jmap, account, vault);
      if (entered) {
        name = await spaces.name(jmap, vault);
        await load();
      }
    } catch (failure) {
      error = failure;
    }
  }
  void enter();

  async function run(work: () => Promise<void>): Promise<void> {
    busy = true;
    error = undefined;
    try {
      await work();
      await load();
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
      uploads = [];
    }
  }

  function go(to: { id: string; name: string }[]): void {
    path = to;
    entries = undefined;
    void load().catch((failure: unknown) => (error = failure));
  }

  function upload(files: FileList | null | undefined): void {
    if (!files?.length) return;
    const chosen = Array.from(files);
    const parent = here;
    uploads = chosen.map((file) => file.name);
    void run(async () => {
      for (const file of chosen) await spaces.upload(jmap, vault, parent, file);
    });
  }

  function newDirectory(): void {
    const directoryName = window.prompt(t("Name of the new folder"));
    if (directoryName?.trim()) void run(async () => void (await spaces.makeDirectory(jmap, vault, here, directoryName.trim())));
  }

  function renameEntry(entry: spaces.Entry): void {
    const newName = window.prompt(t("New name"), entry.name);
    if (newName?.trim() && newName.trim() !== entry.name) void run(() => spaces.rename(jmap, vault, here, entry.id, newName.trim()));
  }

  async function chooseTarget(entry: spaces.Entry): Promise<void> {
    try {
      const targets = (await spaces.directories(jmap, vault, entry.id)).filter((target) => target.id !== here);
      moving = { entry, targets };
    } catch (failure) {
      error = failure;
    }
  }

  async function open(entry: spaces.Entry): Promise<void> {
    const kind = kindOf(entry.name, entry.mediaType);
    if (kind === "other" || kind === "pdf") {
      await run(() => spaces.save(jmap, vault, entry));
      return;
    }
    try {
      const data = await spaces.read(jmap, vault, entry.id);
      const url = URL.createObjectURL(new Blob([data.slice().buffer], { type: entry.mediaType ?? "application/octet-stream" }));
      viewing = { entry, url, body: data };
    } catch (failure) {
      error = failure;
    }
  }

  const shown = $derived((entries ?? []).filter((entry) => entry.trashed === showTrash));
  const when = (iso: string) => new Date(iso).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
</script>

<div class="toolbar">
  <nav class="trail" aria-label={t("Folders")}>
    <button type="button" class="quiet icon" aria-label={t("Back to the files")} data-tip={t("Back to the files")} onclick={onclose}>
      <ArrowLeft size={17} />
    </button>
    <FolderLock size={17} />
    <button type="button" class="quiet" onclick={() => go([])}>{name ?? t("Vault")}</button>
    {#each path as step, index (step.id)}
      <span class="muted">/</span>
      <button type="button" class="quiet" onclick={() => go(path.slice(0, index + 1))}>{step.name}</button>
    {/each}
  </nav>
  <span class="grow"></span>
  {#if entered}
    {#if !showTrash}
      <button type="button" disabled={busy} onclick={newDirectory}><FolderPlus size={17} />{t("New folder")}</button>
      <label class="button primary" class:disabled={busy}>
        <Upload size={17} />{t("Upload")}
        <input type="file" multiple hidden disabled={busy} onchange={(event) => upload(event.currentTarget.files)} />
      </label>
    {/if}
    <button type="button" class="quiet" onclick={() => (showTrash = !showTrash)}>
      {#if showTrash}<FolderLock size={17} />{t("Back to the vault")}{:else}<Trash2 size={17} />{t("Trash of the vault")}{/if}
    </button>
  {/if}
  <button type="button" class="icon quiet" disabled={busy} aria-label={t("Try again")} data-tip={t("Try again")} onclick={() => void enter()}>
    <RefreshCw size={17} />
  </button>
</div>
<Failure {error} />
{#each uploads as upload (upload)}
  <div class="progress"><span class="small">{upload}</span><progress></progress></div>
{/each}
{#if entered === undefined && !error}
  <p class="muted pad">{t("Opening the vault …")}</p>
{:else if entered === false}
  <p class="muted pad">{t("No member has given you access to this vault yet. Once one shares it with you again, it opens here.")}</p>
{:else if entries && shown.length === 0}
  <p class="muted pad">{showTrash ? t("The trash is empty") : t("Nothing here")}</p>
{/if}
<table class="nodes">
  <tbody>
    {#each shown as entry (entry.id)}
      <tr>
        <td class="name">
          {#if entry.directory}
            <button type="button" class="quiet folder" disabled={entry.trashed} onclick={() => go([...path, { id: entry.id, name: entry.name }])}>
              <Folder size={18} />{entry.name}
            </button>
          {:else}
            <button type="button" class="quiet file" disabled={entry.trashed} data-tip={t("Decrypted here")} onclick={() => void open(entry)}>
              <FileIcon name={entry.name} type={entry.mediaType} />{entry.name}
            </button>
          {/if}
        </td>
        <td class="muted small">{entry.directory ? "" : formatSize(entry.size, locale)}</td>
        <td class="muted small">{entry.modified ? when(entry.modified) : ""}</td>
        <td class="end">
          {#if entry.trashed}
            <button type="button" class="quiet icon small" disabled={busy} aria-label={t("Restore")} data-tip={t("Restore")} onclick={() => void run(() => spaces.setTrashed(jmap, vault, here, entry.id, false))}><Undo2 size={17} /></button>
            <button
              type="button"
              class="quiet icon small danger"
              disabled={busy}
              aria-label={t("Delete for good")}
              data-tip={t("Delete for good")}
              onclick={() => window.confirm(t("Delete this for good?")) && void run(() => spaces.remove(jmap, vault, here, entry.id))}
            ><Trash2 size={17} /></button>
          {:else}
            <button type="button" class="quiet icon small" disabled={busy} aria-label={t("Move to …")} data-tip={t("Move to …")} onclick={() => void chooseTarget(entry)}><FolderInput size={17} /></button>
            <button type="button" class="quiet icon small" disabled={busy} aria-label={t("Rename")} data-tip={t("Rename")} onclick={() => renameEntry(entry)}><Pencil size={17} /></button>
            <button type="button" class="quiet icon small danger" disabled={busy} aria-label={t("Delete")} data-tip={t("Delete")} onclick={() => void run(() => spaces.setTrashed(jmap, vault, here, entry.id, true))}><Trash2 size={17} /></button>
          {/if}
        </td>
      </tr>
    {/each}
  </tbody>
</table>
{#if moving}
  {@const choice = moving}
  <div class="overlay" role="dialog" aria-modal="true" aria-label={t("Move to …")}>
    <div class="dialog">
      <h2>{t("Move to …")}</h2>
      <ul class="plain">
        {#each choice.targets as target (target.id ?? "")}
          <li>
            <button
              type="button"
              class="quiet folder"
              onclick={() => {
                const entry = choice.entry.id;
                const to = target.id;
                moving = undefined;
                void run(() => spaces.moveTo(jmap, vault, here, entry, to));
              }}
            ><Folder size={17} />{target.path || t("Top of the vault")}</button>
          </li>
        {/each}
      </ul>
      <div class="actions end">
        <button type="button" onclick={() => (moving = undefined)}>{t("Cancel")}</button>
      </div>
    </div>
  </div>
{/if}
{#if viewing}
  {@const shownFile = viewing}
  <Viewer
    name={shownFile.entry.name}
    type={shownFile.entry.mediaType}
    size={shownFile.entry.size}
    url={shownFile.url}
    inline={shownFile.url}
    body={shownFile.body}
    onclose={() => {
      URL.revokeObjectURL(shownFile.url);
      viewing = undefined;
      touch("FileNode");
    }}
  />
{/if}
