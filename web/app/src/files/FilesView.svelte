<!-- SPDX-License-Identifier: MIT -->
<!-- Files: the stores the user reaches on the side – their own, the tenant's drives, what others share –, one directory
     at a time with the way up; uploading with progress (also by dropping), new folders, renaming, the trash, sharing
     folders, links for people without an account, copying and moving to another store, earlier versions of files,
     files shown in place, how to connect a file manager (WebDAV). What the user may do follows the rights kernoid
     reports. -->
<script lang="ts">
  import {
    Building2,
    Cable,
    Copy,
    Folder,
    FolderPlus,
    HardDrive,
    History,
    Link,
    Pencil,
    Search,
    Share2,
    Trash2,
    Upload,
    UsersRound,
  } from "@lucide/svelte";

  import FileIcon from "../ui/FileIcon.svelte";
  import WebDavHelp from "../account/WebDavHelp.svelte";
  import { changed, resource, touch, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import CopyDialog from "./CopyDialog.svelte";
  import LinkDialog from "./LinkDialog.svelte";
  import {
    type FileNode,
    LEVELS,
    NO_RIGHTS,
    type Rights,
    type Store,
    children,
    createDirectory,
    destroy,
    downloadPath,
    formatSize,
    isDirectory,
    linksAvailable,
    move,
    path,
    rename,
    search,
    sortNodes,
    stores,
    trash,
    uploadFile,
  } from "./model.js";
  import ShareDialog from "./ShareDialog.svelte";
  import VersionsDialog from "./VersionsDialog.svelte";
  import Viewer from "./Viewer.svelte";

  interface Upload {
    name: string;
    sent: number;
    total: number;
  }

  /** `#/files/<account>/<directory>`: the store and directory the URL names. */
  function location(): { account: string | null; directory: string | null } {
    const [, account, directory] = window.location.hash.replace(/^#\/?/, "").split("/");
    return {
      account: account ? decodeURIComponent(account) : null,
      directory: directory ? decodeURIComponent(directory) : null,
    };
  }

  function open(account: string, directory: string | null): void {
    window.location.hash = `#/files/${encodeURIComponent(account)}${directory ? `/${encodeURIComponent(directory)}` : ""}`;
  }

  const jmap = useJmap();
  let place = $state(location());
  $effect(() => {
    const onHash = () => (place = location());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  });

  const all = stores(jmap);
  const store = $derived<Store | undefined>(all.find((entry) => entry.id === place.account) ?? all[0]);
  const account = $derived(store?.id ?? "");
  const directory = $derived(place.account === account ? place.directory : null);

  // A search lists what matches anywhere in the store instead of one directory.
  let query = $state("");
  let typed = $state("");
  const list = resource(
    () => ({ account, id: directory, text: query.trim(), version: changed("FileNode") }),
    ({ account: store, id, text }) => (text ? search(jmap, store, text) : children(jmap, store, id)),
  );
  const trail = resource(
    () => ({ account, id: directory, version: changed("FileNode") }),
    ({ account: store, id }) => path(jmap, store, id),
  );
  const bin = resource(
    () => ({ account, version: changed("FileNode") }),
    ({ account: store }) => trash(jmap, store),
  );
  let busy = $state(false);
  let uploads = $state<Upload[]>([]);
  let error = $state<unknown>();
  let dragging = $state(false);
  let sharing = $state<FileNode>();
  let linking = $state<FileNode>();
  let history = $state<FileNode>();
  let copying = $state<FileNode>();
  let viewing = $state<FileNode>();
  let connecting = $state(false);

  /** The rights here: the directory's, or at the top whether the user may add there. */
  const here = $derived.by((): Rights => {
    const current = trail.value?.at(-1);
    if (current?.myRights) return current.myRights;
    if (directory) return NO_RIGHTS;
    return { ...NO_RIGHTS, mayRead: true, mayAddChildren: store?.mayCreateTopLevel ?? false };
  });

  /** The rights on a node: a directory's own, a file's those of where it lies – at the top all of them in one's own
   * store, else what adding there says. */
  function rightsOf(node: FileNode): Rights {
    if (node.myRights) return node.myRights;
    if (directory) return here;
    if (store?.kind === "own") return LEVELS.full;
    return store?.mayCreateTopLevel ? LEVELS.edit : LEVELS.read;
  }

  const inTrash = $derived.by(() => {
    const id = bin.value?.id;
    return id !== undefined && (trail.value ?? []).some((node) => node.id === id);
  });

  async function run(work: () => Promise<void>): Promise<void> {
    busy = true;
    error = undefined;
    try {
      await work();
      touch("FileNode");
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
      uploads = [];
    }
  }

  function upload(files: FileList | null | undefined): void {
    if (!files?.length || !here.mayAddChildren) return;
    const parent = directory;
    const chosen = Array.from(files);
    uploads = chosen.map((file) => ({ name: file.name, sent: 0, total: file.size }));
    void run(async () => {
      for (const [index, file] of chosen.entries()) {
        const existing = (list.value ?? []).find((node) => node.name === file.name);
        await uploadFile(
          jmap,
          account,
          parent,
          file,
          (sent, total) => {
            const entry = uploads[index];
            if (entry) uploads[index] = { ...entry, sent, total };
          },
          existing,
        );
      }
    });
  }

  function newDirectory(): void {
    const name = window.prompt(t("Name of the new folder"));
    if (name?.trim()) void run(() => createDirectory(jmap, account, directory, name.trim()));
  }

  function renameNode(node: FileNode): void {
    const name = window.prompt(t("New name"), node.name);
    if (name?.trim() && name.trim() !== node.name) void run(() => rename(jmap, account, node, name.trim()));
  }

  function remove(node: FileNode): void {
    const target = bin.value;
    if (inTrash || !target || node.role) {
      if (window.confirm(t("Delete this for good?"))) void run(() => destroy(jmap, account, node));
    } else {
      void run(() => move(jmap, account, node, target.id));
    }
  }

  const label = (node: FileNode) => (node.role === "trash" ? t("Trash") : node.name);
  const storeName = (entry: Store) => (entry.kind === "own" ? t("My files") : entry.name);
  const when = (iso: string) => new Date(iso).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
</script>

<div class="two files-shell">
  <nav class="side" aria-label={t("Files")}>
    <ul class="boxes">
      {#each all as entry (entry.id)}
        {@const Icon = entry.kind === "own" ? HardDrive : entry.kind === "drive" ? Building2 : UsersRound}
        <li>
          <button type="button" class:active={entry.id === account} onclick={() => open(entry.id, null)}>
            <Icon size={18} />
            <span class="label">
              {storeName(entry)}
              {#if entry.kind !== "own"}
                <small class="muted">{entry.kind === "drive" ? t("Drive") : t("Shared")}</small>
              {/if}
            </span>
          </button>
        </li>
      {/each}
    </ul>
  </nav>
  <div
    class="files"
    class:dropping={dragging}
    role="region"
    aria-label={t("Files")}
    ondragover={(event) => {
      event.preventDefault();
      if (here.mayAddChildren) dragging = true;
    }}
    ondragleave={() => (dragging = false)}
    ondrop={(event) => {
      event.preventDefault();
      dragging = false;
      upload(event.dataTransfer?.files);
    }}
  >
    <div class="toolbar">
      <nav class="trail" aria-label={t("Folders")}>
        <button type="button" class="quiet" onclick={() => open(account, null)}>
          {store ? storeName(store) : t("Files")}
        </button>
        {#each trail.value ?? [] as node (node.id)}
          <span class="muted">/</span>
          <button type="button" class="quiet" onclick={() => open(account, node.id)}>{label(node)}</button>
        {/each}
      </nav>
      <span class="grow"></span>
      <form
        role="search"
        onsubmit={(event) => {
          event.preventDefault();
          query = typed;
        }}
      >
        <Search size={16} />
        <input
          type="search"
          placeholder={t("Search names and contents")}
          aria-label={t("Search")}
          bind:value={typed}
          oninput={() => typed === "" && (query = "")}
        />
      </form>
      <button
        type="button"
        class="icon quiet"
        aria-label={t("Connect a file manager")}
        data-tip={t("Connect a file manager")}
        onclick={() => (connecting = true)}
      >
        <Cable size={18} />
      </button>
      {#if !inTrash && here.mayAddChildren}
        <button type="button" disabled={busy} onclick={newDirectory}><FolderPlus size={17} />{t("New folder")}</button>
        <label class="button primary" class:disabled={busy}>
          <Upload size={17} />{t("Upload")}
          <input type="file" multiple hidden disabled={busy} onchange={(event) => upload(event.currentTarget.files)} />
        </label>
      {/if}
    </div>
    <Failure error={error ?? list.error ?? trail.error} />
    {#each uploads as entry, index (index)}
      <div class="progress">
        <span class="small">{entry.name}</span>
        <progress max={entry.total || 1} value={entry.sent}></progress>
        <span class="muted small">{formatSize(entry.sent, locale)} / {formatSize(entry.total, locale)}</span>
      </div>
    {/each}
    {#if list.value?.length === 0 && !list.loading}
      <p class="muted pad">
        {inTrash ? t("The trash is empty") : here.mayAddChildren ? t("No files yet – drop some here") : t("Nothing here")}
      </p>
    {/if}
    <table class="nodes">
      <tbody>
        {#each sortNodes(list.value ?? [], locale) as node (node.id)}
          {@const rights = rightsOf(node)}
          <tr>
            <td class="name">
              {#if isDirectory(node)}
                <button
                  type="button"
                  class="quiet folder"
                  onclick={() => {
                    query = "";
                    typed = "";
                    open(account, node.id);
                  }}
                >
                  {#if node.role === "trash"}<Trash2 size={18} />{:else}<Folder size={18} />{/if}
                  {label(node)}
                </button>
                {#if Object.keys(node.shareWith ?? {}).length > 0}
                  <span class="muted small"> · {t("Shared")}</span>
                {/if}
              {:else if node.blobId}
                <button type="button" class="quiet file" onclick={() => (viewing = node)}>
                  <FileIcon name={node.name} type={node.mediaType} />{node.name}
                </button>
              {:else}
                <span class="file"><FileIcon name={node.name} type={node.mediaType} />{node.name}</span>
              {/if}
            </td>
            <td class="muted small">{node.size == null ? "" : formatSize(node.size, locale)}</td>
            <td class="muted small">{node.modified ? when(node.modified) : ""}</td>
            <td class="end">
              {#if !node.role}
                {#if isDirectory(node) && rights.mayShare}
                  <button type="button" class="quiet icon small" disabled={busy} aria-label={t("Share")} data-tip={t("Share")} onclick={() => (sharing = node)}><Share2 size={17} /></button>
                {/if}
                {#if rights.mayShare && linksAvailable(jmap)}
                  <button type="button" class="quiet icon small" disabled={busy} aria-label={t("Link")} data-tip={t("Link")} onclick={() => (linking = node)}><Link size={17} /></button>
                {/if}
                {#if !isDirectory(node) && rights.mayRead}
                  <button type="button" class="quiet icon small" disabled={busy} aria-label={t("Versions")} data-tip={t("Versions")} onclick={() => (history = node)}><History size={17} /></button>
                {/if}
                {#if rights.mayRead}
                  <button type="button" class="quiet icon small" disabled={busy} aria-label={t("Copy or move")} data-tip={t("Copy or move")} onclick={() => (copying = node)}>
                    <Copy size={17} />
                  </button>
                {/if}
                {#if rights.mayRename}
                  <button type="button" class="quiet icon small" disabled={busy} aria-label={t("Rename")} data-tip={t("Rename")} onclick={() => renameNode(node)}><Pencil size={17} /></button>
                {/if}
                {#if rights.mayDelete}
                  <button
                    type="button"
                    class="quiet icon small danger"
                    disabled={busy}
                    aria-label={inTrash || !bin.value ? t("Delete for good") : t("Delete")}
                    data-tip={inTrash || !bin.value ? t("Delete for good") : t("Delete")}
                    onclick={() => remove(node)}
                  >
                    <Trash2 size={17} />
                  </button>
                {/if}
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if sharing}
    <ShareDialog
      {account}
      node={sharing}
      onclose={(saved) => {
        sharing = undefined;
        if (saved) touch("FileNode");
      }}
    />
  {/if}
  {#if copying}
    <CopyDialog
      {account}
      node={copying}
      mayMove={rightsOf(copying).mayDelete}
      onclose={(done) => {
        copying = undefined;
        if (done) touch("FileNode");
      }}
    />
  {/if}
  {#if linking}
    <LinkDialog {account} node={linking} onclose={() => (linking = undefined)} />
  {/if}
  {#if viewing}
    {@const url = downloadPath(jmap, account, viewing.blobId ?? "", viewing.name, viewing.mediaType)}
    <Viewer
      name={viewing.name}
      type={viewing.mediaType}
      size={viewing.size ?? null}
      {url}
      inline={`${url}&inline=1`}
      onclose={() => (viewing = undefined)}
    />
  {/if}
  {#if connecting}
    <div class="overlay" role="dialog" aria-modal="true" aria-label={t("Connect a file manager")}>
      <div class="dialog">
        <h2>{t("Connect a file manager")}</h2>
        <p class="muted">{t("Your files also appear in Finder, Explorer or the file manager of your phone (WebDAV).")}</p>
        <WebDavHelp address={jmap.session.username} />
        <div class="actions end">
          <a class="button" href="#/account">{t("Make an app password")}</a>
          <button type="button" class="primary" onclick={() => (connecting = false)}>{t("Close")}</button>
        </div>
      </div>
    </div>
  {/if}
  {#if history}
    <VersionsDialog
      {account}
      node={history}
      mayRestore={rightsOf(history).mayModifyContent}
      onclose={(restored) => {
        history = undefined;
        if (restored) touch("FileNode");
      }}
    />
  {/if}
</div>
