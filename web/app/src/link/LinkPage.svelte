<!-- SPDX-License-Identifier: MIT -->
<!-- What a link opens: lists, shows and downloads what the link leads to; where the link lets people add files to a
     folder, they are uploaded with progress (also by dropping them), into a drop box without seeing what is in it. -->
<script lang="ts">
  import { resource } from "../app.svelte.js";
  import { formatSize } from "../files/model.js";
  import Viewer from "../files/Viewer.svelte";
  import { locale, t } from "../i18n.js";
  import {
    ACCESS_KEY,
    type LinkInfo,
    LinkFailure,
    type LinkNode,
    type Sending,
    addFile,
    base,
    download,
    get,
    storedAccess,
  } from "./link.js";

  let access = $state(storedAccess());
  const root = resource(
    () => ({ key: access }),
    ({ key }) => get<LinkInfo>("", key),
  );
  let trail = $state<LinkNode[]>([]);
  const info = $derived(root.ready ? root.value : undefined);
  const top = $derived(info?.node);
  const here = $derived(trail.at(-1) ?? top);
  const list = resource(
    () => (here?.nodeType === "directory" && info?.mayRead ? { node: here, key: access } : undefined),
    ({ node, key }) =>
      get<LinkNode[]>(node.id === top?.id ? "/nodes" : `/nodes?parent=${encodeURIComponent(node.id)}`, key),
  );
  let viewing = $state<LinkNode>();
  let failure = $state<string>();
  const locked = $derived(root.error instanceof LinkFailure && root.error.status === 401);
  const when = (date: string) => new Date(date).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
  let sending = $state<Sending[]>([]);
  let dragging = $state(false);
  let nextId = 0;

  function update(id: number, change: Partial<Sending>): void {
    sending = sending.map((entry) => (entry.id === id ? { ...entry, ...change } : entry));
  }

  // One file after the other, into the folder shown.
  async function addAll(files: FileList | null | undefined): Promise<void> {
    if (!files?.length || !info?.mayAdd) return;
    const parent = trail.at(-1)?.id;
    const queued = [...files].map((file) => ({ file, id: nextId++ }));
    sending = [...sending, ...queued.map(({ file, id }) => ({ id, name: file.name, total: file.size, sent: 0 }))];
    for (const { file, id } of queued) {
      try {
        const added = await addFile(file, parent, access, (sent) => update(id, { sent }));
        update(id, { sent: file.size, added: added.name });
        if (info?.mayRead) void list.refetch();
      } catch (error) {
        update(id, { failed: (error as Error).message });
      }
    }
  }

  async function unlock(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const password = String(new FormData(event.currentTarget as HTMLFormElement).get("password") ?? "");
    const response = await fetch(`${base}/unlock`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ password }),
    });
    if (!response.ok) {
      failure = response.status === 429 ? t("Too many attempts – try again later.") : t("The password is not right.");
      return;
    }
    const { access: key } = (await response.json()) as { access: string };
    try {
      sessionStorage.setItem(ACCESS_KEY, key);
    } catch {
      // Without storage the link opens for this page only.
    }
    failure = undefined;
    access = key;
  }

  function sent(entry: Sending): string {
    if (entry.failed) return entry.failed;
    return entry.added === entry.name ? t("added") : t("added as {name}", { name: entry.added ?? "" });
  }
</script>

<main
  class="link-page"
  class:dropping={dragging}
  ondragover={(event) => {
    event.preventDefault();
    if (info?.mayAdd && here?.nodeType === "directory") dragging = true;
  }}
  ondragleave={() => (dragging = false)}
  ondrop={(event) => {
    event.preventDefault();
    dragging = false;
    void addAll(event.dataTransfer?.files);
  }}
>
  <header class="toolbar">
    <h1 class="grow">kern0id</h1>
  </header>
  {#if locked}
    <form class="dialog" onsubmit={(event) => void unlock(event)}>
      <h2>{t("This link has a password")}</h2>
      <label>
        <span>{t("Password")}</span>
        <input type="password" name="password" required autocomplete="off" />
      </label>
      {#if failure}
        <p class="error">{failure}</p>
      {/if}
      <div class="actions end">
        <button type="submit" class="primary">{t("Open")}</button>
      </div>
    </form>
  {:else if root.error}
    <p class="error pad">{(root.error as Error).message}</p>
  {/if}
  {#if top}
    {@const node = top}
    {#if node.nodeType === "directory"}
      {#if info?.mayRead}
        <nav class="trail">
          <button type="button" class="quiet" onclick={() => (trail = [])}>{node.name}</button>
          {#each trail as step, index (step.id)}
            /
            <button type="button" class="quiet" onclick={() => (trail = trail.slice(0, index + 1))}>{step.name}</button>
          {/each}
        </nav>
      {:else}
        <h2 class="pad">{node.name}</h2>
      {/if}
      {#if info?.mayAdd}
        <section class="add-files pad">
          <p>
            {info.mayRead
              ? t("You can add files to this folder.")
              : t("You can put files into this folder – what is in it stays hidden.")}
          </p>
          <div class="row">
            <label class="button primary">
              {t("Choose files")}
              <input
                type="file"
                multiple
                hidden
                onchange={(event) => {
                  void addAll(event.currentTarget.files);
                  event.currentTarget.value = "";
                }}
              />
            </label>
            <span class="muted small">{t("or drop them on this page")}</span>
          </div>
          {#each sending as entry (entry.id)}
            <div class="progress">
              <span class="small">{entry.name}</span>
              {#if entry.added ?? entry.failed}
                <span class="small" class:error={!!entry.failed}>{sent(entry)}</span>
              {:else}
                <progress max={entry.total || 1} value={entry.sent}></progress>
              {/if}
              <span class="muted small">{formatSize(entry.total, locale)}</span>
            </div>
          {/each}
        </section>
      {/if}
      {#if list.error}
        <p class="error pad">{(list.error as Error).message}</p>
      {/if}
      {#if info?.mayRead}
        <table class="nodes">
          <tbody>
            {#each list.value ?? [] as child (child.id)}
              <tr>
                <td class="name">
                  {#if child.nodeType === "directory"}
                    <button type="button" class="quiet folder" onclick={() => (trail = [...trail, child])}>
                      {child.name}
                    </button>
                  {:else}
                    <button type="button" class="quiet file" onclick={() => (viewing = child)}>{child.name}</button>
                  {/if}
                </td>
                <td class="muted small">{child.size == null ? "" : formatSize(child.size, locale)}</td>
                <td class="muted small">{when(child.modified)}</td>
                <td class="end">
                  {#if child.nodeType === "file"}
                    <a class="button quiet" href={download(child, access)}>{t("Download")}</a>
                  {/if}
                </td>
              </tr>
            {:else}
              <tr><td class="muted">{list.loading ? t("Loading") : t("Nothing here")}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    {:else}
      <section class="pad">
        <h2>{node.name}</h2>
        <p class="muted">{formatSize(node.size ?? 0, locale)} · {when(node.modified)}</p>
        <div class="actions">
          <button type="button" onclick={() => (viewing = node)}>{t("Show")}</button>
          <a class="button primary" href={download(node, access)}>{t("Download")}</a>
        </div>
      </section>
    {/if}
  {/if}
  {#if viewing}
    <Viewer
      name={viewing.name}
      type={viewing.mediaType}
      size={viewing.size}
      url={download(viewing, access)}
      inline={download(viewing, access, true)}
      onclose={() => (viewing = undefined)}
    />
  {/if}
</main>
