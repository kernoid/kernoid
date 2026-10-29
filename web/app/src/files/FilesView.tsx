// SPDX-License-Identifier: MIT
// Files: the stores the user reaches on the side – their own, the tenant's drives, what others share –, one directory
// at a time with the way up; uploading with progress (also by dropping), new folders, renaming, the trash, sharing
// folders, links for people without an account, earlier versions of files, files shown in place (Viewer.tsx), how to connect a file manager (WebDAV).
// What the user may do follows the rights kernoid reports.

import { For, type JSX, Show, createMemo, createResource, createSignal, onCleanup } from "solid-js";

import { Failure, changed, ok, touch, useJmap } from "../App.js";
import { WebDavHelp } from "../account/Connect.js";
import { locale, t } from "../i18n.js";
import {
  type FileLink,
  type FileNode,
  LEVELS,
  NO_RIGHTS,
  type Principal,
  type Rights,
  type Store,
  children,
  createDirectory,
  createLink,
  destroy,
  downloadPath,
  findPrincipals,
  formatSize,
  isDirectory,
  level,
  links,
  linksAvailable,
  move,
  path,
  principals,
  removeLink,
  rename,
  restore,
  share,
  sortNodes,
  stores,
  trash,
  uploadFile,
  versions,
} from "./model.js";
import { Viewer } from "./Viewer.js";

/** `#/files/<account>/<directory>`: the store and directory the URL names. */
function location(): { account: string | null; directory: string | null } {
  const [, account, directory] = window.location.hash.replace(/^#\/?/, "").split("/");
  return { account: account ? decodeURIComponent(account) : null, directory: directory ? decodeURIComponent(directory) : null };
}

function open(account: string, directory: string | null): void {
  window.location.hash = `#/files/${encodeURIComponent(account)}${directory ? `/${encodeURIComponent(directory)}` : ""}`;
}

interface Upload {
  name: string;
  sent: number;
  total: number;
}

export function FilesView(): JSX.Element {
  const jmap = useJmap();
  const [place, setPlace] = createSignal(location());
  const onHash = () => setPlace(location());
  window.addEventListener("hashchange", onHash);
  onCleanup(() => window.removeEventListener("hashchange", onHash));

  const all = stores(jmap);
  const store = createMemo<Store | undefined>(() => all.find((entry) => entry.id === place().account) ?? all[0]);
  const account = () => store()?.id ?? "";
  const directory = () => (place().account === account() ? place().directory : null);

  const [list] = createResource(
    () => ({ account: account(), id: directory(), version: changed("FileNode") }),
    ({ account, id }) => children(jmap, account, id),
  );
  const [trail] = createResource(
    () => ({ account: account(), id: directory(), version: changed("FileNode") }),
    ({ account, id }) => path(jmap, account, id),
  );
  const [bin] = createResource(
    () => ({ account: account(), version: changed("FileNode") }),
    ({ account }) => trash(jmap, account),
  );
  const [busy, setBusy] = createSignal(false);
  const [uploads, setUploads] = createSignal<Upload[]>([]);
  const [error, setError] = createSignal<unknown>();
  const [dragging, setDragging] = createSignal(false);
  const [sharing, setSharing] = createSignal<FileNode>();
  const [linking, setLinking] = createSignal<FileNode>();
  const [history, setHistory] = createSignal<FileNode>();
  const [viewing, setViewing] = createSignal<FileNode>();
  const [connecting, setConnecting] = createSignal(false);

  /** The rights here: the directory's, or at the top whether the user may add there. */
  const here = (): Rights => {
    const current = ok(trail)?.at(-1);
    if (current?.myRights) return current.myRights;
    if (directory()) return NO_RIGHTS;
    const top = store()?.mayCreateTopLevel ?? false;
    return { ...NO_RIGHTS, mayRead: true, mayAddChildren: top };
  };
  /** The rights on a node: a directory's own, a file's those of where it lies – at the top all of them in one's own
   * store, else what adding there says. */
  const rightsOf = (node: FileNode): Rights => {
    if (node.myRights) return node.myRights;
    if (directory()) return here();
    if (store()?.kind === "own") return LEVELS.full;
    return store()?.mayCreateTopLevel ? LEVELS.edit : LEVELS.read;
  };

  const inTrash = () => {
    const id = bin()?.id;
    return id !== undefined && (ok(trail) ?? []).some((node) => node.id === id);
  };

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await work();
      touch("FileNode");
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
      setUploads([]);
    }
  };

  const upload = (files: FileList | null | undefined) => {
    if (!files?.length || !here().mayAddChildren) return;
    const parent = directory();
    const chosen = Array.from(files);
    setUploads(chosen.map((file) => ({ name: file.name, sent: 0, total: file.size })));
    void run(async () => {
      for (const [index, file] of chosen.entries()) {
        const existing = (ok(list) ?? []).find((node) => node.name === file.name);
        await uploadFile(
          jmap,
          account(),
          parent,
          file,
          (sent, total) => setUploads((current) => current.map((entry, at) => (at === index ? { ...entry, sent, total } : entry))),
          existing,
        );
      }
    });
  };

  const newDirectory = () => {
    const name = window.prompt(t("Name of the new folder"));
    if (name?.trim()) void run(() => createDirectory(jmap, account(), directory(), name.trim()));
  };

  const renameNode = (node: FileNode) => {
    const name = window.prompt(t("New name"), node.name);
    if (name?.trim() && name.trim() !== node.name) void run(() => rename(jmap, account(), node, name.trim()));
  };

  const remove = (node: FileNode) => {
    const target = bin();
    if (inTrash() || !target || node.role) {
      if (window.confirm(t("Delete this for good?"))) void run(() => destroy(jmap, account(), node));
    } else {
      void run(() => move(jmap, account(), node, target.id));
    }
  };

  const label = (node: FileNode) => (node.role === "trash" ? t("Trash") : node.name);
  const storeName = (entry: Store) => (entry.kind === "own" ? t("My files") : entry.name);

  return (
    <div class="two files-shell">
      <nav class="side" aria-label={t("Files")}>
        <ul class="boxes">
          <For each={all}>
            {(entry) => (
              <li>
                <button type="button" classList={{ active: entry.id === account() }} onClick={() => open(entry.id, null)}>
                  <span>{storeName(entry)}</span>
                  <Show when={entry.kind !== "own"}>
                    <span class="muted small">{entry.kind === "drive" ? t("Drive") : t("Shared")}</span>
                  </Show>
                </button>
              </li>
            )}
          </For>
        </ul>
      </nav>
      <div
        class="files"
        classList={{ dropping: dragging() }}
        onDragOver={(event) => {
          event.preventDefault();
          if (here().mayAddChildren) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          upload(event.dataTransfer?.files);
        }}
      >
        <div class="toolbar">
          <nav class="trail" aria-label={t("Folders")}>
            <button type="button" class="quiet" onClick={() => open(account(), null)}>
              {store() ? storeName(store() as Store) : t("Files")}
            </button>
            <For each={ok(trail) ?? []}>
              {(node) => (
                <>
                  <span class="muted">/</span>
                  <button type="button" class="quiet" onClick={() => open(account(), node.id)}>
                    {label(node)}
                  </button>
                </>
              )}
            </For>
          </nav>
          <span class="grow" />
          <button type="button" class="quiet" onClick={() => setConnecting(true)}>
            {t("Connect a file manager")}
          </button>
          <Show when={!inTrash() && here().mayAddChildren}>
            <button type="button" disabled={busy()} onClick={newDirectory}>
              {t("New folder")}
            </button>
            <label class="button primary" classList={{ disabled: busy() }}>
              {t("Upload")}
              <input type="file" multiple hidden disabled={busy()} onChange={(event) => upload(event.currentTarget.files)} />
            </label>
          </Show>
        </div>
        <Failure error={error() ?? list.error ?? trail.error} />
        <For each={uploads()}>
          {(entry) => (
            <div class="progress">
              <span class="small">{entry.name}</span>
              <progress max={entry.total || 1} value={entry.sent} />
              <span class="muted small">
                {formatSize(entry.sent, locale)} / {formatSize(entry.total, locale)}
              </span>
            </div>
          )}
        </For>
        <Show when={ok(list)?.length === 0}>
          <p class="muted pad">{inTrash() ? t("The trash is empty") : here().mayAddChildren ? t("No files yet – drop some here") : t("Nothing here")}</p>
        </Show>
        <table class="nodes">
          <tbody>
            <For each={sortNodes(ok(list) ?? [], locale)}>
              {(node) => {
                const rights = () => rightsOf(node);
                const shared = () => Object.keys(node.shareWith ?? {}).length > 0;
                return (
                  <tr>
                    <td class="name">
                      <Show
                        when={isDirectory(node)}
                        fallback={
                          <Show when={node.blobId} fallback={<span>{node.name}</span>}>
                            <button type="button" class="quiet file" onClick={() => setViewing(node)}>
                              {node.name}
                            </button>
                          </Show>
                        }
                      >
                        <button type="button" class="quiet folder" onClick={() => open(account(), node.id)}>
                          {label(node)}
                        </button>
                        <Show when={shared()}>
                          <span class="muted small"> · {t("Shared")}</span>
                        </Show>
                      </Show>
                    </td>
                    <td class="muted small">{node.size == null ? "" : formatSize(node.size, locale)}</td>
                    <td class="muted small">{node.modified ? new Date(node.modified).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" }) : ""}</td>
                    <td class="end">
                      <Show when={!node.role}>
                        <Show when={isDirectory(node) && rights().mayShare}>
                          <button type="button" class="quiet" disabled={busy()} onClick={() => setSharing(node)}>
                            {t("Share")}
                          </button>
                        </Show>
                        <Show when={rights().mayShare && linksAvailable(jmap)}>
                          <button type="button" class="quiet" disabled={busy()} onClick={() => setLinking(node)}>
                            {t("Link")}
                          </button>
                        </Show>
                        <Show when={!isDirectory(node) && rights().mayRead}>
                          <button type="button" class="quiet" disabled={busy()} onClick={() => setHistory(node)}>
                            {t("Versions")}
                          </button>
                        </Show>
                        <Show when={rights().mayRename}>
                          <button type="button" class="quiet" disabled={busy()} onClick={() => renameNode(node)}>
                            {t("Rename")}
                          </button>
                        </Show>
                        <Show when={rights().mayDelete}>
                          <button type="button" class="quiet danger" disabled={busy()} onClick={() => remove(node)}>
                            {inTrash() || !bin() ? t("Delete for good") : t("Delete")}
                          </button>
                        </Show>
                      </Show>
                    </td>
                  </tr>
                );
              }}
            </For>
          </tbody>
        </table>
      </div>
      <Show when={sharing()}>
        {(node) => (
          <ShareDialog
            account={account()}
            node={node()}
            onClose={(saved) => {
              setSharing(undefined);
              if (saved) touch("FileNode");
            }}
          />
        )}
      </Show>
      <Show when={linking()}>{(node) => <LinkDialog account={account()} node={node()} onClose={() => setLinking(undefined)} />}</Show>
      <Show when={viewing()}>
        {(node) => (
          <Viewer
            name={node().name}
            type={node().mediaType}
            size={node().size ?? null}
            url={downloadPath(jmap, account(), node().blobId ?? "", node().name, node().mediaType)}
            inline={`${downloadPath(jmap, account(), node().blobId ?? "", node().name, node().mediaType)}&inline=1`}
            onClose={() => setViewing(undefined)}
          />
        )}
      </Show>
      <Show when={connecting()}>
        <div class="overlay" role="dialog" aria-modal="true" aria-label={t("Connect a file manager")}>
          <div class="dialog">
            <h2>{t("Connect a file manager")}</h2>
            <p class="muted">{t("Your files also appear in Finder, Explorer or the file manager of your phone (WebDAV).")}</p>
            <WebDavHelp address={jmap.session.username} />
            <div class="actions end">
              <a class="button" href="#/account">{t("Make an app password")}</a>
              <button type="button" class="primary" onClick={() => setConnecting(false)}>
                {t("Close")}
              </button>
            </div>
          </div>
        </div>
      </Show>
      <Show when={history()}>
        {(node) => (
          <VersionsDialog
            account={account()}
            node={node()}
            mayRestore={rightsOf(node()).mayModifyContent}
            onClose={(restored) => {
              setHistory(undefined);
              if (restored) touch("FileNode");
            }}
          />
        )}
      </Show>
    </div>
  );
}

type Level = keyof typeof LEVELS;

/** With whom a folder is shared, and at which level: read, edit, or full (which may share on). */
function ShareDialog(props: { account: string; node: FileNode; onClose: (saved: boolean) => void }): JSX.Element {
  const jmap = useJmap();
  const [entries, setEntries] = createSignal<{ principal: Principal; level: Level }[]>([]);
  const [search, setSearch] = createSignal("");
  const [error, setError] = createSignal<unknown>();
  const current = props.node.shareWith ?? {};
  void principals(jmap, Object.keys(current))
    .then((known) => setEntries(known.map((principal) => ({ principal, level: level(current[principal.id] ?? LEVELS.read) }))))
    .catch(setError);
  const [found] = createResource(search, (text) => (text.trim().length >= 2 ? findPrincipals(jmap, text) : Promise.resolve([])));

  const add = (principal: Principal) => {
    if (!entries().some((entry) => entry.principal.id === principal.id)) setEntries([...entries(), { principal, level: "read" }]);
    setSearch("");
  };

  const save = async (event: SubmitEvent) => {
    event.preventDefault();
    const shareWith: Record<string, Rights> = {};
    for (const entry of entries()) shareWith[entry.principal.id] = LEVELS[entry.level];
    try {
      await share(jmap, props.account, props.node, shareWith);
      props.onClose(true);
    } catch (failure) {
      setError(failure);
    }
  };

  return (
    <div class="overlay" role="dialog" aria-modal="true" aria-label={t("Share")}>
      <form class="dialog" onSubmit={(event) => void save(event)}>
        <h2>
          {t("Share")} „{props.node.name}“
        </h2>
        <ul class="items shares">
          <For each={entries()}>
            {(entry, index) => (
              <li class="row">
                <span class="grow">
                  {entry.principal.name}
                  <span class="muted small"> {entry.principal.type === "group" ? t("Group") : (entry.principal.email ?? "")}</span>
                </span>
                <select
                  value={entry.level}
                  onChange={(event) =>
                    setEntries(entries().map((other, at) => (at === index() ? { ...other, level: event.currentTarget.value as Level } : other)))
                  }
                >
                  <option value="read">{t("Can view")}</option>
                  <option value="edit">{t("Can edit")}</option>
                  <option value="full">{t("Can edit and share")}</option>
                </select>
                <button type="button" class="quiet danger" onClick={() => setEntries(entries().filter((_, at) => at !== index()))}>
                  {t("Remove")}
                </button>
              </li>
            )}
          </For>
        </ul>
        <label>
          <span>{t("Add people or groups")}</span>
          <input type="search" value={search()} placeholder={t("Name or address")} onInput={(event) => setSearch(event.currentTarget.value)} />
        </label>
        <ul class="items">
          <For each={(ok(found) ?? []).filter((principal) => !entries().some((entry) => entry.principal.id === principal.id))}>
            {(principal) => (
              <li>
                <button type="button" onClick={() => add(principal)}>
                  <span class="who">{principal.name}</span>
                  <span class="preview">{principal.type === "group" ? t("Group") : (principal.email ?? "")}</span>
                </button>
              </li>
            )}
          </For>
        </ul>
        <Failure error={error()} />
        <div class="actions end">
          <button type="button" class="quiet" onClick={() => props.onClose(false)}>
            {t("Cancel")}
          </button>
          <button type="submit" class="primary">
            {t("Save")}
          </button>
        </div>
      </form>
    </div>
  );
}

/** Links to a file or folder for people without an account: made with an expiry and a password if wanted, shown
 * once when made (kernoid keeps only a hash), removed when no longer wanted. */
function LinkDialog(props: { account: string; node: FileNode; onClose: () => void }): JSX.Element {
  const jmap = useJmap();
  const [list, { refetch }] = createResource(() => links(jmap, props.account, props.node));
  const [made, setMade] = createSignal<string>();
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await work();
      await refetch();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };
  const make = (event: SubmitEvent) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    const date = String(form.get("expires") ?? "");
    const password = String(form.get("password") ?? "");
    // The link works through the whole day chosen.
    const expires = date ? new Date(`${date}T23:59:59`).toISOString() : null;
    void run(async () => {
      setMade(await createLink(jmap, props.account, props.node, expires, password || null));
      (event.currentTarget as HTMLFormElement | null)?.reset();
    });
  };
  const when = (date: string) => new Date(date).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });

  return (
    <div class="overlay" role="dialog" aria-modal="true" aria-label={t("Links")}>
      <div class="dialog">
        <h2>
          {t("Links")} „{props.node.name}“
        </h2>
        <p class="muted small">{t("Anyone with a link can view and download what it leads to – without an account.")}</p>
        <Show when={made()}>
          {(url) => (
            <div class="notice">
              <p>{t("The new link – copy it now; it is not shown again:")}</p>
              <div class="row">
                <input class="grow" readOnly value={url()} onFocus={(event) => event.currentTarget.select()} />
                <button type="button" onClick={() => void navigator.clipboard?.writeText(url())}>
                  {t("Copy")}
                </button>
              </div>
            </div>
          )}
        </Show>
        <table class="nodes">
          <tbody>
            <For each={ok(list) ?? []} fallback={<tr><td class="muted">{t("No links yet.")}</td></tr>}>
              {(link: FileLink) => (
                <tr>
                  <td class="small">
                    {t("made {date}", { date: when(link.created) })}
                    <div class="muted">
                      {link.expires ? t("valid until {date}", { date: when(link.expires) }) : t("no expiry")}
                      {link.hasPassword ? ` · ${t("with password")}` : ""}
                    </div>
                  </td>
                  <td class="end">
                    <button type="button" class="quiet danger" disabled={busy()} onClick={() => void run(() => removeLink(jmap, props.account, link))}>
                      {t("Remove")}
                    </button>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
        <form onSubmit={make}>
          <h3>{t("New link")}</h3>
          <label>
            <span>{t("Valid until (optional)")}</span>
            <input type="date" name="expires" min={new Date().toISOString().slice(0, 10)} />
          </label>
          <label>
            <span>{t("Password (optional)")}</span>
            <input type="password" name="password" autocomplete="new-password" />
          </label>
          <Failure error={error() ?? list.error} />
          <div class="actions end">
            <button type="button" class="quiet" onClick={() => props.onClose()}>
              {t("Close")}
            </button>
            <button type="submit" class="primary" disabled={busy()}>
              {t("Make a link")}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/** A file's current content and its earlier versions, each to download; an earlier one can become current again. */
function VersionsDialog(props: { account: string; node: FileNode; mayRestore: boolean; onClose: (restored: boolean) => void }): JSX.Element {
  const jmap = useJmap();
  const [list] = createResource(() => versions(jmap, props.account, props.node));
  const [error, setError] = createSignal<unknown>();
  const when = (date: string) => new Date(date).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });

  return (
    <div class="overlay" role="dialog" aria-modal="true" aria-label={t("Versions")}>
      <div class="dialog">
        <h2>
          {t("Versions")} „{props.node.name}“
        </h2>
        <table class="nodes">
          <tbody>
            <For each={ok(list) ?? []}>
              {(version) => (
                <tr>
                  <td class="name">
                    <a href={downloadPath(jmap, props.account, version.blobId, props.node.name, props.node.mediaType)} download={props.node.name}>
                      {when(version.modified)}
                    </a>
                    <Show when={version.isCurrent}>
                      <span class="muted small"> · {t("Current")}</span>
                    </Show>
                  </td>
                  <td class="muted small">{formatSize(version.size, locale)}</td>
                  <td class="end">
                    <Show when={!version.isCurrent && props.mayRestore}>
                      <button
                        type="button"
                        class="quiet"
                        onClick={() =>
                          void restore(jmap, props.account, props.node, version)
                            .then(() => props.onClose(true))
                            .catch(setError)
                        }
                      >
                        {t("Restore")}
                      </button>
                    </Show>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
        <Failure error={error() ?? list.error} />
        <div class="actions end">
          <button type="button" class="primary" onClick={() => props.onClose(false)}>
            {t("Close")}
          </button>
        </div>
      </div>
    </div>
  );
}
