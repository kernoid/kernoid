// SPDX-License-Identifier: MIT
// What a link opens (RFC 0005, 11.3), for people without an account: link.html#<token>. The token stays in the
// fragment, which the browser does not send; the page asks /v1/links/<token> – for the password first, where the link
// has one – and lists, shows and downloads what the link leads to; where the link lets people add files to a folder,
// they are uploaded with progress (also by dropping them), into a drop box without seeing what is in it. No session,
// no JMAP.

import { For, Index, type JSX, Show, createResource, createSignal } from "solid-js";
import { render } from "solid-js/web";

import { Viewer } from "../files/Viewer.js";
import { formatSize } from "../files/model.js";
import { locale, setDocumentLanguage, t } from "../i18n.js";
import "../style.css";
import "../theme.js";

interface LinkNode {
  id: string;
  parentId: string | null;
  name: string;
  nodeType: "directory" | "file";
  size: number | null;
  mediaType: string | null;
  modified: string;
}

interface LinkInfo {
  node: LinkNode;
  mayRead: boolean;
  mayAdd: boolean;
}

/** A file on its way in, or arrived. */
interface Sending {
  id: number;
  name: string;
  total: number;
  sent: number;
  /** The name it got – a taken one gets a number. */
  added?: string;
  failed?: string;
}

const token = decodeURIComponent(window.location.hash.replace(/^#/, ""));
const base = `/v1/links/${encodeURIComponent(token)}`;
/** The access token of a link opened with its password, for this tab. */
const ACCESS_KEY = `kernoid-link-${token}`;

function storedAccess(): string {
  try {
    return sessionStorage.getItem(ACCESS_KEY) ?? "";
  } catch {
    return "";
  }
}

class LinkFailure extends Error {
  constructor(readonly status: number) {
    super(status === 404 ? t("This link does not exist or has expired.") : t("The link could not be opened ({status}).", { status }));
  }
}

async function get<T>(path: string, access: string): Promise<T> {
  const separator = path.includes("?") ? "&" : "?";
  const response = await fetch(`${base}${path}${separator}access=${encodeURIComponent(access)}`, { headers: { accept: "application/json" } });
  if (!response.ok) throw new LinkFailure(response.status);
  return (await response.json()) as T;
}

function addFailure(status: number, detail: string | undefined): string {
  if (status === 413) return t("The file is too large.");
  if (status === 507) return t("There is no room left for it.");
  return detail ?? t("The file could not be added ({status}).", { status });
}

/** Adds a file to the folder `parent` – the link's own if not given –, reporting the bytes sent. */
function addFile(file: File, parent: string | undefined, access: string, progress: (sent: number) => void): Promise<LinkNode> {
  return new Promise((resolve, reject) => {
    const query = new URLSearchParams({ name: file.name, access });
    if (parent) query.set("parent", parent);
    const request = new XMLHttpRequest();
    request.open("POST", `${base}/files?${query}`);
    request.setRequestHeader("content-type", file.type || "application/octet-stream");
    request.setRequestHeader("accept", "application/json");
    request.upload.onprogress = (event) => progress(event.loaded);
    request.onload = () => {
      let answer: Partial<LinkNode> & { detail?: string } = {};
      try {
        answer = JSON.parse(request.responseText) as typeof answer;
      } catch {
        // No JSON: the status says it.
      }
      if (request.status === 201) resolve(answer as LinkNode);
      else reject(new Error(addFailure(request.status, answer.detail)));
    };
    request.onerror = () => reject(new Error(t("The connection broke off.")));
    request.send(file);
  });
}

function download(node: LinkNode, access: string, inline = false): string {
  return `${base}/download/${encodeURIComponent(node.id)}?access=${encodeURIComponent(access)}${inline ? "&inline=1" : ""}`;
}

function LinkPage(): JSX.Element {
  const [access, setAccess] = createSignal(storedAccess());
  const [root] = createResource(access, (key) => get<LinkInfo>("", key));
  const [trail, setTrail] = createSignal<LinkNode[]>([]);
  // Reading a resource that failed throws: only a loaded one counts.
  const info = () => (root.state === "ready" ? root() : undefined);
  const loaded = () => info()?.node;
  const here = () => trail().at(-1) ?? loaded();
  const [list, { refetch: refetchList }] = createResource(
    () => {
      const node = here();
      return node?.nodeType === "directory" && info()?.mayRead ? { node, key: access() } : undefined;
    },
    ({ node, key }) => get<LinkNode[]>(node.id === loaded()?.id ? "/nodes" : `/nodes?parent=${encodeURIComponent(node.id)}`, key),
  );
  const [viewing, setViewing] = createSignal<LinkNode>();
  const [failure, setFailure] = createSignal<string>();
  const locked = () => root.error instanceof LinkFailure && root.error.status === 401;
  const when = (date: string) => new Date(date).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
  const [sending, setSending] = createSignal<Sending[]>([]);
  const [dragging, setDragging] = createSignal(false);
  let nextId = 0;
  const update = (id: number, change: Partial<Sending>) =>
    setSending((list) => list.map((entry) => (entry.id === id ? { ...entry, ...change } : entry)));
  // One file after the other, into the folder shown.
  const addAll = async (files: FileList | null | undefined) => {
    if (!files?.length || !info()?.mayAdd) return;
    const parent = trail().at(-1)?.id;
    const queued = [...files].map((file) => ({ file, id: nextId++ }));
    setSending([...sending(), ...queued.map(({ file, id }) => ({ id, name: file.name, total: file.size, sent: 0 }))]);
    for (const { file, id } of queued) {
      try {
        const added = await addFile(file, parent, access(), (sent) => update(id, { sent }));
        update(id, { sent: file.size, added: added.name });
        if (info()?.mayRead) void refetchList();
      } catch (failure) {
        update(id, { failed: (failure as Error).message });
      }
    }
  };

  const unlock = async (event: SubmitEvent) => {
    event.preventDefault();
    const password = String(new FormData(event.currentTarget as HTMLFormElement).get("password") ?? "");
    const response = await fetch(`${base}/unlock`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ password }),
    });
    if (!response.ok) {
      setFailure(response.status === 429 ? t("Too many attempts – try again later.") : t("The password is not right."));
      return;
    }
    const { access: key } = (await response.json()) as { access: string };
    try {
      sessionStorage.setItem(ACCESS_KEY, key);
    } catch {
      // Without storage the link opens for this page only.
    }
    setFailure(undefined);
    setAccess(key);
  };

  return (
    <main
      class="link-page"
      classList={{ dropping: dragging() }}
      onDragOver={(event) => {
        event.preventDefault();
        if (info()?.mayAdd && here()?.nodeType === "directory") setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        void addAll(event.dataTransfer?.files);
      }}
    >
      <header class="toolbar">
        <h1 class="grow">kern0id</h1>
      </header>
      <Show when={locked()}>
        <form class="dialog" onSubmit={(event) => void unlock(event)}>
          <h2>{t("This link has a password")}</h2>
          <label>
            <span>{t("Password")}</span>
            <input type="password" name="password" required autocomplete="off" />
          </label>
          <Show when={failure()}>
            <p class="error">{failure()}</p>
          </Show>
          <div class="actions end">
            <button type="submit" class="primary">
              {t("Open")}
            </button>
          </div>
        </form>
      </Show>
      <Show when={root.error && !locked()}>
        <p class="error pad">{(root.error as Error).message}</p>
      </Show>
      <Show when={loaded()}>
        {(node) => (
          <Show
            when={node().nodeType === "directory"}
            fallback={
              <section class="pad">
                <h2>{node().name}</h2>
                <p class="muted">
                  {formatSize(node().size ?? 0, locale)} · {when(node().modified)}
                </p>
                <div class="actions">
                  <button type="button" onClick={() => setViewing(node())}>
                    {t("Show")}
                  </button>
                  <a class="button primary" href={download(node(), access())}>
                    {t("Download")}
                  </a>
                </div>
              </section>
            }
          >
            <Show when={info()?.mayRead} fallback={<h2 class="pad">{node().name}</h2>}>
              <nav class="trail">
                <button type="button" class="quiet" onClick={() => setTrail([])}>
                  {node().name}
                </button>
                <For each={trail()}>
                  {(step, index) => (
                    <>
                      {" / "}
                      <button type="button" class="quiet" onClick={() => setTrail(trail().slice(0, index() + 1))}>
                        {step.name}
                      </button>
                    </>
                  )}
                </For>
              </nav>
            </Show>
            <Show when={info()?.mayAdd}>
              <section class="add-files pad">
                <p>
                  {info()?.mayRead
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
                      onChange={(event) => {
                        void addAll(event.currentTarget.files);
                        event.currentTarget.value = "";
                      }}
                    />
                  </label>
                  <span class="muted small">{t("or drop them on this page")}</span>
                </div>
                <Index each={sending()}>
                  {(entry) => (
                    <div class="progress">
                      <span class="small">{entry().name}</span>
                      <Show
                        when={entry().added ?? entry().failed}
                        fallback={<progress max={entry().total || 1} value={entry().sent} />}
                      >
                        <span classList={{ small: true, error: !!entry().failed }}>
                          {entry().failed ?? (entry().added === entry().name ? t("added") : t("added as {name}", { name: entry().added ?? "" }))}
                        </span>
                      </Show>
                      <span class="muted small">{formatSize(entry().total, locale)}</span>
                    </div>
                  )}
                </Index>
              </section>
            </Show>
            <Show when={list.error}>
              <p class="error pad">{(list.error as Error).message}</p>
            </Show>
            <Show when={info()?.mayRead}>
            <table class="nodes">
              <tbody>
                <For each={list() ?? []} fallback={<tr><td class="muted">{list.loading ? t("Loading") : t("Nothing here")}</td></tr>}>
                  {(child) => (
                    <tr>
                      <td class="name">
                        <Show
                          when={child.nodeType === "directory"}
                          fallback={
                            <button type="button" class="quiet file" onClick={() => setViewing(child)}>
                              {child.name}
                            </button>
                          }
                        >
                          <button type="button" class="quiet folder" onClick={() => setTrail([...trail(), child])}>
                            {child.name}
                          </button>
                        </Show>
                      </td>
                      <td class="muted small">{child.size == null ? "" : formatSize(child.size, locale)}</td>
                      <td class="muted small">{when(child.modified)}</td>
                      <td class="end">
                        <Show when={child.nodeType === "file"}>
                          <a class="button quiet" href={download(child, access())}>
                            {t("Download")}
                          </a>
                        </Show>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
            </Show>
          </Show>
        )}
      </Show>
      <Show when={viewing()}>
        {(node) => (
          <Viewer
            name={node().name}
            type={node().mediaType}
            size={node().size}
            url={download(node(), access())}
            inline={download(node(), access(), true)}
            onClose={() => setViewing(undefined)}
          />
        )}
      </Show>
    </main>
  );
}

setDocumentLanguage();
// Another link in the same tab: start over.
window.addEventListener("hashchange", () => window.location.reload());
const element = document.getElementById("app");
if (element) render(() => <LinkPage />, element);
