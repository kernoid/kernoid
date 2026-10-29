// SPDX-License-Identifier: MIT
// What a link opens (RFC 0005, 11.3), for people without an account: link.html#<token>. The token stays in the
// fragment, which the browser does not send; the page asks /v1/links/<token> – for the password first, where the link
// has one – and lists, shows and downloads what the link leads to. No session, no JMAP.

import { For, type JSX, Show, createResource, createSignal } from "solid-js";
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

function download(node: LinkNode, access: string, inline = false): string {
  return `${base}/download/${encodeURIComponent(node.id)}?access=${encodeURIComponent(access)}${inline ? "&inline=1" : ""}`;
}

function LinkPage(): JSX.Element {
  const [access, setAccess] = createSignal(storedAccess());
  const [root] = createResource(access, (key) => get<{ node: LinkNode }>("", key).then((answer) => answer.node));
  const [trail, setTrail] = createSignal<LinkNode[]>([]);
  // Reading a resource that failed throws: only a loaded one counts.
  const loaded = () => (root.state === "ready" ? root() : undefined);
  const here = () => trail().at(-1) ?? loaded();
  const [list] = createResource(
    () => {
      const node = here();
      return node?.nodeType === "directory" ? { node, key: access() } : undefined;
    },
    ({ node, key }) => get<LinkNode[]>(node.id === loaded()?.id ? "/nodes" : `/nodes?parent=${encodeURIComponent(node.id)}`, key),
  );
  const [viewing, setViewing] = createSignal<LinkNode>();
  const [failure, setFailure] = createSignal<string>();
  const locked = () => root.error instanceof LinkFailure && root.error.status === 401;
  const when = (date: string) => new Date(date).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });

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
    <main class="link-page">
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
            <Show when={list.error}>
              <p class="error pad">{(list.error as Error).message}</p>
            </Show>
            <table class="nodes">
              <tbody>
                <For each={list() ?? []} fallback={<tr><td class="muted">{t("Nothing here")}</td></tr>}>
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
