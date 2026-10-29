// SPDX-License-Identifier: MIT
// A file shown in place: images, audio and video as the browser plays them, PDFs in the browser's viewer, text as
// text. The browser loads the content from the download URL with the session's cookie; the server serves it with a
// policy that keeps it from running as a page (jmap.rs, download_response). Office documents and the rest: download.

import { type JSX, Match, Show, Switch, createResource, onCleanup, onMount } from "solid-js";

import { Failure, ok } from "../App.js";
import { t } from "../i18n.js";

export type Kind = "image" | "audio" | "video" | "pdf" | "text" | "other";

const TEXT_TYPES = /^(text\/|application\/(json|xml|javascript|x-sh|x-yaml|yaml|toml|x-toml|sql|ld\+json))/;
const TEXT_NAMES = /\.(txt|md|markdown|csv|tsv|log|json|xml|ya?ml|toml|ini|conf|cfg|sh|py|rs|ts|tsx|js|jsx|css|html?|sql|ics|vcf|eml)$/i;
const EXTENSIONS: [RegExp, Kind][] = [
  [/\.(png|jpe?g|gif|webp|avif|svg|bmp|ico)$/i, "image"],
  [/\.(mp3|m4a|aac|ogg|oga|opus|wav|flac|weba)$/i, "audio"],
  [/\.(mp4|m4v|webm|ogv|mov)$/i, "video"],
  [/\.pdf$/i, "pdf"],
];

/** How a file can be shown, from its type – or its name, where the type says little. */
export function kindOf(name: string, type: string | null | undefined): Kind {
  const media = (type ?? "").toLowerCase();
  if (media.startsWith("image/")) return "image";
  if (media.startsWith("audio/")) return "audio";
  if (media.startsWith("video/")) return "video";
  if (media === "application/pdf") return "pdf";
  if (TEXT_TYPES.test(media)) return "text";
  for (const [pattern, kind] of EXTENSIONS) if (pattern.test(name)) return kind;
  return TEXT_NAMES.test(name) ? "text" : "other";
}

/** Text larger than this is not shown, only downloaded. */
const TEXT_LIMIT = 2 * 1024 * 1024;

async function text(url: string, size: number | null): Promise<string> {
  if (size != null && size > TEXT_LIMIT) throw new Error(t("Too large to show – download it instead."));
  const response = await fetch(url, { credentials: "same-origin" });
  if (!response.ok) throw new Error(t("The file could not be loaded ({status}).", { status: response.status }));
  return response.text();
}

/** `url` saves the file; `inline` shows it in place (the server's `inline=1`). */
export function Viewer(props: { name: string; type: string | null | undefined; size: number | null; url: string; inline: string; onClose: () => void }): JSX.Element {
  const kind = kindOf(props.name, props.type);
  const [content] = createResource(() => (kind === "text" ? text(props.inline, props.size) : Promise.resolve("")));
  const onKey = (event: KeyboardEvent) => {
    if (event.key === "Escape") props.onClose();
  };
  onMount(() => window.addEventListener("keydown", onKey));
  onCleanup(() => window.removeEventListener("keydown", onKey));

  return (
    <div class="overlay viewer" role="dialog" aria-modal="true" aria-label={props.name} onClick={(event) => event.target === event.currentTarget && props.onClose()}>
      <div class="sheet">
        <header class="toolbar">
          <h2 class="grow">{props.name}</h2>
          <Show when={kind === "pdf"}>
            {/* Some browsers – on phones especially – show no PDF in a frame. */}
            <a class="button" href={props.inline} target="_blank" rel="noopener">
              {t("Open in a new tab")}
            </a>
          </Show>
          <a class="button" href={props.url} download={props.name}>
            {t("Download")}
          </a>
          <button type="button" onClick={() => props.onClose()}>
            {t("Close")}
          </button>
        </header>
        <div class="stage">
          <Switch>
            <Match when={kind === "image"}>
              <img src={props.inline} alt={props.name} />
            </Match>
            <Match when={kind === "audio"}>
              <audio controls autoplay src={props.inline} />
            </Match>
            <Match when={kind === "video"}>
              <video controls autoplay src={props.inline} />
            </Match>
            <Match when={kind === "pdf"}>
              <iframe src={props.inline} title={props.name} />
            </Match>
            <Match when={kind === "text"}>
              <Failure error={content.error} />
              <Show when={ok(content) !== undefined} fallback={<p class="muted">{t("Loading")}</p>}>
                <pre class="text">{ok(content)}</pre>
              </Show>
            </Match>
            <Match when={kind === "other"}>
              <p class="muted">{t("There is no preview for this file. Download it to open it.")}</p>
            </Match>
          </Switch>
        </div>
      </div>
    </div>
  );
}
