// SPDX-License-Identifier: MIT
// How a file can be shown in place (Viewer.svelte): images, audio and video as the browser plays them, PDFs in the
// browser's viewer, text as text – and loading the text.

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

export async function text(url: string, size: number | null): Promise<string> {
  if (size != null && size > TEXT_LIMIT) throw new Error(t("Too large to show – download it instead."));
  const response = await fetch(url, { credentials: "same-origin" });
  if (!response.ok) throw new Error(t("The file could not be loaded ({status}).", { status: response.status }));
  return response.text();
}
