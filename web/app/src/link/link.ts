// SPDX-License-Identifier: MIT
// What a link opens (RFC 0005, 11.3), for people without an account: link.html#<token>. The token stays in the
// fragment, which the browser does not send; the page (LinkPage.svelte) asks /v1/links/<token> – for the password
// first, where the link has one. No session, no JMAP.

import { t } from "../i18n.js";

export interface LinkNode {
  id: string;
  parentId: string | null;
  name: string;
  nodeType: "directory" | "file";
  size: number | null;
  mediaType: string | null;
  modified: string;
}

export interface LinkInfo {
  node: LinkNode;
  mayRead: boolean;
  mayAdd: boolean;
}

/** A file on its way in, or arrived. */
export interface Sending {
  id: number;
  name: string;
  total: number;
  sent: number;
  /** The name it got – a taken one gets a number. */
  added?: string;
  failed?: string;
}

export const token = decodeURIComponent(window.location.hash.replace(/^#/, ""));
export const base = `/v1/links/${encodeURIComponent(token)}`;
/** The access token of a link opened with its password, for this tab. */
export const ACCESS_KEY = `kernoid-link-${token}`;

export function storedAccess(): string {
  try {
    return sessionStorage.getItem(ACCESS_KEY) ?? "";
  } catch {
    return "";
  }
}

export class LinkFailure extends Error {
  constructor(readonly status: number) {
    super(status === 404 ? t("This link does not exist or has expired.") : t("The link could not be opened ({status}).", { status }));
  }
}

export async function get<T>(path: string, access: string): Promise<T> {
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
export function addFile(file: File, parent: string | undefined, access: string, progress: (sent: number) => void): Promise<LinkNode> {
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

export function download(node: LinkNode, access: string, inline = false): string {
  return `${base}/download/${encodeURIComponent(node.id)}?access=${encodeURIComponent(access)}${inline ? "&inline=1" : ""}`;
}
