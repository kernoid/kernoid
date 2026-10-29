// SPDX-License-Identifier: MIT
// What every administration page shares: actions that tell how they ended, the tenant's directory (accounts and
// groups, for names and choosers), the way between pages, and how values are shown and read.

import { getContext, setContext } from "svelte";

import { t } from "../i18n.js";
import type { AccountDetails, GroupView } from "./api.svelte.js";

/** Runs changes one at a time and tells how they ended. */
export class Action {
  busy = $state(false);
  error = $state<unknown>();
  notice = $state<string>();

  async run(work: () => Promise<unknown>, done?: string): Promise<boolean> {
    this.busy = true;
    this.error = undefined;
    this.notice = undefined;
    try {
      await work();
      if (done) this.notice = done;
      return true;
    } catch (failure) {
      this.error = failure;
      return false;
    } finally {
      this.busy = false;
    }
  }

  say(text: string | undefined): void {
    this.notice = text;
  }
}

/** The tenant's accounts and groups, for names and choosers on every page. */
export interface Directory {
  readonly accounts: AccountDetails[];
  readonly groups: GroupView[];
  /** Whether the accounts or groups are still on their way. */
  readonly loading: boolean;
  reload(): void;
  name(kind: string, id: string): string;
}

const DIRECTORY = Symbol("directory");

export function provideDirectory(directory: Directory): void {
  setContext(DIRECTORY, directory);
}

export function useDirectory(): Directory {
  const directory = getContext<Directory | undefined>(DIRECTORY);
  if (!directory) throw new Error("no directory");
  return directory;
}

export function go(page: string, id?: string): void {
  window.location.hash = `#/admin/${page}${id ? `/${encodeURIComponent(id)}` : ""}`;
}

/** `account:<id>` → ["account", id]. */
export function principal(value: string): [string, string] {
  const at = value.indexOf(":");
  return [value.slice(0, at), value.slice(at + 1)];
}

export const when = (date: string | null | undefined) => (date ? new Date(date).toLocaleString() : "–");

/** Bytes as "1.5 GB"; none as "no limit". */
export function bytes(value: number | null | undefined): string {
  if (value == null) return t("no limit");
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {
    size /= 1000;
    unit++;
  }
  return `${size.toLocaleString(undefined, { maximumFractionDigits: 1 })} ${units[unit]}`;
}

/** "5 GB", "500 MB" or a plain number of bytes; empty for no limit. */
export function parseBytes(text: string): number | null {
  const match = text.trim().match(/^(\d+(?:[.,]\d+)?)\s*(b|kb|mb|gb|tb)?$/i);
  if (!text.trim()) return null;
  if (!match) throw new Error(t("Give a size such as 5 GB or 500 MB, or nothing for no limit."));
  const factor = { b: 1, kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12 }[(match[2] ?? "b").toLowerCase() as "b"];
  return Math.round(Number.parseFloat((match[1] ?? "0").replace(",", ".")) * factor);
}

/** Text for a list of lines (one per line) and back. */
export const lines = (list: string[] | null | undefined) => (list ?? []).join("\n");
export const toList = (text: string) =>
  text
    .split(/[\n,]/)
    .map((line) => line.trim())
    .filter(Boolean);
