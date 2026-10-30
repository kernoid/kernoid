// SPDX-License-Identifier: MIT
// Short messages at the bottom of the window ("Sent"), each gone after a while – some with an action ("Undo") that
// works until then. Toasts.svelte shows them.

export interface Toast {
  id: number;
  text: string;
  kind: "info" | "error";
  action?: { label: string; run: () => void | Promise<void> };
  /** When it goes, for a countdown. */
  until: number;
}

const shown = $state<{ list: Toast[] }>({ list: [] });
let next = 0;

export function toasts(): Toast[] {
  return shown.list;
}

export function dismiss(id: number): void {
  shown.list = shown.list.filter((toast) => toast.id !== id);
}

/** Shows a toast for `seconds`; returns its id. */
export function toast(text: string, options: { kind?: Toast["kind"]; action?: Toast["action"]; seconds?: number } = {}): number {
  const id = ++next;
  const seconds = options.seconds ?? 4;
  const entry: Toast = { id, text, kind: options.kind ?? "info", until: Date.now() + seconds * 1000 };
  if (options.action) entry.action = options.action;
  shown.list = [...shown.list, entry];
  setTimeout(() => dismiss(id), seconds * 1000);
  return id;
}
