// SPDX-License-Identifier: MIT
// The pieces every administration page is made of: actions that show what came of them, dialogs with forms, fields.

import { type JSX, type ParentProps, Show, createSignal, onCleanup, onMount, splitProps } from "solid-js";

import { Failure } from "../App.js";
import { t } from "../i18n.js";

/** Runs changes one at a time and tells how they ended. */
export function useAction() {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const [notice, setNotice] = createSignal<string>();
  const run = async (work: () => Promise<unknown>, done?: string): Promise<boolean> => {
    setBusy(true);
    setError(undefined);
    setNotice(undefined);
    try {
      await work();
      if (done) setNotice(done);
      return true;
    } catch (failure) {
      setError(failure);
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, notice, run, setError };
}

export type Action = ReturnType<typeof useAction>;

export function Outcome(props: { action: Action }): JSX.Element {
  return (
    <>
      <Show when={props.action.notice()}>
        <p class="notice" role="status">
          {props.action.notice()}
        </p>
      </Show>
      <Failure error={props.action.error()} />
    </>
  );
}

/** A modal dialog; Escape or a click beside it closes it. */
export function Dialog(props: ParentProps<{ title: string; onClose: () => void; wide?: boolean }>): JSX.Element {
  const onKey = (event: KeyboardEvent) => event.key === "Escape" && props.onClose();
  onMount(() => window.addEventListener("keydown", onKey));
  onCleanup(() => window.removeEventListener("keydown", onKey));
  return (
    <div class="overlay" role="dialog" aria-modal="true" aria-label={props.title} onClick={(event) => event.target === event.currentTarget && props.onClose()}>
      <div class="dialog" classList={{ wide: props.wide }}>
        <h2>{props.title}</h2>
        {props.children}
      </div>
    </div>
  );
}

/** A form whose fields arrive by name, trimmed; checkboxes as "on" or missing. */
export function Form(props: ParentProps<{ submit: (field: (name: string) => string, all: (name: string) => string[]) => void; class?: string }>): JSX.Element {
  return (
    <form
      class={props.class}
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        props.submit(
          (name) => String(data.get(name) ?? "").trim(),
          (name) => data.getAll(name).map((value) => String(value)),
        );
      }}
    >
      {props.children}
    </form>
  );
}

export function Field(props: { label: string; hint?: string } & JSX.InputHTMLAttributes<HTMLInputElement>): JSX.Element {
  const [own, input] = splitProps(props, ["label", "hint"]);
  return (
    <label>
      <span>{own.label}</span>
      <input {...input} />
      <Show when={own.hint}>
        <small class="muted">{own.hint}</small>
      </Show>
    </label>
  );
}

export function Check(props: { label: string; name: string; value?: string; checked?: boolean; hint?: string }): JSX.Element {
  return (
    <label class="inline">
      <input type="checkbox" name={props.name} value={props.value ?? "on"} checked={props.checked ?? false} />
      <span>
        {props.label}
        <Show when={props.hint}>
          <small class="muted"> – {props.hint}</small>
        </Show>
      </span>
    </label>
  );
}

export function Buttons(props: { busy: boolean; onCancel?: () => void; label?: string }): JSX.Element {
  return (
    <div class="actions end">
      <Show when={props.onCancel}>
        <button type="button" onClick={() => props.onCancel?.()}>
          {t("Cancel")}
        </button>
      </Show>
      <button type="submit" class="primary" disabled={props.busy}>
        {props.label ?? t("Save")}
      </button>
    </div>
  );
}

/** A page's heading with its buttons. */
export function Head(props: ParentProps<{ title: string; description?: string | undefined }>): JSX.Element {
  return (
    <>
      <div class="toolbar head">
        <h1 class="grow">{props.title}</h1>
        {props.children}
      </div>
      <Show when={props.description}>
        <p class="muted">{props.description}</p>
      </Show>
    </>
  );
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

export function Area(props: { label: string; name: string; value?: string; hint?: string; rows?: number }): JSX.Element {
  return (
    <label>
      <span>{props.label}</span>
      <textarea name={props.name} rows={props.rows ?? 3} value={props.value ?? ""} />
      <Show when={props.hint}>
        <small class="muted">{props.hint}</small>
      </Show>
    </label>
  );
}

export function Select(props: { label: string; name: string; value?: string; options: [string, string][] }): JSX.Element {
  return (
    <label>
      <span>{props.label}</span>
      <select name={props.name}>
        {props.options.map(([value, text]) => (
          <option value={value} selected={value === props.value}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}

/** A secret shown once, with a way to copy it. */
export function Secret(props: { label: string; value: string; onDone: () => void }): JSX.Element {
  return (
    <div class="answer">
      <span class="grow">
        {props.label} <code class="secret">{props.value}</code>
        <br />
        <small class="muted">{t("Shown only now – copy it.")}</small>
      </span>
      <button type="button" class="quiet" onClick={() => void navigator.clipboard?.writeText(props.value)}>
        {t("Copy")}
      </button>
      <button type="button" class="quiet" onClick={() => props.onDone()}>
        {t("Done")}
      </button>
    </div>
  );
}
