// SPDX-License-Identifier: MIT
// An account's Sieve scripts (RFC 5228): which runs when mail arrives, each to read, change, switch on or remove –
// kernoid checks that a script compiles before it keeps it. The vacation response is the account's own (account page).

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { emptyText, ok } from "../App.js";
import { t } from "../i18n.js";
import { api, seg } from "./api.js";
import { Buttons, Check, Field, Form, Outcome, useAction } from "./ui.js";

interface Script {
  name: string;
  content: string;
  active: boolean;
}

const EXAMPLE = `require ["fileinto"];
if header :contains "list-id" "newsletter" {
  fileinto "Newsletter";
}`;

export function SieveScripts(props: { base: string }): JSX.Element {
  const action = useAction();
  const path = `${props.base}/mail/sieve`;
  const [scripts, { refetch }] = createResource(() => api<Script[]>("GET", path).catch(() => []));
  // The script being written: a new one, or one of the list by its name.
  const [editing, setEditing] = createSignal<Script>();
  const run = (work: () => Promise<unknown>, done: string) => void action.run(work, done).then((worked) => worked && refetch());

  return (
    <section>
      <h2>{t("Filters (Sieve)")}</h2>
      <p class="muted">{t("What happens to mail when it arrives: one script runs at a time.")}</p>
      <Outcome action={action} />
      <ul class="rows">
        <For each={ok(scripts) ?? []} fallback={<li class="muted">{emptyText(scripts, t("No scripts."))}</li>}>
          {(script) => (
            <li>
              <span class="grow">
                <code>{script.name}</code>
                <Show when={script.active}>
                  <span class="badge">{t("runs")}</span>
                </Show>
              </span>
              <button type="button" class="quiet" onClick={() => setEditing(script)}>
                {t("Edit")}
              </button>
              <button
                type="button"
                class="quiet"
                disabled={action.busy()}
                onClick={() =>
                  run(
                    () => api("PUT", `${props.base}/mail/sieve-active`, { name: script.active ? null : script.name }),
                    script.active ? t("No script runs.") : t("The script runs."),
                  )
                }
              >
                {script.active ? t("Stop") : t("Run")}
              </button>
              <button
                type="button"
                class="quiet danger"
                disabled={action.busy()}
                onClick={() => window.confirm(t("Delete this?")) && run(() => api("DELETE", `${path}/${seg(script.name)}`), t("Deleted."))}
              >
                {t("Delete")}
              </button>
            </li>
          )}
        </For>
      </ul>
      <Show
        when={editing()}
        keyed
        fallback={
          <button type="button" onClick={() => setEditing({ name: "", content: EXAMPLE, active: false })}>
            {t("New script")}
          </button>
        }
      >
        {(script) => (
          <Form
            class="stack"
            submit={(field, all) =>
              void action
                .run(() => api("PUT", `${path}/${seg(field("name"))}`, { content: field("content"), activate: all("activate").length > 0 }), t("Saved."))
                .then((worked) => {
                  if (worked) {
                    setEditing(undefined);
                    void refetch();
                  }
                })
            }
          >
            <Field label={t("Name")} name="name" required value={script.name} readOnly={script.name !== ""} pattern="[^/]+" />
            <label>
              <span>{t("Script")}</span>
              <textarea name="content" class="code" rows={12} spellcheck={false} value={script.content} />
            </label>
            <Check label={t("Run this script")} name="activate" checked={script.active} />
            <Buttons busy={action.busy()} onCancel={() => setEditing(undefined)} />
          </Form>
        )}
      </Show>
    </section>
  );
}
