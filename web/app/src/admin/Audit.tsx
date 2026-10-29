// SPDX-License-Identifier: MIT
// The audit log: what happened in the tenant – or the instance – and who did it, newest first, from kernoid's events.
// `#/admin/audit/<type>:<id>` shows one object's history (an account's, a group's …).

import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { ok } from "../App.js";
import { t } from "../i18n.js";
import { useDirectory } from "./AdminView.js";
import { api } from "./api.js";
import { Head, Outcome, useAction, when } from "./ui.js";

interface Entry {
  position: number;
  aggregate_type: string;
  aggregate_id: string;
  sequence: number;
  event_type: string;
  payload: unknown;
  creator: string;
  created_at: string;
}

const TYPES = ["account", "group", "tenant", "session", "project", "authorization", "application", "identity_provider", "instance", "signing_keys"];
const PAGE = 50;

export function Audit(props: { object: string | undefined; instance: boolean }): JSX.Element {
  const directory = useDirectory();
  const action = useAction();
  const [scope, setScope] = createSignal<"tenant" | "instance">("tenant");
  const [type, setType] = createSignal(props.object?.split(":")[0] ?? "");
  const [object, setObject] = createSignal(props.object?.split(":").slice(1).join(":") ?? "");
  const [older, setOlder] = createSignal<Entry[]>([]);
  const [more, setMore] = createSignal(true);
  const [open, setOpen] = createSignal<number>();

  const query = (before?: number) => {
    const params = new URLSearchParams({ scope: scope(), limit: String(PAGE) });
    if (type()) params.set("aggregate_type", type());
    if (type() && object()) params.set("aggregate_id", object());
    if (before !== undefined) params.set("before", String(before));
    return api<Entry[]>("GET", `/v1/audit?${params}`);
  };
  const [first] = createResource(
    () => ({ scope: scope(), type: type(), object: object() }),
    async () => {
      setOlder([]);
      const page = await query();
      setMore(page.length === PAGE);
      return page;
    },
  );
  const entries = () => [...(ok(first) ?? []), ...older()];
  const loadOlder = () =>
    void action.run(async () => {
      const last = entries().at(-1);
      const page = await query(last?.position);
      setOlder([...older(), ...page]);
      setMore(page.length === PAGE);
    });

  /** Whose: an account's address, a group's name – else the id. */
  const subject = (entry: Entry) =>
    entry.aggregate_type === "account" || entry.aggregate_type === "group" ? directory.name(entry.aggregate_type, entry.aggregate_id) : entry.aggregate_id;
  /** `account:<id>` as the account's address; `system`, `operator` and the like as they are. */
  const who = (creator: string) => (creator.startsWith("account:") ? directory.name("account", creator.slice("account:".length)) : creator);

  return (
    <>
      <Head title={t("Audit log")} description={t("What happened and who did it – from kernoid's events, newest first. Passwords and other secrets never appear here.")} />
      <div class="row filters">
        <Show when={props.instance}>
          <select aria-label={t("Scope")} onChange={(event) => setScope(event.currentTarget.value as "tenant" | "instance")}>
            <option value="tenant">{t("Tenant")}</option>
            <option value="instance">{t("Instance")}</option>
          </select>
        </Show>
        <select
          aria-label={t("Kind")}
          onChange={(event) => {
            setType(event.currentTarget.value);
            setObject("");
          }}
        >
          <option value="">{t("everything")}</option>
          <For each={TYPES}>{(name) => <option value={name} selected={type() === name}>{name}</option>}</For>
        </select>
        <Show when={object()}>
          <span class="chip">
            {type() === "account" || type() === "group" ? directory.name(type(), object()) : object()}
            <button type="button" class="quiet" aria-label={t("Remove")} onClick={() => setObject("")}>
              ×
            </button>
          </span>
        </Show>
      </div>
      <Outcome action={action} />
      <Show when={first.error}>
        <p class="error">{String(first.error?.message ?? first.error)}</p>
      </Show>
      <table class="nodes audit">
        <tbody>
          <For each={entries()} fallback={<tr><td class="muted">{first.loading ? t("Loading") : t("Nothing here")}</td></tr>}>
            {(entry) => (
              <>
                <tr>
                  <td class="small muted nowrap">{when(entry.created_at)}</td>
                  <td class="name">
                    <button type="button" class="quiet file" onClick={() => setOpen(open() === entry.position ? undefined : entry.position)}>
                      <code>{entry.event_type}</code>
                    </button>
                    <div class="small muted">
                      {entry.aggregate_type} ·{" "}
                      <button
                        type="button"
                        class="quiet link"
                        onClick={() => {
                          setType(entry.aggregate_type);
                          setObject(entry.aggregate_id);
                        }}
                      >
                        {subject(entry)}
                      </button>
                    </div>
                  </td>
                  <td class="small">{who(entry.creator)}</td>
                </tr>
                <Show when={open() === entry.position}>
                  <tr>
                    <td colSpan={3}>
                      <pre class="payload">{JSON.stringify(entry.payload, null, 2)}</pre>
                    </td>
                  </tr>
                </Show>
              </>
            )}
          </For>
        </tbody>
      </table>
      <Show when={more() && entries().length > 0}>
        <div class="actions">
          <button type="button" disabled={action.busy()} onClick={loadOlder}>
            {t("Load older")}
          </button>
        </div>
      </Show>
    </>
  );
}
