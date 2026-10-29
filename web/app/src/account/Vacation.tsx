// SPDX-License-Identifier: MIT
// The vacation response (JMAP, RFC 8621, 8): on or off, from and to a time, a subject and a text – kernoid answers
// mail with it while it is on, once per sender within a week, not to lists or automatic mail.

import { type JSX, Show, createResource, createSignal } from "solid-js";

import { Failure, ok, useJmap } from "../App.js";
import { t } from "../i18n.js";
import { JmapError, VACATION } from "../jmap.js";
import { localInput } from "../calendar/model.js";

interface VacationResponse {
  isEnabled: boolean;
  fromDate: string | null;
  toDate: string | null;
  subject: string | null;
  textBody: string | null;
}

/** A UTCDate as an `<input type=datetime-local>` value in the browser's time, and back. */
const local = (date: string | null) => (date ? localInput(new Date(date)) : "");
const utc = (value: string) => (value ? new Date(value).toISOString().replace(/\.\d{3}Z$/, "Z") : null);

export function Vacation(): JSX.Element {
  const jmap = useJmap();
  const accountId = jmap.session.primaryAccounts[VACATION];
  const [current, { refetch }] = createResource(
    () => accountId,
    async (account) => {
      const result = await jmap.call<{ list: VacationResponse[] }>([VACATION], "VacationResponse/get", { accountId: account, ids: ["singleton"] });
      return result.list[0];
    },
  );
  const [error, setError] = createSignal<unknown>();
  const [saved, setSaved] = createSignal(false);

  const save = async (form: HTMLFormElement) => {
    const data = new FormData(form);
    const text = (name: string) => String(data.get(name) ?? "").trim() || null;
    setError(undefined);
    setSaved(false);
    try {
      const result = await jmap.call<{ notUpdated?: Record<string, { type: string; description?: string }> }>([VACATION], "VacationResponse/set", {
        accountId,
        update: {
          singleton: {
            isEnabled: data.get("enabled") === "on",
            fromDate: utc(String(data.get("from") ?? "")),
            toDate: utc(String(data.get("to") ?? "")),
            subject: text("subject"),
            textBody: text("body"),
          },
        },
      });
      const failed = result.notUpdated?.singleton;
      if (failed) throw new JmapError(failed.type, failed.description);
      setSaved(true);
      await refetch();
    } catch (failure) {
      setError(failure);
    }
  };

  return (
    <Show when={accountId}>
      <section>
        <h2>{t("Vacation response")}</h2>
        <p class="muted">{t("Answers mail while you are away – each sender once a week, not mailing lists or automatic mail.")}</p>
        <Show when={ok(current)}>
          {(vacation) => (
            <form
              class="stack"
              onSubmit={(event) => {
                event.preventDefault();
                void save(event.currentTarget);
              }}
            >
              <label class="inline">
                <input type="checkbox" name="enabled" checked={vacation().isEnabled} />
                <span>{t("Answer mail")}</span>
              </label>
              <div class="pair">
                <label>
                  <span>{t("From (optional)")}</span>
                  <input type="datetime-local" name="from" value={local(vacation().fromDate)} />
                </label>
                <label>
                  <span>{t("Until (optional)")}</span>
                  <input type="datetime-local" name="to" value={local(vacation().toDate)} />
                </label>
              </div>
              <label>
                <span>{t("Subject")}</span>
                <input type="text" name="subject" value={vacation().subject ?? ""} placeholder={t("Auto: and the subject of the mail answered")} />
              </label>
              <label>
                <span>{t("Text")}</span>
                <textarea name="body" rows={5} value={vacation().textBody ?? ""} />
              </label>
              <div class="actions">
                <button type="submit" class="primary">
                  {t("Save")}
                </button>
                <Show when={saved()}>
                  <span class="muted">{t("Saved.")}</span>
                </Show>
              </div>
            </form>
          )}
        </Show>
        <Failure error={error() ?? current.error} />
      </section>
    </Show>
  );
}
