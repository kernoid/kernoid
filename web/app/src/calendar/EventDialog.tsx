// SPDX-License-Identifier: MIT
// One event: made or changed by its organizer (or anyone, without participants), answered by those invited.

import { For, type JSX, Show, createEffect, createResource, createSignal } from "solid-js";

import { Failure, ok, useJmap } from "../App.js";
import { locale, t } from "../i18n.js";
import { type Calendar, type CalendarEvent, type EventForm, address, answer, create, event as load, localInput, me, remove, update } from "./model.js";

export interface EventStart {
  day: Date;
  event?: CalendarEvent;
}

const STATUS: Record<string, string> = {
  accepted: "Accepted",
  declined: "Declined",
  tentative: "Tentative",
  "needs-action": "No answer yet",
};

/** The form's start and end for an existing event (its whole series for instances). */
function times(event: CalendarEvent): [string, string] {
  if (event.showWithoutTime) {
    const start = event.start.slice(0, 10);
    const days = Number(/P(\d+)D/.exec(event.duration ?? "")?.[1] ?? "1");
    const end = new Date(`${start}T00:00:00`);
    end.setDate(end.getDate() + days - 1);
    return [start, localInput(end).slice(0, 10)];
  }
  const start = new Date(event.utcStart ?? event.start);
  const end = new Date(event.utcEnd ?? event.utcStart ?? event.start);
  return [localInput(start), localInput(end)];
}

export function EventDialog(props: {
  start: EventStart;
  calendars: Calendar[];
  addresses: string[];
  onClose: (saved: boolean) => void;
}): JSX.Element {
  const jmap = useJmap();
  const instance = props.start.event;
  // An instance of a series is changed through its event.
  const [base] = createResource(
    () => (instance ? { accountId: instance.accountId, id: instance.baseEventId ?? instance.id } : undefined),
    ({ accountId, id }) => load(jmap, accountId, id),
  );
  const writable = props.calendars.filter((calendar) => calendar.myRights.mayWriteAll);
  const calendarOf = (event: CalendarEvent) =>
    props.calendars.find((calendar) => calendar.accountId === event.accountId && event.calendarIds[calendar.id]);
  const initialCalendar = instance ? calendarOf(instance) : (writable.find((calendar) => calendar.isDefault) ?? writable[0]);
  const [calendarId, setCalendarId] = createSignal(initialCalendar ? `${initialCalendar.accountId}/${initialCalendar.id}` : "");
  const defaultStart = new Date(props.start.day);
  defaultStart.setHours(new Date().getHours() + 1, 0, 0, 0);
  const defaultEnd = new Date(defaultStart.getTime() + 3_600_000);
  const [startText, endText] = instance ? times(instance) : [localInput(defaultStart), localInput(defaultEnd)];
  const [title, setTitle] = createSignal(instance?.title ?? "");
  const [allDay, setAllDay] = createSignal(instance?.showWithoutTime ?? false);
  const [start, setStart] = createSignal(startText);
  const [end, setEnd] = createSignal(endText);
  const [location, setLocation] = createSignal(Object.values(instance?.locations ?? {})[0]?.name ?? "");
  const [description, setDescription] = createSignal(instance?.description ?? "");
  const others = Object.values(instance?.participants ?? {})
    .map(address)
    .filter((entry) => entry && !props.addresses.includes(entry.toLowerCase()));
  const [participants, setParticipants] = createSignal(others.join(", "));
  const [repeat, setRepeat] = createSignal<EventForm["repeat"]>((instance?.recurrenceRule?.frequency as EventForm["repeat"]) ?? "");
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  // A series is edited as a whole: its own start and end, not the instance's.
  createEffect(() => {
    const series = ok(base);
    if (series && instance?.baseEventId) {
      const [seriesStart, seriesEnd] = times(series);
      setStart(seriesStart);
      setEnd(seriesEnd);
      setRepeat((series.recurrenceRule?.frequency as EventForm["repeat"]) ?? "");
    }
  });

  const own = props.addresses[0] ?? jmap.session.username;
  const mine = () => (instance ? me(instance, props.addresses) : undefined);
  // The organizer edits; an invited person answers. Without participants anyone who may write edits.
  const organizer = () =>
    !instance ||
    !instance.organizerCalendarAddress ||
    props.addresses.includes(address({ calendarAddress: instance.organizerCalendarAddress }).toLowerCase());
  const canEdit = () => organizer() && (!instance || (calendarOf(instance)?.myRights.mayWriteAll ?? false));

  const run = (action: () => Promise<void>) => async () => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      props.onClose(true);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  const form = (): EventForm => {
    const [accountId, id] = calendarId().split("/");
    const calendar = props.calendars.find((entry) => entry.accountId === accountId && entry.id === id);
    if (!calendar) throw new Error(t("Calendars"));
    return {
      calendar,
      title: title(),
      allDay: allDay(),
      start: allDay() ? start().slice(0, 10) : start(),
      end: allDay() ? end().slice(0, 10) : end(),
      location: location(),
      description: description(),
      participants: participants().split(/[,;\s]+/).filter(Boolean),
      repeat: repeat(),
    };
  };

  const save = run(async () => {
    if (instance) await update(jmap, instance.baseEventId ?? instance.id, form(), own);
    else await create(jmap, form(), own);
  });

  return (
    <div class="overlay" role="dialog" aria-modal="true" aria-label={instance?.title ?? t("New event")}>
      <form
        class="dialog"
        onSubmit={(event) => {
          event.preventDefault();
          if (canEdit()) void save();
        }}
      >
        <Show when={instance?.baseEventId}>
          <p class="muted">
            {t("Part of a series")} – {t("Changes apply to the whole series.")}
          </p>
        </Show>
        <label>
          <span>{t("Title")}</span>
          <input type="text" required value={title()} disabled={!canEdit()} onInput={(event) => setTitle(event.currentTarget.value)} />
        </label>
        <label class="inline">
          <input type="checkbox" checked={allDay()} disabled={!canEdit()} onChange={(event) => setAllDay(event.currentTarget.checked)} />
          <span>{t("All day")}</span>
        </label>
        <div class="pair">
          <label>
            <span>{t("Start")}</span>
            <input
              type={allDay() ? "date" : "datetime-local"}
              required
              value={allDay() ? start().slice(0, 10) : start()}
              disabled={!canEdit()}
              onInput={(event) => setStart(event.currentTarget.value)}
            />
          </label>
          <label>
            <span>{t("End")}</span>
            <input
              type={allDay() ? "date" : "datetime-local"}
              required
              value={allDay() ? end().slice(0, 10) : end()}
              disabled={!canEdit()}
              onInput={(event) => setEnd(event.currentTarget.value)}
            />
          </label>
        </div>
        <label>
          <span>{t("Calendar")}</span>
          <select value={calendarId()} disabled={!canEdit()} onChange={(event) => setCalendarId(event.currentTarget.value)}>
            <For each={writable}>
              {(calendar) => <option value={`${calendar.accountId}/${calendar.id}`}>{calendar.shared ? `${calendar.name} (${calendar.shared})` : calendar.name}</option>}
            </For>
          </select>
        </label>
        <label>
          <span>{t("Repeat")}</span>
          <select value={repeat()} disabled={!canEdit()} onChange={(event) => setRepeat(event.currentTarget.value as EventForm["repeat"])}>
            <option value="">{t("Never")}</option>
            <option value="daily">{t("Daily")}</option>
            <option value="weekly">{t("Weekly")}</option>
            <option value="monthly">{t("Monthly")}</option>
            <option value="yearly">{t("Yearly")}</option>
          </select>
        </label>
        <label>
          <span>{t("Location")}</span>
          <input type="text" value={location()} disabled={!canEdit()} onInput={(event) => setLocation(event.currentTarget.value)} />
        </label>
        <label>
          <span>{t("Participants")}</span>
          <input
            type="text"
            placeholder={t("Addresses, separated by commas")}
            value={participants()}
            disabled={!canEdit()}
            onInput={(event) => setParticipants(event.currentTarget.value)}
          />
        </label>
        <Show when={instance?.participants}>
          <ul class="participants">
            <Show when={instance?.organizerCalendarAddress}>
              <li>
                {t("Organizer")}: {address({ calendarAddress: instance?.organizerCalendarAddress ?? "" })}
              </li>
            </Show>
            <For each={Object.values(instance?.participants ?? {}).filter((entry) => !entry.roles?.owner)}>
              {(entry) => (
                <li>
                  {entry.name ?? address(entry)} – <span class="muted">{t(STATUS[entry.participationStatus ?? "needs-action"] ?? "No answer yet")}</span>
                </li>
              )}
            </For>
          </ul>
        </Show>
        <label>
          <span>{t("Description")}</span>
          <textarea rows={4} value={description()} disabled={!canEdit()} onInput={(event) => setDescription(event.currentTarget.value)} />
        </label>
        <Show when={instance && !organizer() && mine()}>
          {(entry) => (
            <div class="answer">
              <span>
                {t("Your answer")}: <b>{t(STATUS[entry()[1].participationStatus ?? "needs-action"] ?? "No answer yet")}</b>
              </span>
              <For each={[["accepted", "Accept"], ["tentative", "Maybe"], ["declined", "Decline"]] as const}>
                {([status, label]) => (
                  <button
                    type="button"
                    disabled={busy() || !instance}
                    onClick={() => instance && void run(() => answer(jmap, instance.accountId, instance.baseEventId ?? instance.id, entry()[0], status))()}
                  >
                    {t(label)}
                  </button>
                )}
              </For>
            </div>
          )}
        </Show>
        <Show when={instance && ok(base)}>
          <p class="muted small">{new Date(instance?.utcStart ?? "").toLocaleString(locale)}</p>
        </Show>
        <Failure error={error()} />
        <div class="actions end">
          <Show when={instance && canEdit()}>
            <button
              type="button"
              class="danger"
              disabled={busy()}
              onClick={() => instance && window.confirm(t("Delete this?")) && void run(() => remove(jmap, instance.accountId, instance.baseEventId ?? instance.id))()}
            >
              {t("Delete")}
            </button>
          </Show>
          <span class="grow" />
          <button type="button" class="quiet" onClick={() => props.onClose(false)}>
            {t("Cancel")}
          </button>
          <Show when={canEdit()}>
            <button type="submit" class="primary" disabled={busy()}>
              {t("Save")}
            </button>
          </Show>
        </div>
      </form>
    </div>
  );
}
