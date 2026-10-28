// SPDX-License-Identifier: MIT
// The calendar: a month at a time, the account's calendars and those shared with it; events made, changed and
// answered here send their invitations and answers.

import { For, type JSX, Show, createMemo, createResource, createSignal } from "solid-js";

import { Failure, changed, ok, touch, useJmap } from "../App.js";
import { locale, t } from "../i18n.js";
import { identities } from "../mail/model.js";
import { EventDialog, type EventStart } from "./EventDialog.js";
import { type CalendarEvent, calendars, instances } from "./model.js";

function startOfMonth(date: Date): Date {
  return new Date(date.getFullYear(), date.getMonth(), 1);
}

/** The 6×7 days shown for a month, from the Monday before its first day. */
function days(month: Date): Date[] {
  const first = startOfMonth(month);
  const offset = (first.getDay() + 6) % 7;
  return Array.from({ length: 42 }, (_, index) => new Date(first.getFullYear(), first.getMonth(), 1 - offset + index));
}

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** Whether an instance touches a day (all-day events by their date, the others by their UTC times). */
function onDay(event: CalendarEvent, day: Date): boolean {
  if (event.showWithoutTime) {
    const start = event.start.slice(0, 10);
    const days = Number(/P(\d+)D/.exec(event.duration ?? "")?.[1] ?? "1");
    const key = (date: Date) => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
    const startDate = new Date(`${start}T00:00:00`);
    for (let index = 0; index < days; index++) {
      if (key(new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate() + index)) === key(day)) return true;
    }
    return false;
  }
  const start = new Date(event.utcStart ?? event.start);
  const end = new Date(event.utcEnd ?? event.utcStart ?? event.start);
  const dayStart = new Date(day.getFullYear(), day.getMonth(), day.getDate());
  const dayEnd = new Date(day.getFullYear(), day.getMonth(), day.getDate() + 1);
  return start < dayEnd && (end > dayStart || start.getTime() === end.getTime() && start >= dayStart);
}

export function CalendarView(): JSX.Element {
  const jmap = useJmap();
  const [month, setMonth] = createSignal(startOfMonth(new Date()));
  const [list] = createResource(() => changed("Calendar"), () => calendars(jmap));
  const [own] = createResource(() => identities(jmap).then((found) => found.map((entry) => entry.email.toLowerCase())).catch(() => [jmap.session.username]));
  const grid = createMemo(() => days(month()));
  const [events] = createResource(
    () => {
      const shown = ok(list);
      return shown ? { shown, month: month(), version: changed("CalendarEvent") } : undefined;
    },
    ({ shown }) => {
      const span = grid();
      const first = span[0] ?? new Date();
      const last = span[span.length - 1] ?? new Date();
      return instances(jmap, shown, first, new Date(last.getFullYear(), last.getMonth(), last.getDate() + 1));
    },
  );
  const [dialog, setDialog] = createSignal<EventStart>();
  const colour = (event: CalendarEvent) =>
    ok(list)?.find((calendar) => event.calendarIds[calendar.id] && calendar.accountId === event.accountId)?.color ?? "var(--mint)";
  const time = (event: CalendarEvent) =>
    event.showWithoutTime || !event.utcStart ? "" : new Date(event.utcStart).toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });

  const writable = () => (ok(list) ?? []).filter((calendar) => calendar.myRights.mayWriteAll);

  return (
    <div class="calendar">
      <div class="toolbar">
        <button type="button" onClick={() => setMonth(new Date(month().getFullYear(), month().getMonth() - 1, 1))} aria-label="‹">
          ‹
        </button>
        <button type="button" onClick={() => setMonth(startOfMonth(new Date()))}>
          {t("Today")}
        </button>
        <button type="button" onClick={() => setMonth(new Date(month().getFullYear(), month().getMonth() + 1, 1))} aria-label="›">
          ›
        </button>
        <h2>{month().toLocaleDateString(locale, { month: "long", year: "numeric" })}</h2>
        <span class="grow" />
        <Show when={writable().length > 0}>
          <button type="button" class="primary" onClick={() => setDialog({ day: new Date() })}>
            {t("New event")}
          </button>
        </Show>
      </div>
      <Failure error={list.error ?? events.error} />
      <div class="legend">
        <For each={ok(list) ?? []}>
          {(calendar) => (
            <span class="chip">
              <i style={{ background: calendar.color ?? "var(--mint)" }} />
              {calendar.name}
              <Show when={calendar.shared}>
                <small class="muted"> · {calendar.shared}</small>
              </Show>
            </span>
          )}
        </For>
      </div>
      <div class="month" role="grid">
        <For each={grid().slice(0, 7)}>
          {(day) => <div class="weekday">{day.toLocaleDateString(locale, { weekday: "short" })}</div>}
        </For>
        <For each={grid()}>
          {(day) => (
            <div
              class="day"
              classList={{ other: day.getMonth() !== month().getMonth(), today: sameDay(day, new Date()) }}
              onDblClick={() => writable().length > 0 && setDialog({ day })}
            >
              <span class="date">{day.getDate()}</span>
              <For each={(ok(events) ?? []).filter((event) => onDay(event, day))}>
                {(event) => (
                  <button
                    type="button"
                    class="event"
                    style={{ "border-color": colour(event) }}
                    onClick={(click) => {
                      click.stopPropagation();
                      setDialog({ day, event });
                    }}
                  >
                    <span class="time">{time(event)}</span> {event.title || t("(no subject)")}
                  </button>
                )}
              </For>
            </div>
          )}
        </For>
      </div>
      <Show when={dialog()}>
        {(start) => (
          <EventDialog
            start={start()}
            calendars={ok(list) ?? []}
            addresses={ok(own) ?? []}
            onClose={(saved) => {
              setDialog(undefined);
              if (saved) touch("CalendarEvent");
            }}
          />
        )}
      </Show>
    </div>
  );
}
