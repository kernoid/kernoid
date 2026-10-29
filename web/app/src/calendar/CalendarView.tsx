// SPDX-License-Identifier: MIT
// The calendar: a month, a week or a day at a time, the account's calendars and those shared with it; events made,
// changed and answered here send their invitations and answers.

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

type View = "month" | "week" | "day";

/** The seven days of the week of `date`, from Monday. */
function week(date: Date): Date[] {
  const offset = (date.getDay() + 6) % 7;
  return Array.from({ length: 7 }, (_, index) => new Date(date.getFullYear(), date.getMonth(), date.getDate() - offset + index));
}

function storedView(): View {
  try {
    const view = localStorage.getItem("kernoid.calendar.view");
    return view === "week" || view === "day" ? view : "month";
  } catch {
    return "month";
  }
}

/** Where a timed instance lies on a day, in minutes from midnight (local time): its start and end, cut to the day. */
function minutes(event: CalendarEvent, day: Date): [number, number] {
  const dayStart = new Date(day.getFullYear(), day.getMonth(), day.getDate()).getTime();
  const start = new Date(event.utcStart ?? event.start).getTime();
  const end = new Date(event.utcEnd ?? event.utcStart ?? event.start).getTime();
  const from = Math.max(0, (start - dayStart) / 60_000);
  const to = Math.min(1440, (end - dayStart) / 60_000);
  return [from, Math.max(to, from + 20)];
}

/** Side by side what overlaps: each timed instance of a day with its lane and the number of lanes it shares. */
function lanes(events: CalendarEvent[], day: Date): { event: CalendarEvent; from: number; to: number; lane: number; of: number }[] {
  const placed = events
    .map((event) => {
      const [from, to] = minutes(event, day);
      return { event, from, to, lane: 0, of: 1 };
    })
    .sort((a, b) => a.from - b.from || b.to - a.to);
  let group: typeof placed = [];
  let groupEnd = -1;
  const close = () => {
    for (const entry of group) entry.of = Math.max(...group.map((other) => other.lane)) + 1;
  };
  for (const entry of placed) {
    if (entry.from >= groupEnd) {
      close();
      group = [];
    }
    const taken = new Set(group.filter((other) => other.to > entry.from).map((other) => other.lane));
    while (taken.has(entry.lane)) entry.lane++;
    group.push(entry);
    groupEnd = Math.max(groupEnd, entry.to);
  }
  close();
  return placed;
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
  const [view, setViewSignal] = createSignal<View>(storedView());
  const [anchor, setAnchor] = createSignal(new Date());
  const month = () => startOfMonth(anchor());
  const setView = (next: View) => {
    setViewSignal(next);
    try {
      localStorage.setItem("kernoid.calendar.view", next);
    } catch {
      // Not kept: the month next time.
    }
  };
  const step = (direction: number) => {
    const date = anchor();
    if (view() === "month") setAnchor(new Date(date.getFullYear(), date.getMonth() + direction, 1));
    else setAnchor(new Date(date.getFullYear(), date.getMonth(), date.getDate() + direction * (view() === "week" ? 7 : 1)));
  };
  const title = () => {
    const date = anchor();
    if (view() === "month") return date.toLocaleDateString(locale, { month: "long", year: "numeric" });
    if (view() === "day") return date.toLocaleDateString(locale, { weekday: "long", day: "numeric", month: "long", year: "numeric" });
    const days = week(date);
    const first = days[0] ?? date;
    const last = days[6] ?? date;
    return `${first.toLocaleDateString(locale, { day: "numeric", month: "short" })} – ${last.toLocaleDateString(locale, { day: "numeric", month: "short", year: "numeric" })}`;
  };
  const [list] = createResource(() => changed("Calendar"), () => calendars(jmap));
  const [own] = createResource(() => identities(jmap).then((found) => found.map((entry) => entry.email.toLowerCase())).catch(() => [jmap.session.username]));
  const grid = createMemo(() => (view() === "month" ? days(month()) : view() === "week" ? week(anchor()) : [new Date(anchor().getFullYear(), anchor().getMonth(), anchor().getDate())]));
  const [events] = createResource(
    () => {
      const shown = ok(list);
      return shown ? { shown, span: grid(), version: changed("CalendarEvent") } : undefined;
    },
    ({ shown, span }) => {
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
  const open = (day: Date, event: CalendarEvent) => setDialog({ day, event });
  const eventButton = (day: Date, event: CalendarEvent, style: JSX.CSSProperties = {}) => (
    <button
      type="button"
      class="event"
      style={{ "border-color": colour(event), ...style }}
      onClick={(click) => {
        click.stopPropagation();
        open(day, event);
      }}
    >
      <span class="time">{time(event)}</span> {event.title || t("(no subject)")}
    </button>
  );

  /** A week or a day: all-day events on top, the others placed by their times over 24 hours. */
  const timeGrid = () => (
    <div
      class="timegrid"
      style={{ "--days": String(grid().length) }}
      // The working day in view first: from seven.
      ref={(element) => requestAnimationFrame(() => (element.scrollTop = 7 * 44))}
    >
      <div class="corner" />
      <For each={grid()}>
        {(day) => (
          <div class="head" classList={{ today: sameDay(day, new Date()) }}>
            {day.toLocaleDateString(locale, { weekday: "short", day: "numeric" })}
          </div>
        )}
      </For>
      <div class="corner" />
      <For each={grid()}>
        {(day) => (
          <div class="allday">
            <For each={(ok(events) ?? []).filter((event) => event.showWithoutTime && onDay(event, day))}>{(event) => eventButton(day, event)}</For>
          </div>
        )}
      </For>
      <div class="hours">
        <For each={Array.from({ length: 24 }, (_, hour) => hour)}>
          {(hour) => <div class="hour">{new Date(2026, 0, 1, hour).toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" })}</div>}
        </For>
      </div>
      <For each={grid()}>
        {(day) => (
          <div
            class="column"
            onDblClick={(click) => {
              if (writable().length === 0) return;
              const box = click.currentTarget.getBoundingClientRect();
              const hour = Math.max(0, Math.min(23, Math.floor(((click.clientY - box.top) / box.height) * 24)));
              setDialog({ day: new Date(day.getFullYear(), day.getMonth(), day.getDate(), hour), timed: true });
            }}
          >
            <For each={lanes((ok(events) ?? []).filter((event) => !event.showWithoutTime && onDay(event, day)), day)}>
              {(placed) =>
                eventButton(day, placed.event, {
                  top: `${(placed.from / 1440) * 100}%`,
                  height: `${((placed.to - placed.from) / 1440) * 100}%`,
                  left: `${(placed.lane / placed.of) * 100}%`,
                  width: `${100 / placed.of}%`,
                })
              }
            </For>
          </div>
        )}
      </For>
    </div>
  );

  return (
    <div class="calendar">
      <div class="toolbar">
        <button type="button" onClick={() => step(-1)} aria-label={t("Earlier")}>
          ‹
        </button>
        <button type="button" onClick={() => setAnchor(new Date())}>
          {t("Today")}
        </button>
        <button type="button" onClick={() => step(1)} aria-label={t("Later")}>
          ›
        </button>
        <h2>{title()}</h2>
        <span class="grow" />
        <div class="segmented" role="group" aria-label={t("View")}>
          <For each={[["month", t("Month")], ["week", t("Week")], ["day", t("Day")]] as const}>
            {([key, label]) => (
              <button type="button" classList={{ active: view() === key }} aria-pressed={view() === key} onClick={() => setView(key)}>
                {label}
              </button>
            )}
          </For>
        </div>
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
      <Show when={view() === "month"} fallback={timeGrid()}>
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
      </Show>
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
