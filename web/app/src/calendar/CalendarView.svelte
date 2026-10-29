<!-- SPDX-License-Identifier: MIT -->
<!-- The calendar: a month, a week or a day at a time, the account's calendars and those shared with it; events made,
     changed and answered here send their invitations and answers. Colours and positions are set as style properties
     (style:), which the Content-Security-Policy allows – not as style attributes. -->
<script lang="ts">
  import { changed, loaded, resource, touch, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import { identities } from "../mail/model.js";
  import EventDialog, { type EventStart } from "./EventDialog.svelte";
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

  const jmap = useJmap();
  let view = $state<View>(storedView());
  let anchor = $state(new Date());
  const month = $derived(startOfMonth(anchor));

  function setView(next: View): void {
    view = next;
    try {
      localStorage.setItem("kernoid.calendar.view", next);
    } catch {
      // Not kept: the month next time.
    }
  }

  function step(direction: number): void {
    const date = anchor;
    if (view === "month") anchor = new Date(date.getFullYear(), date.getMonth() + direction, 1);
    else anchor = new Date(date.getFullYear(), date.getMonth(), date.getDate() + direction * (view === "week" ? 7 : 1));
  }

  const title = $derived.by(() => {
    const date = anchor;
    if (view === "month") return date.toLocaleDateString(locale, { month: "long", year: "numeric" });
    if (view === "day")
      return date.toLocaleDateString(locale, { weekday: "long", day: "numeric", month: "long", year: "numeric" });
    const shown = week(date);
    const first = shown[0] ?? date;
    const last = shown[6] ?? date;
    return `${first.toLocaleDateString(locale, { day: "numeric", month: "short" })} – ${last.toLocaleDateString(locale, { day: "numeric", month: "short", year: "numeric" })}`;
  });

  const list = resource(() => changed("Calendar") + 1, () => calendars(jmap));
  const own = loaded(() =>
    identities(jmap)
      .then((found) => found.map((entry) => entry.email.toLowerCase()))
      .catch(() => [jmap.session.username]),
  );
  const grid = $derived(
    view === "month"
      ? days(month)
      : view === "week"
        ? week(anchor)
        : [new Date(anchor.getFullYear(), anchor.getMonth(), anchor.getDate())],
  );
  const events = resource(
    () => (list.value ? { shown: list.value, span: grid, version: changed("CalendarEvent") } : undefined),
    ({ shown, span }) => {
      const first = span[0] ?? new Date();
      const last = span[span.length - 1] ?? new Date();
      return instances(jmap, shown, first, new Date(last.getFullYear(), last.getMonth(), last.getDate() + 1));
    },
  );
  let dialog = $state<EventStart>();

  const colour = (event: CalendarEvent) =>
    list.value?.find((calendar) => event.calendarIds[calendar.id] && calendar.accountId === event.accountId)?.color ??
    "var(--mint)";
  const time = (event: CalendarEvent) =>
    event.showWithoutTime || !event.utcStart
      ? ""
      : new Date(event.utcStart).toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
  const writable = $derived((list.value ?? []).filter((calendar) => calendar.myRights.mayWriteAll));
  const hours = Array.from({ length: 24 }, (_, hour) => hour);
  const views = [
    ["month", "Month"],
    ["week", "Week"],
    ["day", "Day"],
  ] as const;

  function openNew(click: MouseEvent, day: Date): void {
    if (writable.length === 0) return;
    const box = (click.currentTarget as HTMLElement).getBoundingClientRect();
    const hour = Math.max(0, Math.min(23, Math.floor(((click.clientY - box.top) / box.height) * 24)));
    dialog = { day: new Date(day.getFullYear(), day.getMonth(), day.getDate(), hour), timed: true };
  }
</script>

{#snippet eventButton(day: Date, event: CalendarEvent, place?: { from: number; to: number; lane: number; of: number })}
  <button
    type="button"
    class="event"
    style:border-color={colour(event)}
    style:top={place ? `${(place.from / 1440) * 100}%` : undefined}
    style:height={place ? `${((place.to - place.from) / 1440) * 100}%` : undefined}
    style:left={place ? `${(place.lane / place.of) * 100}%` : undefined}
    style:width={place ? `${100 / place.of}%` : undefined}
    onclick={(click) => {
      click.stopPropagation();
      dialog = { day, event };
    }}
  >
    <span class="time">{time(event)}</span>
    {event.title || t("(no subject)")}
  </button>
{/snippet}

<div class="calendar">
  <div class="toolbar">
    <button type="button" onclick={() => step(-1)} aria-label={t("Earlier")}>‹</button>
    <button type="button" onclick={() => (anchor = new Date())}>{t("Today")}</button>
    <button type="button" onclick={() => step(1)} aria-label={t("Later")}>›</button>
    <h2>{title}</h2>
    <span class="grow"></span>
    <div class="segmented" role="group" aria-label={t("View")}>
      {#each views as [key, label] (key)}
        <button type="button" class:active={view === key} aria-pressed={view === key} onclick={() => setView(key)}>
          {t(label)}
        </button>
      {/each}
    </div>
    {#if writable.length > 0}
      <button type="button" class="primary" onclick={() => (dialog = { day: new Date() })}>{t("New event")}</button>
    {/if}
  </div>
  <Failure error={list.error ?? events.error} />
  <div class="legend">
    {#each list.value ?? [] as calendar (`${calendar.accountId}/${calendar.id}`)}
      <span class="chip">
        <i style:background={calendar.color ?? "var(--mint)"}></i>
        {calendar.name}
        {#if calendar.shared}
          <small class="muted"> · {calendar.shared}</small>
        {/if}
      </span>
    {/each}
  </div>
  {#if view === "month"}
    <div class="month" role="grid">
      {#each grid.slice(0, 7) as day (day.getTime())}
        <div class="weekday">{day.toLocaleDateString(locale, { weekday: "short" })}</div>
      {/each}
      {#each grid as day (day.getTime())}
        <div
          class="day"
          role="gridcell"
          tabindex="-1"
          class:other={day.getMonth() !== month.getMonth()}
          class:today={sameDay(day, new Date())}
          ondblclick={() => writable.length > 0 && (dialog = { day })}
        >
          <span class="date">{day.getDate()}</span>
          {#each (events.value ?? []).filter((event) => onDay(event, day)) as event, index (index)}
            {@render eventButton(day, event)}
          {/each}
        </div>
      {/each}
    </div>
  {:else}
    <!-- A week or a day: all-day events on top, the others placed by their times over 24 hours. -->
    <div
      class="timegrid"
      style:--days={String(grid.length)}
      {@attach (element) => {
        // The working day in view first: from seven.
        requestAnimationFrame(() => (element.scrollTop = 7 * 44));
      }}
    >
      <div class="corner"></div>
      {#each grid as day (day.getTime())}
        <div class="head" class:today={sameDay(day, new Date())}>
          {day.toLocaleDateString(locale, { weekday: "short", day: "numeric" })}
        </div>
      {/each}
      <div class="corner"></div>
      {#each grid as day (day.getTime())}
        <div class="allday">
          {#each (events.value ?? []).filter((event) => event.showWithoutTime && onDay(event, day)) as event, index (index)}
            {@render eventButton(day, event)}
          {/each}
        </div>
      {/each}
      <div class="hours">
        {#each hours as hour (hour)}
          <div class="hour">
            {new Date(2026, 0, 1, hour).toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" })}
          </div>
        {/each}
      </div>
      {#each grid as day (day.getTime())}
        <div class="column" role="presentation" ondblclick={(click) => openNew(click, day)}>
          {#each lanes((events.value ?? []).filter((event) => !event.showWithoutTime && onDay(event, day)), day) as placed, index (index)}
            {@render eventButton(day, placed.event, placed)}
          {/each}
        </div>
      {/each}
    </div>
  {/if}
  {#if dialog}
    <EventDialog
      start={dialog}
      calendars={list.value ?? []}
      addresses={own.value ?? []}
      onclose={(saved) => {
        dialog = undefined;
        if (saved) touch("CalendarEvent");
      }}
    />
  {/if}
</div>
