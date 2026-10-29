<!-- SPDX-License-Identifier: MIT -->
<!-- One event: made or changed by its organizer (or anyone, without participants), answered by those invited. -->
<script lang="ts" module>
  import type { CalendarEvent } from "./model.js";

  export interface EventStart {
    day: Date;
    /** `day` names a time, not only a day. */
    timed?: boolean;
    event?: CalendarEvent;
  }
</script>

<script lang="ts">
  import { loaded, resource, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { locale, t } from "../i18n.js";
  import {
    type Calendar,
    type EventForm,
    address,
    answer,
    create,
    event as load,
    localInput,
    me,
    meetingsOffered,
    newMeeting,
    remove,
    removeInstance,
    update,
    updateInstance,
  } from "./model.js";

  let {
    start: begin,
    calendars,
    addresses,
    onclose,
  }: { start: EventStart; calendars: Calendar[]; addresses: string[]; onclose: (saved: boolean) => void } = $props();

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

  const jmap = useJmap();
  // svelte-ignore state_referenced_locally
  const instance = begin.event;
  // An instance of a series is changed through its event.
  const base = resource(
    () => (instance ? { accountId: instance.accountId, id: instance.baseEventId ?? instance.id } : undefined),
    ({ accountId, id }) => load(jmap, accountId, id),
  );
  // svelte-ignore state_referenced_locally
  const writable = calendars.filter((calendar) => calendar.myRights.mayWriteAll);
  const calendarOf = (event: CalendarEvent) =>
    calendars.find((calendar) => calendar.accountId === event.accountId && event.calendarIds[calendar.id]);
  const initialCalendar = instance ? calendarOf(instance) : (writable.find((calendar) => calendar.isDefault) ?? writable[0]);
  // svelte-ignore state_referenced_locally
  const defaultStart = new Date(begin.day);
  // A day: the next full hour; a time on a day (the week and day views): that time.
  // svelte-ignore state_referenced_locally
  if (!begin.timed) defaultStart.setHours(new Date().getHours() + 1, 0, 0, 0);
  const defaultEnd = new Date(defaultStart.getTime() + 3_600_000);
  const [startText, endText] = instance ? times(instance) : [localInput(defaultStart), localInput(defaultEnd)];

  let calendarId = $state(initialCalendar ? `${initialCalendar.accountId}/${initialCalendar.id}` : "");
  let title = $state(instance?.title ?? "");
  let allDay = $state(instance?.showWithoutTime ?? false);
  let start = $state(startText);
  let end = $state(endText);
  let location = $state(Object.values(instance?.locations ?? {})[0]?.name ?? "");
  let meeting = $state(Object.values(instance?.virtualLocations ?? {})[0]?.uri ?? "");
  let description = $state(instance?.description ?? "");
  const others = Object.values(instance?.participants ?? {})
    .map(address)
    // svelte-ignore state_referenced_locally
    .filter((entry) => entry && !addresses.includes(entry.toLowerCase()));
  let participants = $state(others.join(", "));
  let repeat = $state<EventForm["repeat"]>((instance?.recurrenceRule?.frequency as EventForm["repeat"]) ?? "");
  let error = $state<unknown>();
  let busy = $state(false);
  // An instance of a series: this one alone, or the whole series – with the series' own start and end.
  let scope = $state<"one" | "all">("one");
  // An instance of a series only if its event repeats: the server names the base event of single events too.
  const series = $derived(Boolean(instance?.baseEventId) && Boolean(base.value?.recurrenceRule));
  const single = $derived(series && scope === "one");
  const offered = loaded(meetingsOffered);

  $effect(() => {
    const event = base.value;
    if (!event || !series) return;
    [start, end] = scope === "all" ? times(event) : [startText, endText];
    repeat = (event.recurrenceRule?.frequency as EventForm["repeat"]) ?? "";
  });

  // The link goes into the description too: not every calendar program shows a conference (RFC 7986).
  const meetingLine = (url: string) => `${t("Video meeting")}: ${url}`;
  function addMeeting(url: string): void {
    meeting = url;
    description = description.trim() ? `${description.trimEnd()}\n\n${meetingLine(url)}` : meetingLine(url);
  }
  function removeMeeting(): void {
    description = description.replace(meetingLine(meeting), "").trim();
    meeting = "";
  }

  // svelte-ignore state_referenced_locally
  const own = addresses[0] ?? jmap.session.username;
  const mine = $derived(instance ? me(instance, addresses) : undefined);
  // The organizer edits; an invited person answers. Without participants anyone who may write edits.
  const organizer = $derived(
    !instance ||
      !instance.organizerCalendarAddress ||
      addresses.includes(address({ calendarAddress: instance.organizerCalendarAddress }).toLowerCase()),
  );
  const canEdit = $derived(organizer && (!instance || (calendarOf(instance)?.myRights.mayWriteAll ?? false)));

  async function run(action: () => Promise<void>): Promise<void> {
    busy = true;
    error = undefined;
    try {
      await action();
      onclose(true);
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
    }
  }

  function form(): EventForm {
    const [accountId, id] = calendarId.split("/");
    const calendar = calendars.find((entry) => entry.accountId === accountId && entry.id === id);
    if (!calendar) throw new Error(t("Calendars"));
    return {
      calendar,
      title,
      allDay,
      start: allDay ? start.slice(0, 10) : start,
      end: allDay ? end.slice(0, 10) : end,
      location,
      meeting,
      description,
      participants: participants.split(/[,;\s]+/).filter(Boolean),
      repeat,
    };
  }

  const save = () =>
    run(async () => {
      const event = base.value;
      if (instance && single && event && instance.recurrenceId)
        await updateInstance(jmap, event, instance.recurrenceId, form(), own);
      else if (instance) await update(jmap, instance.baseEventId ?? instance.id, form(), own);
      else await create(jmap, form(), own);
    });
  const destroy = () =>
    run(async () => {
      const event = base.value;
      if (!instance) return;
      if (single && event && instance.recurrenceId) await removeInstance(jmap, event, instance.recurrenceId);
      else await remove(jmap, instance.accountId, instance.baseEventId ?? instance.id);
    });

  const answers = [
    ["accepted", "Accept"],
    ["tentative", "Maybe"],
    ["declined", "Decline"],
  ] as const;
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={instance?.title ?? t("New event")}>
  <form
    class="dialog"
    onsubmit={(event) => {
      event.preventDefault();
      if (canEdit) void save();
    }}
  >
    {#if series}
      <fieldset class="choice">
        <legend class="muted">{t("Part of a series")}</legend>
        <label class="inline">
          <input type="radio" name="scope" value="one" bind:group={scope} />
          <span>{t("This event")}</span>
        </label>
        <label class="inline">
          <input type="radio" name="scope" value="all" bind:group={scope} />
          <span>{t("All events of the series")}</span>
        </label>
      </fieldset>
    {/if}
    <label>
      <span>{t("Title")}</span>
      <input type="text" required bind:value={title} disabled={!canEdit} />
    </label>
    <label class="inline">
      <input type="checkbox" bind:checked={allDay} disabled={!canEdit} />
      <span>{t("All day")}</span>
    </label>
    <div class="pair">
      <label>
        <span>{t("Start")}</span>
        <input
          type={allDay ? "date" : "datetime-local"}
          required
          value={allDay ? start.slice(0, 10) : start}
          disabled={!canEdit}
          oninput={(event) => (start = event.currentTarget.value)}
        />
      </label>
      <label>
        <span>{t("End")}</span>
        <input
          type={allDay ? "date" : "datetime-local"}
          required
          value={allDay ? end.slice(0, 10) : end}
          disabled={!canEdit}
          oninput={(event) => (end = event.currentTarget.value)}
        />
      </label>
    </div>
    <label>
      <span>{t("Calendar")}</span>
      <select bind:value={calendarId} disabled={!canEdit}>
        {#each writable as calendar (`${calendar.accountId}/${calendar.id}`)}
          <option value={`${calendar.accountId}/${calendar.id}`}>
            {calendar.shared ? `${calendar.name} (${calendar.shared})` : calendar.name}
          </option>
        {/each}
      </select>
    </label>
    <label>
      <span>{t("Repeat")}</span>
      <select bind:value={repeat} disabled={!canEdit || single}>
        <option value="">{t("Never")}</option>
        <option value="daily">{t("Daily")}</option>
        <option value="weekly">{t("Weekly")}</option>
        <option value="monthly">{t("Monthly")}</option>
        <option value="yearly">{t("Yearly")}</option>
      </select>
    </label>
    <label>
      <span>{t("Location")}</span>
      <input type="text" bind:value={location} disabled={!canEdit} />
    </label>
    <div class="field">
      <span>{t("Video meeting")}</span>
      {#if meeting}
        <span class="row">
          <a class="button primary" href={meeting} target="_blank" rel="noopener noreferrer">{t("Join")}</a>
          {#if canEdit}
            <button type="button" onclick={removeMeeting}>{t("Remove")}</button>
          {/if}
        </span>
      {:else if canEdit && offered.value}
        <button
          type="button"
          disabled={busy}
          onclick={() => void newMeeting().then(addMeeting, (failure: unknown) => (error = failure))}
        >
          {t("Add video meeting")}
        </button>
      {/if}
    </div>
    <label>
      <span>{t("Participants")}</span>
      <input type="text" placeholder={t("Addresses, separated by commas")} bind:value={participants} disabled={!canEdit} />
    </label>
    {#if instance?.participants}
      <ul class="participants">
        {#if instance.organizerCalendarAddress}
          <li>{t("Organizer")}: {address({ calendarAddress: instance.organizerCalendarAddress })}</li>
        {/if}
        {#each Object.values(instance.participants).filter((entry) => !entry.roles?.owner) as entry, index (index)}
          <li>
            {entry.name ?? address(entry)} –
            <span class="muted">{t(STATUS[entry.participationStatus ?? "needs-action"] ?? "No answer yet")}</span>
          </li>
        {/each}
      </ul>
    {/if}
    <label>
      <span>{t("Description")}</span>
      <textarea rows={4} bind:value={description} disabled={!canEdit}></textarea>
    </label>
    {#if instance && !organizer && mine}
      <div class="answer">
        <span>
          {t("Your answer")}: <b>{t(STATUS[mine[1].participationStatus ?? "needs-action"] ?? "No answer yet")}</b>
        </span>
        {#each answers as [status, label] (status)}
          <button
            type="button"
            disabled={busy}
            onclick={() =>
              void run(() => answer(jmap, instance.accountId, instance.baseEventId ?? instance.id, mine[0], status))}
          >
            {t(label)}
          </button>
        {/each}
      </div>
    {/if}
    {#if instance && base.value}
      <p class="muted small">{new Date(instance.utcStart ?? "").toLocaleString(locale)}</p>
    {/if}
    <Failure {error} />
    <div class="actions end">
      {#if instance && canEdit}
        <button
          type="button"
          class="danger"
          disabled={busy}
          onclick={() =>
            window.confirm(single ? t("Delete this event of the series?") : t("Delete this?")) && void destroy()}
        >
          {t("Delete")}
        </button>
      {/if}
      <span class="grow"></span>
      <button type="button" class="quiet" onclick={() => onclose(false)}>{t("Cancel")}</button>
      {#if canEdit}
        <button type="submit" class="primary" disabled={busy}>{t("Save")}</button>
      {/if}
    </div>
  </form>
</div>
