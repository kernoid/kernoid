// SPDX-License-Identifier: MIT
// Calendars over JMAP (draft-ietf-jmap-calendars): calendars, the instances of a time window, events as JSCalendar
// 2.0 as kernoid writes them, invitations and answers (`sendSchedulingMessages`).

import { CALENDARS, type Jmap } from "../jmap.js";

export interface Calendar {
  id: string;
  name: string;
  color: string | null;
  isDefault: boolean;
  isVisible: boolean;
  myRights: { mayWriteAll: boolean; mayRSVP: boolean; mayAdmin: boolean };
  accountId: string;
  shared: string | null;
}

export interface Participant {
  calendarAddress?: string;
  name?: string;
  participationStatus?: string;
  expectReply?: boolean;
  roles?: Record<string, boolean>;
}

/** An event, or an instance of a recurring one. */
export interface CalendarEvent {
  id: string;
  baseEventId?: string;
  calendarIds: Record<string, boolean>;
  title?: string;
  description?: string;
  start: string;
  timeZone?: string | null;
  duration?: string;
  showWithoutTime?: boolean;
  utcStart?: string;
  utcEnd?: string;
  recurrenceRule?: { frequency: string } | null;
  recurrenceId?: string;
  locations?: Record<string, { name?: string }>;
  virtualLocations?: Record<string, { uri?: string; name?: string }>;
  organizerCalendarAddress?: string;
  participants?: Record<string, Participant>;
  isOrigin?: boolean;
  accountId: string;
}

/** The account's calendars and those shared with it. */
export async function calendars(jmap: Jmap): Promise<Calendar[]> {
  const out: Calendar[] = [];
  for (const [accountId, account] of Object.entries(jmap.session.accounts)) {
    if (!account.accountCapabilities[CALENDARS]) continue;
    const result = await jmap.call<{ list: Omit<Calendar, "accountId" | "shared">[] }>([CALENDARS], "Calendar/get", { accountId });
    for (const calendar of result.list) {
      out.push({ ...calendar, accountId, shared: account.isPersonal ? null : account.name });
    }
  }
  return out;
}

/** The instances of the visible calendars between `after` and `before`. */
export async function instances(jmap: Jmap, list: Calendar[], after: Date, before: Date): Promise<CalendarEvent[]> {
  const out: CalendarEvent[] = [];
  const accounts = [...new Set(list.map((calendar) => calendar.accountId))];
  for (const accountId of accounts) {
    const visible = new Set(list.filter((calendar) => calendar.accountId === accountId && calendar.isVisible).map((c) => c.id));
    if (visible.size === 0) continue;
    const responses = await jmap.request(
      [CALENDARS],
      [
        [
          "CalendarEvent/query",
          { accountId, expandRecurrences: true, filter: { after: after.toISOString().replace(/\.\d+Z$/, "Z"), before: before.toISOString().replace(/\.\d+Z$/, "Z") } },
          "q",
        ],
        ["CalendarEvent/get", { accountId, "#ids": { resultOf: "q", name: "CalendarEvent/query", path: "/ids" } }, "g"],
      ],
    );
    const get = responses.get("g")?.[0] as { list: Omit<CalendarEvent, "accountId">[] } | undefined;
    for (const event of get?.list ?? []) {
      if (Object.keys(event.calendarIds).some((id) => visible.has(id))) out.push({ ...event, accountId });
    }
  }
  return out.sort((a, b) => (a.utcStart ?? "").localeCompare(b.utcStart ?? ""));
}

export async function event(jmap: Jmap, accountId: string, id: string): Promise<CalendarEvent | undefined> {
  const result = await jmap.call<{ list: Omit<CalendarEvent, "accountId">[] }>([CALENDARS], "CalendarEvent/get", { accountId, ids: [id] });
  const found = result.list[0];
  return found ? { ...found, accountId } : undefined;
}

export interface EventForm {
  calendar: Calendar;
  title: string;
  allDay: boolean;
  /** `YYYY-MM-DDTHH:MM` in the browser's time zone, or `YYYY-MM-DD` for all-day events. */
  start: string;
  end: string;
  location: string;
  /** The link of a video meeting (JSCalendar `virtualLocations`). */
  meeting: string;
  description: string;
  participants: string[];
  repeat: "" | "daily" | "weekly" | "monthly" | "yearly";
}

const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;

/** The duration between two local times, as ISO 8601 (`PT1H30M`, `P2D`). */
function duration(form: EventForm): string {
  if (form.allDay) {
    const days = Math.max(1, Math.round((Date.parse(`${form.end}T00:00:00Z`) - Date.parse(`${form.start}T00:00:00Z`)) / 86_400_000) + 1);
    return `P${days}D`;
  }
  const minutes = Math.max(0, Math.round((new Date(form.end).getTime() - new Date(form.start).getTime()) / 60_000));
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return `PT${hours ? `${hours}H` : ""}${rest || !hours ? `${rest}M` : ""}`;
}

/** The JSCalendar object of a form; `own` is the organizer's address. */
function object(form: EventForm, own: string): Record<string, unknown> {
  const value: Record<string, unknown> = {
    "@type": "Event",
    title: form.title,
    start: form.allDay ? `${form.start}T00:00:00` : `${form.start}:00`,
    duration: duration(form),
    showWithoutTime: form.allDay,
    timeZone: form.allDay ? null : zone,
    description: form.description || null,
    locations: form.location ? { l1: { "@type": "Location", name: form.location } } : null,
    virtualLocations: form.meeting ? { v1: { "@type": "VirtualLocation", name: "Video", uri: form.meeting } } : null,
    recurrenceRule: form.repeat ? { "@type": "RecurrenceRule", frequency: form.repeat } : null,
  };
  const others = form.participants.map((address) => address.trim().toLowerCase()).filter((address) => address && address !== own);
  if (others.length > 0) {
    value.organizerCalendarAddress = `mailto:${own}`;
    const participants: Record<string, Participant> = {
      p0: { calendarAddress: `mailto:${own}`, roles: { owner: true, attendee: true }, participationStatus: "accepted" },
    };
    others.forEach((address, index) => {
      participants[`p${index + 1}`] = { calendarAddress: `mailto:${address}`, roles: { attendee: true }, participationStatus: "needs-action", expectReply: true };
    });
    value.participants = participants;
  } else {
    value.participants = null;
    value.organizerCalendarAddress = null;
  }
  return value;
}

export async function create(jmap: Jmap, form: EventForm, own: string): Promise<void> {
  await jmap.set([CALENDARS], "CalendarEvent", form.calendar.accountId, {
    create: { e: { ...object(form, own), calendarIds: { [form.calendar.id]: true } } },
  }, { sendSchedulingMessages: true });
}

export async function update(jmap: Jmap, id: string, form: EventForm, own: string): Promise<void> {
  await jmap.set([CALENDARS], "CalendarEvent", form.calendar.accountId, {
    update: { [id]: { ...object(form, own), calendarIds: { [form.calendar.id]: true } } },
  }, { sendSchedulingMessages: true });
}

export async function remove(jmap: Jmap, accountId: string, id: string): Promise<void> {
  await jmap.set([CALENDARS], "CalendarEvent", accountId, { destroy: [id] }, { sendSchedulingMessages: true });
}

/** Answers an invitation: the participant with one of `own` addresses gets `status`. */
export async function answer(jmap: Jmap, accountId: string, id: string, participant: string, status: string): Promise<void> {
  await jmap.set([CALENDARS], "CalendarEvent", accountId, {
    update: { [id]: { [`participants/${participant}/participationStatus`]: status } },
  }, { sendSchedulingMessages: true });
}

/** The participant entry that is the user, by its address. */
export function me(event: CalendarEvent, addresses: string[]): [string, Participant] | undefined {
  const own = new Set(addresses.map((address) => `mailto:${address.toLowerCase()}`));
  return Object.entries(event.participants ?? {}).find(([, participant]) => own.has((participant.calendarAddress ?? "").toLowerCase()));
}

export function address(participant: Participant): string {
  return (participant.calendarAddress ?? "").replace(/^mailto:/i, "");
}

/** A local time for an `<input type=datetime-local>`. */
export function localInput(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Whether the account's tenant offers video meetings (the module jitsi). */
export async function meetingsOffered(): Promise<boolean> {
  const response = await fetch("/modules/jitsi/status", { headers: { "kernoid-csrf": "1" }, credentials: "same-origin" });
  if (!response.ok) return false;
  return ((await response.json()) as { enabled?: boolean }).enabled === true;
}

/** A new video meeting; its link. */
export async function newMeeting(): Promise<string> {
  const response = await fetch("/modules/jitsi/meetings", { method: "POST", headers: { "kernoid-csrf": "1" }, credentials: "same-origin" });
  if (!response.ok) throw new Error(`${response.status}`);
  return ((await response.json()) as { url: string }).url;
}
