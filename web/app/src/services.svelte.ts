// SPDX-License-Identifier: AGPL-3.0-or-later
// What the installation runs (RFC 0008, 4): views of a service that is off are not offered.

export type Services = { mail: boolean; calendars: boolean; files: boolean };

let current = $state<Services>({ mail: true, calendars: true, files: true });

/** Asks the server once; an older kernoid without the route runs everything. */
export async function loadServices(): Promise<Services> {
  try {
    const response = await fetch("/v1/services", { credentials: "same-origin" });
    if (response.ok) current = (await response.json()) as Services;
  } catch {
    // Keep the default: everything.
  }
  return current;
}

export function services(): Services {
  return current;
}

/** Whether JMAP is there at all: for mail, calendars or files. */
export function hasJmap(value: Services = current): boolean {
  return value.mail || value.calendars || value.files;
}
