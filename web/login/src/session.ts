// SPDX-License-Identifier: MIT
// The session of this browser lives in kernoid's HttpOnly cookie, so that one login serves every application of the
// instance (single sign-on) and no script – not even this page's – can read the token. Changes carry the CSRF header
// the SDK adds.

import { type KernoidError, LoginClient, type Session } from "@kernoid/sdk";

export const client = new LoginClient({ cookies: true });

// Before the cookie, the token was kept in localStorage: remove what an earlier version left there.
try {
  localStorage.removeItem("kernoid.session");
} catch {
  // Private mode: nothing stored.
}

const DEVICES = "kernoid.devices";

/** This device's token for a login name, from an earlier login (see `device_token`). */
export function deviceToken(address: string): string | undefined {
  try {
    const known = JSON.parse(localStorage.getItem(DEVICES) ?? "{}") as Record<string, string>;
    return known[address.trim().toLowerCase()];
  } catch {
    return undefined;
  }
}

export function rememberDevice(address: string, token: string | undefined): void {
  if (!token) return;
  try {
    const known = JSON.parse(localStorage.getItem(DEVICES) ?? "{}") as Record<string, string>;
    known[address.trim().toLowerCase()] = token;
    localStorage.setItem(DEVICES, JSON.stringify(known));
  } catch {
    // Private mode: the device is not remembered.
  }
}

/** The current session, or nothing if there is none or it ended. */
export async function currentSession(): Promise<Session | undefined> {
  try {
    return await client.session();
  } catch (error) {
    if ((error as KernoidError).kind !== "unauthenticated") throw error;
    return undefined;
  }
}
