// SPDX-License-Identifier: MIT
// kernoid's errors in the page's words.

import { KernoidError } from "@kernoid/sdk";

import { type Key, t } from "./i18n.js";

/** kernoid's error texts the page shows in its own words. */
const KNOWN: Record<string, Key> = {
  "the address or the password is wrong": "The address or the password is wrong.",
  "the code is not valid or was used already": "The code is not valid or was used already.",
  "the passkey was not accepted": "The passkey was not accepted.",
  "the account is deactivated": "The account is deactivated.",
  "the session is not valid": "The session is not valid.",
  "this needs a login with a second factor": "This needs a login with a second factor.",
  "log in again to change how you log in": "Log in again to change how you log in.",
};

export function describe(error: unknown): string {
  if (error instanceof DOMException && error.name === "NotAllowedError") return t("The passkey was not used.");
  if (error instanceof KernoidError) {
    if (error.kind === "too-many-attempts") {
      return t("Too many failed attempts – try again in {minutes} minutes.", { minutes: Math.ceil((error.retryAfter ?? 60) / 60) });
    }
    if (error.kind === "unavailable") return t("kernoid cannot be reached right now.");
    const known = KNOWN[error.message];
    return known ? t(known) : error.message;
  }
  if (error instanceof Error) return error.message;
  return String(error);
}
