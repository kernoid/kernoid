// SPDX-License-Identifier: MIT
// What the account section shares: kernoid's session API with the same cookie as JMAP, and a few texts.

import { LoginClient } from "@kernoid/sdk";

import { t } from "../i18n.js";

export const client = new LoginClient({ cookies: true });

/** A language by its own name. */
export function languageName(code: string): string {
  return ({ de: "Deutsch", en: "English" } as Record<string, string>)[code] ?? code;
}

export interface AppPassword {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export const when = (date: string): string => new Date(date).toLocaleString();

export function deviceName(): string {
  const agent = navigator.userAgent;
  const platform = /iPhone|iPad/.test(agent) ? "iPhone/iPad" : /Android/.test(agent) ? "Android" : /Mac/.test(agent) ? "Mac" : /Windows/.test(agent) ? "Windows" : /Linux/.test(agent) ? "Linux" : t("this device");
  return t("Passkey on {platform}", { platform });
}

/** Changing how one logs in needs a recent login: log in again and come back here. */
export async function relogin(): Promise<void> {
  await client.logout().catch(() => undefined);
  window.location.assign(`/login/account?next=${encodeURIComponent("/app/#/account")}`);
}
