// SPDX-License-Identifier: MIT
// /login/account: logs in if needed, then goes where `?next=` said – or to the account section of the web app, which
// holds the account page (name, password, second factors, sessions …).

import { showLogin } from "./factors.js";
import { t } from "./i18n.js";
import { currentSession } from "./session.js";

/**
 * Where to go once logged in: a path of this origin from `?next=` (e.g. `/app/`, the web app), kept for the page's
 * session so that it survives the steps of logging in. Anything else – another origin, `//host` – is ignored.
 */
const NEXT = "kernoid.next";

export function rememberNext(): void {
  const next = new URLSearchParams(window.location.search).get("next");
  try {
    if (next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\")) {
      sessionStorage.setItem(NEXT, next);
    }
  } catch {
    // Private mode: the account page is where one lands.
  }
}

function takeNext(): string | undefined {
  try {
    const next = sessionStorage.getItem(NEXT) ?? undefined;
    sessionStorage.removeItem(NEXT);
    return next;
  } catch {
    return undefined;
  }
}

export async function account(notice?: string): Promise<void> {
  document.title = t("Your account – kernoid");
  const session = await currentSession();
  if (!session) return showLogin(() => account(), notice ? { notice } : {});
  // The account itself is a section of the web app (web/app, #/account).
  window.location.assign(takeNext() ?? "/app/#/account");
}
