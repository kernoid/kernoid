// SPDX-License-Identifier: MIT
// /login/account: logs in if needed, then goes where `?next=` said – or to the account section of the web app, which
// holds the account page (name, password, second factors, sessions …).

import { showLogin, showSecondFactor, showSetup } from "./factors.js";
import { t, when } from "./i18n.js";
import { show } from "./screen.svelte.js";
import Choice from "./screens/Choice.svelte";
import { client, currentSession } from "./session.js";

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

/** Within the tenant's grace period, setting up a second factor is offered once per page. */
let offered = false;

export async function account(notice?: string): Promise<void> {
  document.title = t("Your account – kernoid");
  const session = await currentSession();
  if (!session) return showLogin(() => account(), notice ? { notice } : {});
  // The tenant may require a second factor: a session without one gets it asked for – or set up – first; the app
  // and the administration would refuse it.
  const factors = await client.secondFactors().catch(() => undefined);
  const multiFactor = session.checks.length > 1 || session.checks.includes("passkey");
  if (factors?.required && !multiFactor) {
    const relogin = () => showLogin(() => account(), { notice: t("Log in again to set up a second factor.") });
    const due = factors.setup_due && new Date(factors.setup_due) > new Date() ? factors.setup_due : null;
    if (!due) return showSecondFactor(() => account(), relogin);
    if (!offered) {
      offered = true;
      return show(Choice, {
        title: t("Set up a second factor"),
        notice: { text: t("Your organisation requires a second factor. Until {date} you can log in without one.", { date: when(due, false) }), kind: "info" },
        actions: [
          { label: t("Set it up now"), run: async () => showSetup(() => account(), relogin), kind: "primary" },
          { label: t("Later"), run: () => account(), kind: "link" },
        ],
      });
    }
  }
  // The account itself is a section of the web app (web/app, #/account).
  window.location.assign(takeNext() ?? "/app/#/account");
}
