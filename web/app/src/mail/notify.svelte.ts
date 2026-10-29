// SPDX-License-Identifier: MIT
// Notifications for new mail: while the app is open but not in front, each new unread email in the inbox is shown by
// the browser – if the user switched them on (account page) and the browser allows it. Kept per browser.

import type { Jmap } from "../jmap.js";
import { MAIL } from "../jmap.js";
import { t } from "../i18n.js";

const KEY = "kernoid.notifications";

export function notificationsSupported(): boolean {
  return typeof Notification !== "undefined";
}

function stored(): boolean {
  try {
    return localStorage.getItem(KEY) === "on";
  } catch {
    return false;
  }
}

const setting = $state({ wanted: stored() });

export function notificationsWanted(): boolean {
  return setting.wanted;
}

/** Switches notifications on – asking the browser – or off; whether they are on. */
export async function setNotifications(on: boolean): Promise<boolean> {
  if (on && notificationsSupported() && Notification.permission !== "granted") {
    if ((await Notification.requestPermission()) !== "granted") on = false;
  }
  try {
    localStorage.setItem(KEY, on ? "on" : "off");
  } catch {
    // Not kept: off after the next reload.
  }
  setting.wanted = on;
  return on;
}

interface Arrived {
  id: string;
  subject: string | null;
  receivedAt: string;
  from: { name: string | null; email: string }[] | null;
}

/** Watches the inbox: `check` shows what arrived since the watcher began (MailNotifications.svelte calls it on push). */
export function inboxWatcher(jmap: Jmap): { check: () => Promise<void>; stop: () => void } {
  let since = new Date().toISOString();
  let inbox: string | undefined;
  const shown = new Set<string>();
  const check = async () => {
    const quiet =
      !setting.wanted || !notificationsSupported() || Notification.permission !== "granted" || document.hasFocus();
    if (quiet) {
      since = new Date().toISOString();
      return;
    }
    const accountId = jmap.account(MAIL);
    if (!inbox) {
      const found = await jmap.call<{ ids: string[] }>([MAIL], "Mailbox/query", { accountId, filter: { role: "inbox" } });
      inbox = found.ids[0];
      if (!inbox) return;
    }
    const responses = await jmap.request(
      [MAIL],
      [
        ["Email/query", { accountId, filter: { inMailbox: inbox, after: since, notKeyword: "$seen" }, sort: [{ property: "receivedAt", isAscending: false }], limit: 5 }, "q"],
        ["Email/get", { accountId, "#ids": { resultOf: "q", name: "Email/query", path: "/ids" }, properties: ["subject", "receivedAt", "from"] }, "g"],
      ],
    );
    const list = ((responses.get("g")?.[0] as { list?: Arrived[] } | undefined)?.list ?? []).filter((email) => !shown.has(email.id));
    for (const email of list) {
      shown.add(email.id);
      const sender = email.from?.[0];
      const notification = new Notification(sender?.name || sender?.email || t("New email"), {
        body: email.subject || t("(no subject)"),
        tag: email.id,
      });
      notification.onclick = () => {
        window.focus();
        window.location.hash = "#/mail";
        notification.close();
      };
      if (email.receivedAt > since) since = email.receivedAt;
    }
  };
  return { check, stop: () => shown.clear() };
}
