// SPDX-License-Identifier: MIT
// How mailboxes are shown: those with a role by the role's name in the browser's language and its icon; the account's
// own folders by their name and a folder.

import { Archive, FileText, Folder, Inbox, Send, ShieldAlert, Trash2 } from "@lucide/svelte";

import { t } from "../i18n.js";
import type { Mailbox } from "./model.js";

const ROLE_NAMES: Record<string, string> = {
  inbox: "Inbox",
  drafts: "Drafts",
  sent: "Sent",
  archive: "Archive",
  junk: "Junk",
  trash: "Trash",
};

const ROLE_ICONS: Record<string, typeof Inbox> = {
  inbox: Inbox,
  drafts: FileText,
  sent: Send,
  archive: Archive,
  junk: ShieldAlert,
  trash: Trash2,
};

export function boxName(box: Mailbox): string {
  return box.role && ROLE_NAMES[box.role] ? t(ROLE_NAMES[box.role] ?? box.name) : box.name;
}

export function boxIcon(box: Mailbox): typeof Inbox {
  return (box.role && ROLE_ICONS[box.role]) || Folder;
}
