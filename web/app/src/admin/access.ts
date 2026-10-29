// SPDX-License-Identifier: MIT
// What the logged-in account may administer: its permissions in its tenant, and whether it administers the instance.

import { api } from "./api.svelte.js";

export interface Access {
  permissions: string[];
  instance: boolean;
}

export async function adminAccess(): Promise<Access> {
  const [permissions, instance] = await Promise.all([
    api<{ permissions: string[] }>("GET", "/v1/tenant/permissions").then((view) => view.permissions).catch(() => []),
    api("GET", "/v1/instance/details").then(() => true).catch(() => false),
  ]);
  return { permissions, instance };
}
