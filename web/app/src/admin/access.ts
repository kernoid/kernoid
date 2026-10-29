// SPDX-License-Identifier: MIT
// What the logged-in account may administer: its permissions in the tenant worked on (role.rs), and whether it
// administers the instance. Nothing for most; kernoid checks again on every request.

import { admin, need } from "./api.svelte.js";

export interface Access {
  permissions: string[];
  instance: boolean;
}

export async function adminAccess(): Promise<Access> {
  const [permissions, instance] = await Promise.all([
    need(admin.GET("/v1/tenant/permissions")).then((view) => view.permissions).catch(() => []),
    need(admin.GET("/v1/instance/details")).then(() => true).catch(() => false),
  ]);
  return { permissions, instance };
}
