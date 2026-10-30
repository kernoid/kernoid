// SPDX-License-Identifier: MIT
// What the logged-in account may administer: its permissions in the tenant worked on (role.rs), and whether it
// administers the instance. Nothing for most; kernoid checks again on every request.
//
// Only a question: any refusal – also "log in with a second factor" – means nothing to administer here, never a way
// back to the login (which would send the browser straight back: a loop).

import { tenant } from "./api.svelte.js";

export interface Access {
  permissions: string[];
  instance: boolean;
}

async function ask(path: string): Promise<Response> {
  const headers: Record<string, string> = { accept: "application/json", "kernoid-csrf": "1" };
  const target = tenant();
  if (target) headers["kernoid-tenant"] = target;
  return fetch(path, { headers, credentials: "same-origin" });
}

export async function adminAccess(): Promise<Access> {
  const [permissions, instance] = await Promise.all([
    ask("/v1/tenant/permissions")
      .then(async (response) => (response.ok ? ((await response.json()) as { permissions: string[] }).permissions : []))
      .catch(() => []),
    ask("/v1/instance/details")
      .then((response) => response.ok)
      .catch(() => false),
  ]);
  return { permissions, instance };
}
