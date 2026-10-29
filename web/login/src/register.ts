// SPDX-License-Identifier: MIT
// Registering (/login/register, RFC 0003; Registration.svelte).

import { t } from "./i18n.js";
import { show } from "./screen.svelte.js";
import Registration from "./screens/Registration.svelte";
import { client } from "./session.js";

/** The registration form; `done` runs once the new account is logged in. */
export async function showRegistration(done: () => Promise<void>): Promise<void> {
  document.title = t("Create an account – kernoid");
  const [options, providers] = await Promise.all([client.registrationOptions(), client.loginProviders()]);
  show(Registration, { options, providers, done });
}
