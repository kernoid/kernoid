// SPDX-License-Identifier: MIT
// Logging in and second factors – the steps the login flow, registering and the account page share.

import { type KernoidError, passkeyAutofillAvailable } from "@kernoid/sdk";

import { describe } from "./describe.js";
import { t } from "./i18n.js";
import { show } from "./screen.svelte.js";
import Choice from "./screens/Choice.svelte";
import Login from "./screens/Login.svelte";
import RecoveryCodes from "./screens/RecoveryCodes.svelte";
import SecondFactor from "./screens/SecondFactor.svelte";
import TotpSetup from "./screens/TotpSetup.svelte";
import { client } from "./session.js";

export interface LoginOptions {
  notice?: string;
  address?: string;
  cancel?: () => Promise<void>;
  authRequest?: string;
}

/** Logging in (Login.svelte); calls `done` once there is a session. */
export function showLogin(done: () => Promise<void>, options: LoginOptions = {}): void {
  stopAutofill();
  show(Login, { done, options });
}

/** The passkey request waiting in the address field's autofill, if any. */
let autofill: AbortController | undefined;

/** Offers the person's passkeys in the autofill of the address field, where the browser can; picking one logs in. */
export async function offerPasskeys(done: () => Promise<void>, report: (text: string) => void): Promise<void> {
  if (!(await passkeyAutofillAvailable())) return;
  const controller = new AbortController();
  autofill = controller;
  try {
    await client.loginWithPasskey(undefined, { conditional: true, signal: controller.signal });
    if (controller.signal.aborted) return;
    autofill = undefined;
    await done();
  } catch (error) {
    // Aborted because the person went another way, or the browser gave up: nothing to say.
    if (controller.signal.aborted || (error instanceof DOMException && ["AbortError", "NotAllowedError"].includes(error.name))) return;
    report(describe(error));
  }
}

/** Ends a waiting autofill request – before another passkey request, or when the page moves on. */
export function stopAutofill(): void {
  autofill?.abort();
  autofill = undefined;
}

/** Asks for a second factor the account has – or has one set up if it has none. */
export async function showSecondFactor(done: () => Promise<void>, relogin: () => void): Promise<void> {
  const factors = await client.secondFactors();
  if (!factors.totp && factors.passkeys === 0 && factors.recovery_codes_left === 0) {
    showSetup(done, relogin);
    return;
  }
  show(SecondFactor, { factors, done, back: () => showSecondFactor(done, relogin) });
}

/** Setting up a first second factor, when one is required: a passkey, or an authenticator app. */
export function showSetup(done: () => Promise<void>, relogin: () => void): void {
  const guard = (run: () => Promise<void>) => async () => {
    try {
      await run();
    } catch (error) {
      if ((error as KernoidError).kind === "login-required") relogin();
      else throw error;
    }
  };
  show(Choice, {
    title: t("Set up a second factor"),
    notice: { text: t("Your organisation requires a second factor. Set one up to continue."), kind: "info" },
    actions: [
      {
        label: t("Create a passkey"),
        kind: "primary",
        run: guard(async () => {
          await client.registerPasskey(deviceName());
          showConfirmPasskey(done, guard);
        }),
      },
      { label: t("Use an authenticator app"), run: guard(async () => showTotpSetup(async () => showRecoveryCodes(done))) },
    ],
  });
}

/** The new passkey confirms this login – asked for on a click of its own: browsers allow a passkey request only right
 * after something the person did, not after the request that created it. */
function showConfirmPasskey(done: () => Promise<void>, guard: (run: () => Promise<void>) => () => Promise<void>): void {
  show(Choice, {
    title: t("Passkey created"),
    notice: { text: t("Now confirm this login with it once."), kind: "info" },
    actions: [
      {
        label: t("Confirm with the passkey"),
        kind: "primary",
        run: guard(async () => {
          await client.checkPasskey();
          await showRecoveryCodes(done);
        }),
      },
    ],
  });
}

/** A TOTP secret to scan or type in, confirmed with a first code. */
export async function showTotpSetup(done: () => Promise<void>): Promise<void> {
  show(TotpSetup, { setup: await client.startTotp(), done });
}

/** New recovery codes, shown once. */
export async function showRecoveryCodes(done: () => Promise<void>): Promise<void> {
  show(RecoveryCodes, { codes: await client.generateRecoveryCodes(), done });
}

export function deviceName(): string {
  const agent = navigator.userAgent;
  const platform = /iPhone|iPad/.test(agent) ? "iPhone or iPad" : /Android/.test(agent) ? "Android" : /Mac/.test(agent) ? "Mac" : /Windows/.test(agent) ? "Windows" : /Linux/.test(agent) ? "Linux" : t("this device");
  return t("Passkey on {platform}", { platform });
}
