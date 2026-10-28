// SPDX-License-Identifier: MIT
// Logging in and second factors – shared by the login flow and the account page.

import { type KernoidError, passkeyAutofillAvailable } from "@kernoid/sdk";

import { action, card, describe, field, form, h, message, show } from "./dom.js";
import { t } from "./i18n.js";
import { client, deviceToken, rememberDevice } from "./session.js";

/** Logging in: the address first – which may belong to an identity provider – then the password; or a passkey
 * alone. Calls `done` once there is a session. */
export function showLogin(
  done: () => Promise<void>,
  options: { notice?: string; address?: string; cancel?: () => Promise<void>; authRequest?: string } = {},
): void {
  stopAutofill();
  const others = h("div", { class: "others" });
  const passkey = action(t("Log in with a passkey"), async () => {
    stopAutofill();
    const session = await client.loginWithPasskey();
    await done();
  });
  const status = h("div", { class: "status" });
  show(
    card(
      t("Log in"),
      options.notice ? message(options.notice, "info") : null,
      form(
        t("Continue"),
        [field(t("Email address or username"), { name: "address", autocomplete: "username webauthn", required: true, value: options.address, spellcheck: "false" })],
        async ({ address = "" }) => {
          stopAutofill();
          const trimmed = address.trim();
          const found = await client.loginOptions(trimmed);
          if (found.identity_provider) {
            const start = { loginHint: trimmed, ...(options.authRequest ? { authRequest: options.authRequest } : {}) };
            window.location.assign(await client.startIdpLogin(found.identity_provider.id, start));
            return;
          }
          showPassword(trimmed, done, options);
        },
      ),
      status,
      h("p", { class: "or" }, t("or")),
      passkey,
      others,
      options.cancel ? action(t("Cancel"), options.cancel, "link") : null,
    ),
  );
  void offerPasskeys(done, status);
  void offerOthers(others, options.authRequest);
}

/** "Sign in with …" for the instance's open providers, and registering where it is possible. */
async function offerOthers(container: HTMLElement, authRequest?: string): Promise<void> {
  const [providers, registration] = await Promise.all([
    client.loginProviders().catch(() => []),
    client.registrationOptions().catch(() => undefined),
  ]);
  const start = authRequest ? { authRequest } : {};
  container.replaceChildren(
    ...providers.map((provider) =>
      action(t("Continue with {provider}", { provider: provider.name }), async () => {
        stopAutofill();
        window.location.assign(await client.startIdpLogin(provider.id, start));
      }),
    ),
  );
  if (registration && registration.by_email && (registration.open || registration.domains.length > 0)) {
    container.append(h("p", { class: "muted" }, h("a", { href: "/login/register" }, t("Create an account"))));
  }
}

/** The passkey request waiting in the address field's autofill, if any. */
let autofill: AbortController | undefined;

/** Offers the person's passkeys in the autofill of the address field, where the browser can; picking one logs in. */
async function offerPasskeys(done: () => Promise<void>, status: HTMLElement): Promise<void> {
  if (!(await passkeyAutofillAvailable())) return;
  const controller = new AbortController();
  autofill = controller;
  try {
    const session = await client.loginWithPasskey(undefined, { conditional: true, signal: controller.signal });
    if (controller.signal.aborted) return;
    autofill = undefined;
    await done();
  } catch (error) {
    // Aborted because the person went another way, or the browser gave up: nothing to say.
    if (controller.signal.aborted || (error instanceof DOMException && ["AbortError", "NotAllowedError"].includes(error.name))) return;
    status.replaceChildren(message(describe(error)));
  }
}

/** Ends a waiting autofill request – before another passkey request, or when the page moves on. */
function stopAutofill(): void {
  autofill?.abort();
  autofill = undefined;
}

function showPassword(address: string, done: () => Promise<void>, options: Parameters<typeof showLogin>[1] = {}): void {
  show(
    card(
      t("Log in"),
      h("p", { class: "muted" }, address),
      form(
        t("Log in"),
        [
          h("input", { type: "hidden", name: "address", value: address, autocomplete: "username" }),
          field(t("Password"), { name: "password", type: "password", autocomplete: "current-password", required: true }),
        ],
        async ({ password = "" }) => {
          const session = await client.login(address, password, undefined, deviceToken(address));
          rememberDevice(address, session.device_token);
          await done();
        },
      ),
      action(t("Use another address"), async () => showLogin(done, { ...options, address })),
    ),
  );
}

/** Asks for a second factor the account has – or has one set up if it has none. */
export async function showSecondFactor(done: () => Promise<void>, relogin: () => void): Promise<void> {
  const factors = await client.secondFactors();
  if (!factors.totp && factors.passkeys === 0 && factors.recovery_codes_left === 0) {
    showSetup(done, relogin);
    return;
  }
  const recovery = () =>
    show(
      card(
        t("Use a recovery code"),
        form(
          t("Continue"),
          [field(t("Recovery code"), { name: "code", autocomplete: "off", required: true, spellcheck: "false" })],
          async ({ code = "" }) => {
            await client.checkRecoveryCode(code.trim());
            await done();
          },
        ),
        action(t("Back"), () => showSecondFactor(done, relogin), "link"),
      ),
    );
  show(
    card(
      t("Confirm it is you"),
      message(t("This login needs a second factor."), "info"),
      factors.totp
        ? form(
            t("Continue"),
            [field(t("Code from your authenticator app"), { name: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", required: true })],
            async ({ code = "" }) => {
              await client.checkTotp(code.replace(/\s/g, ""));
              await done();
            },
          )
        : null,
      factors.passkeys > 0
        ? action(t("Use a passkey"), async () => {
            await client.checkPasskey();
            await done();
          }, factors.totp ? "secondary" : "primary")
        : null,
      factors.recovery_codes_left > 0 ? action(t("Use a recovery code"), async () => recovery(), "link") : null,
    ),
  );
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
  show(
    card(
      t("Set up a second factor"),
      message(t("Your organisation requires a second factor. Set one up to continue."), "info"),
      action(t("Create a passkey"), guard(async () => {
        await client.registerPasskey(deviceName());
        await client.checkPasskey();
        await showRecoveryCodes(done);
      }), "primary"),
      action(t("Use an authenticator app"), guard(async () => showTotpSetup(async () => showRecoveryCodes(done)))),
    ),
  );
}

/** A TOTP secret to scan or type in, confirmed with a first code. */
export async function showTotpSetup(done: () => Promise<void>): Promise<void> {
  const setup = await client.startTotp();
  show(
    card(
      t("Authenticator app"),
      h("p", {}, t("Scan this code with your authenticator app, open the link on this device, or type in the key:")),
      h("img", { src: setup.qr_code, alt: t("QR code for the authenticator app"), class: "qr", width: "200", height: "200" }),
      h("p", {}, h("a", { href: setup.uri, class: "button secondary" }, t("Open in authenticator app"))),
      h("p", { class: "secret", "aria-label": t("Key") }, setup.secret.replace(/(.{4})/g, "$1 ").trim()),
      form(
        t("Confirm"),
        [field(t("Code shown by the app"), { name: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", required: true })],
        async ({ code = "" }) => {
          await client.confirmTotp(code.replace(/\s/g, ""));
          await done();
        },
      ),
    ),
  );
}

/** New recovery codes, shown once. */
export async function showRecoveryCodes(done: () => Promise<void>): Promise<void> {
  const codes = await client.generateRecoveryCodes();
  show(
    card(
      t("Recovery codes"),
      h("p", {}, t("If you lose your devices, each of these codes lets you log in once. Keep them somewhere safe – they are shown only now.")),
      h("ol", { class: "codes" }, ...codes.map((code) => h("li", {}, code))),
      action(t("I have saved them"), done, "primary"),
    ),
  );
}

export function deviceName(): string {
  const agent = navigator.userAgent;
  const platform = /iPhone|iPad/.test(agent) ? "iPhone or iPad" : /Android/.test(agent) ? "Android" : /Mac/.test(agent) ? "Mac" : /Windows/.test(agent) ? "Windows" : /Linux/.test(agent) ? "Linux" : t("this device");
  return t("Passkey on {platform}", { platform });
}

export { describe };
