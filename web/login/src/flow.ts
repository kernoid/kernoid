// SPDX-License-Identifier: MIT
// Answering an OpenID Connect auth request: kernoid sends the browser to /login?authRequest=<id>; this page logs the
// person in – honouring prompt and max_age – and finishes the request, which sends the browser back to the
// application.

import { type AuthRequest, type DeclineReason, type KernoidError } from "@kernoid/sdk";

import { action, card, h, message, show } from "./dom.js";
import { showLogin, showSecondFactor, showSetup } from "./factors.js";
import { t, when } from "./i18n.js";
import { client, currentSession } from "./session.js";

export async function answer(id: string): Promise<void> {
  let request: AuthRequest;
  try {
    request = await client.authRequest(id);
  } catch (error) {
    if ((error as KernoidError).kind !== "not-found") throw error;
    show(card(t("This login has expired"), message(t("Go back to the application and start again."), "info")));
    return;
  }
  const decline = async (reason: DeclineReason) => window.location.assign(await client.declineAuthRequest(id, reason));
  const cancel = () => decline("access_denied");
  const silent = request.prompt.includes("none");
  const session = await currentSession();

  // prompt=none: only an existing session that needs nothing more.
  if (silent && !session) return decline("login_required");

  const login = (notice?: string) =>
    showLogin(finish, {
      cancel,
      authRequest: id,
      ...(notice ? { notice } : {}),
      ...(session ? { address: session.account.address } : {}),
    });

  // Within the tenant's grace period, someone without a second factor is offered to set one up – once.
  let offered = silent;

  async function finish(consent = false): Promise<void> {
    if (!offered) {
      offered = true;
      const due = (await client.secondFactors().catch(() => undefined))?.setup_due;
      if (due) {
        const relogin = () => login(t("Log in again to set up a second factor."));
        return show(
          card(
            t("Set up a second factor"),
            message(t("Your organisation requires a second factor. Until {date} you can log in without one.", { date: when(due, false) }), "info"),
            action(t("Set it up now"), async () => showSetup(() => finish(consent), relogin), "primary"),
            action(t("Later"), () => finish(consent), "link"),
          ),
        );
      }
    }
    try {
      window.location.assign(await client.finishAuthRequest(id, { consent }));
    } catch (error) {
      const kind = (error as KernoidError).kind;
      if (silent) return decline(silentError(kind));
      if (kind === "consent-required") return askConsent(request, () => finish(true), cancel);
      if (kind === "login-required") return login(t("{application} asks you to log in again.", { application: request.application }));
      if (kind === "mfa-required") return showSecondFactor(finish, () => login(t("Log in again to set up a second factor.")));
      if (kind === "forbidden") return refused(request, cancel);
      throw error;
    }
  }

  if (!session || request.prompt.includes("login")) {
    if (session && request.prompt.includes("login")) {
      await client.logout().catch(() => undefined);
    }
    return login(t("Log in to continue to {application}.", { application: request.application }));
  }
  if (request.prompt.includes("select_account")) {
    return show(
      card(
        t("Continue to {application}", { application: request.application }),
        h("p", {}, t("You are logged in as {name} ({address}).", { name: session.account.display_name, address: session.account.address })),
        action(t("Continue as {name}", { name: session.account.display_name }), () => finish(), "primary"),
        action(t("Use another account"), async () => {
          await client.logout().catch(() => undefined);
          login();
        }),
        action(t("Cancel"), cancel, "link"),
      ),
    );
  }
  return finish();
}

function silentError(kind: string): DeclineReason {
  if (kind === "login-required") return "login_required";
  if (kind === "consent-required") return "consent_required";
  if (kind === "mfa-required") return "interaction_required";
  return "access_denied";
}

/** What a scope means, for the person asked; scopes kernoid does not know are shown as they are. */
function describeScope(scope: string): string | null {
  switch (scope) {
    case "openid":
      return t("Know who you are");
    case "profile":
      return t("See your name");
    case "email":
      return t("See your email address");
    case "offline_access":
      return t("Stay connected while you are not logged in");
    case "mail":
      return t("Read and send your email (IMAP, SMTP)");
    case "urn:kernoid:project:roles":
      return t("See your roles in this application");
    default:
      return scope.startsWith("urn:kernoid:tenant:id:") ? null : scope;
  }
}

/** The application needs the person's agreement: show what it asks for. */
function askConsent(request: AuthRequest, accept: () => Promise<void>, cancel: () => Promise<void>): void {
  const items = request.scopes.map(describeScope).filter((text): text is string => text !== null);
  show(
    card(
      t("Allow {application}?", { application: request.application }),
      h("p", {}, t("{application} asks to:", { application: request.application })),
      h("ul", { class: "list" }, ...items.map((text) => h("li", {}, text))),
      h("p", { class: "muted" }, t("You can withdraw this on your account page at any time.")),
      action(t("Allow"), accept, "primary"),
      action(t("Cancel"), cancel, "link"),
    ),
  );
}

function refused(request: AuthRequest, cancel: () => Promise<void>): void {
  show(
    card(
      t("Not allowed"),
      message(t("This account may not use {application}.", { application: request.application })),
      action(t("Use another account"), async () => {
        await client.logout().catch(() => undefined);
        window.location.reload();
      }, "primary"),
      action(t("Back to the application"), cancel, "link"),
    ),
  );
}
