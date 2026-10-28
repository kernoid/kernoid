// SPDX-License-Identifier: MIT
// kernoid's login UI. /login?authRequest=<id> answers an OpenID Connect auth request; /login/account is the account
// page; /login/register registers; /login/idp is where kernoid sends the browser back from an identity provider;
// /login alone logs in and goes to the account page.

import "./style.css";

import { applyTheme } from "./theme.js";

import { account, rememberNext } from "./account.js";
import { action, card, describe, h, message, show } from "./dom.js";
import { showLogin } from "./factors.js";
import { answer } from "./flow.js";
import { lang, t } from "./i18n.js";
import { showRegistration } from "./register.js";
import { client } from "./session.js";

applyTheme();

/** Back from an identity provider: the fragment holds a one-time code for the session, or an error. */
async function returned(): Promise<void> {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  window.history.replaceState(null, "", window.location.pathname);
  const login = fragment.get("login");
  const request = fragment.get("authRequest");
  const link = fragment.get("link");
  const next = async (authRequest: string | null) => {
    if (authRequest) return answer(authRequest);
    window.history.replaceState(null, "", "/login/account");
    return account();
  };
  if (link) return propose(link, request, next);
  if (!login) {
    const again = request ? `/login?authRequest=${encodeURIComponent(request)}` : "/login/account";
    return show(card(t("Login failed"), message(fragment.get("error") ?? t("The login could not be completed.")), h("p", {}, h("a", { href: again }, t("Try again")))));
  }
  const result = await client.exchangeIdpLogin(login);
  return next(result.authRequest);
}

/** A provider login found an account with the same verified address (RFC 0003, 3): log in to it to link the
 * provider – or create a separate account. */
async function propose(link: string, request: string | null, next: (authRequest: string | null) => Promise<void>): Promise<void> {
  const proposal = await client.linkProposal(link);
  show(
    card(
      t("Link {provider}?", { provider: proposal.provider }),
      message(t("There is an account with {email} already. Log in to it to sign in with {provider} from now on.", { email: proposal.email, provider: proposal.provider }), "info"),
      action(t("Log in and link"), async () =>
        showLogin(async () => {
          await client.confirmIdpLink(link);
          await next(request);
        }, { address: proposal.email }), "primary"),
      proposal.may_register
        ? action(t("Create a separate account"), async () => {
            const result = await client.registerInstead(link);
            await next(result.authRequest ?? request);
          })
        : null,
    ),
  );
}

async function start(): Promise<void> {
  document.documentElement.lang = lang;
  document.title = t("Log in – kernoid");
  if (window.location.pathname.replace(/\/+$/, "").endsWith("/idp")) return returned();
  if (window.location.pathname.replace(/\/+$/, "").endsWith("/register")) {
    return showRegistration(async () => {
      window.history.replaceState(null, "", "/login/account");
      return account();
    });
  }
  const id = new URLSearchParams(window.location.search).get("authRequest");
  if (id) return answer(id);
  rememberNext();
  if (!window.location.pathname.replace(/\/+$/, "").endsWith("/account")) {
    window.history.replaceState(null, "", "/login/account");
  }
  return account();
}

start().catch((error: unknown) => show(card(t("Something went wrong"), message(describe(error)))));
