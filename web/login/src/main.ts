// SPDX-License-Identifier: MIT
// kernoid's login UI. /login?authRequest=<id> answers an OpenID Connect auth request; /login/account is the account
// page; /login/register registers; /login/idp is where kernoid sends the browser back from an identity provider;
// /login alone logs in and goes to the account page.

import "./style.css";

import { mount } from "svelte";

import { applyTheme } from "./theme.js";

import { account, rememberNext } from "./account.js";
import App from "./App.svelte";
import { describe } from "./describe.js";
import { showLogin } from "./factors.js";
import { answer } from "./flow.js";
import { lang, t } from "./i18n.js";
import { showRegistration } from "./register.js";
import { show } from "./screen.svelte.js";
import Choice from "./screens/Choice.svelte";
import { client } from "./session.js";

applyTheme();
const target = document.getElementById("app");
if (target) {
  target.replaceChildren();
  mount(App, { target });
}

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
    return show(Choice, {
      title: t("Login failed"),
      notice: { text: fragment.get("error") ?? t("The login could not be completed.") },
      link: { href: again, text: t("Try again") },
    });
  }
  const result = await client.exchangeIdpLogin(login);
  return next(result.authRequest);
}

/** A provider login found an account with the same verified address (RFC 0003, 3): log in to it to link the
 * provider – or create a separate account. */
async function propose(link: string, request: string | null, next: (authRequest: string | null) => Promise<void>): Promise<void> {
  const proposal = await client.linkProposal(link);
  show(Choice, {
    title: t("Link {provider}?", { provider: proposal.provider }),
    notice: {
      text: t("There is an account with {email} already. Log in to it to sign in with {provider} from now on.", { email: proposal.email, provider: proposal.provider }),
      kind: "info",
    },
    actions: [
      {
        label: t("Log in and link"),
        run: async () =>
          showLogin(
            async () => {
              await client.confirmIdpLink(link);
              await next(request);
            },
            { address: proposal.email },
          ),
        kind: "primary",
      },
      ...(proposal.may_register
        ? [
            {
              label: t("Create a separate account"),
              run: async () => {
                const result = await client.registerInstead(link);
                await next(result.authRequest ?? request);
              },
            },
          ]
        : []),
    ],
  });
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

start().catch((error: unknown) => show(Choice, { title: t("Something went wrong"), notice: { text: describe(error) } }));
