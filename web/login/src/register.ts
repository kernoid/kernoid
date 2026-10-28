// SPDX-License-Identifier: MIT
// Registering (/login/register, RFC 0003): a name, an email address and a password – where the instance offers it,
// an address of one's own on one of its domains (a mailbox) or a username – then the code kernoid sends.

import { type RegistrationOptions } from "@kernoid/sdk";

import { action, card, field, form, h, message, show } from "./dom.js";
import { t } from "./i18n.js";
import { client } from "./session.js";

/** The registration form; `done` runs once the new account is logged in. */
export async function showRegistration(done: () => Promise<void>): Promise<void> {
  document.title = t("Create an account – kernoid");
  const [options, providers] = await Promise.all([client.registrationOptions(), client.loginProviders()]);
  const back = action(t("Back to logging in"), async () => window.location.assign("/login/account"), "link");
  const withProviders = providers.map((provider) =>
    action(t("Continue with {provider}", { provider: provider.name }), async () => {
      window.location.assign(await client.startIdpLogin(provider.id));
    }),
  );
  if (!options.by_email || (!options.open && options.domains.length === 0)) {
    return show(
      card(
        t("Create an account"),
        withProviders.length > 0 ? null : message(t("Registering is not possible here."), "info"),
        ...withProviders,
        back,
      ),
    );
  }
  show(
    card(
      t("Create an account"),
      form(t("Continue"), fields(options), async (values) => {
        const nativeAddress = values.local ? `${values.local.trim()}@${values.domain ?? options.domains[0]}` : undefined;
        const email = (values.email ?? "").trim();
        const id = await client.register({
          email,
          password: values.password ?? "",
          displayName: (values.name ?? "").trim(),
          ...(nativeAddress ? { nativeAddress } : {}),
          ...(values.username ? { username: values.username.trim() } : {}),
        });
        askCode(id, email, values.password ?? "", done);
      }),
      withProviders.length > 0 ? h("p", { class: "or" }, t("or")) : null,
      ...withProviders,
      back,
    ),
  );
}

function fields(options: RegistrationOptions): HTMLElement[] {
  const list = [
    field(t("Name"), { name: "name", autocomplete: "name", required: true }),
    field(t("Email address"), { name: "email", type: "email", autocomplete: "email", required: true }),
    field(t("Password"), { name: "password", type: "password", autocomplete: "new-password", required: true, minlength: "12" }),
  ];
  if (options.domains.length > 0) {
    // An address of one's own – a mailbox; optional where people may register without one.
    const domain =
      options.domains.length === 1
        ? h("div", { class: "suffix" }, `@${options.domains[0]}`)
        : h("select", { name: "domain" }, ...options.domains.map((name) => h("option", { value: name }, `@${name}`)));
    list.push(
      h(
        "label",
        { for: "f-local" },
        h("span", {}, options.open ? t("Your own address (optional)") : t("Your own address")),
        h("div", { class: "address" }, h("input", { id: "f-local", name: "local", autocomplete: "off", required: !options.open }), domain),
      ),
    );
  }
  if (options.usernames) list.push(field(t("Username (optional)"), { name: "username", autocomplete: "username" }));
  return list;
}

function askCode(id: string, email: string, password: string, done: () => Promise<void>): void {
  show(
    card(
      t("Confirm your email address"),
      message(t("We sent a code to {email}.", { email }), "info"),
      form(
        t("Create the account"),
        [field(t("Code"), { name: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{8}", required: true })],
        async ({ code = "" }) => {
          await client.confirmRegistration(id, code.replace(/\s/g, ""));
          await client.login(email, password);
          await done();
        },
      ),
    ),
  );
}
