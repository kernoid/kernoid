// SPDX-License-Identifier: MIT
// Building the page from elements, never from HTML strings: nothing the server or the URL says can become markup.

import { KernoidError } from "@kernoid/sdk";

import { type Key, t } from "./i18n.js";

type Child = Node | string | false | null | undefined;
type Attributes = Record<string, string | boolean | ((event: Event) => void) | undefined>;

export function h(tag: string, attributes: Attributes = {}, ...children: Child[]): HTMLElement {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (value === undefined || value === false) continue;
    if (typeof value === "function") element.addEventListener(name.replace(/^on/, ""), value);
    else if (value === true) element.setAttribute(name, "");
    else element.setAttribute(name, value);
  }
  for (const child of children) {
    if (child === false || child === null || child === undefined) continue;
    element.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return element;
}

const root = (): HTMLElement => document.getElementById("app") as HTMLElement;

/** Replaces the page's content and moves focus to the first field (or the heading). */
export function show(...children: Child[]): void {
  const app = root();
  app.replaceChildren(...children.filter((child): child is Node | string => Boolean(child)));
  const focus = app.querySelector<HTMLElement>("input:not([type=hidden]), button, h1");
  focus?.focus();
}

/** Whether the page is light: as the web app chose (theme.ts), else as the system is. */
function lightTheme(): boolean {
  const chosen = document.documentElement.getAttribute("data-theme");
  return chosen ? chosen === "light" : window.matchMedia("(prefers-color-scheme: light)").matches;
}

/** The page frame: wordmark, heading, content. */
export function card(title: string, ...children: Child[]): HTMLElement {
  return h(
    "section",
    { class: "card" },
    h("img", { src: `/login/kernoid-wordmark-flat-on-${lightTheme() ? "light" : "dark"}.svg`, alt: "kernoid", class: "wordmark", width: "140" }),
    h("h1", { tabindex: "-1" }, title),
    ...children,
  );
}

export function message(text: string, kind: "error" | "info" = "error"): HTMLElement {
  return h("p", { class: `message ${kind}`, role: kind === "error" ? "alert" : "status" }, text);
}

export function field(label: string, input: Attributes): HTMLElement {
  const id = `f-${String(input.name)}`;
  return h("label", { for: id }, h("span", {}, label), h("input", { id, ...input }));
}

/** A form whose submit handler gets the values; the button is disabled while it runs. */
export function form(
  submitLabel: string,
  fields: HTMLElement[],
  onSubmit: (values: Record<string, string>) => Promise<void>,
  ...extra: Child[]
): HTMLElement {
  const status = h("div", { class: "status" });
  const button = h("button", { type: "submit", class: "primary" }, submitLabel) as HTMLButtonElement;
  const element = h("form", { novalidate: true }, ...fields, status, button, ...extra) as HTMLFormElement;
  element.addEventListener("submit", (event) => {
    event.preventDefault();
    const values: Record<string, string> = {};
    for (const [key, value] of new FormData(element)) values[key] = String(value);
    button.disabled = true;
    status.replaceChildren();
    onSubmit(values)
      .catch((error: unknown) => status.replaceChildren(message(describe(error))))
      .finally(() => {
        button.disabled = false;
      });
  });
  return element;
}

/** A button that runs an action, showing its error next to it. */
export function action(label: string, run: () => Promise<void>, kind = "secondary"): HTMLElement {
  const status = h("span", { class: "status" });
  const button = h("button", { type: "button", class: kind }, label) as HTMLButtonElement;
  button.addEventListener("click", () => {
    button.disabled = true;
    status.replaceChildren();
    run()
      .catch((error: unknown) => status.replaceChildren(message(describe(error))))
      .finally(() => {
        button.disabled = false;
      });
  });
  return h("div", { class: "action" }, button, status);
}

/** kernoid's error texts the page shows in its own words. */
const KNOWN: Record<string, Key> = {
  "the address or the password is wrong": "The address or the password is wrong.",
  "the code is not valid or was used already": "The code is not valid or was used already.",
  "the passkey was not accepted": "The passkey was not accepted.",
  "the account is deactivated": "The account is deactivated.",
  "the session is not valid": "The session is not valid.",
  "this needs a login with a second factor": "This needs a login with a second factor.",
  "log in again to change how you log in": "Log in again to change how you log in.",
};

export function describe(error: unknown): string {
  if (error instanceof DOMException && error.name === "NotAllowedError") return t("The passkey was not used.");
  if (error instanceof KernoidError) {
    if (error.kind === "too-many-attempts") {
      return t("Too many failed attempts – try again in {minutes} minutes.", { minutes: Math.ceil((error.retryAfter ?? 60) / 60) });
    }
    if (error.kind === "unavailable") return t("kernoid cannot be reached right now.");
    const known = KNOWN[error.message];
    return known ? t(known) : error.message;
  }
  if (error instanceof Error) return error.message;
  return String(error);
}
