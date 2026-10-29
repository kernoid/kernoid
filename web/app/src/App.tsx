// SPDX-License-Identifier: MIT
// The frame: navigation between mail, calendar, contacts and files (by the URL's fragment) – those the account has –,
// the account (#/account), and the views.

import { LoginClient } from "@kernoid/sdk";
import { ErrorBoundary, type JSX, Match, type Resource, Show, Switch, createContext, createResource, createSignal, onCleanup, useContext } from "solid-js";

import { AccountView } from "./account/AccountView.js";
import { AdminView, adminAccess } from "./admin/AdminView.js";
import { CalendarView } from "./calendar/CalendarView.js";
import { ContactsView } from "./contacts/ContactsView.js";
import { FilesView } from "./files/FilesView.js";
import { t } from "./i18n.js";
import { FILENODE, Jmap, MAIL, fetchSession } from "./jmap.js";
import { MailNotifications } from "./mail/notify.js";
import { MailView } from "./mail/MailView.js";
import { THEMES, setTheme, theme } from "./theme.js";

const JmapContext = createContext<Jmap>();

export function useJmap(): Jmap {
  const jmap = useContext(JmapContext);
  if (!jmap) throw new Error("no JMAP session");
  return jmap;
}

/** Bumped whenever kernoid announces a change (push), per type – views refetch what they show. */
const [changes, setChanges] = createSignal<Record<string, number>>({});

export function changed(type: string): number {
  return changes()[type] ?? 0;
}

export function touch(...types: string[]): void {
  setChanges((current) => {
    const next = { ...current };
    for (const type of types) next[type] = (next[type] ?? 0) + 1;
    return next;
  });
}

type Section = "mail" | "calendar" | "contacts" | "files" | "account" | "admin";

/** The section the URL names, if the account has it; else the first it has. */
function section(available: Section[]): Section {
  const name = window.location.hash.replace(/^#\/?/, "").split("/")[0] as Section;
  if (name === "account" || name === "admin") return name;
  return available.includes(name) ? name : (available[0] ?? "account");
}

function sections(jmap: Jmap | undefined): Section[] {
  const primary = jmap?.session.primaryAccounts ?? {};
  const out: Section[] = [];
  if (primary[MAIL]) out.push("mail", "calendar", "contacts");
  // Files also for someone with no store of their own who reaches a drive or someone's shared folders.
  const accounts = Object.values(jmap?.session.accounts ?? {});
  if (primary[FILENODE] || accounts.some((account) => account.accountCapabilities[FILENODE])) out.push("files");
  return out;
}

export function App(): JSX.Element {
  const [jmap] = createResource(async () => {
    const jmap = new Jmap(await fetchSession());
    const stop = jmap.listen((types) => touch(...types));
    onCleanup(stop);
    return jmap;
  });
  const available = () => sections(jmap.error ? undefined : jmap());
  // Administration appears for those who may administer something.
  const [admin] = createResource(() => adminAccess().then((access) => access.instance || access.permissions.length > 0).catch(() => false));
  const [hash, setHash] = createSignal(window.location.hash);
  const onHash = () => setHash(window.location.hash);
  window.addEventListener("hashchange", onHash);
  onCleanup(() => window.removeEventListener("hashchange", onHash));
  const current = () => {
    hash();
    return section(available());
  };
  const login = new LoginClient({ cookies: true });
  const logout = async () => {
    const next = await login.logout().catch(() => null);
    window.location.assign(next ?? "/login/account");
  };

  const link = (name: Section, label: string) => (
    <a href={`#/${name}`} classList={{ active: current() === name }}>
      {t(label)}
    </a>
  );

  return (
    <Switch>
      <Match when={jmap.error}>
        <main class="center">
          <h1>{t("Something went wrong")}</h1>
          <p class="muted">{String(jmap.error)}</p>
          <button type="button" onClick={() => window.location.reload()}>
            {t("Try again")}
          </button>
        </main>
      </Match>
      <Match when={jmap()}>
        {(session) => (
          <JmapContext.Provider value={session()}>
            <div class="shell">
              <header class="bar">
                <span class="brand" aria-label="kernoid">
                  kern<b>0</b>
                  <i>id</i>
                </span>
                <nav>
                  <Show when={available().includes("mail")}>
                    {link("mail", "Mail")}
                    {link("calendar", "Calendar")}
                    {link("contacts", "Contacts")}
                  </Show>
                  <Show when={available().includes("files")}>{link("files", "Files")}</Show>
                  <Show when={admin()}>{link("admin", "Administration")}</Show>
                </nav>
                <span class="who">
                  <button
                    type="button"
                    class="quiet"
                    title={t("Theme")}
                    onClick={() => setTheme(THEMES[(THEMES.indexOf(theme()) + 1) % THEMES.length] ?? "system")}
                  >
                    {t(theme() === "system" ? "System" : theme() === "light" ? "Light" : "Dark")}
                  </button>
                  <a href="#/account" classList={{ active: current() === "account" }}>
                    {session().session.username}
                  </a>
                  <button type="button" class="quiet" onClick={() => void logout()}>
                    {t("Log out")}
                  </button>
                </span>
              </header>
              <Show when={available().includes("mail")}>
                <MailNotifications />
              </Show>
              <ErrorBoundary fallback={(error, reset) => <Failed error={error} reset={reset} />}>
                <Switch>
                  <Match when={current() === "mail"}>
                    <MailView />
                  </Match>
                  <Match when={current() === "calendar"}>
                    <CalendarView />
                  </Match>
                  <Match when={current() === "contacts"}>
                    <ContactsView />
                  </Match>
                  <Match when={current() === "files"}>
                    <FilesView />
                  </Match>
                  <Match when={current() === "account"}>
                    <AccountView />
                  </Match>
                  <Match when={current() === "admin"}>
                    <AdminView />
                  </Match>
                </Switch>
              </ErrorBoundary>
            </div>
          </JmapContext.Provider>
        )}
      </Match>
      <Match when={jmap.loading}>
        <main class="center muted">{t("Loading")}</main>
      </Match>
    </Switch>
  );
}

/** A resource's value, or nothing while it loads or after it failed – reading a failed resource would throw. */
export function ok<T>(resource: Resource<T>): T | undefined {
  return resource.error ? undefined : resource();
}

/** A failure shown in place. */
export function Failure(props: { error: unknown }): JSX.Element {
  return (
    <Show when={props.error}>
      <p class="error" role="alert">
        {props.error instanceof Error ? props.error.message : String(props.error)}
      </p>
    </Show>
  );
}

function Failed(props: { error: unknown; reset: () => void }): JSX.Element {
  return (
    <main class="center">
      <h1>{t("Something went wrong")}</h1>
      <p class="muted">{props.error instanceof Error ? props.error.message : String(props.error)}</p>
      <button type="button" onClick={() => props.reset()}>
        {t("Try again")}
      </button>
    </main>
  );
}
