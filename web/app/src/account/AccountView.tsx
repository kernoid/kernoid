// SPDX-License-Identifier: MIT
// The account, as a section of the app: name, appearance, password, second factors, recovery codes, app passwords for
// mail programs, applications and sessions – through kernoid's session API with the same cookie as JMAP.

import { type KernoidError, LoginClient, type Session } from "@kernoid/sdk";
import { For, type JSX, Show, createResource, createSignal } from "solid-js";

import { Failure, ok } from "../App.js";
import { t } from "../i18n.js";
import { notificationsSupported, notificationsWanted, setNotifications } from "../mail/notify.js";
import { THEMES, type Theme, setTheme, theme } from "../theme.js";
import { Connect } from "./Connect.js";
import { Vacation } from "./Vacation.js";

export const client = new LoginClient({ cookies: true });

/** A language by its own name. */
export function languageName(code: string): string {
  return ({ de: "Deutsch", en: "English" } as Record<string, string>)[code] ?? code;
}

interface AppPassword {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

const when = (date: string) => new Date(date).toLocaleString();

function deviceName(): string {
  const agent = navigator.userAgent;
  const platform = /iPhone|iPad/.test(agent) ? "iPhone/iPad" : /Android/.test(agent) ? "Android" : /Mac/.test(agent) ? "Mac" : /Windows/.test(agent) ? "Windows" : /Linux/.test(agent) ? "Linux" : t("this device");
  return t("Passkey on {platform}", { platform });
}

/** Changing how one logs in needs a recent login: log in again and come back here. */
async function relogin(): Promise<void> {
  await client.logout().catch(() => undefined);
  window.location.assign(`/login/account?next=${encodeURIComponent("/app/#/account")}`);
}

export function AccountView(): JSX.Element {
  const [session, { refetch: refetchSession }] = createResource(() => client.session());
  const [emailLanguage, { refetch: refetchLanguage }] = createResource(() => client.emailLanguage());
  const [factors, { refetch: refetchFactors }] = createResource(() => client.secondFactors());
  const [passkeys, { refetch: refetchPasskeys }] = createResource(() => client.passkeys());
  const [idpLinks, { refetch: refetchIdpLinks }] = createResource(() => client.idpLinks());
  const [providers] = createResource(() => client.linkableProviders());
  const [consents, { refetch: refetchConsents }] = createResource(() => client.consents());
  const [sessions, { refetch: refetchSessions }] = createResource(() => client.sessions());
  const [appPasswords, { refetch: refetchAppPasswords }] = createResource(() => client.http.request<AppPassword[]>("GET", "/v1/account/app-passwords"));
  const [notice, setNotice] = createSignal<string>();
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const [totp, setTotp] = createSignal<{ secret: string; uri: string; qr_code: string }>();
  const [codes, setCodes] = createSignal<string[]>();
  const [created, setCreated] = createSignal<{ name: string; password: string }>();

  /** Runs a change; a request for a recent login sends one to the login and back. */
  const run = (work: () => Promise<string | undefined>) => async (event?: Event) => {
    event?.preventDefault();
    setBusy(true);
    setError(undefined);
    setNotice(undefined);
    try {
      const text = await work();
      if (text) setNotice(text);
    } catch (failure) {
      if ((failure as KernoidError).kind === "login-required") return relogin();
      setError(failure);
    } finally {
      setBusy(false);
    }
  };
  /** A form's submission: its trimmed fields, and the form (to reset it). */
  const submit = (work: (field: (name: string) => string, form: HTMLFormElement) => Promise<string | undefined>) => (event: SubmitEvent) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    void run(() => work((name) => String(data.get(name) ?? "").trim(), form))();
  };

  return (
    <main class="page">
      <Show when={ok(session)} fallback={<p class="muted">{t("Loading")}</p>}>
        {(me) => (
          <>
            <h1>{me().account.display_name}</h1>
            <p class="muted">{me().account.address}</p>
            <Show when={notice()}>
              <p class="notice" role="status">{notice()}</p>
            </Show>
            <Failure error={error()} />

            <section>
              <h2>{t("Name")}</h2>
              <form
                class="row"
                onSubmit={submit(async (field) => {
                  await client.updateProfile(field("name"));
                  await refetchSession();
                  return t("Saved.");
                })}
              >
                <input name="name" autocomplete="name" required value={me().account.display_name} aria-label={t("Display name")} />
                <button type="submit" disabled={busy()}>{t("Save")}</button>
              </form>
            </section>

            <section>
              <h2>{t("Theme")}</h2>
              <div class="row" role="radiogroup" aria-label={t("Theme")}>
                <For each={THEMES}>
                  {(choice: Theme) => (
                    <label class="inline">
                      <input type="radio" name="theme" checked={theme() === choice} onChange={() => setTheme(choice)} />
                      <span>{t(choice === "system" ? "System" : choice === "light" ? "Light" : "Dark")}</span>
                    </label>
                  )}
                </For>
              </div>
            </section>

            <Show when={ok(emailLanguage)}>
              {(language) => (
                <section>
                  <h2>{t("Language of emails from kernoid")}</h2>
                  <p class="muted small">{t("Invitations sent for you and notices to you are written in it; the app follows your browser.")}</p>
                  <form
                    class="row"
                    onSubmit={submit(async (field) => {
                      await client.setEmailLanguage(field("language") || null);
                      await refetchLanguage();
                      return t("Saved.");
                    })}
                  >
                    <select name="language" aria-label={t("Language of emails from kernoid")}>
                      <option value="" selected={language().language === null}>
                        {language().language === null ? t("As the tenant ({language})", { language: languageName(language().used) }) : t("As the tenant")}
                      </option>
                      <For each={language().available}>
                        {(code) => (
                          <option value={code} selected={language().language === code}>
                            {languageName(code)}
                          </option>
                        )}
                      </For>
                    </select>
                    <button type="submit" disabled={busy()}>{t("Save")}</button>
                  </form>
                </section>
              )}
            </Show>

            <Vacation />

            <Show when={notificationsSupported()}>
              <section>
                <h2>{t("Notifications")}</h2>
                <label class="inline">
                  <input
                    type="checkbox"
                    checked={notificationsWanted()}
                    onChange={(event) => {
                      const box = event.currentTarget;
                      void setNotifications(box.checked).then((on) => (box.checked = on));
                    }}
                  />
                  <span>{t("Show new emails while the app is open in the background")}</span>
                </label>
                <Show when={notificationsWanted() && Notification.permission === "denied"}>
                  <p class="muted small">{t("The browser does not allow notifications for this page.")}</p>
                </Show>
              </section>
            </Show>

            <section>
              <h2>{t("Password")}</h2>
              <form
                class="stack"
                onSubmit={submit(async (field, form) => {
                  await client.changePassword(field("current"), field("new"));
                  form.reset();
                  await refetchSessions();
                  return t("Password changed – your other sessions have ended.");
                })}
              >
                <label>
                  <span>{t("Current password")}</span>
                  <input name="current" type="password" autocomplete="current-password" required />
                </label>
                <label>
                  <span>{t("New password")}</span>
                  <input name="new" type="password" autocomplete="new-password" required minlength="12" />
                </label>
                <button type="submit" disabled={busy()}>{t("Change password")}</button>
              </form>
            </section>

            <section>
              <h2>{t("Authenticator app")}</h2>
              <Show
                when={totp()}
                fallback={
                  <Show
                    when={ok(factors)?.totp}
                    fallback={
                      <button type="button" disabled={busy()} onClick={() => void run(async () => (setTotp(await client.startTotp()), undefined))()}>
                        {t("Set up an authenticator app")}
                      </button>
                    }
                  >
                    <button type="button" class="danger" disabled={busy()} onClick={() => void run(async () => {
                      await client.removeTotp();
                      await refetchFactors();
                      return t("The authenticator app was removed.");
                    })()}>
                      {t("Remove the authenticator app")}
                    </button>
                  </Show>
                }
              >
                {(setup) => (
                  <div class="stack">
                    <p>{t("Scan this code with your authenticator app, open the link on this device, or type in the key:")}</p>
                    <img src={setup().qr_code} alt={t("QR code for the authenticator app")} class="qr" width="200" height="200" />
                    <p>
                      <a href={setup().uri}>{t("Open in authenticator app")}</a>
                    </p>
                    <p class="secret">{setup().secret.replace(/(.{4})/g, "$1 ").trim()}</p>
                    <form
                      class="row"
                      onSubmit={submit(async (field) => {
                        await client.confirmTotp(field("code").replace(/\s/g, ""));
                        setTotp(undefined);
                        await refetchFactors();
                        return t("The authenticator app is set up.");
                      })}
                    >
                      <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" required aria-label={t("Code shown by the app")} placeholder={t("Code shown by the app")} />
                      <button type="submit" class="primary" disabled={busy()}>{t("Confirm")}</button>
                      <button type="button" class="quiet" onClick={() => setTotp(undefined)}>{t("Cancel")}</button>
                    </form>
                  </div>
                )}
              </Show>
            </section>

            <section>
              <h2>{t("Passkeys")}</h2>
              <ul class="rows">
                <For each={ok(passkeys) ?? []} fallback={<li class="muted">{t("No passkeys yet.")}</li>}>
                  {(passkey) => (
                    <li>
                      <span class="grow">
                        {passkey.name}
                        <small class="muted"> – {t("last used {date}", { date: passkey.last_used_at ? when(passkey.last_used_at) : t("never") })}</small>
                      </span>
                      <button type="button" class="quiet danger" disabled={busy()} onClick={() => void run(async () => {
                        await client.removePasskey(passkey.id);
                        await refetchPasskeys();
                        return t("The passkey was removed.");
                      })()}>
                        {t("Remove")}
                      </button>
                    </li>
                  )}
                </For>
              </ul>
              <button type="button" disabled={busy()} onClick={() => void run(async () => {
                await client.registerPasskey(deviceName());
                await refetchPasskeys();
                return t("The passkey was created.");
              })()}>
                {t("Create a passkey")}
              </button>
            </section>

            <Show when={(ok(providers)?.length ?? 0) > 0 || (ok(idpLinks)?.length ?? 0) > 0}>
              <section>
                <h2>{t("Logging in with other services")}</h2>
                <ul class="rows">
                  <For each={ok(idpLinks) ?? []} fallback={<li class="muted">{t("No services linked yet.")}</li>}>
                    {(link) => (
                      <li>
                        <span class="grow">
                          {link.name}
                          <small class="muted"> – {t("linked {date}", { date: when(link.created_at) })}</small>
                        </span>
                        <button type="button" class="quiet danger" disabled={busy()} onClick={() => void run(async () => {
                          await client.unlinkIdp(link);
                          await refetchIdpLinks();
                          return t("The service was unlinked.");
                        })()}>
                          {t("Unlink")}
                        </button>
                      </li>
                    )}
                  </For>
                </ul>
                <div class="row">
                  <For each={ok(providers) ?? []}>
                    {(provider) => (
                      <button type="button" disabled={busy()} onClick={() => void run(async () => {
                        window.location.assign(await client.startIdpLink(provider.id));
                        return undefined;
                      })()}>
                        {t("Link {name}", { name: provider.name })}
                      </button>
                    )}
                  </For>
                </div>
              </section>
            </Show>

            <section>
              <h2>{t("Recovery codes")}</h2>
              <Show
                when={codes()}
                fallback={
                  <>
                    <p class="muted">{t("{count} left.", { count: ok(factors)?.recovery_codes_left ?? 0 })}</p>
                    <button type="button" disabled={busy()} onClick={() => void run(async () => (setCodes(await client.generateRecoveryCodes()), undefined))()}>
                      {t("Make new recovery codes")}
                    </button>
                  </>
                }
              >
                {(list) => (
                  <div class="stack">
                    <p>{t("If you lose your devices, each of these codes lets you log in once. Keep them somewhere safe – they are shown only now.")}</p>
                    <ol class="codes">
                      <For each={list()}>{(code) => <li>{code}</li>}</For>
                    </ol>
                    <button type="button" class="primary" onClick={() => (setCodes(undefined), void refetchFactors())}>
                      {t("I have saved them")}
                    </button>
                  </div>
                )}
              </Show>
            </section>

            <section>
              <h2>{t("Mail programs and devices")}</h2>
              <p class="muted">{t("Programs such as Thunderbird, Apple Mail or a file manager log in with your address and an app password of their own – never with your password.")}</p>
              <Show when={created()}>
                {(made) => (
                  <div class="answer">
                    <span class="grow">
                      {t("App password for {name}:", { name: made().name })} <code class="secret">{made().password}</code>
                      <br />
                      <small class="muted">{t("Shown only now – enter it in the program.")}</small>
                    </span>
                    <button type="button" class="quiet" onClick={() => setCreated(undefined)}>{t("Done")}</button>
                  </div>
                )}
              </Show>
              <ul class="rows">
                <For each={ok(appPasswords) ?? []} fallback={<li class="muted">{t("No app passwords yet.")}</li>}>
                  {(entry) => (
                    <li>
                      <span class="grow">
                        {entry.name}
                        <small class="muted"> – {t("last used {date}", { date: entry.last_used_at ? when(entry.last_used_at) : t("never") })}</small>
                      </span>
                      <button type="button" class="quiet danger" disabled={busy()} onClick={() => void run(async () => {
                        await client.http.request("DELETE", `/v1/account/app-passwords/${encodeURIComponent(entry.id)}`);
                        await refetchAppPasswords();
                        return t("The app password was removed.");
                      })()}>
                        {t("Remove")}
                      </button>
                    </li>
                  )}
                </For>
              </ul>
              <form
                class="row"
                onSubmit={submit(async (field, form) => {
                  const name = field("name");
                  const made = await client.http.request<{ id: string; password: string }>("POST", "/v1/account/app-passwords", { name });
                  setCreated({ name, password: made.password });
                  form.reset();
                  await refetchAppPasswords();
                  return undefined;
                })}
              >
                <input name="name" required placeholder={t("e.g. Thunderbird at home")} aria-label={t("Program or device")} />
                <button type="submit" disabled={busy()}>{t("Make an app password")}</button>
              </form>
              <Connect address={me().account.address} />
            </section>

            <section>
              <h2>{t("Applications")}</h2>
              <ul class="rows">
                <For each={ok(consents) ?? []} fallback={<li class="muted">{t("You have not allowed any application anything yet.")}</li>}>
                  {(consent) => (
                    <li>
                      <span class="grow">
                        {consent.application_name}
                        <small class="muted">
                          {consent.scopes.includes("offline_access")
                            ? t(" – also while you are not logged in, since {date}", { date: when(consent.granted_at) })
                            : t(" – since {date}", { date: when(consent.granted_at) })}
                        </small>
                      </span>
                      <button type="button" class="quiet danger" disabled={busy()} onClick={() => void run(async () => {
                        await client.revokeConsent(consent.application);
                        await refetchConsents();
                        return t("{application} no longer has access.", { application: consent.application_name });
                      })()}>
                        {t("Withdraw")}
                      </button>
                    </li>
                  )}
                </For>
              </ul>
            </section>

            <section>
              <h2>{t("Sessions")}</h2>
              <SessionList current={me()} sessions={ok(sessions) ?? []} busy={busy()} end={(id) => void run(async () => {
                await client.endSession(id);
                await refetchSessions();
                return t("The session has ended.");
              })()} />
            </section>
          </>
        )}
      </Show>
    </main>
  );
}

function SessionList(props: { current: Session; sessions: Awaited<ReturnType<typeof client.sessions>>; busy: boolean; end: (id: string) => void }): JSX.Element {
  return (
    <ul class="rows">
      <For each={props.sessions}>
        {(entry) => (
          <li>
            <span class="grow">
              {entry.id === props.current.id ? t("This browser") : (entry.user_agent ?? t("Unknown device")).slice(0, 60)}
              <small class="muted">
                {t(" – since {date}", { date: when(entry.created_at) })}
                {entry.client_address ? `, ${entry.client_address}` : ""}
              </small>
            </span>
            <Show when={entry.id !== props.current.id}>
              <button type="button" class="quiet danger" disabled={props.busy} onClick={() => props.end(entry.id)}>
                {t("End")}
              </button>
            </Show>
          </li>
        )}
      </For>
    </ul>
  );
}
