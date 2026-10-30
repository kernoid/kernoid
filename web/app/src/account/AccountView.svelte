<!-- SPDX-License-Identifier: MIT -->
<!-- The account, as a section of the app: name, appearance, password, second factors, recovery codes, app passwords
     for mail programs, applications and sessions – through kernoid's session API with the same cookie as JMAP. -->
<script lang="ts">
  import type { KernoidError } from "@kernoid/sdk";
  import { Check, Copy, ImageUp, Trash2 } from "@lucide/svelte";

  import { emptyText, loaded } from "../app.svelte.js";
  import { avatarOfAccount, removeAvatar, setAvatar, squareImage } from "../avatars.svelte.js";
  import Avatar from "../ui/Avatar.svelte";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { notificationsSupported, notificationsWanted, setNotifications } from "../mail/notify.svelte.js";
  import { THEMES, setTheme, theme } from "../theme.svelte.js";
  import { type AppPassword, client, deviceName, languageName, relogin, when } from "./account.js";
  import Connect from "./Connect.svelte";
  import MailSettings from "./MailSettings.svelte";
  import Vacation from "./Vacation.svelte";

  const session = loaded(() => client.session());
  const emailLanguage = loaded(() => client.emailLanguage());
  const factors = loaded(() => client.secondFactors());
  const passkeys = loaded(() => client.passkeys());
  const idpLinks = loaded(() => client.idpLinks());
  const providers = loaded(() => client.linkableProviders());
  const consents = loaded(() => client.consents());
  const sessions = loaded(() => client.sessions());
  const appPasswords = loaded(() => client.http.request<AppPassword[]>("GET", "/v1/account/app-passwords"));
  let notice = $state<string>();
  let error = $state<unknown>();
  let busy = $state(false);
  let totp = $state<{ secret: string; uri: string; qr_code: string }>();
  let codes = $state<string[]>();
  let created = $state<{ name: string; password: string }>();

  /** Runs a change; a request for a recent login sends one to the login and back. */
  async function run(work: () => Promise<string | undefined>): Promise<void> {
    busy = true;
    error = undefined;
    notice = undefined;
    try {
      const text = await work();
      if (text) notice = text;
    } catch (failure) {
      if ((failure as KernoidError).kind === "login-required") return relogin();
      error = failure;
    } finally {
      busy = false;
    }
  }

  /** A form's submission: its trimmed fields, and the form (to reset it). */
  const submit = (work: (field: (name: string) => string, form: HTMLFormElement) => Promise<string | undefined>) => (event: SubmitEvent) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    void run(() => work((name) => String(data.get(name) ?? "").trim(), form));
  };

  const themeName = { system: "System", light: "Light", dark: "Dark" } as const;

  let copied = $state(false);
  async function copy(text: string): Promise<void> {
    await navigator.clipboard?.writeText(text);
    copied = true;
    setTimeout(() => (copied = false), 2000);
  }
</script>

<main class="page">
  {#if session.value}
    {@const me = session.value}
    <div class="profile-head">
      <Avatar name={me.account.display_name} address={me.account.address} src={avatarOfAccount(me.account.id)} size={72} />
      <div class="grow">
        <h1>{me.account.display_name}</h1>
        <p class="muted">{me.account.address}</p>
      </div>
      <div class="row">
        <label class="button" data-tip={t("PNG, JPEG or WebP – cut to a square")}>
          <ImageUp size={17} />{t("Change picture")}
          <input
            type="file"
            accept="image/png,image/jpeg,image/webp"
            hidden
            onchange={(event) => {
              const file = event.currentTarget.files?.[0];
              event.currentTarget.value = "";
              if (file) void run(async () => (await setAvatar(await squareImage(file)), t("The picture is set.")));
            }}
          />
        </label>
        {#if avatarOfAccount(me.account.id)}
          <button
            type="button"
            class="icon danger"
            aria-label={t("Remove picture")}
            data-tip={t("Remove picture")}
            disabled={busy}
            onclick={() => run(async () => (await removeAvatar(), t("The picture is removed.")))}
          >
            <Trash2 size={17} />
          </button>
        {/if}
      </div>
    </div>
    {#if notice}
      <p class="notice" role="status">{notice}</p>
    {/if}
    <Failure {error} />

    <section>
      <h2>{t("Name")}</h2>
      <form
        class="row"
        onsubmit={submit(async (field) => {
          await client.updateProfile(field("name"));
          await session.refetch();
          return t("Saved.");
        })}
      >
        <input name="name" autocomplete="name" required value={me.account.display_name} aria-label={t("Display name")} />
        <button type="submit" disabled={busy}>{t("Save")}</button>
      </form>
    </section>

    <section>
      <h2>{t("Theme")}</h2>
      <div class="row" role="radiogroup" aria-label={t("Theme")}>
        {#each THEMES as choice (choice)}
          <label class="inline">
            <input type="radio" name="theme" checked={theme() === choice} onchange={() => setTheme(choice)} />
            <span>{t(themeName[choice])}</span>
          </label>
        {/each}
      </div>
    </section>

    {#if emailLanguage.value}
      {@const language = emailLanguage.value}
      <section>
        <h2>{t("Language of emails from kernoid")}</h2>
        <p class="muted small">{t("Invitations sent for you and notices to you are written in it; the app follows your browser.")}</p>
        <form
          class="row"
          onsubmit={submit(async (field) => {
            await client.setEmailLanguage(field("language") || null);
            await emailLanguage.refetch();
            return t("Saved.");
          })}
        >
          <select name="language" aria-label={t("Language of emails from kernoid")} value={language.language ?? ""}>
            <option value="">
              {language.language === null ? t("As the tenant ({language})", { language: languageName(language.used) }) : t("As the tenant")}
            </option>
            {#each language.available as code (code)}
              <option value={code}>{languageName(code)}</option>
            {/each}
          </select>
          <button type="submit" disabled={busy}>{t("Save")}</button>
        </form>
      </section>
    {/if}

    <MailSettings />

    <Vacation />

    {#if notificationsSupported()}
      <section>
        <h2>{t("Notifications")}</h2>
        <label class="inline">
          <input
            type="checkbox"
            checked={notificationsWanted()}
            onchange={(event) => {
              const box = event.currentTarget;
              void setNotifications(box.checked).then((on) => (box.checked = on));
            }}
          />
          <span>{t("Show new emails while the app is open in the background")}</span>
        </label>
        {#if notificationsWanted() && Notification.permission === "denied"}
          <p class="muted small">{t("The browser does not allow notifications for this page.")}</p>
        {/if}
      </section>
    {/if}

    <section>
      <h2>{t("Password")}</h2>
      <form
        class="stack"
        onsubmit={submit(async (field, form) => {
          await client.changePassword(field("current"), field("new"));
          form.reset();
          await sessions.refetch();
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
        <button type="submit" disabled={busy}>{t("Change password")}</button>
      </form>
    </section>

    <section>
      <h2>{t("Authenticator app")}</h2>
      {#if totp}
        {@const setup = totp}
        <div class="stack">
          <p>{t("Scan this code with your authenticator app, open the link on this device, or type in the key:")}</p>
          <img src={setup.qr_code} alt={t("QR code for the authenticator app")} class="qr" width="200" height="200" />
          <p><a href={setup.uri}>{t("Open in authenticator app")}</a></p>
          <p class="secret">{setup.secret.replace(/(.{4})/g, "$1 ").trim()}</p>
          <form
            class="row"
            onsubmit={submit(async (field) => {
              await client.confirmTotp(field("code").replace(/\s/g, ""));
              totp = undefined;
              await factors.refetch();
              return t("The authenticator app is set up.");
            })}
          >
            <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern={"[0-9 ]{6,7}"} required aria-label={t("Code shown by the app")} placeholder={t("Code shown by the app")} />
            <button type="submit" class="primary" disabled={busy}>{t("Confirm")}</button>
            <button type="button" class="quiet" onclick={() => (totp = undefined)}>{t("Cancel")}</button>
          </form>
        </div>
      {:else if factors.value?.totp}
        <button
          type="button"
          class="danger"
          disabled={busy}
          onclick={() =>
            run(async () => {
              await client.removeTotp();
              await factors.refetch();
              return t("The authenticator app was removed.");
            })}
        >
          {t("Remove the authenticator app")}
        </button>
      {:else}
        <button type="button" disabled={busy} onclick={() => run(async () => ((totp = await client.startTotp()), undefined))}>
          {t("Set up an authenticator app")}
        </button>
      {/if}
    </section>

    <section>
      <h2>{t("Passkeys")}</h2>
      <ul class="rows">
        {#each passkeys.value ?? [] as passkey (passkey.id)}
          <li>
            <span class="grow">
              {passkey.name}
              <small class="muted"> – {t("last used {date}", { date: passkey.last_used_at ? when(passkey.last_used_at) : t("never") })}</small>
            </span>
            <button
              type="button"
              class="quiet danger"
              disabled={busy}
              onclick={() =>
                run(async () => {
                  await client.removePasskey(passkey.id);
                  await passkeys.refetch();
                  return t("The passkey was removed.");
                })}
            >
              {t("Remove")}
            </button>
          </li>
        {:else}
          <li class="muted">{emptyText(passkeys, t("No passkeys yet."))}</li>
        {/each}
      </ul>
      <button
        type="button"
        disabled={busy}
        onclick={() =>
          run(async () => {
            await client.registerPasskey(deviceName());
            await passkeys.refetch();
            return t("The passkey was created.");
          })}
      >
        {t("Create a passkey")}
      </button>
    </section>

    {#if (providers.value?.length ?? 0) > 0 || (idpLinks.value?.length ?? 0) > 0}
      <section>
        <h2>{t("Logging in with other services")}</h2>
        <ul class="rows">
          {#each idpLinks.value ?? [] as link (link)}
            <li>
              <span class="grow">
                {link.name}
                <small class="muted"> – {t("linked {date}", { date: when(link.created_at) })}</small>
              </span>
              <button
                type="button"
                class="quiet danger"
                disabled={busy}
                onclick={() =>
                  run(async () => {
                    await client.unlinkIdp(link);
                    await idpLinks.refetch();
                    return t("The service was unlinked.");
                  })}
              >
                {t("Unlink")}
              </button>
            </li>
          {:else}
            <li class="muted">{emptyText(idpLinks, t("No services linked yet."))}</li>
          {/each}
        </ul>
        <div class="row">
          {#each providers.value ?? [] as provider (provider.id)}
            <button
              type="button"
              disabled={busy}
              onclick={() =>
                run(async () => {
                  window.location.assign(await client.startIdpLink(provider.id));
                  return undefined;
                })}
            >
              {t("Link {name}", { name: provider.name })}
            </button>
          {/each}
        </div>
      </section>
    {/if}

    <section>
      <h2>{t("Recovery codes")}</h2>
      {#if codes}
        <div class="stack">
          <p>{t("If you lose your devices, each of these codes lets you log in once. Keep them somewhere safe – they are shown only now.")}</p>
          <ol class="codes">
            {#each codes as code (code)}
              <li>{code}</li>
            {/each}
          </ol>
          <button
            type="button"
            class="primary"
            onclick={() => {
              codes = undefined;
              void factors.refetch();
            }}
          >
            {t("I have saved them")}
          </button>
        </div>
      {:else}
        <p class="muted">{t("{count} left.", { count: factors.value?.recovery_codes_left ?? 0 })}</p>
        <button type="button" disabled={busy} onclick={() => run(async () => ((codes = await client.generateRecoveryCodes()), undefined))}>
          {t("Make new recovery codes")}
        </button>
      {/if}
    </section>

    <section>
      <h2>{t("Mail programs and devices")}</h2>
      <p class="muted">{t("Programs such as Thunderbird, Apple Mail or a file manager log in with your address and an app password of their own – never with your password.")}</p>
      {#if created}
        <div class="answer">
          <span class="grow">
            {t("App password for {name}:", { name: created.name })} <code class="secret">{created.password}</code>
            <button
              type="button"
              class="icon quiet small"
              aria-label={copied ? t("Copied") : t("Copy")}
              data-tip={copied ? t("Copied") : t("Copy")}
              onclick={() => created && copy(created.password)}
            >
              {#if copied}<Check size={16} />{:else}<Copy size={16} />{/if}
            </button>
            <br />
            <small class="muted">{t("Shown only now – enter it in the program.")}</small>
          </span>
          <button type="button" class="quiet" onclick={() => (created = undefined)}>{t("Done")}</button>
        </div>
      {/if}
      <ul class="rows">
        {#each appPasswords.value ?? [] as entry (entry.id)}
          <li>
            <span class="grow">
              {entry.name}
              <small class="muted"> – {t("last used {date}", { date: entry.last_used_at ? when(entry.last_used_at) : t("never") })}</small>
            </span>
            <button
              type="button"
              class="quiet danger"
              disabled={busy}
              onclick={() =>
                run(async () => {
                  await client.http.request("DELETE", `/v1/account/app-passwords/${encodeURIComponent(entry.id)}`);
                  await appPasswords.refetch();
                  return t("The app password was removed.");
                })}
            >
              {t("Remove")}
            </button>
          </li>
        {:else}
          <li class="muted">{emptyText(appPasswords, t("No app passwords yet."))}</li>
        {/each}
      </ul>
      <form
        class="row"
        onsubmit={submit(async (field, form) => {
          const name = field("name");
          const made = await client.http.request<{ id: string; password: string }>("POST", "/v1/account/app-passwords", { name });
          created = { name, password: made.password };
          form.reset();
          await appPasswords.refetch();
          return undefined;
        })}
      >
        <input name="name" required placeholder={t("e.g. Thunderbird at home")} aria-label={t("Program or device")} />
        <button type="submit" disabled={busy}>{t("Make an app password")}</button>
      </form>
      <Connect address={me.account.address} />
    </section>

    <section>
      <h2>{t("Applications")}</h2>
      <ul class="rows">
        {#each consents.value ?? [] as consent (consent.application)}
          <li>
            <span class="grow">
              {consent.application_name}
              <small class="muted">
                {consent.scopes.includes("offline_access")
                  ? t(" – also while you are not logged in, since {date}", { date: when(consent.granted_at) })
                  : t(" – since {date}", { date: when(consent.granted_at) })}
              </small>
            </span>
            <button
              type="button"
              class="quiet danger"
              disabled={busy}
              onclick={() =>
                run(async () => {
                  await client.revokeConsent(consent.application);
                  await consents.refetch();
                  return t("{application} no longer has access.", { application: consent.application_name });
                })}
            >
              {t("Withdraw")}
            </button>
          </li>
        {:else}
          <li class="muted">{emptyText(consents, t("You have not allowed any application anything yet."))}</li>
        {/each}
      </ul>
    </section>

    <section>
      <h2>{t("Sessions")}</h2>
      <ul class="rows">
        {#each sessions.value ?? [] as entry (entry.id)}
          <li>
            <span class="grow">
              {entry.id === me.id ? t("This browser") : (entry.user_agent ?? t("Unknown device")).slice(0, 60)}
              <small class="muted">
                {t(" – since {date}", { date: when(entry.created_at) })}{entry.client_address ? `, ${entry.client_address}` : ""}
              </small>
            </span>
            {#if entry.id !== me.id}
              <button
                type="button"
                class="quiet danger"
                disabled={busy}
                onclick={() =>
                  run(async () => {
                    await client.endSession(entry.id);
                    await sessions.refetch();
                    return t("The session has ended.");
                  })}
              >
                {t("End")}
              </button>
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {:else}
    <Failure error={session.error} />
    {#if !session.error}
      <p class="muted">{t("Loading")}</p>
    {/if}
  {/if}
</main>
