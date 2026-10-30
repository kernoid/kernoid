<!-- SPDX-License-Identifier: MIT -->
<!-- End-to-end encryption of the account (RFC 0006): its key – made here, kept on the server only as protected
     copies –, how it is unlocked (passkeys, the recovery code), and whether mail is encrypted on arrival, as the
     tenant allows. Says what it costs: programs without OpenPGP cannot read encrypted mail, and a lost key means lost
     mail. -->
<script lang="ts">
  import { Download, KeyRound, Lock, ShieldCheck } from "@lucide/svelte";

  import { loaded, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { MAIL } from "../jmap.js";
  import { identities } from "../mail/model.js";
  import Unlock from "../e2e/Unlock.svelte";
  import { addPasskey, current, e2e, exportSecret, importRecovered, lock, refresh, removeCopy, setMail, setup } from "../e2e/e2e.svelte.js";

  const jmap = useJmap();
  const settingsLoad = loaded(() => refresh(jmap));
  let kind = $state<"pqc" | "compatible">("pqc");
  let code = $state<string | undefined>();
  let busy = $state(false);
  let error = $state<unknown>();
  let exported = $state<string | undefined>();

  async function run(action: () => Promise<unknown>): Promise<void> {
    busy = true;
    error = undefined;
    try {
      await action();
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
    }
  }

  /** The key names every address the account sends from. */
  async function makeKey(): Promise<void> {
    const own = jmap.account(MAIL);
    const addresses = (await identities(jmap, own)).map((identity) => identity.email);
    if (addresses.length === 0) addresses.push(jmap.session.username);
    code = await setup(jmap, kind, [...new Set(addresses)]);
  }

  const key = $derived(current());
  const policy = $derived(e2e.settings?.policy);
  const passkeyCopies = $derived(Object.keys(key?.copies ?? {}).filter((label) => label.startsWith("passkey:")));
</script>

{#if e2e.available || settingsLoad.loading}
  <section>
    <h2>{t("End-to-end encryption")}</h2>
    <p class="muted">
      {t("With it, mail is stored so that only you can read it – not the operator, not kernoid. Programs without OpenPGP can then no longer read that mail, and without your key it is lost.")}
    </p>
    {#if policy?.recovery}
      <p class="notice">{t("Your organisation can recover your key: end to end then means you and your organisation.")}</p>
    {/if}
    {#if code}
      <div class="notice stack">
        <strong>{t("Your recovery code")}</strong>
        <code class="secret">{code}</code>
        <span>{t("Keep it somewhere safe. It is shown only now, and it is the only way back if you lose every passkey.")}</span>
        <button type="button" onclick={() => (code = undefined)}>{t("I have kept it")}</button>
      </div>
    {/if}
    {#if !key && e2e.settings}
      {#if policy?.mail === "forbidden" && policy.vaults === "forbidden" && policy.collections === "forbidden"}
        <p class="muted">{t("Your organisation does not allow end-to-end encryption.")}</p>
      {:else}
        <div class="stack">
          <label>
            <span>{t("Kind of key")}</span>
            <select bind:value={kind}>
              <option value="pqc">{t("Post-quantum (recommended)")}</option>
              <option value="compatible">{t("Compatible with older mail programs")}</option>
            </select>
          </label>
          <p class="muted small">
            {kind === "pqc"
              ? t("Also safe against mail recorded today being decrypted by quantum computers later. Many mail programs cannot use it yet.")
              : t("For correspondents whose programs know only older keys (GnuPG, many mail programs). Not safe against quantum computers later.")}
          </p>
          <div class="actions">
            <button type="button" class="primary" disabled={busy} onclick={() => void run(makeKey)}><KeyRound size={17} />{t("Make my key")}</button>
          </div>
        </div>
      {/if}
    {:else if key}
      <dl class="facts">
        <dt>{t("Key")}</dt>
        <dd><code>{key.id.slice(0, 16)}…</code> · {key.kind === "pqc" ? t("Post-quantum") : t("Compatible")}</dd>
        <dt>{t("On this page")}</dt>
        <dd>{e2e.unlocked ? t("Unlocked") : t("Locked")}</dd>
      </dl>
      {#if !e2e.unlocked}
        <Unlock />
        <details>
          <summary class="small">{t("Set in a recovered key")}</summary>
          <p class="muted small">{t("A key your organisation recovered, or one you kept as a file. You get a new recovery code.")}</p>
          <label class="button">
            {t("Choose the key file")}
            <input
              type="file"
              accept=".asc,.gpg,application/pgp-keys"
              hidden
              onchange={(event) => {
                const file = event.currentTarget.files?.[0];
                if (file) void run(async () => (code = await importRecovered(jmap, new Uint8Array(await file.arrayBuffer()))));
              }}
            />
          </label>
        </details>
      {:else}
        <div class="actions">
          <button type="button" disabled={busy} onclick={() => void run(() => addPasskey(jmap))}><KeyRound size={17} />{t("Unlock with a passkey from now on")}</button>
          <button type="button" disabled={busy} onclick={() => void run(async () => (exported = await exportSecret()))}><Download size={17} />{t("Show my secret key")}</button>
          <button type="button" class="quiet" onclick={() => void lock()}><Lock size={17} />{t("Lock")}</button>
        </div>
      {/if}
      {#if passkeyCopies.length > 0}
        <p class="muted small">{t("{count} passkeys unlock the key.", { count: passkeyCopies.length })}</p>
        <ul class="plain">
          {#each passkeyCopies as label (label)}
            <li class="row"><span class="muted small">{label.slice(8, 20)}…</span><button type="button" class="quiet small" onclick={() => void run(() => removeCopy(jmap, label))}>{t("Remove")}</button></li>
          {/each}
        </ul>
      {/if}
      {#if exported}
        <textarea readonly rows={6} class="secret">{exported}</textarea>
        <p class="muted small">{t("Anyone with this text can read your mail. Keep it only where only you can.")}</p>
      {/if}
      {#if policy && policy.mail !== "forbidden"}
        <label class="inline">
          <input
            type="checkbox"
            checked={e2e.settings?.mail ?? false}
            disabled={busy || (policy.mail === "required" && e2e.settings?.mail)}
            onchange={(event) => void run(() => setMail(jmap, event.currentTarget.checked))}
          />
          <span><ShieldCheck size={16} /> {t("Encrypt my mail as it arrives")}</span>
        </label>
        <p class="muted small">{t("Mail already stored is encrypted too, in the background. Search then finds senders and dates, not text.")}</p>
      {/if}
    {/if}
    <Failure error={error ?? settingsLoad.error} />
  </section>
{/if}
