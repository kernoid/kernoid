<!-- SPDX-License-Identifier: MIT -->
<!-- Unlocks the account's key on this page (RFC 0006, 4.2): with a passkey that has a copy – its PRF extension gives
     the passphrase –, or with the recovery code. The key stays in this page's memory until it closes. -->
<script lang="ts">
  import { KeyRound, LockOpen } from "@lucide/svelte";

  import { touch, useJmap } from "../app.svelte.js";
  import Failure from "../Failure.svelte";
  import { t } from "../i18n.js";
  import { current, unlockWithCode, unlockWithPasskey } from "./e2e.svelte.js";

  let { onunlock = () => {} }: { onunlock?: () => void } = $props();
  const jmap = useJmap();
  let code = $state("");
  let busy = $state(false);
  let error = $state<unknown>();
  const passkeys = $derived(Object.keys(current()?.copies ?? {}).some((label) => label.startsWith("passkey:")));

  async function run(unlock: () => Promise<void>): Promise<void> {
    busy = true;
    error = undefined;
    try {
      await unlock();
      code = "";
      touch("Email");
      onunlock();
    } catch (failure) {
      error = failure;
    } finally {
      busy = false;
    }
  }
</script>

<div class="stack unlock">
  {#if passkeys}
    <button type="button" class="primary" disabled={busy} onclick={() => void run(() => unlockWithPasskey(jmap))}>
      <KeyRound size={17} />{t("Unlock with a passkey")}
    </button>
  {/if}
  <form
    class="row"
    onsubmit={(event) => {
      event.preventDefault();
      void run(() => unlockWithCode(code, jmap));
    }}
  >
    <input type="text" autocomplete="off" spellcheck="false" placeholder={t("Recovery code")} aria-label={t("Recovery code")} bind:value={code} />
    <button type="submit" disabled={busy || !code.trim()}><LockOpen size={17} />{t("Unlock")}</button>
  </form>
  <Failure {error} />
</div>
