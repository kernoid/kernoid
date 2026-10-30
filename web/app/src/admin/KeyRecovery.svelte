<!-- SPDX-License-Identifier: MIT -->
<!-- Recovers an account's key with the tenant's recovery key (RFC 0006, 8.2): the account's copy for the recovery key
     comes from kernoid, the recovery key's secret from a file chosen here – both meet only in this browser. The result
     is the account's secret key as a file, to hand to its owner, who sets it in again on their account page. -->
<script lang="ts">
  import { library } from "../e2e/e2e.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import { Action } from "./ui.svelte.js";
  import Outcome from "./ui/Outcome.svelte";

  let { id, name }: { id: string; name: string } = $props();
  const action = new Action();

  const binary = (text: string): Uint8Array => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

  function recover(file: File | undefined): void {
    if (!file) return;
    void action.run(async () => {
      const copy = await need(admin.GET("/v1/accounts/{id}/e2e-recovery-copy", { params: { path: { id } } }));
      const module = await library();
      const ring = new module.Keyring();
      ring.importSecret(new Uint8Array(await file.arrayBuffer()));
      const secret = ring.decrypt(binary(copy.protected), []).data;
      const link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([secret.slice().buffer], { type: "application/pgp-keys" }));
      link.download = `kernoid-key-${copy.fingerprint.slice(0, 16)}.asc`;
      link.click();
    }, t("The key of {name} was saved as a file. Hand it over in person; whoever has it can read their mail.", { name }));
  }
</script>

<section>
  <h2>{t("Recover the key")}</h2>
  <p class="muted">{t("If the account lost every way to unlock its key: choose the recovery key's file. It is read only in this browser.")}</p>
  <Outcome {action} />
  <label class="button">
    {t("Choose the recovery key")}
    <input type="file" accept=".asc,.gpg,application/pgp-keys" hidden onchange={(event) => recover(event.currentTarget.files?.[0])} />
  </label>
</section>
