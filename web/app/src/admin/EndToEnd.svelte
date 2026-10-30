<!-- SPDX-License-Identifier: MIT -->
<!-- The tenant's end-to-end policy (RFC 0006, 8): what its accounts may encrypt, and recovery through the tenant. The
     recovery key is made in this browser: its public key goes to kernoid, its secret key is saved here as a file – it
     never reaches the server, and without it no key can be recovered. -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import { base64, library } from "../e2e/e2e.svelte.js";
  import { t } from "../i18n.js";
  import { admin, need } from "./api.svelte.js";
  import { Action } from "./ui.svelte.js";
  import Buttons from "./ui/Buttons.svelte";
  import Check from "./ui/Check.svelte";
  import Form from "./ui/Form.svelte";
  import Outcome from "./ui/Outcome.svelte";
  import Select from "./ui/Select.svelte";

  const action = new Action();
  const policy = loaded(() => need(admin.GET("/v1/tenant/e2e")));
  const rules: [string, string][] = [
    ["allowed", t("Allowed")],
    ["required", t("Required")],
    ["forbidden", t("Forbidden")],
  ];
  type Rule = "allowed" | "required" | "forbidden";

  function save(field: (name: string) => string, all: (name: string) => string[]): void {
    void action.run(async () => {
      await need(
        admin.PUT("/v1/tenant/e2e", {
          body: { mail: field("mail") as Rule, vaults: field("vaults") as Rule, collections: field("collections") as Rule, recovery: all("recovery").length > 0 },
        }),
      );
      await policy.refetch();
    }, t("Saved."));
  }

  /** Makes the recovery key here, saves its secret as a file, then sends its public key. */
  function makeRecoveryKey(): void {
    void action.run(async () => {
      const module = await library();
      const ring = new module.Keyring();
      const fingerprint = ring.generate("pqc", [`recovery@${location.hostname}`]);
      const secret = ring.exportSecret(fingerprint);
      const link = document.createElement("a");
      link.href = URL.createObjectURL(new Blob([secret], { type: "application/pgp-keys" }));
      link.download = `kernoid-recovery-key-${fingerprint.slice(0, 16)}.asc`;
      link.click();
      await need(admin.PUT("/v1/tenant/e2e/recovery-key", { body: { public_key: base64(ring.publicKey(fingerprint)) } }));
      await policy.refetch();
    }, t("The recovery key's secret was saved as a file. Keep it apart, offline – kernoid does not have it."));
  }
</script>

<section>
  <h2>{t("End-to-end encryption")}</h2>
  <p class="muted">
    {t("What accounts may encrypt so that only they can read it. Encrypted mail cannot be read by programs without OpenPGP, nor searched on the server; forbid it if the organisation must be able to read its mail.")}
  </p>
  <Outcome {action} />
  {#if policy.value}
    {@const view = policy.value}
    <Form class="stack" submit={save}>
      <Select label={t("Mail encrypted on arrival")} name="mail" value={view.mail} options={rules} />
      <Select label={t("Vaults (encrypted folders)")} name="vaults" value={view.vaults} options={rules} />
      <Select label={t("Encrypted calendars and address books")} name="collections" value={view.collections} options={rules} />
      <Check
        label={t("Keys can be recovered by the organisation")}
        name="recovery"
        checked={view.recovery}
        hint={view.recovery_key ? t("with the recovery key {id}…", { id: view.recovery_key.fingerprint.slice(0, 16) }) : t("needs a recovery key first")}
      />
      <Buttons busy={action.busy} />
    </Form>
    <div class="actions">
      <button type="button" disabled={action.busy} onclick={makeRecoveryKey}>
        {view.recovery_key ? t("Make a new recovery key") : t("Make the recovery key")}
      </button>
    </div>
    {#if view.recovery_key}
      <p class="muted small">{t("A new recovery key applies to keys made from then on; earlier ones stay recoverable only with the old one.")}</p>
    {/if}
  {/if}
</section>
