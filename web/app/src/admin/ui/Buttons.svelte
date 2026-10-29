<!-- SPDX-License-Identifier: MIT -->
<!-- A form's buttons: perhaps Cancel, and the one that submits. -->
<script lang="ts">
  import { t } from "../../i18n.js";

  let { busy, onCancel, label }: { busy: boolean; onCancel?: (() => void) | undefined; label?: string | undefined } = $props();
</script>

<div class="actions end">
  {#if onCancel}
    <button type="button" onclick={() => onCancel?.()}>{t("Cancel")}</button>
  {/if}
  <button type="submit" class="primary" disabled={busy}>{label ?? t("Save")}</button>
</div>
