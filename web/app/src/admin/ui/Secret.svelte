<!-- SPDX-License-Identifier: MIT -->
<!-- A secret shown once, with a way to copy it. -->
<script lang="ts">
  import { t } from "../../i18n.js";

  let { label, value, onDone }: { label: string; value: string; onDone: () => void } = $props();
</script>

<div class="answer">
  <span class="grow">
    {label} <code class="secret">{value}</code>
    <br />
    <small class="muted">{t("Shown only now – copy it.")}</small>
  </span>
  <button type="button" class="quiet" onclick={() => void navigator.clipboard?.writeText(value)}>{t("Copy")}</button>
  <button type="button" class="quiet" onclick={() => onDone()}>{t("Done")}</button>
</div>
