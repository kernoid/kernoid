<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Watches the inbox while mounted and shows what arrives, if the user wants it (notify.svelte.ts). -->
<script lang="ts">
  import { changed, useJmap } from "../app.svelte.js";
  import { inboxWatcher } from "./notify.svelte.js";

  const watcher = inboxWatcher(useJmap());
  let first = true;
  $effect(() => {
    changed("Email");
    if (first) {
      first = false;
      return;
    }
    void watcher.check().catch(() => undefined);
  });
  $effect(() => () => watcher.stop());
</script>
