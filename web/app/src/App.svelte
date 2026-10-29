<!-- SPDX-License-Identifier: MIT -->
<!-- Loads the JMAP session – and whether the account may administer something –, then shows the frame. -->
<script lang="ts">
  import { adminAccess } from "./admin/access.js";
  import { message, touch } from "./app.svelte.js";
  import { t } from "./i18n.js";
  import { Jmap, fetchSession } from "./jmap.js";
  import Shell from "./Shell.svelte";

  let jmap = $state<Jmap>();
  let failure = $state<unknown>();
  let admin = $state(false);

  $effect(() => {
    let stop = () => {};
    fetchSession()
      .then((session) => {
        const value = new Jmap(session);
        stop = value.listen((types) => touch(...types));
        jmap = value;
      })
      .catch((error: unknown) => (failure = error));
    // Administration appears for those who may administer something.
    adminAccess()
      .then((access) => (admin = access.instance || access.permissions.length > 0))
      .catch(() => (admin = false));
    return () => stop();
  });
</script>

{#if failure}
  <main class="center">
    <h1>{t("Something went wrong")}</h1>
    <p class="muted">{message(failure)}</p>
    <button type="button" onclick={() => window.location.reload()}>{t("Try again")}</button>
  </main>
{:else if jmap}
  <Shell {jmap} {admin} />
{:else}
  <main class="center muted">{t("Loading")}</main>
{/if}
