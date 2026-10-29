<!-- SPDX-License-Identifier: MIT -->
<!-- How programs connect: mail (from the instance's mail autoconfiguration), calendars and contacts (CalDAV, CardDAV),
     files (WebDAV) – each with the address as user name and an app password. -->
<script lang="ts">
  import { loaded } from "../app.svelte.js";
  import { t } from "../i18n.js";
  import { mailServers } from "./connect.js";
  import WebDavHelp from "./WebDavHelp.svelte";

  let { address }: { address: string } = $props();

  const servers = loaded(mailServers);
</script>

<div class="connect">
  {#if (servers.value ?? []).length > 0}
    <h3>{t("Mail (IMAP, SMTP)")}</h3>
    <table class="settings">
      <tbody>
        {#each servers.value ?? [] as server, index (index)}
          <tr>
            <td>{server.protocol}</td>
            <td><code>{server.host}</code></td>
            <td>{t("Port {port}", { port: server.port })}</td>
            <td>{server.socket}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    <p class="muted small">
      {t("User name: your address {address}. Thunderbird finds these settings by itself.", { address })}
    </p>
  {/if}
  <h3>{t("Calendars and contacts (CalDAV, CardDAV)")}</h3>
  <p>
    {t("Server")}: <code>{window.location.host}</code> –
    {t("programs find the rest themselves; otherwise {url}.", { url: `${window.location.origin}/dav/` })}
  </p>
  <h3>{t("Files (WebDAV)")}</h3>
  <WebDavHelp {address} />
</div>
