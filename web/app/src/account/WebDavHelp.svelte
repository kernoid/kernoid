<!-- SPDX-License-Identifier: MIT -->
<!-- Connecting a file manager over WebDAV, per system: the address as user name and an app password. -->
<script lang="ts">
  import { t } from "../i18n.js";

  let { address }: { address: string } = $props();

  const url = `${window.location.origin}/webdav/`;
  const steps: [string, string][] = [
    ["macOS (Finder)", t("Go → Connect to Server (⌘K), enter {url}, then your address and an app password.", { url })],
    [
      "Windows (Explorer)",
      t(
        "This PC → Map network drive, folder {url}, tick “Connect using different credentials”, then your address and an app password.",
        { url },
      ),
    ],
    [
      "Linux (GNOME Files, Dolphin)",
      t("Other Locations → Connect to Server: {url}, then your address and an app password.", {
        url: `davs://${window.location.host}/webdav/`,
      }),
    ],
    ["iOS / iPadOS (Files)", t("… → Connect to Server: {url}, then your address and an app password.", { url })],
    ["Android", t("A WebDAV app (e.g. a file manager with WebDAV support) with the address {url}.", { url })],
  ];
</script>

<div class="connect">
  <dl class="headers">
    <dt>{t("Server")}</dt>
    <dd><code>{url}</code></dd>
    <dt>{t("User name")}</dt>
    <dd><code>{address}</code></dd>
    <dt>{t("Password")}</dt>
    <dd>{t("an app password (Account → Mail programs and devices)")}</dd>
  </dl>
  <ul class="steps">
    {#each steps as [system, text] (system)}
      <li><b>{system}:</b> {text}</li>
    {/each}
  </ul>
  <p class="muted small">
    {t("There you find one folder per store: your own files, each team folder and what others share with you.")}
  </p>
</div>
