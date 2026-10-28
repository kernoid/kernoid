// SPDX-License-Identifier: MIT
// How programs connect: mail (from the instance's mail autoconfiguration), calendars and contacts (CalDAV, CardDAV),
// files (WebDAV) – each with the address as user name and an app password.

import { For, type JSX, Show, createResource } from "solid-js";

import { ok } from "../App.js";
import { t } from "../i18n.js";

interface MailServer {
  protocol: string;
  host: string;
  port: string;
  socket: string;
}

/** The servers of `/.well-known/autoconfig/mail/config-v1.1.xml`; none where kernoid handles no mail. */
async function mailServers(): Promise<MailServer[]> {
  const response = await fetch("/.well-known/autoconfig/mail/config-v1.1.xml", { credentials: "omit" });
  if (!response.ok) return [];
  const xml = new DOMParser().parseFromString(await response.text(), "application/xml");
  return [...xml.querySelectorAll("incomingServer, outgoingServer")].map((server) => ({
    protocol: (server.getAttribute("type") ?? "").toUpperCase(),
    host: server.querySelector("hostname")?.textContent ?? "",
    port: server.querySelector("port")?.textContent ?? "",
    socket: server.querySelector("socketType")?.textContent === "SSL" ? "SSL/TLS" : "STARTTLS",
  }));
}

const origin = () => window.location.origin;
const host = () => window.location.host;

/** Connecting a file manager over WebDAV, per system. */
export function WebDavHelp(props: { address: string }): JSX.Element {
  const url = () => `${origin()}/webdav/`;
  const steps: [string, () => string][] = [
    ["macOS (Finder)", () => t("Go → Connect to Server (⌘K), enter {url}, then your address and an app password.", { url: url() })],
    ["Windows (Explorer)", () => t("This PC → Map network drive, folder {url}, tick “Connect using different credentials”, then your address and an app password.", { url: url() })],
    ["Linux (GNOME Files, Dolphin)", () => t("Other Locations → Connect to Server: {url}, then your address and an app password.", { url: `davs://${host()}/webdav/` })],
    ["iOS / iPadOS (Files)", () => t("… → Connect to Server: {url}, then your address and an app password.", { url: url() })],
    ["Android", () => t("A WebDAV app (e.g. a file manager with WebDAV support) with the address {url}.", { url: url() })],
  ];
  return (
    <div class="connect">
      <dl class="headers">
        <dt>{t("Server")}</dt>
        <dd><code>{url()}</code></dd>
        <dt>{t("User name")}</dt>
        <dd><code>{props.address}</code></dd>
        <dt>{t("Password")}</dt>
        <dd>{t("an app password (Account → Mail programs and devices)")}</dd>
      </dl>
      <ul class="steps">
        <For each={steps}>
          {([system, text]) => (
            <li>
              <b>{system}:</b> {text()}
            </li>
          )}
        </For>
      </ul>
      <p class="muted small">{t("There you find one folder per store: your own files, each team folder and what others share with you.")}</p>
    </div>
  );
}

export function Connect(props: { address: string }): JSX.Element {
  const [servers] = createResource(mailServers);
  return (
    <div class="connect">
      <Show when={(ok(servers) ?? []).length > 0}>
        <h3>{t("Mail (IMAP, SMTP)")}</h3>
        <table class="settings">
          <tbody>
            <For each={ok(servers) ?? []}>
              {(server) => (
                <tr>
                  <td>{server.protocol}</td>
                  <td><code>{server.host}</code></td>
                  <td>{t("Port {port}", { port: server.port })}</td>
                  <td>{server.socket}</td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
        <p class="muted small">{t("User name: your address {address}. Thunderbird finds these settings by itself.", { address: props.address })}</p>
      </Show>
      <h3>{t("Calendars and contacts (CalDAV, CardDAV)")}</h3>
      <p>
        {t("Server")}: <code>{host()}</code> – {t("programs find the rest themselves; otherwise {url}.", { url: `${origin()}/dav/` })}
      </p>
      <h3>{t("Files (WebDAV)")}</h3>
      <WebDavHelp address={props.address} />
    </div>
  );
}
