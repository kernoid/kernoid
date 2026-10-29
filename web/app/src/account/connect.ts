// SPDX-License-Identifier: MIT
// How programs connect: the mail servers of the instance's mail autoconfiguration (Connect.svelte, WebDavHelp.svelte).

export interface MailServer {
  protocol: string;
  host: string;
  port: string;
  socket: string;
}

/** The servers of `/.well-known/autoconfig/mail/config-v1.1.xml`; none where kernoid handles no mail. */
export async function mailServers(): Promise<MailServer[]> {
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
