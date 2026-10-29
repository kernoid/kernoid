// SPDX-License-Identifier: MIT
// JMAP (RFC 8620) from the browser: the session of the instance's HttpOnly cookie – the same login as the account
// page – with the CSRF header kernoid asks for. Without a session the browser goes to the login, and comes back.

export const CORE = "urn:ietf:params:jmap:core";
export const MAIL = "urn:ietf:params:jmap:mail";
export const SUBMISSION = "urn:ietf:params:jmap:submission";
export const CALENDARS = "urn:ietf:params:jmap:calendars";
export const CONTACTS = "urn:ietf:params:jmap:contacts";
export const FILENODE = "urn:ietf:params:jmap:filenode";
export const FILE_VERSIONS = "https://kernoid.dev/jmap/file-versions";
export const FILE_LINKS = "https://kernoid.dev/jmap/file-links";
export const PRINCIPALS = "urn:ietf:params:jmap:principals";

export interface JmapSession {
  apiUrl: string;
  downloadUrl: string;
  uploadUrl: string;
  eventSourceUrl: string;
  username: string;
  state: string;
  primaryAccounts: Record<string, string>;
  capabilities: Record<string, Record<string, unknown>>;
  accounts: Record<string, { name: string; isPersonal: boolean; isReadOnly: boolean; accountCapabilities: Record<string, unknown>; "kernoid:drive"?: boolean }>;
}

export type Invocation = [string, Record<string, unknown>, string];

export class JmapError extends Error {
  constructor(
    readonly type: string,
    description?: string,
  ) {
    super(description ? `${type}: ${description}` : type);
  }
}

const HEADERS = { "content-type": "application/json", accept: "application/json", "kernoid-csrf": "1" };

function toLogin(): never {
  const here = window.location.pathname + window.location.search + window.location.hash;
  window.location.assign(`/login/account?next=${encodeURIComponent(here)}`);
  throw new JmapError("unauthenticated");
}

export async function fetchSession(): Promise<JmapSession> {
  const response = await fetch("/jmap/session", { headers: HEADERS, credentials: "same-origin" });
  if (response.status === 401) toLogin();
  if (!response.ok) throw new JmapError("serverFail", `the session answered ${response.status}`);
  return (await response.json()) as JmapSession;
}

export class Jmap {
  constructor(readonly session: JmapSession) {}

  /** The account's own id for a capability. */
  account(capability: string): string {
    const id = this.session.primaryAccounts[capability];
    if (!id) throw new JmapError("accountNotFound", capability);
    return id;
  }

  /** Runs method calls; returns the responses by call id, and throws the first method error. */
  async request(using: string[], calls: Invocation[]): Promise<Map<string, Record<string, unknown>[]>> {
    const response = await fetch(new URL(this.session.apiUrl).pathname, {
      method: "POST",
      headers: HEADERS,
      credentials: "same-origin",
      body: JSON.stringify({ using: [CORE, ...using], methodCalls: calls }),
    });
    if (response.status === 401) toLogin();
    const body = (await response.json()) as { methodResponses?: [string, Record<string, unknown>, string][]; detail?: string; type?: string };
    if (!response.ok || !body.methodResponses) throw new JmapError(body.type ?? "serverFail", body.detail);
    const out = new Map<string, Record<string, unknown>[]>();
    for (const [name, result, id] of body.methodResponses) {
      if (name === "error") throw new JmapError(String(result.type), result.description as string | undefined);
      const list = out.get(id) ?? [];
      list.push(result);
      out.set(id, list);
    }
    return out;
  }

  /** One method call; its (first) response. */
  async call<T = Record<string, unknown>>(using: string[], name: string, args: Record<string, unknown>): Promise<T> {
    const responses = await this.request(using, [[name, args, "0"]]);
    return responses.get("0")?.[0] as T;
  }

  /** `*\/set` with one change; throws the SetError if it was refused. */
  async set(using: string[], type: string, accountId: string, change: { create?: Record<string, unknown>; update?: Record<string, unknown>; destroy?: string[] }, extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const result = await this.call<Record<string, Record<string, { type: string; description?: string }> | undefined>>(using, `${type}/set`, {
      accountId,
      ...change,
      ...extra,
    });
    for (const key of ["notCreated", "notUpdated", "notDestroyed"]) {
      const failed = result[key];
      const first = failed ? Object.values(failed)[0] : undefined;
      if (first) throw new JmapError(first.type, first.description);
    }
    return result as unknown as Record<string, unknown>;
  }

  /** Where a blob is downloaded (RFC 8620, 6.2), on this page's origin. */
  downloadPath(accountId: string, blobId: string, name: string, type: string): string {
    const url = new URL(
      this.session.downloadUrl
        .replace("{accountId}", encodeURIComponent(accountId))
        .replace("{blobId}", encodeURIComponent(blobId))
        .replace("{name}", encodeURIComponent(name))
        .replace("{type}", encodeURIComponent(type)),
    );
    return url.pathname + url.search;
  }

  /** Uploads a file (RFC 8620, 6.1); its blob id. */
  async upload(accountId: string, file: Blob): Promise<{ blobId: string; type: string; size: number }> {
    const url = new URL(this.session.uploadUrl.replace("{accountId}", encodeURIComponent(accountId)));
    const response = await fetch(url.pathname, {
      method: "POST",
      headers: { "content-type": file.type || "application/octet-stream", "kernoid-csrf": "1" },
      credentials: "same-origin",
      body: file,
    });
    if (response.status === 401) toLogin();
    if (!response.ok) throw new JmapError("uploadFailed", `${response.status}`);
    return (await response.json()) as { blobId: string; type: string; size: number };
  }

  /** Uploads a file of any size, telling how far it got; its blob id. */
  uploadWithProgress(accountId: string, file: Blob, progress: (sent: number, total: number) => void): Promise<{ blobId: string; size: number }> {
    const url = new URL(this.session.uploadUrl.replace("{accountId}", encodeURIComponent(accountId)));
    return new Promise((resolve, reject) => {
      const request = new XMLHttpRequest();
      request.open("POST", url.pathname);
      request.withCredentials = true;
      request.setRequestHeader("content-type", file.type || "application/octet-stream");
      request.setRequestHeader("kernoid-csrf", "1");
      request.upload.onprogress = (event) => progress(event.loaded, event.total || file.size);
      request.onload = () => {
        if (request.status === 401) toLogin();
        if (request.status < 200 || request.status >= 300) reject(new JmapError("uploadFailed", `${request.status}`));
        else resolve(JSON.parse(request.responseText) as { blobId: string; size: number });
      };
      request.onerror = () => reject(new JmapError("uploadFailed", "the connection broke"));
      request.send(file);
    });
  }

  /** Hears of changes (RFC 8620, 7.3): `changed` is called with the types whose state moved. */
  listen(changed: (types: string[]) => void): () => void {
    const url = this.session.eventSourceUrl.replace("{types}", "*").replace("{closeafter}", "no").replace("{ping}", "60");
    const source = new EventSource(new URL(url).pathname + new URL(url).search, { withCredentials: true });
    source.addEventListener("state", (event) => {
      try {
        const data = JSON.parse((event as MessageEvent<string>).data) as { changed?: Record<string, Record<string, string>> };
        const types = new Set<string>();
        for (const account of Object.values(data.changed ?? {})) for (const type of Object.keys(account)) types.add(type);
        changed([...types]);
      } catch {
        // A ping or something unreadable: nothing changed.
      }
    });
    return () => source.close();
  }
}
