// SPDX-License-Identifier: MIT
// Requests to kernoid's REST API: JSON in, JSON out, problems thrown as KernoidError.

import { KernoidError, type Problem } from "./errors.js";

export interface HttpOptions {
  /** Where kernoid is reached, e.g. `https://login.example.org`; empty for the page's own origin. */
  baseUrl?: string;
  /** A session token (`ks1.…`), sent as `Authorization: Bearer`. */
  token?: string;
  /** For instance administrators: the tenant to act on (`kernoid-tenant`). */
  tenant?: string;
  /**
   * In a browser: keep the session in kernoid's HttpOnly cookie instead of a token the page holds. Requests then
   * carry the cookie and the `kernoid-csrf` header that changes with the cookie need.
   */
  cookies?: boolean;
  /** Defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

export class Http {
  readonly baseUrl: string;
  token: string | undefined;
  tenant: string | undefined;
  readonly cookies: boolean;
  private readonly fetcher: typeof fetch;

  constructor(options: HttpOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "").replace(/\/+$/, "");
    this.token = options.token;
    this.tenant = options.tenant;
    this.cookies = options.cookies ?? false;
    this.fetcher = options.fetch ?? ((input, init) => fetch(input, init));
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    if (this.tenant) headers["kernoid-tenant"] = this.tenant;
    if (this.cookies) headers["kernoid-csrf"] = "1";
    // The cookie goes to kernoid only: to the page's own origin, or – on the same site – to `baseUrl`.
    const credentials: RequestCredentials = this.cookies ? (this.baseUrl ? "include" : "same-origin") : "omit";
    const init: RequestInit = { method, headers, credentials };
    if (body !== undefined) init.body = JSON.stringify(body);
    let response: Response;
    try {
      response = await this.fetcher(`${this.baseUrl}${path}`, init);
    } catch (cause) {
      throw new KernoidError({ type: "about:blank", title: "Service Unavailable", status: 503, detail: `kernoid cannot be reached: ${String(cause)}` });
    }
    if (response.status === 204) return undefined as T;
    const text = await response.text();
    const json: unknown = text ? JSON.parse(text) : undefined;
    if (!response.ok) {
      const problem: Problem = isProblem(json)
        ? json
        : { type: "about:blank", title: response.statusText || "Error", status: response.status };
      const retry = Number(response.headers.get("retry-after"));
      throw new KernoidError(problem, Number.isFinite(retry) && retry > 0 ? retry : undefined);
    }
    return json as T;
  }
}

function isProblem(value: unknown): value is Problem {
  return typeof value === "object" && value !== null && typeof (value as Problem).status === "number";
}
