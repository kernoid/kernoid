// SPDX-License-Identifier: MIT
// The administration API (REST, /v1/…) from the browser: the session cookie with the CSRF header, and – for an
// instance administrator working on another tenant – the tenant in `kernoid-tenant`. Errors are kernoid's problem
// details (RFC 9457).

import createClient from "openapi-fetch";

import type { components, paths } from "./api-types.js";

/** The tenant an instance administrator works on; none for one's own. */
const chosen = $state<{ tenant: string | undefined }>({ tenant: undefined });

export function tenant(): string | undefined {
  return chosen.tenant;
}

export function setTenant(id: string | undefined): void {
  chosen.tenant = id;
}

export class AdminError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** kernoid's problem details as an error. */
function failure(status: number, problem: unknown): AdminError {
  const details = (problem ?? {}) as { title?: string; detail?: string };
  return new AdminError(status, details.detail ?? details.title ?? `${status}`);
}

/** Sends a browser that is no longer logged in to the login, and back here after. */
function relogin(response: Response): void {
  if (response.status === 401) {
    window.location.assign(`/login/account?next=${encodeURIComponent(window.location.pathname + window.location.hash)}`);
  }
}

/** The API, typed after its OpenAPI document (`pnpm api` writes api-types.ts). */
export const admin = createClient<paths>({ credentials: "same-origin" });
admin.use({
  onRequest({ request }) {
    request.headers.set("kernoid-csrf", "1");
    const target = tenant();
    if (target) request.headers.set("kernoid-tenant", target);
    return request;
  },
  onResponse({ response }) {
    relogin(response);
    return undefined;
  },
});

/** The answer of a request, or its problem as an `AdminError`. */
export async function need<T>(request: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  const { data, error, response } = await request;
  if (!response.ok) throw failure(response.status, error);
  return data as T;
}

/** A request with a body of another type than JSON, or for an answer that is not JSON (mbox); the response. */
export async function send(method: string, path: string, body?: { type: string; content: BodyInit }): Promise<Response> {
  const headers: Record<string, string> = { accept: "application/json", "kernoid-csrf": "1" };
  if (body) headers["content-type"] = body.type;
  const target = tenant();
  if (target) headers["kernoid-tenant"] = target;
  const init: RequestInit = { method, headers, credentials: "same-origin" };
  if (body) init.body = body.content;
  const response = await fetch(path, init);
  relogin(response);
  if (!response.ok) {
    let problem: unknown;
    try {
      problem = await response.json();
    } catch {
      // No problem details: the status says it.
    }
    throw failure(response.status, problem);
  }
  return response;
}

/** What the API takes and returns. */
export type Schema<Name extends keyof components["schemas"]> = components["schemas"][Name];
export type DomainView = Schema<"DomainView">;
export type TenantView = Schema<"TenantView">;
export type AccountDetails = Schema<"AccountDetails">;
export type ServiceView = Schema<"ServiceView">;
export type SessionSummaryView = Schema<"SessionSummaryView">;
export type ConsentView = Schema<"ConsentView">;
export type MailOverviewView = Schema<"MailOverviewView">;
export type FilesOverviewView = Schema<"FilesOverviewView">;
/** A project granted to another tenant. */
export type GrantView = Schema<"GrantView">;
export type GroupView = Schema<"GroupView">;
export type DriveView = Schema<"DriveView">;
export type RoleView = Schema<"RoleView">;
export type AssignmentView = Schema<"AssignmentView">;
export type RolesView = Schema<"RolesView">;
export type ServicePolicyView = Schema<"ServicePolicyView">;
export type ProjectView = Schema<"ProjectView">;
export type AuthorizationView = Schema<"AuthorizationView">;
export type ApplicationView = Schema<"ApplicationView">;
export type SamlView = Schema<"SamlView">;
export type ProviderView = Schema<"ProviderView">;
export type ScimTokenView = Schema<"ScimTokenView">;
export type InstanceDetails = Schema<"InstanceDetails">;
export type TenantSummary = Schema<"TenantSummary">;
export type SigningKeyView = Schema<"SigningKeyView">;
export type SamlKeyView = Schema<"SamlKeyView">;
export type QueuedView = Schema<"QueuedView">;
export type RecordCheckView = Schema<"RecordCheckView">;
