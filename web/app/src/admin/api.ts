// SPDX-License-Identifier: MIT
// The administration API (REST, /v1/…) from the browser: the session cookie with the CSRF header, and – for an
// instance administrator working on another tenant – the tenant in `kernoid-tenant`. Errors are kernoid's problem
// details (RFC 9457).

import { createSignal } from "solid-js";

/** The tenant an instance administrator works on; none for one's own. */
const [tenant, setTenant] = createSignal<string | undefined>();
export { setTenant, tenant };

export class AdminError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await send(method, path, body === undefined ? undefined : { type: "application/json", content: JSON.stringify(body) });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
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
  if (response.status === 401) {
    window.location.assign(`/login/account?next=${encodeURIComponent(window.location.pathname + window.location.hash)}`);
  }
  if (!response.ok) {
    let message = `${response.status}`;
    try {
      const problem = (await response.json()) as { title?: string; detail?: string };
      message = problem.detail ?? problem.title ?? message;
    } catch {
      // No problem details: the status says it.
    }
    throw new AdminError(response.status, message);
  }
  return response;
}

/** A path segment. */
export const seg = (value: string) => encodeURIComponent(value);

// What the API returns (docs/_data/openapi.json).

export interface DomainView {
  domain: string;
  verified: boolean;
  record?: { kind: string; name: string; value: string } | null;
}
export interface TenantView {
  id: string;
  instance: string;
  name: string;
  active: boolean;
  domains: DomainView[];
  mfa_required: boolean;
  mfa_grace_days: number;
  modules: string[];
}
export interface AccountDetails {
  id: string;
  tenant: string;
  address: string;
  display_name: string;
  active: boolean;
  native: boolean;
  shared: boolean;
  /** A team folder: listed under Team folders, not with the accounts. */
  drive: boolean;
}
export interface ServiceView {
  service: string;
  state: string;
}
export interface SessionSummaryView {
  id: string;
  checks: string[];
  created_at: string;
  expires_at: string;
  client_address?: string | null;
  user_agent?: string | null;
}
export interface ConsentView {
  application: string;
  application_name: string;
  granted_at: string;
  scopes: string[];
}
export interface LinkView {
  identity_provider: string;
  subject: string;
  created_at: string;
}
export interface MailOverviewView {
  quota?: number | null;
  effective_quota?: number | null;
  used_bytes: number;
  shared: boolean;
  mailboxes: { id: string; name: string; role?: string | null; total_emails: number; unread_emails: number }[];
}
export interface FilesOverviewView {
  quota?: number | null;
  effective_quota?: number | null;
  used_bytes: number;
}
export interface GrantView {
  grantee_kind: string;
  grantee_id: string;
  grantee_name?: string;
  rights: string;
  mailbox?: string | null;
  node?: string | null;
  send_as?: boolean;
}
export interface GroupView {
  id: string;
  name: string;
  addresses: string[];
  members: string[];
  /** The members may send from the group's addresses. */
  members_send_as: boolean;
}
export interface DriveView {
  id: string;
  name: string;
  active: boolean;
}
export interface RoleView {
  name: string;
  builtin: boolean;
  permissions: string[];
  tenant_permissions?: string[];
}
export interface AssignmentView {
  role: string;
  principal_kind: string;
  principal_id: string;
}
export interface RolesView {
  roles: RoleView[];
  assignments: AssignmentView[];
}
export interface ServicePolicyView {
  service?: string;
  assign: string;
  approval: boolean;
}
export interface ProjectView {
  id: string;
  name: string;
  role_assertion: boolean;
  role_check: boolean;
  roles: { key: string; display_name: string; group?: string | null }[];
}
export interface AuthorizationView {
  role: string;
  principal_kind: string;
  principal_id: string;
  tenant: string;
}
export interface ProjectGrantView {
  project: string;
  project_name: string;
  tenant: string;
  tenant_name: string;
  owner: string;
  roles: string[];
}
export interface ApplicationView {
  id: string;
  name: string;
  kind: string;
  active: boolean;
  project?: string | null;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  mfa_required: boolean;
  options: {
    access_token_format?: string;
    consent_required?: boolean;
    offline_access?: boolean;
    backchannel_logout_uri?: string | null;
    frontchannel_logout_uri?: string | null;
  };
}
export interface SamlView {
  sso_url: string;
  slo_url?: string | null;
  certificates: string[];
  sign_requests?: boolean;
  email_attribute?: string | null;
  name_attribute?: string | null;
}
export interface ProviderView {
  id: string;
  name: string;
  kind: string;
  active: boolean;
  issuer: string;
  client_id: string;
  has_secret: boolean;
  scopes: string[];
  domains: string[];
  auto_create: boolean;
  auto_link: boolean;
  register: boolean;
  sync_profile: boolean;
  instance_wide: boolean;
  redirect_uri: string;
  sp_entity_id?: string | null;
  saml?: SamlView | null;
}
export interface ScimTokenView {
  id: string;
  name: string;
  created_at: string;
  last_used_at?: string | null;
}
export interface InstanceDetails {
  id: string;
  name: string;
  domains: string[];
  primary_domain: string;
  login_ui_url?: string | null;
  passkey_rp_id: string;
}
export interface TenantSummary {
  id: string;
  name: string;
  active: boolean;
}
export interface SigningKeyView {
  kid: string;
  algorithm: string;
  state: string;
  state_since: string;
  created_at: string;
}
export interface SamlKeyView {
  id: string;
  state: string;
  state_since: string;
  created_at: string;
  fingerprint: string;
}
export interface QueuedView {
  message: string;
  address: string;
  status: string;
  attempts: number;
  next_attempt_at: string;
  last_error?: string | null;
}
export interface RecordCheckView {
  kind: string;
  name: string;
  record_type: string;
  expected: string;
  found: string[];
  status: string;
}
