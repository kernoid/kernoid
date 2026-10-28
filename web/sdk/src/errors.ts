// SPDX-License-Identifier: MIT
// kernoid answers errors as problem details (RFC 9457); the SDK throws them as KernoidError.

/** An error as kernoid describes it. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
}

/** What a login UI has to do about an error. */
export type ErrorKind =
  /** A fresh login is needed: the session is too old for what was asked. */
  | "login-required"
  /** A second factor is needed: TOTP, a passkey or a recovery code. */
  | "mfa-required"
  /** The application needs the person's consent: show what it asks for, then finish with `consent: true`. */
  | "consent-required"
  /** No valid session, or wrong credentials. */
  | "unauthenticated"
  /** The session may not do this. */
  | "forbidden"
  | "not-found"
  | "conflict"
  | "too-many-attempts"
  | "bad-request"
  | "unavailable";

export class KernoidError extends Error {
  readonly status: number;
  readonly problem: Problem;
  readonly kind: ErrorKind;
  /** Seconds to wait, for `too-many-attempts`. */
  readonly retryAfter: number | undefined;

  constructor(problem: Problem, retryAfter?: number) {
    super(problem.detail ?? problem.title);
    this.name = "KernoidError";
    this.status = problem.status;
    this.problem = problem;
    this.kind = kindOf(problem);
    this.retryAfter = retryAfter;
  }
}

function kindOf(problem: Problem): ErrorKind {
  if (problem.type === "urn:kernoid:problem:login-required") return "login-required";
  if (problem.type === "urn:kernoid:problem:mfa-required") return "mfa-required";
  if (problem.type === "urn:kernoid:problem:consent-required") return "consent-required";
  switch (problem.status) {
    case 401:
      return "unauthenticated";
    case 403:
      return "forbidden";
    case 404:
      return "not-found";
    case 409:
      return "conflict";
    case 429:
      return "too-many-attempts";
    case 503:
      return "unavailable";
    default:
      return problem.status >= 500 ? "unavailable" : "bad-request";
  }
}
