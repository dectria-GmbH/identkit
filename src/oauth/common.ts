import type { Context } from "../context.js";
import { InvalidArgumentError } from "../errors.js";
import { isRecord } from "../oidc-jwt.js";
import type { SecretSealer } from "../sealer.js";
import type { IdentkitStore, OAuthClientRecord } from "../storage/types.js";
import type { OAuthAdmitRequest, OAuthClientView, OAuthSettings } from "./options.js";

export type OAuthStore = NonNullable<IdentkitStore["oauth"]>;

/** What every part of the OAuth module shares. */
export interface OAuthInternals {
  ctx: Context;
  settings: OAuthSettings;
  store: OAuthStore;
  sealer: SecretSealer;
}

/** The raw parameters of a request: `URLSearchParams` lets identkit refuse duplicates. */
export type OAuthParams = URLSearchParams | Record<string, string | undefined>;

/**
 * The result of an endpoint call. Write `body` as JSON (or an empty body if it is null) with
 * `httpStatus` and `headers`. identkit suggests the status; you may change it.
 */
export interface OAuthEndpointResult {
  httpStatus: 200 | 201 | 400 | 401 | 429;
  body: Record<string, unknown> | null;
  headers: Record<string, string>;
}

/** Token responses and errors must not be cached (RFC 6749 section 5.1). */
const NO_STORE = { "Cache-Control": "no-store", Pragma: "no-cache" } as const;

export function endpointResult(
  httpStatus: OAuthEndpointResult["httpStatus"],
  body: Record<string, unknown> | null,
  headers: Record<string, string> = {},
): OAuthEndpointResult {
  return { httpStatus, body, headers: { ...NO_STORE, ...headers } };
}

/** An error body with an RFC error code and a fixed English description, never input echo. */
export function errorResult(
  httpStatus: 400 | 401 | 429,
  error: string,
  description: string,
  headers: Record<string, string> = {},
): OAuthEndpointResult {
  return endpointResult(httpStatus, { error, error_description: description }, headers);
}

/**
 * Reads the parameters. Returns null for a parameter sent more than once (RFC 6749 section
 * 3.1 and 3.2), which only `URLSearchParams` can show, and for a record value that is not a
 * string. Throws `InvalidArgumentError` if `params` is neither form.
 */
export function readParams(params: unknown): Map<string, string> | null {
  const values = new Map<string, string>();
  if (params instanceof URLSearchParams) {
    for (const [name, value] of params) {
      if (values.has(name)) return null;
      values.set(name, value);
    }
    return values;
  }
  if (!isRecord(params)) {
    throw new InvalidArgumentError("params must be URLSearchParams or an object");
  }
  for (const [name, value] of Object.entries(params)) {
    if (value === undefined) continue;
    if (typeof value !== "string") return null;
    values.set(name, value);
  }
  return values;
}

/** The names of the parameters sent more than once, for `URLSearchParams`. */
export function duplicateNames(params: unknown): Set<string> {
  const seen = new Set<string>();
  const twice = new Set<string>();
  if (params instanceof URLSearchParams) {
    for (const name of params.keys()) {
      if (seen.has(name)) twice.add(name);
      seen.add(name);
    }
  }
  return twice;
}

/** Characters that a name must not show: control, format, surrogate and separators. */
const UNSAFE = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/gu;
/** Characters that show nothing; see `api-tokens.ts`. */
const BLANK = /[\p{White_Space}\p{Z}͏ᅟᅠ⠀ㅤﾠ]/gu;
const MAX_NAME_CHARACTERS = 100;

/**
 * A client name from untrusted input: unsafe characters removed, cut at 100 characters (code
 * points), null if nothing visible is left. HTML escaping is the page's job.
 */
export function sanitizeClientName(value: string): string | null {
  const cleaned = Array.from(value.replace(UNSAFE, ""))
    .slice(0, MAX_NAME_CHARACTERS)
    .join("")
    .trim();
  return cleaned.replace(BLANK, "") === "" ? null : cleaned;
}

export function toClientView(record: OAuthClientRecord): OAuthClientView {
  return {
    id: record.id,
    name: record.name,
    redirectUris: [...record.redirectUris],
    grantTypes: [...record.grantTypes],
    authMethod: record.authMethod,
    source: record.source,
    createdAt: record.createdAt,
    lastUsedAt: record.lastUsedAt,
    legacyDigest: record.secretDigestAlgorithm === "sha256",
  };
}

export function requireId(value: unknown, what: string): string {
  if (typeof value !== "string" || value === "") {
    throw new InvalidArgumentError(`${what} must be a non-empty string`);
  }
  return value;
}

/** A client id that identkit may look up: visible ASCII, 1 to 128 characters. */
export const CLIENT_ID = /^[\x21-\x7e]{1,128}$/;

/** The start of the UTC day of `at`. */
export function utcDayStart(at: Date): Date {
  return new Date(Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate()));
}

/**
 * Asks the `admit` policy, if any. It can only refuse: a missing policy admits. A result that is
 * not a boolean throws `TypeError`, so a policy bug fails the call instead of admitting.
 */
export async function admits(
  internals: OAuthInternals,
  request: OAuthAdmitRequest,
): Promise<boolean> {
  const hook = internals.settings.admit;
  if (!hook) return true;
  const allowed: unknown = await hook(request);
  if (typeof allowed !== "boolean") throw new TypeError("oauth.admit must return a boolean");
  return allowed;
}

/** The scopes in the order of the options: defaults, then the chosen opt-in scopes. */
export function orderedScopes(settings: OAuthSettings, optIn: readonly string[]): string[] {
  return [...settings.defaultScopes, ...settings.optInScopes.filter((s) => optIn.includes(s))];
}
