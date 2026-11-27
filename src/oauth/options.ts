import { z } from "zod";
import type { AccountView } from "../accounts.js";
import type { AuditEvent } from "../audit.js";
import { InvalidArgumentError } from "../errors.js";
import type { OAuthClientAuthMethod } from "../storage/types.js";

const DAY_SECONDS = 86_400;

/** A scope token of RFC 6749 section 3.3: visible ASCII without space, `"` and `\`. */
export const SCOPE = /^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/;
const PREFIX = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
/** A path of an endpoint: starts with `/`, no query, no fragment, no white space. */
const PATH = /^\/[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*$/;
/** The realm of `WWW-Authenticate: Basic`: visible ASCII and space, no `"` and `\`. */
const REALM = /^[\x20\x21\x23-\x5b\x5d-\x7e]{1,128}$/;
/** A display name: no control, format, surrogate or line and paragraph separator characters. */
const DISPLAY_NAME = /^[^\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]{1,128}$/u;

const AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"] as const;

const unique = (values: readonly unknown[]) => new Set(values).size === values.length;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1"]);

/**
 * Checks an issuer or resource URL: absolute, `https:` (or `http:` on `localhost` and
 * `127.0.0.1`, for development), no user info, no query, no fragment, no trailing slash, and
 * equal to its normalized form. Returns a reason, or null.
 */
function urlProblem(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "must be an absolute URL";
  }
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))
  ) {
    return "must use https (http only on localhost or 127.0.0.1)";
  }
  if (url.username !== "" || url.password !== "") return "must have no user info";
  if (url.search !== "" || value.includes("?")) return "must have no query";
  if (url.hash !== "" || value.includes("#")) return "must have no fragment";
  const normalized = url.pathname === "/" ? url.origin : `${url.origin}${url.pathname}`;
  if (value !== normalized) {
    return "must be in normalized form, without a trailing slash";
  }
  return null;
}

const absoluteUrl = z.string().superRefine((value, context) => {
  const problem = urlProblem(value);
  if (problem) context.addIssue({ code: z.ZodIssueCode.custom, message: problem });
});

const scope = z
  .string()
  .regex(SCOPE, "scope must be visible ASCII without space, quote or backslash");
const prefix = (fallback: string) =>
  z.string().regex(PREFIX, "prefix must be a letter, then [A-Za-z0-9_]").default(fallback);
const endpoint = z.string().refine((value) => PATH.test(value) || URL.canParse(value), {
  message: "endpoint must be a path or an absolute URL",
});

/**
 * Options of `createIdentkit({ oauth })`. `issuer`, `resources` and `defaultScopes` are required;
 * every other value has a default. See the README section on the OAuth authorization server.
 */
export const oauthOptionsSchema = z
  .object({
    /**
     * The issuer identifier (RFC 8414): one static `https:` URL, without query, fragment or
     * trailing slash. Never derive it from a request: an attacker could choose it.
     */
    issuer: absoluteUrl,
    /**
     * The protected resources (RFC 8707) that tokens may be for, 1 to 8 URLs. The first is the
     * default `resource` of an authorization request.
     */
    resources: z
      .array(absoluteUrl)
      .min(1)
      .max(8)
      .refine(unique, { message: "resources must not repeat a value" }),
    /** `resource_name` in the protected resource metadata (RFC 9728). */
    resourceName: z
      .string()
      .regex(DISPLAY_NAME, "resourceName must be 1 to 128 visible characters")
      .optional(),
    /**
     * Paths under the issuer's origin, or absolute URLs on it. `register: null` turns dynamic
     * client registration off.
     */
    endpoints: z
      .object({
        authorize: endpoint.default("/oauth/authorize"),
        token: endpoint.default("/oauth/token"),
        register: endpoint.nullable().default("/oauth/register"),
        revoke: endpoint.default("/oauth/revoke"),
      })
      .strict()
      .default({}),
    /** Granted on every grant. Opaque strings for identkit. */
    defaultScopes: z
      .array(scope)
      .min(1)
      .refine(unique, { message: "defaultScopes must not repeat a scope" }),
    /** Granted only if `authorize.approve` names them. Default none. */
    optInScopes: z
      .array(scope)
      .refine(unique, { message: "optInScopes must not repeat a scope" })
      .default([]),
    /** Lifetime of an access token. Default 3600. */
    accessTokenSeconds: z.number().int().min(60).max(DAY_SECONDS).default(3600),
    /** Lifetime of a refresh token, capped at the grant's end. Default 30 days. */
    refreshTokenSeconds: z
      .number()
      .int()
      .min(3600)
      .max(365 * DAY_SECONDS)
      .default(30 * DAY_SECONDS),
    /** Absolute lifetime of a grant. Default 90 days. At least `refreshTokenSeconds`. */
    grantSeconds: z
      .number()
      .int()
      .min(3600)
      .max(3650 * DAY_SECONDS)
      .default(90 * DAY_SECONDS),
    /** Lifetime of an authorization code. Default 300. */
    codeSeconds: z.number().int().min(30).max(600).default(300),
    /** Lifetime of a consent ticket. Default 600. */
    consentSeconds: z.number().int().min(60).max(3600).default(600),
    /**
     * How long after a rotation the previous refresh token gets `invalid_grant` without
     * ending the grant (parallel refreshes of one client). Default 30; 0 turns it off.
     */
    refreshRaceGraceSeconds: z.number().int().min(0).max(120).default(30),
    /** Live grants per account, counting other clients than the one at hand. Default 10. */
    maxGrantsPerAccount: z.number().int().min(1).max(1000).default(10),
    /**
     * `always` (default): every client gets a refresh token, as common MCP clients expect.
     * `if_registered`: only clients whose registered `grant_types` has `refresh_token`.
     */
    refreshTokens: z.enum(["always", "if_registered"]).default("always"),
    registration: z
      .object({
        /** Registrations per UTC day for the deployment. Default 1000. */
        maxPerDay: z.number().int().min(1).max(1_000_000).default(1000),
        /** Registrations per UTC day per `addressKey`. Default 30. */
        maxPerAddressPerDay: z.number().int().min(1).max(1_000_000).default(30),
        /** Size cap of the registration body in UTF-8 bytes. Default 8192. */
        maxBodyBytes: z.number().int().min(1024).max(65_536).default(8192),
        /** Redirect URIs per client. Default 5. */
        maxRedirectUris: z.number().int().min(1).max(20).default(5),
        /** Characters per redirect URI. Default 512. */
        maxRedirectUriLength: z.number().int().min(64).max(2048).default(512),
        /** The method of a registration that names none (RFC 7591 default). */
        defaultAuthMethod: z.enum(AUTH_METHODS).default("client_secret_basic"),
        /** The methods a registration may name. Default all three. */
        allowedAuthMethods: z
          .array(z.enum(AUTH_METHODS))
          .min(1)
          .refine(unique, { message: "allowedAuthMethods must not repeat a method" })
          .default([...AUTH_METHODS]),
      })
      .strict()
      .default({}),
    redirectUris: z
      .object({
        /** Accept `http://[::1]` redirect URIs. Default false. */
        allowIpv6Loopback: z.boolean().default(false),
        /** Accept private-use URI schemes such as `com.example.app:/cb` (RFC 8252). Default false. */
        allowPrivateUseSchemes: z.boolean().default(false),
      })
      .strict()
      .default({}),
    clientRetention: z
      .object({
        /** A client that never got a grant goes this many days after its registration. */
        unusedDays: z.number().int().min(1).max(3650).default(30),
        /** A client that got a grant goes this many days after its last use, never while live. */
        idleDays: z.number().int().min(1).max(3650).default(180),
      })
      .strict()
      .default({}),
    /** Starts of the issued strings. A distinct prefix lets secret scanners find leaks. */
    prefixes: z
      .object({
        clientId: prefix("ikc_"),
        clientSecret: prefix("ikcs_"),
        code: prefix("ikac_"),
        accessToken: prefix("ikat_"),
        refreshToken: prefix("ikrt_"),
      })
      .strict()
      .default({}),
    /**
     * A policy that can refuse a grant: called at `authorize.begin`, at `approve`, at the code
     * exchange and at a refresh. Must return a boolean; anything else fails the call.
     */
    admit: z
      .custom<OAuthAdmitHook>((value) => typeof value === "function", {
        message: "admit must be a function",
      })
      .optional(),
    /**
     * Checks tokens of an earlier system for grants imported with `oauth.importGrant`, so that
     * connected clients keep working after a move to identkit. identkit calls a verifier only
     * for a token that starts with none of its own prefixes, and only before `until`. The
     * verifier checks its own signature and expiry and returns what the token names, or null
     * to refuse; identkit then checks the grant, the account, the audience and the client as
     * for its own tokens. A verifier that throws fails the call; a result of another shape
     * throws `TypeError`.
     */
    legacy: z
      .object({
        verifyAccessToken: z
          .custom<OAuthLegacyAccessTokenVerifier>((value) => typeof value === "function", {
            message: "legacy.verifyAccessToken must be a function",
          })
          .optional(),
        verifyRefreshToken: z
          .custom<OAuthLegacyRefreshTokenVerifier>((value) => typeof value === "function", {
            message: "legacy.verifyRefreshToken must be a function",
          })
          .optional(),
        /**
         * From this time on, identkit calls no verifier. Set it to the latest expiry of a legacy
         * refresh token: after it, no legacy token can be valid.
         */
        until: z
          .date()
          .refine((d) => !Number.isNaN(d.getTime()), {
            message: "legacy.until must be a valid date",
          })
          .optional(),
      })
      .strict()
      .optional(),
    /**
     * Accept imported client secrets stored as unkeyed SHA-256 (`importClient` with
     * `secretSha256`). On the first successful use identkit replaces such a digest with the
     * keyed one. Default false: a client with such a digest cannot authenticate.
     */
    acceptLegacyClientSecrets: z.boolean().default(false),
    /**
     * Receives the error when the audit sink refuses `oauth.token_refreshed`, with the event.
     * The refresh still succeeds: that event is best effort. Without this option the error is
     * dropped. identkit awaits the call and drops what it throws; keep it quick.
     */
    onAuditError: z
      .custom<OAuthAuditErrorHandler>((value) => typeof value === "function", {
        message: "onAuditError must be a function",
      })
      .optional(),
    /**
     * Receives the error when a best-effort store write fails, with the write: the client's
     * last-used time, which identkit writes at most once a day after a code exchange or a
     * refresh took effect, and the upgrade of an imported SHA-256 client secret after it
     * matched. The call still returns its tokens: they are issued already, and an error would
     * make the client retry with a code or a refresh token that is used up. A failed upgrade is
     * tried again at the next use. Without this option the error is dropped. identkit awaits
     * the call and drops what it throws; keep it quick.
     */
    onStoreError: z
      .custom<OAuthStoreErrorHandler>((value) => typeof value === "function", {
        message: "onStoreError must be a function",
      })
      .optional(),
    /** The realm of `WWW-Authenticate: Basic` on `invalid_client`. Default: the issuer's host. */
    basicRealm: z
      .string()
      .regex(REALM, "basicRealm must be 1 to 128 visible ASCII characters")
      .optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const issue = (message: string) => context.addIssue({ code: z.ZodIssueCode.custom, message });
    if (value.optInScopes.some((s) => value.defaultScopes.includes(s))) {
      issue("optInScopes must not repeat a default scope");
    }
    if (value.grantSeconds < value.refreshTokenSeconds) {
      issue("grantSeconds must be at least refreshTokenSeconds");
    }
    if (!value.registration.allowedAuthMethods.includes(value.registration.defaultAuthMethod)) {
      issue("registration.defaultAuthMethod must be one of allowedAuthMethods");
    }
    const prefixes = Object.values(value.prefixes);
    if (prefixesOverlap(prefixes)) {
      issue("prefixes must differ, and none may start another");
    }
    let origin: string | null = null;
    try {
      origin = new URL(value.issuer).origin;
    } catch {
      // The issuer has its own issue.
    }
    if (origin !== null) {
      for (const [name, url] of Object.entries(value.endpoints)) {
        if (url !== null && !PATH.test(url) && new URL(url).origin !== origin) {
          issue(`endpoints.${name} must be on the issuer's origin`);
        }
      }
    }
  });

/** What `admit` receives. */
export interface OAuthAdmitRequest {
  phase: "authorize" | "token" | "refresh";
  account: AccountView;
  client: OAuthClientView;
  /** The scopes the grant would hold or holds. */
  scopes: string[];
}

export type OAuthAdmitHook = (request: OAuthAdmitRequest) => boolean | Promise<boolean>;

/**
 * See the option `legacy`. `audience` is the resource the token is for; it must be one of the
 * option `resources`.
 */
export type OAuthLegacyAccessTokenVerifier = (
  token: string,
) => Promise<{ grantId: string; audience: string; expiresAt: Date } | null>;

/**
 * See the option `legacy`. `generation` is the grant generation that issued the token: equal to
 * the imported grant's generation for its current token.
 */
export type OAuthLegacyRefreshTokenVerifier = (
  token: string,
) => Promise<{ grantId: string; generation: number; expiresAt: Date } | null>;

/** See the option `onAuditError`. */
export type OAuthAuditErrorHandler = (error: unknown, event: AuditEvent) => void | Promise<void>;

/**
 * See the option `onStoreError`. `client_last_used`: the client's `lastUsedAt`.
 * `client_secret_upgrade`: the keyed digest that replaces an imported SHA-256 client secret.
 */
export type OAuthStoreErrorHandler = (
  error: unknown,
  write: { kind: "client_last_used" | "client_secret_upgrade"; clientId: string },
) => void | Promise<void>;

export type OAuthOptions = z.input<typeof oauthOptionsSchema>;
type ParsedOptions = z.output<typeof oauthOptionsSchema>;

/** What a consumer sees of a client. Never contains its secret or the secret's digest. */
export interface OAuthClientView {
  id: string;
  /** The registered `client_name` with unsafe characters removed; escape it for HTML. */
  name: string | null;
  redirectUris: string[];
  grantTypes: string[];
  authMethod: OAuthClientAuthMethod;
  source: "dynamic" | "import";
  createdAt: Date;
  lastUsedAt: Date | null;
  /** True for an imported client whose secret digest is an unkeyed SHA-256. */
  legacyDigest: boolean;
}

/** The parsed options, with the endpoints as absolute URLs. */
export interface OAuthSettings extends Omit<ParsedOptions, "endpoints"> {
  endpoints: {
    authorize: string;
    token: string;
    register: string | null;
    revoke: string;
  };
  /** Default scopes, then opt-in scopes. */
  knownScopes: string[];
  basicRealm: string;
}

/** True if two prefixes are equal or one starts the other. */
export function prefixesOverlap(prefixes: readonly string[]): boolean {
  return prefixes.some((a, i) => prefixes.some((b, j) => i !== j && a.startsWith(b)));
}

export function parseOAuthOptions(options: unknown): OAuthSettings {
  const parsed = oauthOptionsSchema.safeParse(options);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new InvalidArgumentError(
      `oauth: ${issue ? `${issue.path.join(".")} ${issue.message}`.trim() : "invalid options"}`,
    );
  }
  const data = parsed.data;
  const issuer = new URL(data.issuer);
  const absolute = (value: string) =>
    PATH.test(value) ? `${issuer.origin}${value}` : new URL(value).href;
  return {
    ...data,
    endpoints: {
      authorize: absolute(data.endpoints.authorize),
      token: absolute(data.endpoints.token),
      register: data.endpoints.register === null ? null : absolute(data.endpoints.register),
      revoke: absolute(data.endpoints.revoke),
    },
    knownScopes: [...data.defaultScopes, ...data.optInScopes],
    basicRealm: data.basicRealm ?? issuer.host,
  };
}
