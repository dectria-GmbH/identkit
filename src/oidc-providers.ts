import { InvalidArgumentError } from "./errors.js";
import { ID_TOKEN_ALGORITHMS, type IdTokenAlgorithm } from "./oidc-jwt.js";
import type { OidcProviderKind } from "./storage/types.js";

/**
 * Tenant id of Microsoft personal accounts (outlook.com, hotmail.com and others). Such an
 * account never binds by e-mail address: it belongs to no organization's tenant, so no tenant
 * administrator vouches for the domain of its address.
 */
export const MICROSOFT_CONSUMER_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad";

const MICROSOFT_HOST = "https://login.microsoftonline.com";
const GOOGLE_ISSUER = "https://accounts.google.com";
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PROVIDER_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MAX_SUBJECT_LENGTH = 255;

/**
 * An external OpenID Connect provider, created by `microsoftProvider`, `googleProvider` or
 * `oidcProvider`. The client secret stays inside identkit: it is not a property of this object.
 */
export interface OidcProvider {
  /** The name you pass to `oidc.begin({ provider })`. Unique among the configured providers. */
  readonly id: string;
  readonly kind: OidcProviderKind;
  readonly clientId: string;
  /** Register exactly this URI at the provider. */
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly scopes: readonly string[];
}

/** The subject of a verified ID token and what identkit may bind it by. */
export interface ProviderIdentity {
  kind: OidcProviderKind;
  linkKey: string;
  issuer: string;
  subject: string;
  tenantId: string | null;
  /** The provider-verified address, or why the subject cannot bind by address. */
  address:
    | { ok: true; email: string }
    | { ok: false; reason: "unverified_address" | "consumer_tenant" | "guest_account" };
}

export type IdentifyResult =
  | { status: "ok"; identity: ProviderIdentity }
  /** The token is not one this provider issues for this client. */
  | { status: "invalid" }
  /** A valid token of a tenant or domain the operator does not allow. */
  | { status: "organization_not_allowed" };

export interface ProviderInternals {
  clientSecret: string;
  tokenEndpointAuthMethod: "client_secret_basic" | "client_secret_post";
  algorithms: readonly IdTokenAlgorithm[];
  prompt: string | null;
  /** Checks the issuer and the provider-specific claims, and derives the link key. */
  identify(claims: Record<string, unknown>): IdentifyResult;
}

const registry = new WeakMap<OidcProvider, ProviderInternals>();

export function providerInternals(provider: OidcProvider): ProviderInternals {
  const internals = registry.get(provider);
  if (!internals) {
    throw new InvalidArgumentError(
      "an OIDC provider must come from microsoftProvider, googleProvider or oidcProvider",
    );
  }
  return internals;
}

/** Link key for a subject. A JSON array, so no part can be confused with another. */
export function linkKeyOf(kind: OidcProviderKind, ...parts: string[]): string {
  return JSON.stringify([kind, ...parts]);
}

export function isGuid(value: unknown): value is string {
  return typeof value === "string" && GUID.test(value);
}

export function microsoftIssuer(tenantId: string): string {
  return `${MICROSOFT_HOST}/${tenantId}/v2.0`;
}

export function isValidSubject(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_SUBJECT_LENGTH;
}

function requireString(value: unknown, name: string, max = 2048): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new InvalidArgumentError(`${name} must be a non-empty string`);
  }
  return value;
}

function isLocalhost(url: URL): boolean {
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
}

/** An absolute https URL without fragment; plain http only for localhost. */
export function requireUrl(value: unknown, name: string): string {
  const text = requireString(value, name);
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new InvalidArgumentError(`${name} must be an absolute URL`);
  }
  const secure = url.protocol === "https:" || (url.protocol === "http:" && isLocalhost(url));
  if (!secure || url.hash !== "" || url.username !== "" || url.password !== "") {
    throw new InvalidArgumentError(
      `${name} must be an https URL without fragment (http only for localhost)`,
    );
  }
  return text;
}

function requireScopes(value: unknown): readonly string[] {
  if (value === undefined) return Object.freeze(["openid", "email", "profile"]);
  if (
    !Array.isArray(value) ||
    !value.every((s) => typeof s === "string" && /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(s)) ||
    !value.includes("openid")
  ) {
    throw new InvalidArgumentError("scopes must be scope tokens and include openid");
  }
  return Object.freeze(value.map(String));
}

function requirePrompt(value: unknown, fallback: string | null): string | null {
  if (value === undefined) return fallback;
  if (value === null) return null;
  return requireString(value, "prompt", 64);
}

function requireAlgorithms(value: unknown): readonly IdTokenAlgorithm[] {
  if (value === undefined) return Object.freeze(["RS256"] as const);
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((a) => ID_TOKEN_ALGORITHMS.some((known) => known === a))
  ) {
    throw new InvalidArgumentError(`algorithms must list ${ID_TOKEN_ALGORITHMS.join(" or ")}`);
  }
  return Object.freeze(ID_TOKEN_ALGORITHMS.filter((a) => value.includes(a)));
}

/** True for `true` and the string forms some providers send. */
function claimTrue(value: unknown): boolean {
  return value === true || value === "true" || value === 1 || value === "1";
}

const emailClaim = (claims: Record<string, unknown>): string | null =>
  typeof claims["email"] === "string" && claims["email"].length > 0 ? claims["email"] : null;

interface CommonOptions {
  /** Default: the kind (`microsoft`, `google`). Required for `oidcProvider`. */
  id?: string;
  clientId: string;
  /** Kept inside identkit and sent only to the token endpoint. */
  clientSecret: string;
  redirectUri: string;
  /** Default `["openid", "email", "profile"]`. Must include `openid`. */
  scopes?: string[];
}

function register(
  options: CommonOptions & { id: string },
  kind: OidcProviderKind,
  endpoints: { authorizationEndpoint: string; tokenEndpoint: string; jwksUri: string },
  internals: ProviderInternals,
): OidcProvider {
  if (typeof options.id !== "string" || !PROVIDER_ID.test(options.id)) {
    throw new InvalidArgumentError("provider id must match [a-z0-9][a-z0-9_-]{0,63}");
  }
  const provider: OidcProvider = Object.freeze({
    id: options.id,
    kind,
    clientId: requireString(options.clientId, "clientId", 512),
    redirectUri: requireUrl(options.redirectUri, "redirectUri"),
    authorizationEndpoint: requireUrl(endpoints.authorizationEndpoint, "authorizationEndpoint"),
    tokenEndpoint: requireUrl(endpoints.tokenEndpoint, "tokenEndpoint"),
    jwksUri: requireUrl(endpoints.jwksUri, "jwksUri"),
    scopes: requireScopes(options.scopes),
  });
  requireString(internals.clientSecret, "clientSecret", 4096);
  registry.set(provider, internals);
  return provider;
}

export interface MicrosoftProviderOptions extends CommonOptions {
  /**
   * The authority: `common` (default: work, school and personal accounts), `organizations`
   * (work and school only), `consumers` (personal only) or a tenant id (that tenant only).
   */
  tenant?: string;
  /** If set, only these tenant ids may sign in at all. */
  allowedTenants?: string[];
  /**
   * Treat `preferred_username` as a verified address when the token does not mark `email` as
   * domain-verified (`xms_edov`). Default false. See the README for when this is sound. Never
   * applies to a guest account.
   */
  upnAsAddress?: boolean;
  /**
   * Let a guest account (a user homed in another tenant or at another identity provider, signed
   * in to the authority tenant) bind by its `email` with `xms_edov` true. Default false: a guest
   * never binds by address. A guest with a link (for example an imported one) signs in either way.
   */
  allowGuests?: boolean;
  /** Default `select_account`; null sends no prompt. */
  prompt?: string | null;
}

/**
 * Microsoft Entra ID (v2.0 endpoint). The link key is the tenant id and object id (`tid`,
 * `oid`); the issuer must be the token's own tenant issuer.
 */
export function microsoftProvider(options: MicrosoftProviderOptions): OidcProvider {
  const tenant = options.tenant ?? "common";
  const named = tenant === "common" || tenant === "organizations" || tenant === "consumers";
  if (!named && !isGuid(tenant)) {
    throw new InvalidArgumentError("tenant must be common, organizations, consumers or a GUID");
  }
  const authority = named ? tenant : tenant.toLowerCase();
  let allowed: Set<string> | null = null;
  if (options.allowedTenants !== undefined) {
    if (!Array.isArray(options.allowedTenants) || !options.allowedTenants.every(isGuid)) {
      throw new InvalidArgumentError("allowedTenants must be tenant ids (GUIDs)");
    }
    allowed = new Set(options.allowedTenants.map((t) => t.toLowerCase()));
  }
  const upnAsAddress = options.upnAsAddress ?? false;
  if (typeof upnAsAddress !== "boolean") {
    throw new InvalidArgumentError("upnAsAddress must be a boolean");
  }
  const allowGuests = options.allowGuests ?? false;
  if (typeof allowGuests !== "boolean") {
    throw new InvalidArgumentError("allowGuests must be a boolean");
  }
  const base = `${MICROSOFT_HOST}/${authority}`;
  return register(
    { ...options, id: options.id ?? "microsoft" },
    "microsoft",
    {
      authorizationEndpoint: `${base}/oauth2/v2.0/authorize`,
      tokenEndpoint: `${base}/oauth2/v2.0/token`,
      jwksUri: `${base}/discovery/v2.0/keys`,
    },
    {
      clientSecret: options.clientSecret,
      tokenEndpointAuthMethod: "client_secret_post",
      algorithms: Object.freeze(["RS256"] as const),
      prompt: requirePrompt(options.prompt, "select_account"),
      identify(claims) {
        const tid = claims["tid"];
        const oid = claims["oid"];
        // The multi-tenant endpoints sign for every tenant: the issuer must be the token's own.
        if (!isGuid(tid) || claims["iss"] !== microsoftIssuer(tid) || !isGuid(oid)) {
          return { status: "invalid" };
        }
        const tenantId = tid.toLowerCase();
        const consumer = tenantId === MICROSOFT_CONSUMER_TENANT_ID;
        const authorityAllows =
          authority === "common" ||
          (authority === "organizations" && !consumer) ||
          (authority === "consumers" && consumer) ||
          authority === tenantId;
        if (!authorityAllows || (allowed !== null && !allowed.has(tenantId))) {
          return { status: "organization_not_allowed" };
        }
        let address: ProviderIdentity["address"];
        const email = emailClaim(claims);
        const upn = claims["preferred_username"];
        const guest = isMicrosoftGuest(claims, tenantId);
        if (consumer) {
          address = { ok: false, reason: "consumer_tenant" };
        } else if (guest && !allowGuests) {
          address = { ok: false, reason: "guest_account" };
        } else if (email !== null && claimTrue(claims["xms_edov"])) {
          address = { ok: true, email };
        } else if (!guest && upnAsAddress && typeof upn === "string" && upn.includes("@")) {
          address = { ok: true, email: upn };
        } else {
          address = { ok: false, reason: "unverified_address" };
        }
        const objectId = oid.toLowerCase();
        return {
          status: "ok",
          identity: {
            kind: "microsoft",
            linkKey: linkKeyOf("microsoft", tenantId, objectId),
            issuer: microsoftIssuer(tenantId),
            subject: objectId,
            tenantId,
            address,
          },
        };
      },
    },
  );
}

/**
 * True if the token is of a guest: a user who is not homed in the token's tenant. Microsoft's ID
 * token reference: `idp` "is identical to the value of the issuer claim unless the user account
 * isn't in the same tenant as the issuer - guests, for instance"; a missing `idp` means `iss`.
 * For an invited personal account it may be `live.com`. The optional claim `acct` is 1 for a
 * guest. An `idp` that is not a Microsoft STS URI of the token's own tenant counts as a guest,
 * so an unknown form fails closed.
 */
function isMicrosoftGuest(claims: Record<string, unknown>, tenantId: string): boolean {
  const acct = claims["acct"];
  if (acct === 1 || acct === "1") return true;
  const idp = claims["idp"];
  if (idp === undefined || idp === claims["iss"]) return false;
  if (typeof idp !== "string") return true;
  let url: URL;
  try {
    url = new URL(idp);
  } catch {
    return true;
  }
  const stsHost =
    url.hostname === "sts.windows.net" || url.hostname === "login.microsoftonline.com";
  const firstSegment = url.pathname.split("/")[1]?.toLowerCase();
  return !(url.protocol === "https:" && stsHost && firstSegment === tenantId);
}

export interface GoogleProviderOptions extends CommonOptions {
  /** If set, only accounts of these Google Workspace domains (`hd` claim) may sign in. */
  hostedDomains?: string[];
  /** Default none; for example `select_account`. */
  prompt?: string | null;
}

/** Google. The link key is the subject (`sub`), which Google keeps for the life of the account. */
export function googleProvider(options: GoogleProviderOptions): OidcProvider {
  let domains: Set<string> | null = null;
  if (options.hostedDomains !== undefined) {
    if (
      !Array.isArray(options.hostedDomains) ||
      !options.hostedDomains.every((d) => typeof d === "string" && d.length > 0)
    ) {
      throw new InvalidArgumentError("hostedDomains must be domain names");
    }
    domains = new Set(options.hostedDomains.map((d) => d.toLowerCase()));
  }
  return register(
    { ...options, id: options.id ?? "google" },
    "google",
    {
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
    },
    {
      clientSecret: options.clientSecret,
      tokenEndpointAuthMethod: "client_secret_post",
      algorithms: Object.freeze(["RS256"] as const),
      prompt: requirePrompt(options.prompt, null),
      identify(claims) {
        const iss = claims["iss"];
        const sub = claims["sub"];
        // Google documents both forms of its issuer.
        if ((iss !== GOOGLE_ISSUER && iss !== "accounts.google.com") || !isValidSubject(sub)) {
          return { status: "invalid" };
        }
        const hd = claims["hd"];
        if (domains !== null && !(typeof hd === "string" && domains.has(hd.toLowerCase()))) {
          return { status: "organization_not_allowed" };
        }
        const email = emailClaim(claims);
        return {
          status: "ok",
          identity: {
            kind: "google",
            linkKey: linkKeyOf("google", sub),
            issuer: GOOGLE_ISSUER,
            subject: sub,
            tenantId: null,
            address:
              email !== null && claimTrue(claims["email_verified"])
                ? { ok: true, email }
                : { ok: false, reason: "unverified_address" },
          },
        };
      },
    },
  );
}

export interface GenericOidcProviderOptions extends CommonOptions {
  id: string;
  /** Must equal the `iss` claim of the provider's ID tokens exactly. */
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  /** Default `client_secret_basic`, the OpenID Connect default. */
  tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post";
  /** Accepted ID token algorithms. Default `["RS256"]`. */
  algorithms?: IdTokenAlgorithm[];
  /** Default none. */
  prompt?: string | null;
}

/**
 * Any OpenID Connect provider with explicit endpoints (no discovery request). The link key is
 * the issuer and subject. An address binds only with `email_verified` true.
 */
export function oidcProvider(options: GenericOidcProviderOptions): OidcProvider {
  const issuer = requireUrl(options.issuer, "issuer");
  const auth = options.tokenEndpointAuthMethod ?? "client_secret_basic";
  if (auth !== "client_secret_basic" && auth !== "client_secret_post") {
    throw new InvalidArgumentError("tokenEndpointAuthMethod must be client_secret_basic or _post");
  }
  return register(
    options,
    "oidc",
    {
      authorizationEndpoint: options.authorizationEndpoint,
      tokenEndpoint: options.tokenEndpoint,
      jwksUri: options.jwksUri,
    },
    {
      clientSecret: options.clientSecret,
      tokenEndpointAuthMethod: auth,
      algorithms: requireAlgorithms(options.algorithms),
      prompt: requirePrompt(options.prompt, null),
      identify(claims) {
        const sub = claims["sub"];
        if (claims["iss"] !== issuer || !isValidSubject(sub)) return { status: "invalid" };
        const email = emailClaim(claims);
        return {
          status: "ok",
          identity: {
            kind: "oidc",
            linkKey: linkKeyOf("oidc", issuer, sub),
            issuer,
            subject: sub,
            tenantId: null,
            address:
              email !== null && claimTrue(claims["email_verified"])
                ? { ok: true, email }
                : { ok: false, reason: "unverified_address" },
          },
        };
      },
    },
  );
}
