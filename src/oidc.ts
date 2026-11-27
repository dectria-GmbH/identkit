import { newAccountRecord, toAccountView, type AccountView } from "./accounts.js";
import { addSeconds } from "./clock.js";
import type { SecondFactorMethod } from "./config.js";
import type { Context } from "./context.js";
import { bytesEqual, sha256, toBase64Url, utf8 } from "./bytes.js";
import { randomId, randomToken } from "./crypto.js";
import { normalizeEmail } from "./email.js";
import { assertMethodAllowed } from "./email-otp.js";
import { InvalidArgumentError, NotConfiguredError } from "./errors.js";
import { completeFirstFactor } from "./first-factor.js";
import {
  assertJwksCache,
  createJwksCache,
  findKey,
  providerFetch,
  ProviderRequestError,
  readJson,
  type JwksCache,
  type OidcFetch,
} from "./oidc-jwks.js";
import { decodeJwt, isRecord, verifyJwtSignature, type IdTokenAlgorithm } from "./oidc-jwt.js";
import {
  isGuid,
  isValidSubject,
  linkKeyOf,
  microsoftIssuer,
  providerInternals,
  requireUrl,
  type OidcProvider,
  type ProviderIdentity,
  type ProviderInternals,
} from "./oidc-providers.js";
import type { SecretSealer } from "./sealer.js";
import type { IssuedSession, SessionInternals } from "./sessions.js";
import type {
  AccountRecord,
  IdentkitStore,
  OidcLinkRecord,
  OidcLinkSource,
  OidcProviderKind,
} from "./storage/types.js";

/** Context string of the sealed transaction. A value sealed for anything else does not open. */
const TRANSACTION_CONTEXT = "identkit/oidc/transaction/v1";
const MAX_TOKEN_RESPONSE_BYTES = 256 * 1024;
const MAX_LOGIN_HINT_LENGTH = 256;
/** Provider error codes are ASCII words (RFC 6749 section 4.1.2.1); anything else is dropped. */
const PROVIDER_ERROR = /^[a-z0-9_.-]{1,64}$/i;

/** What `mayBind` receives before identkit binds a subject to an account by its address. */
export interface OidcBindRequest {
  /** The configured provider id. */
  provider: string;
  kind: OidcProviderKind;
  issuer: string;
  /** Microsoft: the object id; others: `sub`. */
  subject: string;
  /** Microsoft tenant id; null for other providers. */
  tenantId: string | null;
  /** The provider-verified address, normalized. */
  email: string;
  /** The account with this address, or null if identkit would create one. */
  account: AccountView | null;
}

export interface OidcOptions {
  /** The providers that may sign in. Ids must be unique. Empty is allowed (import only). */
  providers: OidcProvider[];
  /** Default: the global `fetch`. Tests pass the fake provider's `fetch`. */
  fetch?: OidcFetch;
  /**
   * Shared key cache from `createJwksCache()`. Default: one cache per identkit instance. On
   * Workers, create it at module scope, or every request fetches the keys again.
   */
  jwksCache?: JwksCache;
  /**
   * `one` (default): an account holds at most one link, so an account linked to one provider
   * cannot sign in with another, and a second subject of the same provider does not bind.
   * `any`: an account may hold several links.
   */
  linksPerAccount?: "one" | "any";
  /**
   * Your own rule for a first binding by address. Runs after identkit's rules and can only
   * refuse: return false to refuse (`refused_by_hook`). Must return a boolean; anything else
   * fails the sign-in. Not called when the subject has a link already.
   */
  mayBind?: (request: OidcBindRequest) => boolean | Promise<boolean>;
}

export interface OidcBeginResult {
  /** Redirect the browser here. */
  authorizationUrl: string;
  /**
   * Sealed state, nonce and PKCE verifier. Keep it in a short-lived `__Host-` cookie
   * (`HttpOnly`, `Secure`, `SameSite=Lax`) and pass it to `finish` from the callback.
   */
  transaction: string;
  expiresAt: Date;
}

/** The request or the token was not good. Nothing was bound and no account was touched. */
export type OidcFailure =
  | "invalid_transaction"
  | "transaction_expired"
  | "state_mismatch"
  | "provider_error"
  | "missing_code"
  | "token_request_failed"
  | "keys_unavailable"
  | "invalid_id_token";

/** The token was good, but this subject may not sign in or bind. */
export type OidcRefusal =
  | "organization_not_allowed"
  | "consumer_tenant"
  | "unverified_address"
  | "no_account"
  | "account_disabled"
  | "account_has_link"
  | "refused_by_hook";

export type OidcSignInResult =
  | ({
      status: "signed_in";
      account: AccountView;
      accountCreated: boolean;
      /** True if this sign-in bound the subject to the account. */
      linkCreated: boolean;
    } & IssuedSession)
  | {
      status: "second_factor_required";
      pendingToken: string;
      expiresAt: Date;
      methods: SecondFactorMethod[];
    }
  | { status: "second_factor_unavailable"; reason: "enrolment_required" | "method_not_allowed" }
  | { status: "refused"; reason: OidcRefusal }
  /** `providerError`: the provider's `error` code for `provider_error`, if it was a plain word. */
  | { status: "failed"; reason: OidcFailure; providerError?: string };

/** What a consumer sees of a link. */
export interface OidcLinkView {
  id: string;
  accountId: string;
  provider: OidcProviderKind;
  issuer: string;
  subject: string;
  tenantId: string | null;
  source: OidcLinkSource;
  createdAt: Date;
}

export type OidcImportInput =
  | { accountId: string; provider: "microsoft"; tenantId: string; objectId: string }
  | { accountId: string; provider: "google"; subject: string }
  | { accountId: string; provider: "oidc"; issuer: string; subject: string };

export type OidcImportResult =
  | { status: "imported"; link: OidcLinkView }
  | { status: "already_linked"; link: OidcLinkView }
  /** The subject is linked to another account. Nothing changed. */
  | { status: "linked_elsewhere" }
  /** `linksPerAccount` is `one` and the account has another link. Nothing changed. */
  | { status: "account_has_link" }
  | { status: "no_account" };

export interface Oidc {
  /** Starts a sign-in. Throws `MethodNotAllowedError` unless the policy lists `oidc`. */
  begin(input: { provider: string; loginHint?: string }): Promise<OidcBeginResult>;
  /**
   * Completes a sign-in from the provider's callback: `params` are the query parameters of the
   * redirect, `transaction` the value from `begin`.
   */
  finish(input: {
    transaction: string;
    params: URLSearchParams | Record<string, string | undefined>;
  }): Promise<OidcSignInResult>;
  /**
   * Administrative: records a link for an existing account, so its subject signs in to it.
   * Idempotent. Honours `linksPerAccount`. Takes bare ids; trusts its caller.
   */
  importLink(input: OidcImportInput): Promise<OidcImportResult>;
  /** Administrative: the links of an account. */
  listLinks(accountId: string): Promise<OidcLinkView[]>;
  /**
   * Administrative: removes a link and revokes every session of the account. Returns false if
   * the account has no link with this id; it revokes the sessions also then, so a retry after a
   * failed revocation or session hook completes it. Takes bare ids; trusts its caller.
   */
  removeLink(accountId: string, linkId: string): Promise<boolean>;
}

type Links = NonNullable<IdentkitStore["oidcLinks"]>;

interface Transaction {
  provider: string;
  state: string;
  nonce: string;
  verifier: string;
  expiresAt: number;
}

function toLinkView(link: OidcLinkRecord): OidcLinkView {
  return {
    id: link.id,
    accountId: link.accountId,
    provider: link.provider,
    issuer: link.issuer,
    subject: link.subject,
    tenantId: link.tenantId,
    source: link.source,
    createdAt: link.createdAt,
  };
}

function param(
  params: URLSearchParams | Record<string, string | undefined>,
  name: string,
): string | null {
  if (params instanceof URLSearchParams) return params.get(name);
  const value = params[name];
  return typeof value === "string" ? value : null;
}

function parseTransaction(bytes: Uint8Array): Transaction | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== 1) return null;
  const { p, s, n, c, x } = value;
  if (
    typeof p !== "string" ||
    typeof s !== "string" ||
    typeof n !== "string" ||
    typeof c !== "string" ||
    typeof x !== "number"
  ) {
    return null;
  }
  return { provider: p, state: s, nonce: n, verifier: c, expiresAt: x };
}

/** The service behind `identkit.oidc` when the `oidc` option is missing. */
const notConfigured = () => Promise.reject(new NotConfiguredError("oidc"));

export function unconfiguredOidc(): Oidc {
  return {
    begin: notConfigured,
    finish: notConfigured,
    importLink: notConfigured,
    listLinks: notConfigured,
    removeLink: notConfigured,
  };
}

/** Checks the `oidc` option and the collaborators it needs. Throws before any call is made. */
export function checkOidcOptions(ctx: Context, options: OidcOptions): void {
  if (!ctx.config.oidc) throw new NotConfiguredError("config.oidc");
  if (!ctx.sealer) throw new NotConfiguredError("sealer");
  if (!ctx.store.oidcLinks) throw new NotConfiguredError("store.oidcLinks");
  if (!Array.isArray(options.providers)) {
    throw new InvalidArgumentError("oidc.providers must be an array");
  }
  const ids = new Set<string>();
  for (const provider of options.providers) {
    providerInternals(provider);
    if (ids.has(provider.id))
      throw new InvalidArgumentError(`duplicate provider id ${provider.id}`);
    ids.add(provider.id);
  }
  if (options.jwksCache !== undefined) assertJwksCache(options.jwksCache);
  const limit = options.linksPerAccount ?? "one";
  if (limit !== "one" && limit !== "any") {
    throw new InvalidArgumentError("linksPerAccount must be one or any");
  }
  if (options.mayBind !== undefined && typeof options.mayBind !== "function") {
    throw new InvalidArgumentError("mayBind must be a function");
  }
  if (options.fetch !== undefined && typeof options.fetch !== "function") {
    throw new InvalidArgumentError("fetch must be a function");
  }
}

/** Builds the link key of an import, or throws `InvalidArgumentError`. */
function importIdentity(input: OidcImportInput): Omit<ProviderIdentity, "address"> {
  if (typeof input !== "object" || input === null || typeof input.accountId !== "string") {
    throw new InvalidArgumentError("importLink needs an accountId");
  }
  if (input.accountId === "") {
    throw new InvalidArgumentError("importLink needs an accountId");
  }
  if (input.provider === "microsoft") {
    if (!isGuid(input.tenantId) || !isGuid(input.objectId)) {
      throw new InvalidArgumentError("tenantId and objectId must be GUIDs");
    }
    const tenantId = input.tenantId.toLowerCase();
    const objectId = input.objectId.toLowerCase();
    return {
      kind: "microsoft",
      linkKey: linkKeyOf("microsoft", tenantId, objectId),
      issuer: microsoftIssuer(tenantId),
      subject: objectId,
      tenantId,
    };
  }
  if (input.provider === "google") {
    if (!isValidSubject(input.subject)) throw new InvalidArgumentError("invalid subject");
    return {
      kind: "google",
      linkKey: linkKeyOf("google", input.subject),
      issuer: "https://accounts.google.com",
      subject: input.subject,
      tenantId: null,
    };
  }
  if (input.provider === "oidc") {
    const issuer = requireUrl(input.issuer, "issuer");
    if (!isValidSubject(input.subject)) throw new InvalidArgumentError("invalid subject");
    return {
      kind: "oidc",
      linkKey: linkKeyOf("oidc", issuer, input.subject),
      issuer,
      subject: input.subject,
      tenantId: null,
    };
  }
  throw new InvalidArgumentError("provider must be microsoft, google or oidc");
}

export function createOidc(ctx: Context, internals: SessionInternals, options: OidcOptions): Oidc {
  checkOidcOptions(ctx, options);
  const { store, clock, hasher } = ctx;
  // Checked above; repeated for the type.
  const oidcConfig = ctx.config.oidc;
  const oidcSealer = ctx.sealer;
  const links: Links | undefined = store.oidcLinks;
  if (!oidcConfig || !oidcSealer || !links) throw new NotConfiguredError("oidc");
  const config: NonNullable<typeof oidcConfig> = oidcConfig;
  const sealer: SecretSealer = oidcSealer;
  const linkStore: Links = links;
  const providers = new Map(options.providers.map((p) => [p.id, p]));
  const fetcher: OidcFetch = options.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const cache = options.jwksCache ?? createJwksCache();
  const exclusive = (options.linksPerAccount ?? "one") === "one";
  const mayBind = options.mayBind ?? null;
  const timeoutMs = config.httpTimeoutSeconds * 1000;

  function providerById(id: unknown): { provider: OidcProvider; internal: ProviderInternals } {
    const provider = typeof id === "string" ? providers.get(id) : undefined;
    if (!provider) throw new InvalidArgumentError("unknown OIDC provider");
    return { provider, internal: providerInternals(provider) };
  }

  async function openTransaction(sealed: unknown): Promise<Transaction | null> {
    if (typeof sealed !== "string" || sealed.length === 0 || sealed.length > 4096) return null;
    try {
      return parseTransaction(await sealer.open(sealed, TRANSACTION_CONTEXT));
    } catch {
      return null;
    }
  }

  async function failed(
    provider: string | null,
    reason: OidcFailure,
    providerError?: string,
  ): Promise<OidcSignInResult> {
    await ctx.emit({
      type: "oidc.sign_in_failed",
      ...(provider ? { provider } : {}),
      reason,
    });
    return providerError
      ? { status: "failed", reason, providerError }
      : { status: "failed", reason };
  }

  async function refused(
    provider: string,
    reason: OidcRefusal,
    detail: { binding: boolean; accountId?: string; addressDigest?: string },
  ): Promise<OidcSignInResult> {
    await ctx.emit({
      type: detail.binding ? "oidc.binding_refused" : "oidc.sign_in_failed",
      provider,
      reason,
      ...(detail.accountId ? { accountId: detail.accountId } : {}),
      ...(detail.addressDigest ? { addressDigest: detail.addressDigest } : {}),
    });
    return { status: "refused", reason };
  }

  /** Exchanges the code. Returns the ID token, or null if the provider did not give one. */
  async function exchangeCode(
    provider: OidcProvider,
    internal: ProviderInternals,
    code: string,
    verifier: string,
  ): Promise<string | null> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: provider.redirectUri,
      code_verifier: verifier,
      client_id: provider.clientId,
    });
    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    };
    if (internal.tokenEndpointAuthMethod === "client_secret_basic") {
      // RFC 6749 section 2.3.1: both parts form-encoded before Basic encoding.
      const user = encodeURIComponent(provider.clientId);
      const secret = encodeURIComponent(internal.clientSecret);
      headers["authorization"] = `Basic ${btoa(`${user}:${secret}`)}`;
    } else {
      body.set("client_secret", internal.clientSecret);
    }
    const response = await providerFetch(
      fetcher,
      provider.tokenEndpoint,
      { method: "POST", headers, body: body.toString() },
      timeoutMs,
    );
    const { status, body: json } = await readJson(response, MAX_TOKEN_RESPONSE_BYTES);
    const idToken = json["id_token"];
    if (status !== 200 || typeof idToken !== "string") return null;
    return idToken;
  }

  /** Verifies signature and standard claims. Returns the claims, or a failure reason. */
  async function verifyIdToken(
    provider: OidcProvider,
    internal: ProviderInternals,
    token: string,
    nonce: string,
  ): Promise<Record<string, unknown> | "invalid_id_token" | "keys_unavailable"> {
    const jwt = decodeJwt(token);
    if (!jwt) return "invalid_id_token";
    const { header, payload: claims } = jwt;
    const alg = internal.algorithms.find((a) => a === header["alg"]);
    // `crit` names extensions identkit does not implement; such a token must be refused.
    if (!alg || header["crit"] !== undefined) return "invalid_id_token";
    const kid = header["kid"] === undefined ? null : header["kid"];
    if (kid !== null && typeof kid !== "string") return "invalid_id_token";
    let key: Awaited<ReturnType<typeof findKey>>;
    try {
      key = await findKey(
        cache,
        provider.jwksUri,
        { kid, alg: alg satisfies IdTokenAlgorithm },
        {
          fetch: fetcher,
          now: () => clock.now().getTime(),
          ttlMs: config.jwksCacheSeconds * 1000,
          refetchIntervalMs: config.jwksRefetchIntervalSeconds * 1000,
          timeoutMs,
        },
      );
    } catch (error) {
      if (error instanceof ProviderRequestError) return "keys_unavailable";
      throw error;
    }
    if (!key || !(await verifyJwtSignature(alg, key.key, jwt))) return "invalid_id_token";

    const now = clock.now().getTime() / 1000;
    const skew = config.clockSkewSeconds;
    const aud = claims["aud"];
    const audiences = typeof aud === "string" ? [aud] : Array.isArray(aud) ? aud : [];
    const azp = claims["azp"];
    const { exp, iat, nbf } = claims;
    const valid =
      audiences.includes(provider.clientId) &&
      // OpenID Connect Core 3.1.3.7: with several audiences, azp names the client.
      (audiences.length === 1 || azp !== undefined) &&
      (azp === undefined || azp === provider.clientId) &&
      typeof exp === "number" &&
      now < exp + skew &&
      typeof iat === "number" &&
      iat <= now + skew &&
      (nbf === undefined || (typeof nbf === "number" && nbf <= now + skew)) &&
      typeof claims["nonce"] === "string" &&
      bytesEqual(utf8(claims["nonce"]), utf8(nonce)) &&
      isValidSubject(claims["sub"]);
    return valid ? claims : "invalid_id_token";
  }

  async function signIn(
    provider: OidcProvider,
    account: AccountRecord,
    link: OidcLinkRecord,
    flags: { accountCreated: boolean; linkCreated: boolean },
  ): Promise<OidcSignInResult> {
    const policy = await ctx.getPolicy();
    const result = await completeFirstFactor(ctx, internals, {
      account,
      policy,
      method: "oidc",
      // A sign-in at an external provider is not a step-up identkit can vouch for.
      stepUp: null,
    });
    if (result.status !== "signed_in") return result;
    await ctx.emit({
      type: "oidc.signed_in",
      accountId: account.id,
      sessionId: result.session.id,
      provider: provider.id,
      linkId: link.id,
    });
    return { ...result, ...flags };
  }

  /** Sign-in through an existing link. */
  async function signInByLink(
    provider: OidcProvider,
    link: OidcLinkRecord,
    linkCreated: boolean,
    accountCreated: boolean,
  ): Promise<OidcSignInResult> {
    const account = await store.accounts.findById(link.accountId);
    if (!account || account.status !== "active") {
      return refused(provider.id, "account_disabled", {
        binding: false,
        accountId: link.accountId,
      });
    }
    return signIn(provider, account, link, { accountCreated, linkCreated });
  }

  /** First sign-in of a subject: bind it to the account of its verified address. */
  async function bind(
    provider: OidcProvider,
    identity: ProviderIdentity,
  ): Promise<OidcSignInResult> {
    if (!identity.address.ok) {
      return refused(provider.id, identity.address.reason, { binding: true });
    }
    let email: string;
    try {
      email = normalizeEmail(identity.address.email);
    } catch {
      return refused(provider.id, "unverified_address", { binding: true });
    }
    const addressDigest = await hasher.digest("address", email);
    const existing = await store.accounts.findByEmail(email);
    const detail = {
      binding: true,
      addressDigest,
      ...(existing ? { accountId: existing.id } : {}),
    };
    if (existing && existing.status !== "active") {
      return refused(provider.id, "account_disabled", detail);
    }
    if (existing && exclusive) {
      const accountLinks = await linkStore.listByAccount(existing.id);
      // A concurrent first sign-in of this subject bound it a moment ago: the link decides.
      const own = accountLinks.find((l) => l.linkKey === identity.linkKey);
      if (own) return signInByLink(provider, own, false, false);
      if (accountLinks.length > 0) return refused(provider.id, "account_has_link", detail);
    }
    const policy = await ctx.getPolicy();
    if (!existing && !policy.createAccountOnFirstSignIn) {
      return refused(provider.id, "no_account", detail);
    }
    if (mayBind) {
      const allowed: unknown = await mayBind({
        provider: provider.id,
        kind: identity.kind,
        issuer: identity.issuer,
        subject: identity.subject,
        tenantId: identity.tenantId,
        email,
        account: existing ? toAccountView(existing) : null,
      });
      if (typeof allowed !== "boolean") throw new TypeError("mayBind must return a boolean");
      if (!allowed) return refused(provider.id, "refused_by_hook", detail);
    }

    let account = existing;
    let accountCreated = false;
    if (!account) {
      const record = newAccountRecord(email, clock.now());
      if ((await store.accounts.insert(record)) === "inserted") {
        await ctx.emit({ type: "account.created", accountId: record.id, reason: "first_sign_in" });
        account = record;
        accountCreated = true;
      } else {
        // Another request created the account for this address in the meantime.
        account = await store.accounts.findByEmail(email);
        if (!account || account.status !== "active") {
          return refused(provider.id, "account_disabled", detail);
        }
      }
    }

    const link: OidcLinkRecord = {
      id: randomId(),
      accountId: account.id,
      linkKey: identity.linkKey,
      provider: identity.kind,
      issuer: identity.issuer,
      subject: identity.subject,
      tenantId: identity.tenantId,
      source: "sign_in",
      createdAt: clock.now(),
    };
    const inserted = await linkStore.insert(link, { exclusive });
    if (inserted === "account_has_link") {
      return refused(provider.id, "account_has_link", { ...detail, accountId: account.id });
    }
    if (inserted === "link_taken") {
      // A concurrent sign-in of the same subject bound it first: the link decides.
      const winner = await linkStore.findByKey(identity.linkKey);
      if (!winner) return failed(provider.id, "invalid_transaction");
      return signInByLink(provider, winner, false, accountCreated);
    }
    await ctx.emit({
      type: "oidc.link_created",
      accountId: account.id,
      linkId: link.id,
      provider: provider.id,
    });
    return signIn(provider, account, link, { accountCreated, linkCreated: true });
  }

  return {
    async begin(input) {
      assertMethodAllowed((await ctx.getPolicy()).signInMethods, "oidc");
      const { provider, internal } = providerById(input.provider);
      const loginHint = input.loginHint;
      if (
        loginHint !== undefined &&
        (typeof loginHint !== "string" || loginHint.length > MAX_LOGIN_HINT_LENGTH)
      ) {
        throw new InvalidArgumentError("loginHint must be a string of at most 256 characters");
      }
      const state = randomToken();
      const nonce = randomToken();
      // 43 characters of the unreserved set, as RFC 7636 section 4.1 asks.
      const verifier = randomToken();
      const challenge = toBase64Url(await sha256(utf8(verifier)));
      const expiresAt = addSeconds(clock.now(), config.transactionTtlSeconds);
      const transaction = await sealer.seal(
        utf8(
          JSON.stringify({
            v: 1,
            p: provider.id,
            s: state,
            n: nonce,
            c: verifier,
            x: expiresAt.getTime(),
          }),
        ),
        TRANSACTION_CONTEXT,
      );
      const url = new URL(provider.authorizationEndpoint);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", provider.clientId);
      url.searchParams.set("redirect_uri", provider.redirectUri);
      url.searchParams.set("scope", provider.scopes.join(" "));
      url.searchParams.set("state", state);
      url.searchParams.set("nonce", nonce);
      url.searchParams.set("code_challenge", challenge);
      url.searchParams.set("code_challenge_method", "S256");
      if (internal.prompt !== null) url.searchParams.set("prompt", internal.prompt);
      if (loginHint) url.searchParams.set("login_hint", loginHint);
      return { authorizationUrl: url.toString(), transaction, expiresAt };
    },

    async finish(input) {
      assertMethodAllowed((await ctx.getPolicy()).signInMethods, "oidc");
      const params = input.params;
      if (!(params instanceof URLSearchParams) && !isRecord(params)) {
        throw new InvalidArgumentError("params must be URLSearchParams or an object");
      }
      const transaction = await openTransaction(input.transaction);
      const provider = transaction ? providers.get(transaction.provider) : undefined;
      if (!transaction || !provider) return failed(null, "invalid_transaction");
      const internal = providerInternals(provider);
      if (clock.now().getTime() >= transaction.expiresAt) {
        return failed(provider.id, "transaction_expired");
      }
      const state = param(params, "state");
      if (state === null || !bytesEqual(utf8(state), utf8(transaction.state))) {
        return failed(provider.id, "state_mismatch");
      }
      const error = param(params, "error");
      if (error !== null) {
        return PROVIDER_ERROR.test(error)
          ? failed(provider.id, "provider_error", error)
          : failed(provider.id, "provider_error");
      }
      const code = param(params, "code");
      if (!code) return failed(provider.id, "missing_code");

      let idToken: string | null;
      try {
        idToken = await exchangeCode(provider, internal, code, transaction.verifier);
      } catch (cause) {
        if (cause instanceof ProviderRequestError)
          return failed(provider.id, "token_request_failed");
        throw cause;
      }
      if (idToken === null) return failed(provider.id, "token_request_failed");
      const claims = await verifyIdToken(provider, internal, idToken, transaction.nonce);
      if (typeof claims === "string") return failed(provider.id, claims);

      const identified = internal.identify(claims);
      if (identified.status === "invalid") return failed(provider.id, "invalid_id_token");
      if (identified.status === "organization_not_allowed") {
        return refused(provider.id, "organization_not_allowed", { binding: false });
      }
      const { identity } = identified;
      const link = await linkStore.findByKey(identity.linkKey);
      if (link) return signInByLink(provider, link, false, false);
      return bind(provider, identity);
    },

    async importLink(input) {
      const identity = importIdentity(input);
      const account = await store.accounts.findById(input.accountId);
      if (!account) return { status: "no_account" };
      const settle = async (): Promise<OidcImportResult | null> => {
        const existing = await linkStore.findByKey(identity.linkKey);
        if (!existing) return null;
        return existing.accountId === account.id
          ? { status: "already_linked", link: toLinkView(existing) }
          : { status: "linked_elsewhere" };
      };
      const before = await settle();
      if (before) return before;
      const link: OidcLinkRecord = {
        id: randomId(),
        accountId: account.id,
        linkKey: identity.linkKey,
        provider: identity.kind,
        issuer: identity.issuer,
        subject: identity.subject,
        tenantId: identity.tenantId,
        source: "import",
        createdAt: clock.now(),
      };
      const inserted = await linkStore.insert(link, { exclusive });
      if (inserted === "account_has_link") return { status: "account_has_link" };
      if (inserted === "link_taken") return (await settle()) ?? { status: "linked_elsewhere" };
      await ctx.emit({
        type: "oidc.link_imported",
        accountId: account.id,
        linkId: link.id,
        provider: identity.kind,
      });
      return { status: "imported", link: toLinkView(link) };
    },

    async listLinks(accountId) {
      return (await linkStore.listByAccount(accountId)).map(toLinkView);
    },

    async removeLink(accountId, linkId) {
      const found = (await linkStore.listByAccount(accountId)).find((l) => l.id === linkId);
      const removed = found ? await linkStore.delete(linkId, accountId) : false;
      const removedEvent = found
        ? ({ type: "oidc.link_removed", accountId, linkId, provider: found.provider } as const)
        : null;
      // Sessions before the audit event, so a failing sink cannot leave sessions of the removed
      // subject. Always, also when the link is gone: a retry must still reach the revocation
      // and the session hook.
      let runHook: () => Promise<void>;
      try {
        ({ runHook } = await internals.revokeAllDeferringHook(accountId));
      } catch (error) {
        // A retry finds no link and cannot record the removal any more.
        if (removed && removedEvent) await ctx.emit(removedEvent).catch(() => undefined);
        throw error;
      }
      if (removed && removedEvent) await ctx.emit(removedEvent);
      // Last: a throwing hook must not skip the audit event.
      await runHook();
      return removed;
    },
  };
}
