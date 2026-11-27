import { toAccountView } from "../accounts.js";
import type { AuditEvent } from "../audit.js";
import { bytesEqual, sha256, toBase64Url, utf8 } from "../bytes.js";
import { addSeconds } from "../clock.js";
import type { Context } from "../context.js";
import { digestsEqual, randomId, randomToken } from "../crypto.js";
import { InvalidArgumentError, OperationRolledBackError } from "../errors.js";
import { isRecord } from "../oidc-jwt.js";
import type {
  OAuthAccessTokenRecord,
  OAuthClientRecord,
  OAuthGrantLookup,
  OAuthGrantRecord,
} from "../storage/types.js";
import { authenticateClient } from "./client-auth.js";
import {
  admits,
  endpointResult,
  errorResult,
  readParams,
  toClientView,
  type OAuthEndpointResult,
  type OAuthInternals,
  type OAuthParams,
} from "./common.js";
import { SCOPE } from "./options.js";

const DAY_SECONDS = 86_400;
/** Characters after the prefix: base64url of 32 random bytes. */
const TOKEN_BODY = /^[A-Za-z0-9_-]{43}$/;
/** A refresh token after its prefix: the grant's ref (16 bytes), a dot, the secret (32 bytes). */
const REFRESH_BODY = /^([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/;
/** RFC 7636 section 4.1: 43 to 128 unreserved characters. */
const CODE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

/** Why `oauth.token_failed` was recorded. */
export type OAuthTokenFailure =
  | "code_unknown"
  | "code_expired"
  | "client_mismatch"
  | "redirect_mismatch"
  | "pkce_failed"
  | "resource_mismatch"
  | "refresh_unknown"
  | "refresh_raced"
  | "refused_by_policy"
  | "account_disabled"
  | "grant_limit";

/** Why a grant ended, in `oauth.grant_ended`. */
export type OAuthGrantEndReason =
  | "revoked_by_client"
  | "revoked"
  | "revoked_all"
  | "account_disabled"
  | "replaced"
  | "code_reuse"
  | "refresh_reuse"
  | "expired";

/**
 * `malformed`: not a string of the access token format; no read was made. `unknown`: no live
 * token has this digest; this includes every token of a grant that ended, because ending a
 * grant deletes its tokens. `wrong_resource`: the grant is for another resource than the one
 * asked for, or for one that is no longer configured. `no_allowed_scope`: none of the token's
 * scopes is configured any more.
 */
export type OAuthAccessTokenRefusal =
  | "malformed"
  | "unknown"
  | "expired"
  | "grant_expired"
  | "account_disabled"
  | "wrong_resource"
  | "no_allowed_scope";

export type ValidateAccessTokenResult =
  | {
      status: "valid";
      accountId: string;
      clientId: string;
      grantId: string;
      /**
       * The token's scopes that the options still list, in stored order. Opaque strings: your
       * code decides what each one allows.
       */
      scopes: string[];
      resource: string;
      expiresAt: Date;
    }
  | { status: "refused"; reason: OAuthAccessTokenRefusal };

const invalidGrant = (description: string) => errorResult(400, "invalid_grant", description);

function shapedAs(value: unknown, prefix: string): value is string {
  return (
    typeof value === "string" &&
    value.length === prefix.length + 43 &&
    value.startsWith(prefix) &&
    TOKEN_BODY.test(value.slice(prefix.length))
  );
}

/** The ref of an identkit refresh token, or null if the string has another shape. */
export function refreshRef(value: unknown, prefix: string): string | null {
  if (typeof value !== "string" || !value.startsWith(prefix)) return null;
  return REFRESH_BODY.exec(value.slice(prefix.length))?.[1] ?? null;
}

const earlier = (a: Date, b: Date) => (a.getTime() <= b.getTime() ? a : b);

/**
 * Ends every OAuth grant of the account, and its codes, if the store has OAuth, also when the
 * `oauth` option is not set (grants from an earlier configuration must end too). Returns the
 * ended grants.
 */
export async function endAllOAuthGrants(
  ctx: Context,
  accountId: string,
): Promise<OAuthGrantRecord[]> {
  const store = ctx.store.oauth;
  if (!store) return [];
  return store.deleteGrantsForAccount(accountId);
}

/**
 * Records `oauth.grant_ended` for each grant. A throwing sink does not skip the other events;
 * the first error goes up after all of them.
 */
export async function emitOAuthGrantsEnded(
  ctx: Context,
  accountId: string,
  grants: readonly OAuthGrantRecord[],
  reason: OAuthGrantEndReason,
): Promise<void> {
  let failure: { error: unknown } | null = null;
  for (const grant of grants) {
    try {
      await ctx.emit({
        type: "oauth.grant_ended",
        accountId,
        clientId: grant.clientId,
        grantId: grant.id,
        reason,
      });
    } catch (error) {
      failure ??= { error };
    }
  }
  if (failure) throw failure.error;
}

function tokenResponse(
  accessToken: string,
  record: OAuthAccessTokenRecord,
  refreshToken: string | null,
  now: Date,
): OAuthEndpointResult {
  return endpointResult(200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.max(0, Math.floor((record.expiresAt.getTime() - now.getTime()) / 1000)),
    ...(refreshToken === null ? {} : { refresh_token: refreshToken }),
    scope: record.scopes.join(" "),
  });
}

function requireInput(input: unknown, call: string): { form: unknown; authorization: unknown } {
  if (!isRecord(input)) throw new InvalidArgumentError(`${call} needs { form, authorization }`);
  return { form: input["form"], authorization: input["authorization"] ?? null };
}

export function createTokenEndpoint(internals: OAuthInternals) {
  const { ctx, settings, store } = internals;
  const { hasher, clock } = ctx;
  const knownScopes = new Set(settings.knownScopes);

  const failed = async (client: OAuthClientRecord, reason: OAuthTokenFailure) => {
    await ctx.emit({ type: "oauth.token_failed", clientId: client.id, reason });
  };

  const grantEnded = (grant: OAuthGrantRecord, reason: OAuthGrantEndReason) =>
    emitOAuthGrantsEnded(ctx, grant.accountId, [grant], reason);

  /**
   * Records `oauth.token_refreshed`, best effort: the rotation is written already. If a refused
   * event failed the call, the client would keep its old refresh token, which is now the
   * previous one, and its next refresh after the grace would end the grant.
   */
  async function emitRefreshed(event: Omit<AuditEvent, "at">): Promise<void> {
    const full: AuditEvent = { ...event, at: clock.now() };
    try {
      await ctx.emit(full);
    } catch (error) {
      try {
        await settings.onAuditError?.(error, full);
      } catch {
        // Dropped: the handler is a report channel, not a gate.
      }
    }
  }

  /** Writes `lastUsedAt` of the client at most once a day. */
  async function markUsed(client: OAuthClientRecord, now: Date): Promise<void> {
    const notAfter = addSeconds(now, -DAY_SECONDS);
    if (client.lastUsedAt === null || client.lastUsedAt.getTime() <= notAfter.getTime()) {
      await store.markClientUsed(client.id, now, notAfter);
    }
  }

  /** True if the client gets refresh tokens under the option `refreshTokens`. */
  const getsRefreshTokens = (client: OAuthClientRecord) =>
    settings.refreshTokens === "always" || client.grantTypes.includes("refresh_token");

  /** A new refresh token for the grant's ref. */
  async function newRefreshToken(ref: string) {
    const token = `${settings.prefixes.refreshToken}${ref}.${randomToken()}`;
    return { token, digest: await hasher.digest("oauth-refresh-token", token) };
  }

  /** A new access token row of the grant. */
  async function newAccessToken(
    grant: OAuthGrantRecord,
    generation: number,
    scopes: string[],
    now: Date,
  ): Promise<{ token: string; record: OAuthAccessTokenRecord }> {
    const token = `${settings.prefixes.accessToken}${randomToken()}`;
    return {
      token,
      record: {
        digest: await hasher.digest("oauth-access-token", token),
        grantId: grant.id,
        generation,
        scopes,
        createdAt: now,
        expiresAt: earlier(addSeconds(now, settings.accessTokenSeconds), grant.expiresAt),
      },
    };
  }

  /** The account of the grant, if it is active and the policy admits it. */
  async function admitted(
    client: OAuthClientRecord,
    accountId: string,
    phase: "token" | "refresh",
    scopes: string[],
  ): Promise<"account_disabled" | "refused_by_policy" | null> {
    const account = await ctx.store.accounts.findById(accountId);
    if (!account || account.status !== "active") return "account_disabled";
    const allowed = await admits(internals, {
      phase,
      account: toAccountView(account),
      client: toClientView(client),
      scopes: [...scopes],
    });
    return allowed ? null : "refused_by_policy";
  }

  async function exchangeCode(
    client: OAuthClientRecord,
    params: Map<string, string>,
  ): Promise<OAuthEndpointResult> {
    if (!client.grantTypes.includes("authorization_code")) {
      return errorResult(400, "unauthorized_client", "The client may not use this grant type.");
    }
    const code = params.get("code");
    const redirectUri = params.get("redirect_uri");
    const verifier = params.get("code_verifier");
    if (code === undefined || redirectUri === undefined || verifier === undefined) {
      return errorResult(
        400,
        "invalid_request",
        "code, redirect_uri and code_verifier are required.",
      );
    }
    if (!shapedAs(code, settings.prefixes.code)) {
      await failed(client, "code_unknown");
      return invalidGrant("The authorization code is invalid.");
    }
    const codeDigest = await hasher.digest("oauth-code", code);
    // The code goes on the first attempt, also on a failed one, so a guess burns it.
    const record = await store.consumeCode(codeDigest);
    if (!record) {
      // A code that comes back after its exchange was copied: its grant ends (RFC 6749 4.1.2).
      const ended = await store.endGrantByCode(codeDigest);
      if (ended) await grantEnded(ended, "code_reuse");
      else await failed(client, "code_unknown");
      return invalidGrant("The authorization code is invalid.");
    }
    const now = clock.now();
    let failure: OAuthTokenFailure | null = null;
    if (now.getTime() >= record.expiresAt.getTime()) failure = "code_expired";
    else if (record.clientId !== client.id) failure = "client_mismatch";
    else if (record.redirectUri !== redirectUri) failure = "redirect_mismatch";
    else if (
      !CODE_VERIFIER.test(verifier) ||
      !bytesEqual(utf8(toBase64Url(await sha256(utf8(verifier)))), utf8(record.codeChallenge))
    ) {
      failure = "pkce_failed";
    }
    if (failure !== null) {
      await failed(client, failure);
      return invalidGrant("The authorization code is invalid.");
    }
    const resource = params.get("resource");
    if (resource !== undefined && resource !== record.resource) {
      await failed(client, "resource_mismatch");
      return errorResult(400, "invalid_target", "The resource differs from the authorization.");
    }
    const refusal = await admitted(client, record.accountId, "token", record.scopes);
    if (refusal !== null) {
      await failed(client, refusal);
      return invalidGrant("The grant is not allowed.");
    }

    const withRefresh = getsRefreshTokens(client);
    const ref = randomId();
    const refresh = withRefresh ? await newRefreshToken(ref) : null;
    const grant: OAuthGrantRecord = {
      id: randomId(),
      accountId: record.accountId,
      clientId: client.id,
      scopes: [...record.scopes],
      resource: record.resource,
      createdAt: now,
      expiresAt: addSeconds(now, settings.grantSeconds),
      generation: 1,
      refreshRefDigest: refresh === null ? null : await hasher.digest("oauth-refresh-ref", ref),
      refreshDigest: refresh?.digest ?? null,
      refreshDigestAlgorithm: refresh === null ? null : "hmac-sha256",
      previousRefreshDigest: null,
      refreshedAt: null,
      refreshExpiresAt: null,
      codeDigest,
      source: "created",
    };
    grant.refreshExpiresAt =
      refresh === null
        ? null
        : earlier(addSeconds(now, settings.refreshTokenSeconds), grant.expiresAt);
    const access = await newAccessToken(grant, 1, grant.scopes, now);
    const inserted = await store.insertGrant(grant, access.record, {
      maxOtherGrants: settings.maxGrantsPerAccount,
      at: now,
    });
    if (inserted.status !== "inserted") {
      const reason = inserted.status === "limit_reached" ? "grant_limit" : "account_disabled";
      await failed(client, reason);
      return invalidGrant(
        reason === "grant_limit"
          ? "The account has too many connected applications."
          : "The grant is not allowed.",
      );
    }
    try {
      // The replaced grant (the account's earlier grant of this client) ended in the insert.
      // Its event comes first, so it is recorded also if the new grant is rolled back.
      if (inserted.replaced) await grantEnded(inserted.replaced, "replaced");
      await ctx.emit({
        type: "oauth.grant_created",
        accountId: grant.accountId,
        clientId: client.id,
        grantId: grant.id,
        scopes: [...grant.scopes],
      });
    } catch (error) {
      // No grant stands without its audit record. The replaced grant stays ended: its tokens
      // are deleted and cannot come back. If the delete fails, its error goes up and the new
      // grant stands, unusable: its tokens were never returned.
      await store.deleteGrant(grant.id, { clientId: client.id });
      throw new OperationRolledBackError(grant.accountId, { cause: error, hookFailed: false });
    }
    await markUsed(client, now);
    return tokenResponse(access.token, access.record, refresh?.token ?? null, now);
  }

  /**
   * Rotates the grant for a presented refresh token: `presented.ref` is its fixed part, which
   * the new token keeps, and `presented.digest` the digest of the whole token. `lookup` is the
   * grant that the ref names.
   */
  async function refreshGrant(
    client: OAuthClientRecord,
    lookup: OAuthGrantLookup,
    presented: { ref: string; digest: string },
    requestedScopes: string[] | null,
  ): Promise<OAuthEndpointResult> {
    const presentedDigest = presented.digest;
    const { grant } = lookup;
    // A token of another client ends nothing: that client cannot prove it holds the grant.
    if (grant.clientId !== client.id) {
      await failed(client, "client_mismatch");
      return invalidGrant("The refresh token is invalid.");
    }
    const now = clock.now();
    const current =
      grant.refreshDigest !== null &&
      grant.refreshDigestAlgorithm === "hmac-sha256" &&
      digestsEqual(grant.refreshDigest, presentedDigest);
    if (!current) {
      const previous =
        grant.previousRefreshDigest !== null &&
        digestsEqual(grant.previousRefreshDigest, presentedDigest);
      const graceEnd =
        grant.refreshedAt === null
          ? null
          : addSeconds(grant.refreshedAt, settings.refreshRaceGraceSeconds);
      if (previous && graceEnd !== null && now.getTime() < graceEnd.getTime()) {
        // A parallel refresh of the same client: refused, but the grant lives.
        await failed(client, "refresh_raced");
        return invalidGrant("The refresh token was already used.");
      }
      // An older token of this grant: a copy is in other hands. End the grant (RFC 9700 4.14.2).
      const ended = await store.deleteGrant(grant.id, { clientId: client.id });
      if (ended) await grantEnded(ended, "refresh_reuse");
      return invalidGrant("The refresh token is invalid.");
    }
    if (
      now.getTime() >= grant.expiresAt.getTime() ||
      (grant.refreshExpiresAt !== null && now.getTime() >= grant.refreshExpiresAt.getTime())
    ) {
      const ended = await store.deleteGrant(grant.id, { clientId: client.id });
      if (ended) await grantEnded(ended, "expired");
      return invalidGrant("The refresh token has expired.");
    }
    if (lookup.accountStatus !== "active") {
      await failed(client, "account_disabled");
      return invalidGrant("The grant is not allowed.");
    }
    if (requestedScopes !== null && !requestedScopes.every((s) => grant.scopes.includes(s))) {
      return errorResult(400, "invalid_scope", "The scope exceeds the grant.");
    }
    // The policy may refuse; the grant then stays, as a personal token would.
    const refusal = await admitted(client, grant.accountId, "refresh", grant.scopes);
    if (refusal !== null) {
      await failed(client, refusal);
      return invalidGrant("The grant is not allowed.");
    }
    const refDigest = grant.refreshRefDigest;
    if (refDigest === null) return invalidGrant("The refresh token is invalid.");
    const refresh = await newRefreshToken(presented.ref);
    const generation = grant.generation + 1;
    const scopes = requestedScopes ?? grant.scopes;
    const access = await newAccessToken(grant, generation, [...scopes], now);
    const won = await store.rotateGrant(
      grant.id,
      grant.generation,
      {
        generation,
        refreshRefDigest: refDigest,
        refreshDigest: refresh.digest,
        refreshDigestAlgorithm: "hmac-sha256",
        previousRefreshDigest: grant.refreshDigest,
        refreshedAt: now,
        refreshExpiresAt: earlier(addSeconds(now, settings.refreshTokenSeconds), grant.expiresAt),
      },
      access.record,
      now,
    );
    if (!won) {
      await failed(client, "refresh_raced");
      return invalidGrant("The refresh token was already used.");
    }
    await emitRefreshed({
      type: "oauth.token_refreshed",
      accountId: grant.accountId,
      clientId: client.id,
      grantId: grant.id,
    });
    await markUsed(client, now);
    return tokenResponse(access.token, access.record, refresh.token, now);
  }

  async function refreshByToken(
    client: OAuthClientRecord,
    params: Map<string, string>,
  ): Promise<OAuthEndpointResult> {
    if (!getsRefreshTokens(client)) {
      return errorResult(400, "unauthorized_client", "The client may not use this grant type.");
    }
    const token = params.get("refresh_token");
    if (token === undefined) {
      return errorResult(400, "invalid_request", "refresh_token is required.");
    }
    const scopeParam = params.get("scope");
    let requestedScopes: string[] | null = null;
    if (scopeParam !== undefined) {
      requestedScopes = scopeParam.split(" ");
      if (!requestedScopes.every((s) => SCOPE.test(s))) {
        return errorResult(400, "invalid_scope", "The scope is malformed.");
      }
    }
    const ref = refreshRef(token, settings.prefixes.refreshToken);
    if (ref === null) {
      await failed(client, "refresh_unknown");
      return invalidGrant("The refresh token is invalid.");
    }
    const lookup = await store.findGrantByRefreshRef(await hasher.digest("oauth-refresh-ref", ref));
    if (!lookup) {
      await failed(client, "refresh_unknown");
      return invalidGrant("The refresh token is invalid.");
    }
    return refreshGrant(
      client,
      lookup,
      { ref, digest: await hasher.digest("oauth-refresh-token", token) },
      requestedScopes,
    );
  }

  return {
    async token(input: {
      form: OAuthParams;
      authorization: string | null;
    }): Promise<OAuthEndpointResult> {
      const { form, authorization } = requireInput(input, "token");
      const params = readParams(form);
      if (!params) {
        return errorResult(400, "invalid_request", "A parameter was sent more than once.");
      }
      const authenticated = await authenticateClient(internals, params, authorization);
      if (authenticated.error) return authenticated.error;
      const { client } = authenticated;
      const grantType = params.get("grant_type");
      if (grantType === undefined) {
        return errorResult(400, "invalid_request", "grant_type is required.");
      }
      if (grantType === "authorization_code") return exchangeCode(client, params);
      if (grantType === "refresh_token") return refreshByToken(client, params);
      return errorResult(400, "unsupported_grant_type", "The grant type is not supported.");
    },

    async revoke(input: {
      form: OAuthParams;
      authorization: string | null;
    }): Promise<OAuthEndpointResult> {
      const { form, authorization } = requireInput(input, "revoke");
      const params = readParams(form);
      if (!params) {
        return errorResult(400, "invalid_request", "A parameter was sent more than once.");
      }
      const authenticated = await authenticateClient(internals, params, authorization);
      if (authenticated.error) return authenticated.error;
      const { client } = authenticated;
      const token = params.get("token");
      if (token === undefined) return errorResult(400, "invalid_request", "token is required.");
      let grantId: string | null = null;
      if (shapedAs(token, settings.prefixes.accessToken)) {
        const found = await store.findAccessToken(await hasher.digest("oauth-access-token", token));
        if (found) grantId = found.grant.id;
      } else {
        const ref = refreshRef(token, settings.prefixes.refreshToken);
        if (ref !== null) {
          const found = await store.findGrantByRefreshRef(
            await hasher.digest("oauth-refresh-ref", ref),
          );
          if (found) grantId = found.grant.id;
        }
      }
      // Scoped to the authenticated client: a token of another client ends nothing. The answer
      // is 200 either way (RFC 7009 section 2.2).
      if (grantId !== null) {
        const ended = await store.deleteGrant(grantId, { clientId: client.id });
        if (ended) await grantEnded(ended, "revoked_by_client");
      }
      return endpointResult(200, null);
    },

    async validateAccessToken(
      token: string,
      options?: { resource?: string },
    ): Promise<ValidateAccessTokenResult> {
      const wanted = options?.resource;
      if (wanted !== undefined && !settings.resources.includes(wanted)) {
        throw new InvalidArgumentError("resource must be one of the configured resources");
      }
      if (!shapedAs(token, settings.prefixes.accessToken)) {
        return { status: "refused", reason: "malformed" };
      }
      const digest = await hasher.digest("oauth-access-token", token);
      const found = await store.findAccessToken(digest);
      // The read matched by digest; compare again in constant time, as `apiTokens.verify` does.
      if (!found || !digestsEqual(found.token.digest, digest)) {
        return { status: "refused", reason: "unknown" };
      }
      const now = clock.now().getTime();
      const { token: record, grant, accountStatus } = found;
      if (now >= record.expiresAt.getTime()) return { status: "refused", reason: "expired" };
      if (now >= grant.expiresAt.getTime()) return { status: "refused", reason: "grant_expired" };
      if (accountStatus !== "active") return { status: "refused", reason: "account_disabled" };
      if (
        !settings.resources.includes(grant.resource) ||
        (wanted !== undefined && grant.resource !== wanted)
      ) {
        return { status: "refused", reason: "wrong_resource" };
      }
      // Fewer rights, never more: a scope the options no longer list is dropped.
      const scopes = record.scopes.filter((s) => knownScopes.has(s));
      if (scopes.length === 0) return { status: "refused", reason: "no_allowed_scope" };
      return {
        status: "valid",
        accountId: grant.accountId,
        clientId: grant.clientId,
        grantId: grant.id,
        scopes,
        resource: grant.resource,
        expiresAt: record.expiresAt,
      };
    },
  };
}
