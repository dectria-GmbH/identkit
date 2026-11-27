import type { Context } from "../context.js";
import { InvalidArgumentError, NotConfiguredError } from "../errors.js";
import { addSeconds } from "../clock.js";
import {
  requireId,
  toClientView,
  utcDayStart,
  type OAuthEndpointResult,
  type OAuthInternals,
  type OAuthParams,
} from "./common.js";
import {
  createMetadata,
  wwwAuthenticate,
  type OAuthMetadata,
  type WwwAuthenticateInput,
} from "./metadata.js";
import {
  parseOAuthOptions,
  prefixesOverlap,
  type OAuthClientView,
  type OAuthOptions,
} from "./options.js";
import {
  createImport,
  type ImportOAuthClientInput,
  type ImportOAuthClientResult,
  type ImportOAuthGrantInput,
  type ImportOAuthGrantResult,
} from "./import.js";
import { createRegister } from "./register.js";
import { createAuthorize, type OAuthAuthorize } from "./authorize.js";
import {
  createTokenEndpoint,
  emitOAuthGrantsEnded,
  endAllOAuthGrants,
  type ValidateAccessTokenResult,
} from "./token.js";
import type { OAuthGrantRecord } from "../storage/types.js";

export type {
  AuthorizeBeginResult,
  AuthorizeDecisionResult,
  AuthorizeError,
  AuthorizeRefusal,
  OAuthAuthorize,
} from "./authorize.js";
export type { OAuthEndpointResult, OAuthParams } from "./common.js";
export type {
  ImportOAuthClientInput,
  ImportOAuthClientResult,
  ImportOAuthGrantInput,
  ImportOAuthGrantResult,
} from "./import.js";
export {
  emitOAuthGrantsEnded,
  endAllOAuthGrants,
  type OAuthAccessTokenRefusal,
  type OAuthGrantEndReason,
  type OAuthTokenFailure,
  type ValidateAccessTokenResult,
} from "./token.js";

/** What `oauth.purge` removed. */
export interface OAuthPurgeResult {
  /** Clients deleted as unused or idle. */
  clients: number;
  /** Grants past their absolute end. */
  grants: number;
  codes: number;
  accessTokens: number;
  /** Registration counts of earlier UTC days. */
  registrationWindows: number;
}

/** What a consumer sees of a grant. Never contains a token or a digest. */
export interface OAuthGrantView {
  id: string;
  accountId: string;
  clientId: string;
  scopes: string[];
  resource: string;
  createdAt: Date;
  expiresAt: Date;
  /** The last refresh, or null. */
  refreshedAt: Date | null;
  source: "created" | "import";
}

function toGrantView(grant: OAuthGrantRecord): OAuthGrantView {
  return {
    id: grant.id,
    accountId: grant.accountId,
    clientId: grant.clientId,
    scopes: [...grant.scopes],
    resource: grant.resource,
    createdAt: grant.createdAt,
    expiresAt: grant.expiresAt,
    refreshedAt: grant.refreshedAt,
    source: grant.source,
  };
}
export type { OAuthMetadata, WwwAuthenticateInput } from "./metadata.js";
export {
  oauthOptionsSchema,
  type OAuthAdmitHook,
  type OAuthAdmitRequest,
  type OAuthAuditErrorHandler,
  type OAuthClientView,
  type OAuthLegacyAccessTokenVerifier,
  type OAuthLegacyRefreshTokenVerifier,
  type OAuthOptions,
  type OAuthStoreErrorHandler,
} from "./options.js";

/**
 * An OAuth 2.1 authorization server for MCP clients: discovery documents, dynamic client
 * registration, the authorization step, the token and revocation endpoints and the access token
 * check. identkit makes every security decision; your code routes, reads bodies, renders the
 * consent page and writes responses. Administrative calls take bare ids and trust their caller.
 */
export interface OAuth {
  metadata: OAuthMetadata;
  /** The value of `WWW-Authenticate` for a 401 or 403 of the protected resource. */
  wwwAuthenticate(input: WwwAuthenticateInput): string;
  /**
   * Dynamic client registration (RFC 7591). `body` is the raw request body; cap its size before
   * you read it. `addressKey` identifies the caller for the per-address limit (for example the
   * IPv4 address or the IPv6 /64); without it, only the deployment limit applies.
   */
  register(input: { body: string; addressKey?: string }): Promise<OAuthEndpointResult>;
  /** The authorization endpoint: check the request, then the person's approval or denial. */
  authorize: OAuthAuthorize;
  /**
   * The token endpoint: code exchange and refresh. Pass the form as `URLSearchParams` and the
   * raw `Authorization` header value (or null). Rate-limit this route yourself.
   */
  token(input: { form: OAuthParams; authorization: string | null }): Promise<OAuthEndpointResult>;
  /**
   * Token revocation (RFC 7009): ends the grant of an access or refresh token of the calling
   * client. Always 200 with an empty body once the client is authenticated.
   */
  revoke(input: { form: OAuthParams; authorization: string | null }): Promise<OAuthEndpointResult>;
  /**
   * Checks an access token on every request of the protected resource: one read, no write, no
   * event. Pass `resource` to accept only tokens for it. Apply your own per-request policy to
   * the returned account and scopes afterwards.
   */
  validateAccessToken(
    token: string,
    options?: { resource?: string },
  ): Promise<ValidateAccessTokenResult>;
  /** Administrative: the account's live grants, oldest first. */
  listGrants(accountId: string): Promise<OAuthGrantView[]>;
  /** Administrative: ends the grant of the account. Returns true if this call ended it. */
  revokeGrant(input: { accountId: string; grantId: string }): Promise<boolean>;
  /** Administrative: ends every grant of the account. Returns how many this call ended. */
  revokeAll(accountId: string): Promise<number>;
  /** Administrative: the client, or null. */
  getClient(clientId: string): Promise<OAuthClientView | null>;
  /**
   * Administrative: deletes the client with its grants and codes; every token of it stops.
   * Records `oauth.client_deleted`, then `oauth.grant_ended` (reason `client_deleted`) for each
   * ended grant. Returns true if this call deleted it. If the sink refuses an event, the deletion
   * stands, every other event is still sent, and the first error goes up.
   */
  deleteClient(clientId: string): Promise<boolean>;
  /**
   * Administrative: records a client of an earlier system. Idempotent: the same input again
   * answers `already_imported`, and an imported client that was deleted since answers
   * `revoked`. It applies the redirect URI rules of registration, not
   * `registration.allowedAuthMethods`: an administrative import may bring a public client also
   * where registration allows only confidential ones. Records `oauth.client_imported`; if the
   * sink refuses it, the client is deleted again (without a tombstone, so a retry imports) and
   * the call throws `OAuthClientRolledBackError`. A concurrent identical import may answer
   * `already_imported` for a client that the other call then rolls back; run imports one at a
   * time.
   */
  importClient(input: ImportOAuthClientInput): Promise<ImportOAuthClientResult>;
  /**
   * Administrative: records a grant of an earlier system, so that its legacy tokens keep
   * working through the option `legacy`. Never replaces a grant. Idempotent, and an imported
   * grant that ended since answers `revoked`: it never comes back. Records
   * `oauth.grant_imported`; if the sink refuses it, the grant is deleted again (without a
   * tombstone, so a retry imports) and the call throws `OperationRolledBackError`.
   */
  importGrant(input: ImportOAuthGrantInput): Promise<ImportOAuthGrantResult>;
  /**
   * Administrative: deletes expired grants, codes and access tokens, registration counts of
   * earlier days, and clients by `clientRetention`: never used and older than `unusedDays`, or
   * last used more than `idleDays` ago. Never deletes a client that holds a live grant or code;
   * an approval counts as use, so from the approval on a client in the middle of a flow stays
   * (before it, `approve` answers `invalid_ticket` for a purged client). Records
   * `oauth.grant_ended` (reason `expired`) for each grant and `oauth.client_deleted` (reason
   * `unused` or `idle`) for each client. The deletions stand if the sink refuses an event; every
   * other event is still sent, and the first error goes up. Run it on a schedule, for example
   * daily.
   */
  purge(): Promise<OAuthPurgeResult>;
}

const fail = (): never => {
  throw new NotConfiguredError("oauth");
};
const reject = () => Promise.reject(new NotConfiguredError("oauth"));

/** The service behind `identkit.oauth` when the `oauth` option is missing. */
export function unconfiguredOAuth(): OAuth {
  return {
    metadata: {
      authorizationServer: fail,
      protectedResource: fail,
      protectedResourcePath: fail,
      authorizationServerPath: fail,
    },
    wwwAuthenticate: fail,
    register: reject,
    authorize: { begin: reject, approve: reject, deny: reject },
    token: reject,
    revoke: reject,
    validateAccessToken: reject,
    listGrants: reject,
    revokeGrant: reject,
    revokeAll: reject,
    getClient: reject,
    deleteClient: reject,
    importClient: reject,
    importGrant: reject,
    purge: reject,
  };
}

/**
 * Checks the `oauth` option, the sealer and the store, and that no OAuth prefix overlaps the
 * API token prefix. Throws before any call is made.
 */
export function createOAuth(
  ctx: Context,
  options: OAuthOptions,
  apiTokenPrefix: string | null,
): OAuth {
  const settings = parseOAuthOptions(options);
  if (!ctx.sealer) throw new NotConfiguredError("sealer");
  const store = ctx.store.oauth;
  if (!store) throw new NotConfiguredError("store.oauth");
  if (
    apiTokenPrefix !== null &&
    Object.values(settings.prefixes).some((p) => prefixesOverlap([p, apiTokenPrefix]))
  ) {
    throw new InvalidArgumentError("oauth: prefixes must not overlap apiTokens.prefix");
  }
  const internals: OAuthInternals = {
    ctx,
    settings,
    store,
    sealer: ctx.sealer,
    apiTokenPrefix,
  };

  return {
    metadata: createMetadata(settings),
    wwwAuthenticate: (input) => wwwAuthenticate(settings, input),
    register: createRegister(internals),
    authorize: createAuthorize(internals),
    ...createTokenEndpoint(internals),
    ...createImport(internals),

    async listGrants(accountId) {
      requireId(accountId, "accountId");
      return (await store.listGrants(accountId, ctx.clock.now())).map(toGrantView);
    },

    async revokeGrant(input) {
      if (typeof input !== "object" || input === null) {
        throw new InvalidArgumentError("revokeGrant needs { accountId, grantId }");
      }
      const accountId = requireId(input.accountId, "accountId");
      const grantId = requireId(input.grantId, "grantId");
      const ended = await store.deleteGrant(grantId, { accountId }, ctx.clock.now());
      // The event after the delete: a refused event undoes no revocation.
      if (ended) await emitOAuthGrantsEnded(ctx, accountId, [ended], "revoked");
      return ended !== null;
    },

    async revokeAll(accountId) {
      requireId(accountId, "accountId");
      const ended = await endAllOAuthGrants(ctx, accountId);
      await emitOAuthGrantsEnded(ctx, accountId, ended, "revoked_all");
      return ended.length;
    },

    async purge() {
      const now = ctx.clock.now();
      const day = 86_400;
      const { unusedDays, idleDays } = settings.clientRetention;
      const removed = await store.purge({
        at: now,
        unusedBefore: addSeconds(now, -unusedDays * day),
        idleBefore: addSeconds(now, -idleDays * day),
        // Only the current UTC day counts registrations.
        windowBefore: utcDayStart(now),
      });
      // The events after the deletes: a refused event undoes nothing. A throwing sink does not
      // skip the other events; the first error goes up after all of them.
      let failure: { error: unknown } | null = null;
      for (const grant of removed.grants) {
        try {
          await emitOAuthGrantsEnded(ctx, grant.accountId, [grant], "expired");
        } catch (error) {
          failure ??= { error };
        }
      }
      for (const client of removed.clients) {
        try {
          await ctx.emit({
            type: "oauth.client_deleted",
            clientId: client.id,
            reason: client.reason,
          });
        } catch (error) {
          failure ??= { error };
        }
      }
      if (failure) throw failure.error;
      return {
        clients: removed.clients.length,
        grants: removed.grants.length,
        codes: removed.codes,
        accessTokens: removed.accessTokens,
        registrationWindows: removed.registrationWindows,
      };
    },

    async getClient(clientId) {
      const found = await store.findClient(requireId(clientId, "clientId"));
      return found ? toClientView(found) : null;
    },

    async deleteClient(clientId) {
      requireId(clientId, "clientId");
      const ended = await store.deleteClient(clientId, ctx.clock.now());
      if (ended === null) return false;
      // The events after the delete: a refused event undoes no deletion. A throwing sink does
      // not skip the other events; the first error goes up after all of them.
      const failures: { error: unknown }[] = [];
      const record = async (emit: () => Promise<void>) => {
        try {
          await emit();
        } catch (error) {
          failures.push({ error });
        }
      };
      await record(() =>
        ctx.emit({ type: "oauth.client_deleted", clientId, reason: "administrative" }),
      );
      for (const grant of ended) {
        await record(() => emitOAuthGrantsEnded(ctx, grant.accountId, [grant], "client_deleted"));
      }
      const [first] = failures;
      if (first) throw first.error;
      return true;
    },
  };
}
