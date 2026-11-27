import type { Context } from "../context.js";
import { InvalidArgumentError, NotConfiguredError } from "../errors.js";
import {
  requireId,
  toClientView,
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
export {
  emitOAuthGrantsEnded,
  endAllOAuthGrants,
  type OAuthAccessTokenRefusal,
  type OAuthGrantEndReason,
  type OAuthTokenFailure,
  type ValidateAccessTokenResult,
} from "./token.js";

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
   * Returns true if this call deleted it.
   */
  deleteClient(clientId: string): Promise<boolean>;
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
  const internals: OAuthInternals = { ctx, settings, store, sealer: ctx.sealer };

  return {
    metadata: createMetadata(settings),
    wwwAuthenticate: (input) => wwwAuthenticate(settings, input),
    register: createRegister(internals),
    authorize: createAuthorize(internals),
    ...createTokenEndpoint(internals),

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
      const ended = await store.deleteGrant(grantId, { accountId });
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

    async getClient(clientId) {
      const found = await store.findClient(requireId(clientId, "clientId"));
      return found ? toClientView(found) : null;
    },

    async deleteClient(clientId) {
      requireId(clientId, "clientId");
      const deleted = await store.deleteClient(clientId);
      // The event after the delete: a refused event undoes no deletion.
      if (deleted) {
        await ctx.emit({ type: "oauth.client_deleted", clientId, reason: "administrative" });
      }
      return deleted;
    },
  };
}
