import type { Context } from "../context.js";
import { InvalidArgumentError, NotConfiguredError } from "../errors.js";
import {
  requireId,
  toClientView,
  type OAuthEndpointResult,
  type OAuthInternals,
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

export type { OAuthEndpointResult, OAuthParams } from "./common.js";
export type { OAuthMetadata, WwwAuthenticateInput } from "./metadata.js";
export {
  oauthOptionsSchema,
  type OAuthAdmitHook,
  type OAuthAdmitRequest,
  type OAuthAuditErrorHandler,
  type OAuthClientView,
  type OAuthOptions,
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
