import { InvalidArgumentError } from "../errors.js";
import { SCOPE, type OAuthSettings } from "./options.js";

/** The documents of RFC 8414 and RFC 9728, the paths to route them, and `WWW-Authenticate`. */
export interface OAuthMetadata {
  /** The authorization server metadata (RFC 8414). */
  authorizationServer(): Record<string, unknown>;
  /** The protected resource metadata (RFC 9728) of a configured resource; default the first. */
  protectedResource(resource?: string): Record<string, unknown>;
  /**
   * The path on the resource's origin that serves its metadata, for example
   * `/.well-known/oauth-protected-resource/mcp` for `https://example.com/mcp`.
   */
  protectedResourcePath(resource?: string): string;
  /** The path on the issuer's origin that serves the authorization server metadata. */
  authorizationServerPath(): string;
}

/** The well-known path with the URL's path appended (RFC 8414 section 3.1, RFC 9728 3.1). */
function wellKnownPath(name: string, url: string): string {
  const path = new URL(url).pathname;
  return path === "/" ? `/.well-known/${name}` : `/.well-known/${name}${path}`;
}

export function pickResource(settings: OAuthSettings, resource: unknown): string {
  if (resource === undefined) return settings.resources[0] ?? "";
  if (typeof resource !== "string" || !settings.resources.includes(resource)) {
    throw new InvalidArgumentError("resource must be one of the configured resources");
  }
  return resource;
}

export function createMetadata(settings: OAuthSettings): OAuthMetadata {
  const methods = [...settings.registration.allowedAuthMethods];
  return {
    authorizationServer() {
      return {
        issuer: settings.issuer,
        authorization_endpoint: settings.endpoints.authorize,
        token_endpoint: settings.endpoints.token,
        ...(settings.endpoints.register === null
          ? {}
          : { registration_endpoint: settings.endpoints.register }),
        revocation_endpoint: settings.endpoints.revoke,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: [...methods],
        revocation_endpoint_auth_methods_supported: [...methods],
        scopes_supported: [...settings.knownScopes],
        authorization_response_iss_parameter_supported: true,
      };
    },
    protectedResource(resource) {
      const chosen = pickResource(settings, resource);
      return {
        resource: chosen,
        authorization_servers: [settings.issuer],
        scopes_supported: [...settings.knownScopes],
        bearer_methods_supported: ["header"],
        ...(settings.resourceName === undefined ? {} : { resource_name: settings.resourceName }),
      };
    },
    protectedResourcePath(resource) {
      return wellKnownPath("oauth-protected-resource", pickResource(settings, resource));
    },
    authorizationServerPath() {
      return wellKnownPath("oauth-authorization-server", settings.issuer);
    },
  };
}

export interface WwwAuthenticateInput {
  /** The resource the request was for; default the first configured resource. */
  resource?: string;
  /** True if the request carried a bearer token. */
  tokenPresented: boolean;
  /** Default `invalid_token` if a token was presented, else none. */
  error?: "invalid_token" | "insufficient_scope";
  /** The scopes the request needs; default the default scopes. */
  scope?: string[];
}

/**
 * The value of `WWW-Authenticate` for a 401 or 403 of the protected resource (RFC 6750 section
 * 3, RFC 9728 section 5.1): `Bearer resource_metadata="...", scope="..."`, plus `error` when a
 * token was presented.
 */
export function wwwAuthenticate(settings: OAuthSettings, input: WwwAuthenticateInput): string {
  if (typeof input !== "object" || input === null || typeof input.tokenPresented !== "boolean") {
    throw new InvalidArgumentError("wwwAuthenticate needs { tokenPresented: boolean }");
  }
  const resource = pickResource(settings, input.resource);
  const scopes = input.scope ?? settings.defaultScopes;
  if (!Array.isArray(scopes) || !scopes.every((s) => typeof s === "string" && SCOPE.test(s))) {
    throw new InvalidArgumentError("scope must be an array of scope tokens");
  }
  const error = input.error ?? (input.tokenPresented ? "invalid_token" : undefined);
  if (error !== undefined && error !== "invalid_token" && error !== "insufficient_scope") {
    throw new InvalidArgumentError("error must be invalid_token or insufficient_scope");
  }
  const metadataUrl = `${new URL(resource).origin}${wellKnownPath("oauth-protected-resource", resource)}`;
  const parts = [`resource_metadata="${metadataUrl}"`];
  if (scopes.length > 0) parts.push(`scope="${scopes.join(" ")}"`);
  if (error !== undefined) parts.push(`error="${error}"`);
  return `Bearer ${parts.join(", ")}`;
}
