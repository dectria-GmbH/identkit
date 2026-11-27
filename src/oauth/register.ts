import { addSeconds, secondsUntil } from "../clock.js";
import { randomId, randomToken } from "../crypto.js";
import { InvalidArgumentError, NotConfiguredError, OAuthClientRolledBackError } from "../errors.js";
import { isRecord } from "../oidc-jwt.js";
import type { OAuthClientAuthMethod, OAuthClientRecord } from "../storage/types.js";
import {
  endpointResult,
  errorResult,
  sanitizeClientName,
  utcDayStart,
  type OAuthEndpointResult,
  type OAuthInternals,
} from "./common.js";
import { parseRedirectUri } from "./redirect-uris.js";

const GRANT_TYPES = new Set(["authorization_code", "refresh_token"]);
const MAX_ADDRESS_KEY_LENGTH = 256;
/** The count key of the deployment; address keys are hex digests, so they never equal it. */
const DEPLOYMENT_KEY = "deployment";

const invalidMetadata = (description: string) =>
  errorResult(400, "invalid_client_metadata", description);

function stringList(value: unknown): string[] | null {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return null;
  return value;
}

/** The metadata of a registration request, checked, or an error result. */
function parseRegistration(
  internals: OAuthInternals,
  body: string,
):
  | {
      redirectUris: string[];
      authMethod: OAuthClientAuthMethod;
      grantTypes: string[];
      name: string | null;
    }
  | OAuthEndpointResult {
  const { registration, redirectUris: uriRules } = internals.settings;
  if (new TextEncoder().encode(body).byteLength > registration.maxBodyBytes) {
    return invalidMetadata("The registration request is too large.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return invalidMetadata("The registration request is not valid JSON.");
  }
  if (!isRecord(parsed)) return invalidMetadata("The registration request must be a JSON object.");

  const uris = stringList(parsed["redirect_uris"]);
  if (!uris || uris.length === 0 || uris.length > registration.maxRedirectUris) {
    return errorResult(
      400,
      "invalid_redirect_uri",
      `redirect_uris must hold 1 to ${registration.maxRedirectUris} URIs.`,
    );
  }
  const rules = {
    maxLength: registration.maxRedirectUriLength,
    allowIpv6Loopback: uriRules.allowIpv6Loopback,
    allowPrivateUseSchemes: uriRules.allowPrivateUseSchemes,
  };
  if (new Set(uris).size !== uris.length || !uris.every((uri) => parseRedirectUri(uri, rules))) {
    return errorResult(400, "invalid_redirect_uri", "A redirect URI is not allowed.");
  }

  const method = parsed["token_endpoint_auth_method"] ?? registration.defaultAuthMethod;
  const authMethod = registration.allowedAuthMethods.find((m) => m === method);
  if (authMethod === undefined) {
    return invalidMetadata("token_endpoint_auth_method is not supported.");
  }

  const grantTypes =
    parsed["grant_types"] === undefined
      ? ["authorization_code"]
      : stringList(parsed["grant_types"]);
  if (
    !grantTypes ||
    !grantTypes.includes("authorization_code") ||
    !grantTypes.every((g) => GRANT_TYPES.has(g)) ||
    new Set(grantTypes).size !== grantTypes.length
  ) {
    return invalidMetadata("grant_types must hold authorization_code, and refresh_token at most.");
  }

  const responseTypes =
    parsed["response_types"] === undefined ? ["code"] : stringList(parsed["response_types"]);
  if (!responseTypes || responseTypes.length !== 1 || responseTypes[0] !== "code") {
    return invalidMetadata('response_types must be ["code"].');
  }

  const rawName = parsed["client_name"];
  if (rawName !== undefined && typeof rawName !== "string") {
    return invalidMetadata("client_name must be a string.");
  }
  return {
    redirectUris: uris,
    authMethod,
    grantTypes,
    name: rawName === undefined ? null : sanitizeClientName(rawName),
  };
}

/** Dynamic client registration (RFC 7591). */
export function createRegister(internals: OAuthInternals) {
  const { ctx, settings, store } = internals;

  return async function register(input: {
    body: string;
    addressKey?: string;
  }): Promise<OAuthEndpointResult> {
    if (settings.endpoints.register === null) {
      throw new NotConfiguredError("oauth.endpoints.register");
    }
    if (typeof input !== "object" || input === null || typeof input.body !== "string") {
      throw new InvalidArgumentError("register needs { body: string }");
    }
    const addressKey = input.addressKey;
    if (
      addressKey !== undefined &&
      (typeof addressKey !== "string" ||
        addressKey.length === 0 ||
        addressKey.length > MAX_ADDRESS_KEY_LENGTH)
    ) {
      throw new InvalidArgumentError("addressKey must be a string of 1 to 256 characters");
    }
    const metadata = parseRegistration(internals, input.body);
    if ("httpStatus" in metadata) return metadata;

    // The address first: when it refuses, the deployment count stays, so one address at its
    // limit cannot use up the deployment's registrations.
    const now = ctx.clock.now();
    const addressDigest =
      addressKey === undefined
        ? null
        : await ctx.hasher.digest("oauth-registration-address", addressKey);
    const keys = [
      ...(addressDigest === null
        ? []
        : [{ key: addressDigest, max: settings.registration.maxPerAddressPerDay }]),
      { key: DEPLOYMENT_KEY, max: settings.registration.maxPerDay },
    ];
    const reserved = await store.reserveRegistration({ keys, windowStart: utcDayStart(now) });
    if (reserved !== "reserved") {
      const reason = reserved.limitReached === DEPLOYMENT_KEY ? "daily_limit" : "address_limit";
      await ctx.emit({
        type: "oauth.registration_refused",
        reason,
        ...(addressDigest === null ? {} : { addressDigest }),
      });
      return errorResult(
        429,
        "temporarily_unavailable",
        "Too many client registrations. Try again later.",
        { "Retry-After": String(secondsUntil(now, addSeconds(utcDayStart(now), 86_400))) },
      );
    }

    const confidential = metadata.authMethod !== "none";
    const secret = confidential ? `${settings.prefixes.clientSecret}${randomToken()}` : null;
    const client: OAuthClientRecord = {
      id: `${settings.prefixes.clientId}${randomId()}`,
      secretDigest: secret === null ? null : await ctx.hasher.digest("oauth-client-secret", secret),
      secretDigestAlgorithm: secret === null ? null : "hmac-sha256",
      authMethod: metadata.authMethod,
      grantTypes: metadata.grantTypes,
      redirectUris: metadata.redirectUris,
      name: metadata.name,
      source: "dynamic",
      createdAt: now,
      lastUsedAt: null,
    };
    // 128 random bits: an id that exists means a broken random source or store.
    if ((await store.insertClient(client)) !== "inserted")
      throw new Error("oauth client id exists");
    try {
      await ctx.emit({
        type: "oauth.client_registered",
        clientId: client.id,
        method: client.authMethod,
      });
    } catch (error) {
      // No client stands without its audit record.
      await store.deleteClient(client.id, ctx.clock.now());
      throw new OAuthClientRolledBackError(client.id, { cause: error });
    }
    return endpointResult(201, {
      client_id: client.id,
      client_id_issued_at: Math.floor(now.getTime() / 1000),
      ...(secret === null ? {} : { client_secret: secret, client_secret_expires_at: 0 }),
      redirect_uris: [...client.redirectUris],
      grant_types: [...client.grantTypes],
      response_types: ["code"],
      token_endpoint_auth_method: client.authMethod,
      ...(client.name === null ? {} : { client_name: client.name }),
    });
  };
}
