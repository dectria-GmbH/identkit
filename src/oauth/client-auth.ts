import { sha256, toHex, utf8 } from "../bytes.js";
import { digestsEqual } from "../crypto.js";
import { InvalidArgumentError } from "../errors.js";
import type { OAuthClientRecord } from "../storage/types.js";
import { CLIENT_ID, errorResult, type OAuthEndpointResult, type OAuthInternals } from "./common.js";

/** A secret longer than this is no secret identkit issued or imported; it gets no digest. */
export const MAX_SECRET_LENGTH = 512;
const BASIC = /^Basic +([A-Za-z0-9+/]+={0,2})$/i;

/** `application/x-www-form-urlencoded` decoding of one value (RFC 6749 section 2.3.1). */
function formDecode(value: string): string | null {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return null;
  }
}

/** The client id and secret of a Basic header, or null if it is malformed. */
function parseBasic(header: string): { id: string; secret: string } | null {
  const match = BASIC.exec(header.trim());
  const encoded = match?.[1];
  if (encoded === undefined || encoded.length % 4 !== 0) return null;
  let text: string;
  try {
    const binary = atob(encoded);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  const colon = text.indexOf(":");
  if (colon < 0) return null;
  const id = formDecode(text.slice(0, colon));
  const secret = formDecode(text.slice(colon + 1));
  return id === null || secret === null ? null : { id, secret };
}

export type ClientAuthentication =
  { client: OAuthClientRecord; error?: never } | { client?: never; error: OAuthEndpointResult };

/**
 * Authenticates the client of a token or revocation request (RFC 6749 section 2.3). A
 * confidential client must send its secret, by Basic or in the form; a public client must send
 * none. A request with two methods is refused. The presented secret gets its digest before the
 * client lookup, so an unknown client costs the same work as a known one.
 */
export async function authenticateClient(
  internals: OAuthInternals,
  params: Map<string, string>,
  authorization: unknown,
): Promise<ClientAuthentication> {
  const { ctx, settings, store } = internals;
  if (authorization !== null && authorization !== undefined && typeof authorization !== "string") {
    throw new InvalidArgumentError("authorization must be the header value or null");
  }
  const header = typeof authorization === "string" ? authorization.trim() : "";
  const basicAttempt = header !== "";
  const unauthorized = (): ClientAuthentication => ({
    error: errorResult(
      401,
      "invalid_client",
      "Client authentication failed.",
      basicAttempt ? { "WWW-Authenticate": `Basic realm="${settings.basicRealm}"` } : {},
    ),
  });
  const bodyId = params.get("client_id");
  const bodySecret = params.get("client_secret");

  let clientId: string | undefined;
  let secret: string | null;
  if (basicAttempt) {
    const basic = parseBasic(header);
    if (!basic) return unauthorized();
    if (bodySecret !== undefined) {
      return {
        error: errorResult(400, "invalid_request", "Use one client authentication method only."),
      };
    }
    if (bodyId !== undefined && bodyId !== basic.id) {
      return {
        error: errorResult(400, "invalid_request", "client_id differs from the Basic credentials."),
      };
    }
    clientId = basic.id;
    secret = basic.secret;
  } else {
    clientId = bodyId;
    secret = bodySecret ?? null;
  }
  if (clientId === undefined) return unauthorized();
  if (secret !== null && secret.length > MAX_SECRET_LENGTH) return unauthorized();

  // Both digests for every presented secret, before the lookup: the work does not depend on
  // whether the client exists or how its secret is stored.
  const presented =
    secret === null
      ? null
      : {
          keyed: await ctx.hasher.digest("oauth-client-secret", secret),
          legacy: toHex(await sha256(utf8(secret))),
        };
  const client = CLIENT_ID.test(clientId) ? await store.findClient(clientId) : null;
  if (!client) return unauthorized();
  if (client.authMethod === "none") {
    // A public client has no secret; one that sends a secret is not that client.
    return secret === null ? { client } : unauthorized();
  }
  // A confidential client may use either secret method, never none.
  if (presented === null) return unauthorized();
  const matched = secretMatches(client, presented, settings.acceptLegacyClientSecrets);
  if (matched === null) return unauthorized();
  if (matched === "legacy" && client.secretDigest !== null) {
    await upgradeSecret(internals, client.id, client.secretDigest, presented.keyed);
  }
  return { client };
}

/**
 * How the presented secret matched the client's stored digest, or null. A digest stored as
 * unkeyed SHA-256 (an import) counts only with `acceptLegacyClientSecrets`.
 */
function secretMatches(
  client: OAuthClientRecord,
  presented: { keyed: string; legacy: string },
  acceptLegacy: boolean,
): "keyed" | "legacy" | null {
  if (client.secretDigest === null) return null;
  if (client.secretDigestAlgorithm === "hmac-sha256") {
    return digestsEqual(client.secretDigest, presented.keyed) ? "keyed" : null;
  }
  if (client.secretDigestAlgorithm === "sha256" && acceptLegacy) {
    return digestsEqual(client.secretDigest, presented.legacy) ? "legacy" : null;
  }
  return null;
}

/**
 * Replaces an imported SHA-256 digest with the keyed one, compare-and-set, best effort: the
 * client is authenticated already. A lost race means another call upgraded it. A store error
 * goes to `onStoreError`, and the next use tries again.
 */
async function upgradeSecret(
  internals: OAuthInternals,
  clientId: string,
  oldDigest: string,
  keyed: string,
): Promise<void> {
  try {
    await internals.store.upgradeClientSecret(clientId, oldDigest, keyed);
  } catch (error) {
    try {
      await internals.settings.onStoreError?.(error, { kind: "client_secret_upgrade", clientId });
    } catch {
      // Dropped: the handler is a report channel, not a gate.
    }
  }
}
