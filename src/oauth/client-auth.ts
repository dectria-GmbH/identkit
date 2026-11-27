import { digestsEqual } from "../crypto.js";
import { InvalidArgumentError } from "../errors.js";
import type { OAuthClientRecord } from "../storage/types.js";
import { CLIENT_ID, errorResult, type OAuthEndpointResult, type OAuthInternals } from "./common.js";

/** A secret longer than this is no secret identkit issued or imported; it gets no digest. */
const MAX_SECRET_LENGTH = 512;
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

  const presented = secret === null ? null : await ctx.hasher.digest("oauth-client-secret", secret);
  const client = CLIENT_ID.test(clientId) ? await store.findClient(clientId) : null;
  if (!client) return unauthorized();
  if (client.authMethod === "none") {
    // A public client has no secret; one that sends a secret is not that client.
    return secret === null ? { client } : unauthorized();
  }
  // A confidential client may use either secret method, never none.
  if (presented === null || !secretMatches(client, presented)) return unauthorized();
  return { client };
}

/**
 * True if the keyed digest of the presented secret equals the client's. A client whose stored
 * digest is not keyed (`sha256`, imported) does not match here.
 */
function secretMatches(client: OAuthClientRecord, presentedDigest: string): boolean {
  return (
    client.secretDigest !== null &&
    client.secretDigestAlgorithm === "hmac-sha256" &&
    digestsEqual(client.secretDigest, presentedDigest)
  );
}
