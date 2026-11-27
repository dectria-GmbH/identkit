import { InvalidArgumentError } from "./errors.js";
import { importJwk, isRecord, type IdTokenAlgorithm, type VerificationKey } from "./oidc-jwt.js";

/** Fetch as identkit calls it. Pass your own to test or to route requests. */
export type OidcFetch = (url: string, init: RequestInit) => Promise<Response>;

/** Upper bound for a JWKS document and its number of keys. */
const MAX_JWKS_BYTES = 512 * 1024;
const MAX_JWKS_KEYS = 100;

/** A request to a provider failed: network, timeout, status or body. Carries no secret. */
export class ProviderRequestError extends Error {
  constructor(readonly reason: string) {
    super(`provider request failed: ${reason}`);
    this.name = "ProviderRequestError";
  }
}

/** Reads the body as bytes and stops as soon as it exceeds `maxBytes`. */
async function readLimited(response: Response, maxBytes: number): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ProviderRequestError("response too large");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/**
 * Reads a JSON object from a provider response, with a size limit in bytes. Throws
 * `ProviderRequestError` for anything else.
 */
export async function readJson(
  response: Response,
  maxBytes: number,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new ProviderRequestError("response too large");
  let bytes: Uint8Array;
  try {
    bytes = await readLimited(response, maxBytes);
  } catch (error) {
    if (error instanceof ProviderRequestError) throw error;
    throw new ProviderRequestError("network error or timeout");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ProviderRequestError("response is not UTF-8");
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new ProviderRequestError("response is not JSON");
  }
  if (!isRecord(body)) throw new ProviderRequestError("response is not a JSON object");
  return { status: response.status, body };
}

/** Calls `fetch` with a timeout and maps every failure to `ProviderRequestError`. */
export async function providerFetch(
  fetcher: OidcFetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  let response: Response;
  try {
    // Never follow a redirect: a 307 or 308 from the token endpoint would send the client
    // secret again, to the redirect target. `manual` instead of `error`, which not every
    // runtime accepts; a redirect answer then fails here.
    response = await fetcher(url, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    throw new ProviderRequestError("network error or timeout");
  }
  if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
    await response.body?.cancel().catch(() => undefined);
    throw new ProviderRequestError("redirect refused");
  }
  return response;
}

interface Entry {
  keys: VerificationKey[];
  /** When the keys were fetched; -Infinity before the first success. */
  fetchedAt: number;
  /** When the last fetch started, successful or not. */
  lastAttemptAt: number;
  pending: Promise<void> | null;
}

/**
 * Cache of provider signing keys (JWKS), keyed by JWKS URI. Create one per process with
 * `createJwksCache()` and pass it to every `createIdentkit` call that should share it: on
 * Cloudflare Workers, at module scope, so the keys survive between requests in one isolate.
 */
export interface JwksCache {
  /** Drops every cached key, so the next sign-in fetches them again. */
  clear(): void;
}

const entries = new WeakMap<object, Map<string, Entry>>();

export function createJwksCache(): JwksCache {
  const state = new Map<string, Entry>();
  const cache: JwksCache = { clear: () => state.clear() };
  entries.set(cache, state);
  return cache;
}

export function assertJwksCache(cache: unknown): asserts cache is JwksCache {
  if (typeof cache !== "object" || cache === null || !entries.has(cache)) {
    throw new InvalidArgumentError("jwksCache must come from createJwksCache()");
  }
}

export interface KeyLookup {
  fetch: OidcFetch;
  now: () => number;
  ttlMs: number;
  /** Least time between two fetches of one URI for an unknown key id. */
  refetchIntervalMs: number;
  timeoutMs: number;
}

async function fetchKeys(uri: string, lookup: KeyLookup): Promise<VerificationKey[]> {
  const response = await providerFetch(
    lookup.fetch,
    uri,
    { method: "GET", headers: { accept: "application/json" } },
    lookup.timeoutMs,
  );
  const { status, body } = await readJson(response, MAX_JWKS_BYTES);
  if (status !== 200) throw new ProviderRequestError(`key endpoint status ${status}`);
  const list = body["keys"];
  if (!Array.isArray(list) || list.length > MAX_JWKS_KEYS) {
    throw new ProviderRequestError("key endpoint returned no usable key list");
  }
  const keys: VerificationKey[] = [];
  for (const jwk of list) {
    const key = await importJwk(jwk);
    if (key) keys.push(key);
  }
  return keys;
}

/** Fetches the keys of `uri` once; concurrent callers share the request. */
async function refresh(state: Map<string, Entry>, uri: string, lookup: KeyLookup): Promise<Entry> {
  let entry = state.get(uri);
  if (!entry) {
    entry = { keys: [], fetchedAt: -Infinity, lastAttemptAt: -Infinity, pending: null };
    state.set(uri, entry);
  }
  const current = entry;
  if (!current.pending) {
    current.lastAttemptAt = lookup.now();
    current.pending = fetchKeys(uri, lookup)
      .then((keys) => {
        current.keys = keys;
        current.fetchedAt = lookup.now();
      })
      .finally(() => {
        current.pending = null;
      });
  }
  await current.pending;
  return current;
}

function pick(entry: Entry, kid: string | null, alg: IdTokenAlgorithm): VerificationKey | null {
  const candidates = entry.keys.filter((k) => k.alg === alg);
  if (kid !== null) return candidates.find((k) => k.kid === kid) ?? null;
  // Without a key id, only an unambiguous key is used.
  return candidates.length === 1 ? (candidates[0] ?? null) : null;
}

/**
 * The verification key for a token header, or null if the provider has none. Fetches the
 * JWKS when it is missing or older than the TTL. For an unknown key id it fetches once more,
 * only if the last fetch is older than `refetchIntervalMs` and none ran in this call, so one
 * lookup makes at most one request. Throws `ProviderRequestError` if a needed fetch fails.
 */
export async function findKey(
  cache: JwksCache,
  uri: string,
  header: { kid: string | null; alg: IdTokenAlgorithm },
  lookup: KeyLookup,
): Promise<VerificationKey | null> {
  const state = entries.get(cache);
  if (!state) throw new InvalidArgumentError("jwksCache must come from createJwksCache()");
  let entry = state.get(uri);
  if (!entry || lookup.now() - entry.fetchedAt >= lookup.ttlMs) {
    entry = await refresh(state, uri, lookup);
    return pick(entry, header.kid, header.alg);
  }
  const found = pick(entry, header.kid, header.alg);
  if (found) return found;
  if (lookup.now() - entry.lastAttemptAt < lookup.refetchIntervalMs) return null;
  entry = await refresh(state, uri, lookup);
  return pick(entry, header.kid, header.alg);
}
