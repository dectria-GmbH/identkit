import { bytesEqual, randomBytes, sha256, toBase64Url, utf8, type WebCryptoKey } from "../bytes.js";
import type { Clock } from "../clock.js";
import { systemClock } from "../clock.js";
import { InvalidArgumentError } from "../errors.js";
import type { OidcFetch } from "../oidc-jwks.js";
import { microsoftIssuer } from "../oidc-providers.js";
import type { IdTokenAlgorithm } from "../oidc-jwt.js";

export interface FakeOidcProviderOptions {
  /**
   * Which real provider to stand in for. `microsoft` and `google` answer at the URLs of the
   * identkit presets, so the presets run unchanged against the fake. `oidc` (default) answers
   * under `issuer`.
   */
  kind?: "microsoft" | "google" | "oidc";
  clientId: string;
  clientSecret: string;
  /** For `oidc`. Default `https://idp.example`. */
  issuer?: string;
  /** For `microsoft`: the authority in the URLs. Default `common`. */
  tenant?: string;
  /** Signature algorithm of the ID tokens. Default `RS256`. */
  algorithm?: IdTokenAlgorithm;
  /** Times `iat` and `exp`. Pass the fake clock of your test. */
  clock?: Clock;
}

/** Claims for one simulated sign-in. A value of `undefined` removes the claim. */
export type FakeClaims = Record<string, unknown>;

export interface FakeOidcProvider {
  /** Pass this as `oidc.fetch`. It answers the token and key endpoints, nothing else. */
  fetch: OidcFetch;
  /** The endpoints, for `oidcProvider({ ... })` with kind `oidc`. */
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  /**
   * Plays the user at the provider: reads the authorization URL from `oidc.begin`, checks it
   * like a provider would, and returns the query of the redirect back to the application
   * (`code` and `state`). `claims` go into the ID token; issuer, subject (random), audience,
   * nonce and times are filled in unless you set them. For `microsoft`, the issuer follows the
   * `tid` claim.
   */
  authorize(authorizationUrl: string, claims: FakeClaims): Promise<URLSearchParams>;
  /** Signs any claims with the current key, for tests that need a hand-made token. */
  signIdToken(claims: FakeClaims, header?: Record<string, unknown>): Promise<string>;
  /** The next token response carries the ID token that `transform` returns instead. */
  replaceNextIdToken(transform: (idToken: string) => string | Promise<string>): void;
  /** The next request to this endpoint answers with status 500. */
  failNext(endpoint: "token" | "jwks"): void;
  /** Replaces the signing key with a new one under a new key id. The old key is dropped. */
  rotateKey(): Promise<void>;
  /** Requests received so far, per endpoint. */
  requests(): { token: number; jwks: number };
}

interface IssuedCode {
  claims: FakeClaims;
  codeChallenge: string;
  redirectUri: string;
  used: boolean;
}

interface SigningKey {
  kid: string;
  privateKey: WebCryptoKey;
  publicJwk: Record<string, unknown>;
}

async function newKey(algorithm: IdTokenAlgorithm): Promise<SigningKey> {
  const params =
    algorithm === "RS256"
      ? {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        }
      : { name: "ECDSA", namedCurve: "P-256" };
  const pair = await crypto.subtle.generateKey(params, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const kid = toBase64Url(randomBytes(8));
  const publicJwk: Record<string, unknown> =
    algorithm === "RS256"
      ? { kty: "RSA", n: jwk.n, e: jwk.e, kid, alg: "RS256", use: "sig" }
      : { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid, alg: "ES256", use: "sig" };
  return { kid, privateKey: pair.privateKey, publicJwk };
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

/**
 * A fake OpenID Connect provider for tests and demos: it signs ID tokens with a Web Crypto key
 * and serves its JWKS and token endpoint through `fetch`, so no request leaves the process. It
 * runs wherever identkit runs, also in workerd. Not for production: it signs in anyone.
 */
export async function createFakeOidcProvider(
  options: FakeOidcProviderOptions,
): Promise<FakeOidcProvider> {
  const kind = options.kind ?? "oidc";
  const algorithm = options.algorithm ?? "RS256";
  const clock = options.clock ?? systemClock;
  if (!options.clientId || !options.clientSecret) {
    throw new InvalidArgumentError("clientId and clientSecret are required");
  }
  let issuer: string;
  let authorizationEndpoint: string;
  let tokenEndpoint: string;
  let jwksUri: string;
  if (kind === "microsoft") {
    const base = `https://login.microsoftonline.com/${options.tenant ?? "common"}`;
    issuer = `${base}/v2.0`;
    authorizationEndpoint = `${base}/oauth2/v2.0/authorize`;
    tokenEndpoint = `${base}/oauth2/v2.0/token`;
    jwksUri = `${base}/discovery/v2.0/keys`;
  } else if (kind === "google") {
    issuer = "https://accounts.google.com";
    authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    tokenEndpoint = "https://oauth2.googleapis.com/token";
    jwksUri = "https://www.googleapis.com/oauth2/v3/certs";
  } else {
    issuer = options.issuer ?? "https://idp.example";
    authorizationEndpoint = `${issuer}/authorize`;
    tokenEndpoint = `${issuer}/token`;
    jwksUri = `${issuer}/jwks`;
  }

  let key = await newKey(algorithm);
  const codes = new Map<string, IssuedCode>();
  const counts = { token: 0, jwks: 0 };
  const failing = { token: false, jwks: false };
  let replaceNext: ((idToken: string) => string | Promise<string>) | null = null;

  async function signIdToken(claims: FakeClaims, header: Record<string, unknown> = {}) {
    const h = toBase64Url(
      utf8(JSON.stringify({ alg: algorithm, typ: "JWT", kid: key.kid, ...header })),
    );
    const p = toBase64Url(utf8(JSON.stringify(claims)));
    const signature = await crypto.subtle.sign(
      algorithm === "RS256" ? "RSASSA-PKCS1-v1_5" : { name: "ECDSA", hash: "SHA-256" },
      key.privateKey,
      utf8(`${h}.${p}`),
    );
    return `${h}.${p}.${toBase64Url(new Uint8Array(signature))}`;
  }

  function defaultClaims(nonce: string | null): FakeClaims {
    const now = Math.floor(clock.now().getTime() / 1000);
    return {
      iss: issuer,
      // A new subject per sign-in unless the test names one.
      sub: `fake-${toBase64Url(randomBytes(12))}`,
      aud: options.clientId,
      iat: now,
      exp: now + 3600,
      ...(nonce !== null ? { nonce } : {}),
    };
  }

  /** Fills in what the real provider would, then applies the test's claims. */
  function claimsFor(nonce: string | null, claims: FakeClaims): FakeClaims {
    const merged: FakeClaims = { ...defaultClaims(nonce) };
    if (kind === "microsoft" && typeof claims["tid"] === "string") {
      merged["iss"] = microsoftIssuer(claims["tid"]);
    }
    for (const [name, value] of Object.entries(claims)) {
      if (value === undefined) delete merged[name];
      else merged[name] = value;
    }
    return merged;
  }

  async function tokenEndpointAnswer(init: RequestInit | undefined): Promise<Response> {
    counts.token += 1;
    if (failing.token) {
      failing.token = false;
      return json(500, { error: "server_error" });
    }
    const form = new URLSearchParams(typeof init?.body === "string" ? init.body : "");
    const headers = new Headers(init?.headers);
    let clientId = form.get("client_id");
    let secret = form.get("client_secret");
    const basic = headers.get("authorization");
    if (basic?.startsWith("Basic ")) {
      const [user = "", pass = ""] = atob(basic.slice(6)).split(":");
      clientId = decodeURIComponent(user);
      secret = decodeURIComponent(pass);
    }
    if (clientId !== options.clientId || secret !== options.clientSecret) {
      return json(401, { error: "invalid_client" });
    }
    if (form.get("grant_type") !== "authorization_code") {
      return json(400, { error: "unsupported_grant_type" });
    }
    const issued = codes.get(form.get("code") ?? "");
    if (!issued || issued.used || form.get("redirect_uri") !== issued.redirectUri) {
      return json(400, { error: "invalid_grant" });
    }
    const verifier = form.get("code_verifier") ?? "";
    const challenge = toBase64Url(await sha256(utf8(verifier)));
    if (!bytesEqual(utf8(challenge), utf8(issued.codeChallenge))) {
      return json(400, { error: "invalid_grant" });
    }
    issued.used = true;
    let idToken = await signIdToken(issued.claims);
    if (replaceNext) {
      const transform = replaceNext;
      replaceNext = null;
      idToken = await transform(idToken);
    }
    return json(200, {
      access_token: toBase64Url(randomBytes(16)),
      token_type: "Bearer",
      expires_in: 3600,
      id_token: idToken,
    });
  }

  const fetch: OidcFetch = async (url, init) => {
    if (url === tokenEndpoint && init?.method === "POST") return tokenEndpointAnswer(init);
    if (url === jwksUri) {
      counts.jwks += 1;
      if (failing.jwks) {
        failing.jwks = false;
        return json(500, { error: "server_error" });
      }
      return json(200, { keys: [key.publicJwk] });
    }
    return json(404, { error: "not_found" });
  };

  return {
    fetch,
    issuer,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    async authorize(authorizationUrl, claims) {
      const url = new URL(authorizationUrl);
      const q = url.searchParams;
      if (`${url.origin}${url.pathname}` !== authorizationEndpoint) {
        throw new InvalidArgumentError("authorization URL of another provider");
      }
      if (q.get("response_type") !== "code" || q.get("client_id") !== options.clientId) {
        throw new InvalidArgumentError("authorization request: wrong response type or client");
      }
      if (q.get("code_challenge_method") !== "S256" || !q.get("code_challenge")) {
        throw new InvalidArgumentError("authorization request: PKCE S256 missing");
      }
      const state = q.get("state");
      const redirectUri = q.get("redirect_uri");
      if (!state || !redirectUri || !(q.get("scope") ?? "").split(" ").includes("openid")) {
        throw new InvalidArgumentError("authorization request: state, redirect or scope missing");
      }
      const code = toBase64Url(randomBytes(24));
      codes.set(code, {
        claims: claimsFor(q.get("nonce"), claims),
        codeChallenge: q.get("code_challenge") ?? "",
        redirectUri,
        used: false,
      });
      return new URLSearchParams({ code, state });
    },
    signIdToken,
    replaceNextIdToken(transform) {
      replaceNext = transform;
    },
    failNext(endpoint) {
      failing[endpoint] = true;
    },
    async rotateKey() {
      key = await newKey(algorithm);
    },
    requests: () => ({ ...counts }),
  };
}
