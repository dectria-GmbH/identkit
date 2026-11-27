import { sha256, toBase64Url, utf8 } from "../bytes.js";
import { randomToken } from "../crypto.js";
import type { OAuth, OAuthEndpointResult } from "../oauth/index.js";
import type { OAuthClientAuthMethod } from "../storage/types.js";

export interface PkcePair {
  /** 43 characters of the unreserved set (RFC 7636 section 4.1). */
  verifier: string;
  /** BASE64URL(SHA-256(verifier)), for `code_challenge_method=S256`. */
  challenge: string;
}

/** A fresh PKCE verifier and its S256 challenge. */
export async function createPkcePair(): Promise<PkcePair> {
  const verifier = randomToken();
  return { verifier, challenge: toBase64Url(await sha256(utf8(verifier))) };
}

/** `application/x-www-form-urlencoded` of one value, as RFC 6749 section 2.3.1 asks for Basic. */
const formEncode = (value: string) => encodeURIComponent(value).replace(/%20/g, "+");

export interface OAuthTestClientOptions {
  /** Default `http://127.0.0.1/callback`. */
  redirectUri?: string;
  /** Default `none` (a public client). */
  authMethod?: OAuthClientAuthMethod;
  /** Default `["authorization_code", "refresh_token"]`. */
  grantTypes?: string[];
  name?: string;
}

export interface OAuthTestAuthorizeOptions {
  optInScopes?: string[];
  state?: string;
  resource?: string;
  scope?: string;
  /**
   * The redirect URI to request; default the registered one. `null` leaves `redirect_uri` out,
   * which a client with one registered URI may do.
   */
  redirectUri?: string | null;
}

export interface OAuthTestClient {
  clientId: string;
  clientSecret: string | null;
  redirectUri: string;
  authMethod: OAuthClientAuthMethod;
  /**
   * The form and `Authorization` value of a token or revocation call, with the client's
   * credentials added by its method.
   */
  credentials(form: Record<string, string>): {
    form: URLSearchParams;
    authorization: string | null;
  };
  /**
   * Runs `authorize.begin` and `authorize.approve` for the account and returns the code from
   * the redirect, with the PKCE verifier. Throws if a step does not succeed.
   */
  authorize(
    accountId: string,
    options?: OAuthTestAuthorizeOptions,
  ): Promise<{ code: string; verifier: string; location: URL }>;
  /** The code exchange at `oauth.token`, with `extra` form parameters. */
  exchange(
    code: string,
    verifier: string,
    extra?: Record<string, string>,
  ): Promise<OAuthEndpointResult>;
  /**
   * `authorize`, then `exchange`. Returns the tokens of a successful exchange; throws otherwise.
   */
  connect(
    accountId: string,
    options?: OAuthTestAuthorizeOptions,
  ): Promise<{ accessToken: string; refreshToken: string | null; result: OAuthEndpointResult }>;
  /** A refresh at `oauth.token`, with `extra` form parameters such as `scope`. */
  refresh(refreshToken: string, extra?: Record<string, string>): Promise<OAuthEndpointResult>;
  /** A revocation at `oauth.revoke`. */
  revoke(token: string): Promise<OAuthEndpointResult>;
}

/**
 * Registers a client through `oauth.register` and drives the authorization step like an MCP
 * client would. For tests and end-to-end checks of a deployment's wiring; it contacts nothing.
 */
export async function createOAuthTestClient(
  oauth: OAuth,
  options: OAuthTestClientOptions = {},
): Promise<OAuthTestClient> {
  const redirectUri = options.redirectUri ?? "http://127.0.0.1/callback";
  const authMethod = options.authMethod ?? "none";
  const registered = await oauth.register({
    body: JSON.stringify({
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: authMethod,
      grant_types: options.grantTypes ?? ["authorization_code", "refresh_token"],
      ...(options.name === undefined ? {} : { client_name: options.name }),
    }),
  });
  const clientId = registered.body?.["client_id"];
  const secret = registered.body?.["client_secret"];
  if (registered.httpStatus !== 201 || typeof clientId !== "string") {
    throw new Error(`registration failed: ${String(registered.body?.["error"])}`);
  }
  const clientSecret = typeof secret === "string" ? secret : null;

  const client: OAuthTestClient = {
    clientId,
    clientSecret,
    redirectUri,
    authMethod,

    credentials(form) {
      const params = new URLSearchParams(form);
      if (authMethod === "client_secret_basic" && clientSecret !== null) {
        const pair = `${formEncode(clientId)}:${formEncode(clientSecret)}`;
        return { form: params, authorization: `Basic ${btoa(pair)}` };
      }
      params.set("client_id", clientId);
      if (authMethod === "client_secret_post" && clientSecret !== null) {
        params.set("client_secret", clientSecret);
      }
      return { form: params, authorization: null };
    },

    async authorize(accountId, authorizeOptions = {}) {
      const pkce = await createPkcePair();
      const params = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
      });
      if (authorizeOptions.redirectUri !== null) {
        params.set("redirect_uri", authorizeOptions.redirectUri ?? redirectUri);
      }
      if (authorizeOptions.state !== undefined) params.set("state", authorizeOptions.state);
      if (authorizeOptions.resource !== undefined)
        params.set("resource", authorizeOptions.resource);
      if (authorizeOptions.scope !== undefined) params.set("scope", authorizeOptions.scope);
      const begun = await oauth.authorize.begin({ params, accountId });
      if (begun.status !== "consent") {
        throw new Error(
          `authorize failed: ${begun.status === "invalid" ? begun.error : begun.reason}`,
        );
      }
      const approved = await oauth.authorize.approve({
        ticket: begun.ticket,
        accountId,
        optInScopes: authorizeOptions.optInScopes ?? [],
      });
      if (approved.status !== "redirect") {
        throw new Error(
          `approve failed: ${approved.status === "invalid" ? approved.error : approved.reason}`,
        );
      }
      const location = new URL(approved.location);
      const code = location.searchParams.get("code");
      if (code === null) throw new Error("approve returned no code");
      return { code, verifier: pkce.verifier, location };
    },

    exchange(code, verifier, extra = {}) {
      return oauth.token(
        client.credentials({
          grant_type: "authorization_code",
          code,
          code_verifier: verifier,
          redirect_uri: redirectUri,
          ...extra,
        }),
      );
    },

    async connect(accountId, connectOptions = {}) {
      const { code, verifier } = await client.authorize(accountId, connectOptions);
      const result = await client.exchange(code, verifier);
      const accessToken = result.body?.["access_token"];
      const refreshToken = result.body?.["refresh_token"];
      if (result.httpStatus !== 200 || typeof accessToken !== "string") {
        throw new Error(`exchange failed: ${String(result.body?.["error"])}`);
      }
      return {
        accessToken,
        refreshToken: typeof refreshToken === "string" ? refreshToken : null,
        result,
      };
    },

    refresh(refreshToken, extra = {}) {
      return oauth.token(
        client.credentials({ grant_type: "refresh_token", refresh_token: refreshToken, ...extra }),
      );
    },

    revoke(token) {
      return oauth.revoke(client.credentials({ token }));
    },
  };
  return client;
}
