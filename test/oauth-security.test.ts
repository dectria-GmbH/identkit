/**
 * The security review list of the OAuth server: one `it` per row, named by its number. Each test
 * fails when the defence of its row is turned off at its call site.
 */
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createHmacHasher, InvalidArgumentError, type HashPurpose } from "../src/index.js";
import {
  createOAuthTestClient,
  createPkcePair,
  type OAuthTestClient,
} from "../src/testing/index.js";
import { ISSUER, oauthSetup, registration, RESOURCE } from "./oauth-helpers.js";

/** The error code of an endpoint result. */
const errorOf = (result: { body: Record<string, unknown> | null }) => result.body?.["error"];

/** A refresh token and the access token of a successful refresh or exchange. */
function tokensOf(result: { body: Record<string, unknown> | null }) {
  return {
    access: String(result.body?.["access_token"]),
    refresh: String(result.body?.["refresh_token"]),
  };
}

async function refreshTokenOf(client: OAuthTestClient, accountId: string) {
  const tokens = await client.connect(accountId);
  if (tokens.refreshToken === null) throw new Error("no refresh token");
  return { ...tokens, refreshToken: tokens.refreshToken };
}

/** An authorization request of a test client, with changes. */
async function authorizeParams(clientId: string, overrides: Record<string, string> = {}) {
  const { challenge } = await createPkcePair();
  return new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: "http://127.0.0.1/callback",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "st",
    ...overrides,
  });
}

/** A setup with a public test client and an account. */
async function connected(setupOptions: Parameters<typeof oauthSetup>[0] = {}) {
  const setup = oauthSetup(setupOptions);
  const client = await createOAuthTestClient(setup.ik.oauth);
  const accountId = await setup.account();
  return { ...setup, client, accountId };
}

/** Registers a client with these redirect URIs and returns the result. */
async function registerWith(
  ik: ReturnType<typeof oauthSetup>["ik"],
  redirectUris: unknown[],
  addressKey?: string,
) {
  return ik.oauth.register({
    body: registration({ redirect_uris: redirectUris }),
    ...(addressKey === undefined ? {} : { addressKey }),
  });
}

describe("oauth security review list", () => {
  it("row 1: a code is exchanged once, also by parallel calls", async () => {
    const { ik, client, accountId } = await connected();
    const { code, verifier } = await client.authorize(accountId);
    expect((await client.exchange(code, verifier)).httpStatus).toBe(200);
    expect(errorOf(await client.exchange(code, verifier))).toBe("invalid_grant");

    const parallel = await client.authorize(accountId);
    const results = await Promise.all(
      Array.from({ length: 10 }, () => client.exchange(parallel.code, parallel.verifier)),
    );
    expect(results.filter((r) => r.httpStatus === 200)).toHaveLength(1);
    expect(results.filter((r) => errorOf(r) === "invalid_grant")).toHaveLength(9);
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
  });

  it("row 2: a code that comes back after its exchange ends the grant it created", async () => {
    const { ik, client, accountId, audit } = await connected();
    const { code, verifier } = await client.authorize(accountId);
    const tokens = tokensOf(await client.exchange(code, verifier));
    expect((await ik.oauth.validateAccessToken(tokens.access)).status).toBe("valid");
    expect(errorOf(await client.exchange(code, verifier))).toBe("invalid_grant");
    expect(await ik.oauth.validateAccessToken(tokens.access)).toEqual({
      status: "refused",
      reason: "unknown",
    });
    expect(errorOf(await client.refresh(tokens.refresh))).toBe("invalid_grant");
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["code_reuse"]);
  });

  it("row 3: a code of one client does not work for another, and is burned", async () => {
    const { ik, client, accountId } = await connected();
    const other = await createOAuthTestClient(ik.oauth);
    const { code, verifier } = await client.authorize(accountId);
    expect(errorOf(await other.exchange(code, verifier))).toBe("invalid_grant");
    expect(errorOf(await client.exchange(code, verifier))).toBe("invalid_grant");
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
  });

  it("row 4: S256 only; a wrong verifier burns the code", async () => {
    const { ik, client, accountId, audit } = await connected();
    const plain = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId, {
        code_challenge: "a".repeat(43),
        code_challenge_method: "plain",
      }),
      accountId,
    });
    expect(plain).toMatchObject({ status: "invalid", error: "invalid_request" });
    const { code, verifier } = await client.authorize(accountId);
    const wrong = (await createPkcePair()).verifier;
    expect(errorOf(await client.exchange(code, wrong))).toBe("invalid_grant");
    expect(errorOf(await client.exchange(code, verifier))).toBe("invalid_grant");
    const another = await client.authorize(accountId);
    // The challenge itself is not a verifier.
    expect(errorOf(await client.exchange(another.code, "x".repeat(42)))).toBe("invalid_grant");
    expect(audit.ofType("oauth.token_failed").map((e) => e.reason)).toEqual([
      "pkce_failed",
      "code_unknown",
      "pkce_failed",
    ]);
  });

  it("row 5: the redirect URI at the token endpoint must equal the authorization's", async () => {
    const { ik, accountId } = await connected();
    const web = await createOAuthTestClient(ik.oauth, {
      redirectUri: "https://app.example.com:8443/cb",
    });
    const changes = [
      { redirect_uri: "https://app.example.com:8443/cb/other" },
      { redirect_uri: "https://app.example.com:9443/cb" },
      { redirect_uri: "https://app.example.com:8443/cb?x=1" },
    ];
    for (const extra of changes) {
      const { code, verifier } = await web.authorize(accountId);
      expect(errorOf(await web.exchange(code, verifier, extra))).toBe("invalid_grant");
    }
    const { code, verifier } = await web.authorize(accountId);
    const missing = await ik.oauth.token(
      web.credentials({ grant_type: "authorization_code", code, code_verifier: verifier }),
    );
    expect(errorOf(missing)).toBe("invalid_request");
    // A loopback request that changed the port must repeat that exact URI.
    const loop = await createOAuthTestClient(ik.oauth);
    const ported = await loop.authorize(accountId, {
      redirectUri: "http://127.0.0.1:5000/callback",
    });
    expect(errorOf(await loop.exchange(ported.code, ported.verifier))).toBe("invalid_grant");
    const again = await loop.authorize(accountId, {
      redirectUri: "http://127.0.0.1:5000/callback",
    });
    expect(
      (
        await loop.exchange(again.code, again.verifier, {
          redirect_uri: "http://127.0.0.1:5000/callback",
        })
      ).httpStatus,
    ).toBe(200);
  });

  it("row 6: authorization errors never redirect", async () => {
    const { ik, client, accountId } = await connected();
    const cases = [
      { client_id: "ikc_unknownunknownunknown" },
      { redirect_uri: "https://evil.example/cb" },
      { response_type: "token" },
      { code_challenge_method: "plain" },
      { resource: "https://evil.example/mcp" },
    ];
    for (const overrides of cases) {
      const begun = await ik.oauth.authorize.begin({
        params: await authorizeParams(client.clientId, overrides),
        accountId,
      });
      expect(begun.status).toBe("invalid");
      expect(begun).not.toHaveProperty("location");
      expect(JSON.stringify(begun)).not.toContain("evil.example");
    }
  });

  it("row 7: redirect URI tricks at registration are refused", async () => {
    const { ik } = oauthSetup();
    const refused = [
      "https://exаmple.com/cb", // Cyrillic a
      "https://xn--exmple-cua.com/cb\u0000",
      "https://example.com@evil.example/cb",
      "https://user:pass@example.com/cb",
      "https://example.com/cb#x",
      "https://example.com/cb#",
      "http://example.com/cb",
      "http://127.0.0.1.evil.example/cb",
      "http://localhost.evil.example/cb",
      "http://[::1]/cb",
      "http://2130706433/cb",
      "http://0x7f.0.0.1/cb",
      "javascript:alert(1)",
      "data:text/html,hello",
      "file:///etc/passwd",
      "com.example.app:/cb",
      "https://example.com/a/../b",
      "https://example.com/a/./b",
      "https://EXAMPLE.com/cb",
      "HTTPS://example.com/cb",
      "https://example.com:443/cb",
      "http://127.0.0.1:80/cb",
      "https://ex%61mple.com/cb",
      "https://example.com/c b",
      "https://example.com/cb\n",
      " https://example.com/cb",
      "https://example.com\\@evil.example/cb",
      "https://example.com./cb",
      "https:///cb",
      "https://",
      "//example.com/cb",
      "/cb",
      "cb",
      "",
      `https://example.com/${"a".repeat(512)}`,
      "https://exa_mple.com/cb",
      "https://exämple.com/cb",
      "https://[2001:db8::1]/cb",
    ];
    for (const uri of refused) {
      const result = await registerWith(ik, [uri]);
      expect({ uri, status: result.httpStatus, error: result.body?.["error"] }).toEqual({
        uri,
        status: 400,
        error: "invalid_redirect_uri",
      });
    }
    const accepted = [
      "https://example.com/cb",
      "https://example.com",
      "https://example.com/cb?tenant=a",
      "https://app.example.com:8443/oauth/callback",
      "http://127.0.0.1/cb",
      "http://127.0.0.1:33418/callback",
      "http://localhost:5000/cb",
    ];
    for (const uri of accepted) {
      expect({ uri, status: (await registerWith(ik, [uri])).httpStatus }).toEqual({
        uri,
        status: 201,
      });
    }
    // The IPv6 loopback and private-use schemes only when the operator allows them.
    const open = oauthSetup({
      oauth: { redirectUris: { allowIpv6Loopback: true, allowPrivateUseSchemes: true } },
    }).ik;
    expect((await registerWith(open, ["http://[::1]:7000/cb"])).httpStatus).toBe(201);
    expect((await registerWith(open, ["com.example.app:/cb"])).httpStatus).toBe(201);
    expect((await registerWith(open, ["javascript:alert(1)"])).httpStatus).toBe(400);
  });

  it("row 8: a loopback redirect URI ignores only the port; host, scheme, path and query must match", async () => {
    const { ik, client, accountId } = await connected();
    // Registered: http://127.0.0.1/callback
    const status = async (redirectUri: string) =>
      (
        await ik.oauth.authorize.begin({
          params: await authorizeParams(client.clientId, { redirect_uri: redirectUri }),
          accountId,
        })
      ).status;
    expect(await status("http://127.0.0.1/callback")).toBe("consent");
    expect(await status("http://127.0.0.1:5000/callback")).toBe("consent");
    expect(await status("http://127.0.0.1:65535/callback")).toBe("consent");
    expect(await status("http://localhost:5000/callback")).toBe("invalid");
    expect(await status("http://localhost/callback")).toBe("invalid");
    expect(await status("http://127.0.0.1:5000/callback?x=1")).toBe("invalid");
    expect(await status("http://127.0.0.1:5000/callback/")).toBe("invalid");
    expect(await status("http://127.0.0.1:5000/Callback")).toBe("invalid");
    expect(await status("https://127.0.0.1:5000/callback")).toBe("invalid");
    expect(await status("http://127.0.0.1:5000/callback#x")).toBe("invalid");
    expect(await status("http://127.0.0.2:5000/callback")).toBe("invalid");
    // A port written on a non-loopback registration must match exactly.
    const web = await createOAuthTestClient(ik.oauth, {
      redirectUri: "https://app.example.com:8443/cb",
    });
    const webStatus = async (redirectUri: string) =>
      (
        await ik.oauth.authorize.begin({
          params: await authorizeParams(web.clientId, { redirect_uri: redirectUri }),
          accountId,
        })
      ).status;
    expect(await webStatus("https://app.example.com:8443/cb")).toBe("consent");
    expect(await webStatus("https://app.example.com:9443/cb")).toBe("invalid");
    expect(await webStatus("https://app.example.com/cb")).toBe("invalid");
  });

  it("row 9: every authorization response carries the static issuer as iss", async () => {
    const { ik, client, accountId } = await connected();
    expect(ik.oauth.metadata.authorizationServer()).toMatchObject({
      issuer: ISSUER,
      authorization_response_iss_parameter_supported: true,
    });
    const approvedFlow = await client.authorize(accountId);
    expect(approvedFlow.location.searchParams.get("iss")).toBe(ISSUER);
    const begun = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId),
      accountId,
    });
    if (begun.status !== "consent") throw new Error(begun.status);
    const denied = await ik.oauth.authorize.deny({ ticket: begun.ticket, accountId });
    if (denied.status !== "redirect") throw new Error(denied.status);
    expect(new URL(denied.location).searchParams.get("iss")).toBe(ISSUER);
  });

  it("row 10: an older refresh token after the rotation ends the grant", async () => {
    const { ik, client, accountId, clock, audit } = await connected();
    const first = await refreshTokenOf(client, accountId);
    clock.advanceSeconds(60);
    const second = tokensOf(await client.refresh(first.refreshToken));
    clock.advanceSeconds(60);
    const third = tokensOf(await client.refresh(second.refresh));
    // The first token is two rotations old: a copy in other hands.
    expect(errorOf(await client.refresh(first.refreshToken))).toBe("invalid_grant");
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    expect(errorOf(await client.refresh(third.refresh))).toBe("invalid_grant");
    expect((await ik.oauth.validateAccessToken(third.access)).status).toBe("refused");
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["refresh_reuse"]);
  });

  it("row 11: the previous refresh token gets a grace only right after the rotation, and issues nothing", async () => {
    const { ik, client, accountId, clock } = await connected();
    const first = await refreshTokenOf(client, accountId);
    const rotated = tokensOf(await client.refresh(first.refreshToken));
    clock.advanceSeconds(10);
    const raced = await client.refresh(first.refreshToken);
    expect(errorOf(raced)).toBe("invalid_grant");
    expect(raced.body).not.toHaveProperty("access_token");
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
    expect((await ik.oauth.validateAccessToken(rotated.access)).status).toBe("valid");
    clock.advanceSeconds(21);
    expect(errorOf(await client.refresh(first.refreshToken))).toBe("invalid_grant");
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    // With the grace off, the previous token ends the grant at once.
    const strict = await connected({ oauth: { refreshRaceGraceSeconds: 0 } });
    const token = await refreshTokenOf(strict.client, strict.accountId);
    await strict.client.refresh(token.refreshToken);
    expect(errorOf(await strict.client.refresh(token.refreshToken))).toBe("invalid_grant");
    expect(await strict.ik.oauth.listGrants(strict.accountId)).toEqual([]);
  });

  it("row 12: parallel refreshes with one token issue one pair and keep the grant", async () => {
    const { ik, client, accountId } = await connected();
    const { refreshToken } = await refreshTokenOf(client, accountId);
    const results = await Promise.all(
      Array.from({ length: 10 }, () => client.refresh(refreshToken)),
    );
    const won = results.filter((r) => r.httpStatus === 200);
    expect(won).toHaveLength(1);
    expect(results.filter((r) => errorOf(r) === "invalid_grant")).toHaveLength(9);
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
    const [winner] = won;
    if (!winner) throw new Error("no winner");
    expect((await client.refresh(tokensOf(winner).refresh)).httpStatus).toBe(200);
  });

  it("row 13: another client can neither refresh nor revoke a client's tokens", async () => {
    const { ik, client, accountId } = await connected();
    const tokens = await refreshTokenOf(client, accountId);
    const other = await createOAuthTestClient(ik.oauth);
    expect(errorOf(await other.refresh(tokens.refreshToken))).toBe("invalid_grant");
    expect((await other.revoke(tokens.refreshToken)).httpStatus).toBe(200);
    expect((await other.revoke(tokens.accessToken)).httpStatus).toBe(200);
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
    expect((await ik.oauth.validateAccessToken(tokens.accessToken)).status).toBe("valid");
    expect((await client.refresh(tokens.refreshToken)).httpStatus).toBe(200);
  });

  it("row 14: registrations per address and per day are capped, the address first", async () => {
    const { ik, audit } = oauthSetup({
      oauth: { registration: { maxPerAddressPerDay: 3, maxPerDay: 5 } },
    });
    for (let i = 0; i < 3; i += 1) {
      expect((await registerWith(ik, ["http://127.0.0.1/cb"], "198.51.100.1")).httpStatus).toBe(
        201,
      );
    }
    const blocked = await registerWith(ik, ["http://127.0.0.1/cb"], "198.51.100.1");
    expect(blocked.httpStatus).toBe(429);
    expect(blocked.body?.["error"]).toBe("temporarily_unavailable");
    expect(Number(blocked.headers["Retry-After"])).toBeGreaterThan(0);
    // The refused address used none of the deployment's registrations.
    expect((await registerWith(ik, ["http://127.0.0.1/cb"], "198.51.100.2")).httpStatus).toBe(201);
    expect((await registerWith(ik, ["http://127.0.0.1/cb"])).httpStatus).toBe(201);
    const daily = await registerWith(ik, ["http://127.0.0.1/cb"], "198.51.100.3");
    expect(daily.httpStatus).toBe(429);
    const refusals = audit.ofType("oauth.registration_refused");
    expect(refusals.map((e) => e.reason)).toEqual(["address_limit", "daily_limit"]);
    // A keyed digest of the address key, never the key itself.
    expect(refusals[0]?.addressDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(audit.events)).not.toContain("198.51.100");
  });

  it("row 15: a client secret check digests the presented secret, also for an unknown client", async () => {
    const calls: HashPurpose[] = [];
    const inner = createHmacHasher(new Uint8Array(randomBytes(32)));
    const hasher = {
      digest: (purpose: HashPurpose, value: string) => {
        calls.push(purpose);
        return inner.digest(purpose, value);
      },
    };
    const { ik } = oauthSetup({ hasher });
    const client = await createOAuthTestClient(ik.oauth, { authMethod: "client_secret_post" });
    const attempt = async (clientId: string) => {
      calls.length = 0;
      const result = await ik.oauth.token({
        form: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          client_secret: "ikcs_guess",
        }),
        authorization: null,
      });
      expect(errorOf(result)).toBe("invalid_client");
      return calls.filter((p) => p === "oauth-client-secret").length;
    };
    expect(await attempt(client.clientId)).toBe(1);
    expect(await attempt("ikc_unknownclientidxxxxx")).toBe(1);
    expect(await attempt("not a client id")).toBe(1);
  });

  it("row 16: a confidential client never passes with none, a public one never with a secret, two methods never", async () => {
    const { ik } = oauthSetup();
    const confidential = await createOAuthTestClient(ik.oauth, {
      authMethod: "client_secret_basic",
    });
    const publicClient = await createOAuthTestClient(ik.oauth);
    // A complete exchange request, so that an authenticated client gets invalid_grant (the
    // code is unknown), never one of the answers this row expects.
    const call = (form: Record<string, string>, authorization: string | null = null) =>
      ik.oauth.token({
        form: new URLSearchParams({
          grant_type: "authorization_code",
          code: `ikac_${"c".repeat(43)}`,
          redirect_uri: "http://127.0.0.1/callback",
          code_verifier: "v".repeat(43),
          ...form,
        }),
        authorization,
      });
    expect(errorOf(await call({}, confidential.credentials({}).authorization))).toBe(
      "invalid_grant",
    );
    expect(errorOf(await call({ client_id: confidential.clientId }))).toBe("invalid_client");
    expect(errorOf(await call({ client_id: publicClient.clientId, client_secret: "ikcs_x" }))).toBe(
      "invalid_client",
    );
    expect(errorOf(await call({}, `Basic ${btoa(`${publicClient.clientId}:`)}`))).toBe(
      "invalid_client",
    );
    const basic = confidential.credentials({}).authorization;
    expect(errorOf(await call({ client_secret: confidential.clientSecret ?? "" }, basic))).toBe(
      "invalid_request",
    );
    expect(errorOf(await call({ client_id: publicClient.clientId }, basic))).toBe(
      "invalid_request",
    );
  });

  it("row 17: no secret, digest, ref, redirect URI, state or client name in events or errors", async () => {
    const { ik, audit, hasher, account } = oauthSetup();
    const accountId = await account();
    const client = await createOAuthTestClient(ik.oauth, {
      authMethod: "client_secret_post",
      name: "Leaky Name",
      redirectUri: "https://app.example.com/secret-path",
    });
    const state = "state-value-123";
    const authorized = await client.authorize(accountId, { state, optInScopes: ["mcp:events"] });
    const exchanged = await client.exchange(authorized.code, authorized.verifier);
    const first = tokensOf(exchanged);
    const refreshed = tokensOf(await client.refresh(first.refresh));
    const failures = [
      await client.refresh(first.refresh),
      await client.exchange(authorized.code, authorized.verifier),
      await client.exchange(`ikac_${"z".repeat(43)}`, authorized.verifier),
      await ik.oauth.token({
        form: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: client.clientId,
          client_secret: "ikcs_wrong-secret-value",
        }),
        authorization: null,
      }),
    ];
    await client.revoke(refreshed.access);
    const secrets = [
      client.clientSecret ?? "",
      authorized.code,
      authorized.verifier,
      first.access,
      first.refresh,
      refreshed.access,
      refreshed.refresh,
      (first.refresh.split(".")[0] ?? "").slice(5),
      "https://app.example.com/secret-path",
      "secret-path",
      state,
      "Leaky Name",
      "wrong-secret-value",
    ];
    const digests = await Promise.all([
      hasher.digest("oauth-client-secret", client.clientSecret ?? ""),
      hasher.digest("oauth-code", authorized.code),
      hasher.digest("oauth-access-token", first.access),
      hasher.digest("oauth-refresh-token", first.refresh),
      hasher.digest("oauth-refresh-ref", (first.refresh.split(".")[0] ?? "").slice(5)),
    ]);
    const events = JSON.stringify(audit.events);
    const errors = JSON.stringify(failures.map((f) => f.body));
    expect(audit.events.length).toBeGreaterThan(5);
    for (const value of [...secrets, ...digests]) {
      expect({ value, inEvents: events.includes(value) }).toEqual({ value, inEvents: false });
      expect({ value, inErrors: errors.includes(value) }).toEqual({ value, inErrors: false });
    }
    // A thrown error carries no input either.
    const thrown = await ik.oauth.authorize
      .approve({ ticket: "x", accountId, optInScopes: ["Leaky Name"] })
      .catch((error: unknown) => error);
    expect(thrown).toBeInstanceOf(InvalidArgumentError);
    expect(String(thrown)).not.toContain("Leaky Name");
  });

  it("row 18: a token is for its resource only", async () => {
    const { ik, client, accountId } = await connected();
    const forIssuer = await client.connect(accountId, { resource: ISSUER });
    expect(
      await ik.oauth.validateAccessToken(forIssuer.accessToken, { resource: RESOURCE }),
    ).toEqual({ status: "refused", reason: "wrong_resource" });
    expect(
      (await ik.oauth.validateAccessToken(forIssuer.accessToken, { resource: ISSUER })).status,
    ).toBe("valid");
    const unknown = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId, { resource: "https://evil.example/mcp" }),
      accountId,
    });
    expect(unknown).toMatchObject({ status: "invalid", error: "invalid_target" });
    const { code, verifier } = await client.authorize(accountId, { resource: RESOURCE });
    expect(errorOf(await client.exchange(code, verifier, { resource: ISSUER }))).toBe(
      "invalid_target",
    );
  });

  it("row 19: parallel exchanges never pass the grant cap", async () => {
    const { ik, accountId } = await connected();
    const clients = await Promise.all(
      Array.from({ length: 20 }, () => createOAuthTestClient(ik.oauth)),
    );
    const codes = await Promise.all(clients.map((c) => c.authorize(accountId)));
    const results = await Promise.all(
      clients.map((c, i) => c.exchange(codes[i]?.code ?? "", codes[i]?.verifier ?? "")),
    );
    expect(results.filter((r) => r.httpStatus === 200)).toHaveLength(10);
    expect(results.filter((r) => errorOf(r) === "invalid_grant")).toHaveLength(10);
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(10);
  });

  it("row 20: a disabled account gets no grant, and its tokens stop", async () => {
    const { ik, client, accountId, account } = await connected();
    const { code, verifier } = await client.authorize(accountId);
    await ik.accounts.disable(accountId);
    expect(errorOf(await client.exchange(code, verifier))).toBe("invalid_grant");
    const other = await account();
    const tokens = await client.connect(other);
    await ik.accounts.disable(other);
    expect(await ik.oauth.validateAccessToken(tokens.accessToken)).toMatchObject({
      status: "refused",
    });
  });

  it("row 21: a consent ticket works only for its own account and only unchanged", async () => {
    const { ik, client, accountId, account } = await connected();
    const begun = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId),
      accountId,
    });
    if (begun.status !== "consent") throw new Error(begun.status);
    const attacker = await account();
    for (const decide of [
      (input: { ticket: string; accountId: string }) => ik.oauth.authorize.approve(input),
      (input: { ticket: string; accountId: string }) => ik.oauth.authorize.deny(input),
    ]) {
      expect(await decide({ ticket: begun.ticket, accountId: attacker })).toMatchObject({
        status: "invalid",
        error: "account_mismatch",
      });
    }
    const parts = begun.ticket.split(".");
    const body = parts[3] ?? "";
    const flipped = `${body.slice(0, -2)}${body.at(-2) === "A" ? "B" : "A"}${body.at(-1)}`;
    const tampered = [...parts.slice(0, 3), flipped, ...parts.slice(4)].join(".");
    expect(await ik.oauth.authorize.approve({ ticket: tampered, accountId })).toMatchObject({
      status: "invalid",
      error: "invalid_ticket",
    });
    expect(
      await ik.oauth.authorize.approve({ ticket: begun.ticket.slice(0, -1), accountId }),
    ).toMatchObject({ status: "invalid", error: "invalid_ticket" });
    // The untouched ticket still works for its account.
    expect((await ik.oauth.authorize.approve({ ticket: begun.ticket, accountId })).status).toBe(
      "redirect",
    );
  });

  it("row 22: a value sealed for another purpose never opens as a consent ticket", async () => {
    const { ik, client, accountId, sealer } = await connected();
    const begun = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId),
      accountId,
    });
    if (begun.status !== "consent") throw new Error(begun.status);
    // The same content, sealed with the same key for the OIDC transaction context.
    const content = await sealer.open(begun.ticket, "identkit/oauth/consent/v1");
    const foreign = await sealer.seal(content, "identkit/oidc/transaction/v1");
    for (const decide of [
      (input: { ticket: string; accountId: string }) => ik.oauth.authorize.approve(input),
      (input: { ticket: string; accountId: string }) => ik.oauth.authorize.deny(input),
    ]) {
      expect(await decide({ ticket: foreign, accountId })).toMatchObject({
        status: "invalid",
        error: "invalid_ticket",
      });
    }
  });

  it("row 23: a parameter sent twice is refused at authorize and at token", async () => {
    const { ik, client, accountId } = await connected();
    const params = await authorizeParams(client.clientId);
    params.append("client_id", client.clientId);
    expect(await ik.oauth.authorize.begin({ params, accountId })).toMatchObject({
      status: "invalid",
      error: "invalid_request",
    });
    const { code, verifier } = await client.authorize(accountId);
    const { form } = client.credentials({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      redirect_uri: client.redirectUri,
    });
    form.append("client_id", client.clientId);
    expect(errorOf(await ik.oauth.token({ form, authorization: null }))).toBe("invalid_request");
    // The code was not touched: the request failed before.
    expect((await client.exchange(code, verifier)).httpStatus).toBe(200);
  });

  it("row 25: scopes grow only through approve, never at refresh", async () => {
    const { ik, client, accountId } = await connected();
    const begun = await ik.oauth.authorize.begin({
      params: await authorizeParams(client.clientId, { scope: "admin mcp:read" }),
      accountId,
    });
    if (begun.status !== "consent") throw new Error(begun.status);
    expect(begun.requestedOptInScopes).toEqual([]);
    await expect(
      ik.oauth.authorize.approve({ ticket: begun.ticket, accountId, optInScopes: ["admin"] }),
    ).rejects.toThrow(InvalidArgumentError);
    const approved = await ik.oauth.authorize.approve({ ticket: begun.ticket, accountId });
    if (approved.status !== "redirect") throw new Error(approved.status);
    const tokens = await client.connect(accountId);
    expect(tokens.result.body?.["scope"]).toBe("mcp:read");
    if (tokens.refreshToken === null) throw new Error("no refresh token");
    expect(
      errorOf(await client.refresh(tokens.refreshToken, { scope: "mcp:read mcp:events" })),
    ).toBe("invalid_scope");
    expect(await ik.oauth.validateAccessToken(tokens.accessToken)).toMatchObject({
      status: "valid",
      scopes: ["mcp:read"],
    });
  });

  it("row 26: a hostile client_name loses control, bidi and separator characters and is cut at 100", async () => {
    const { ik, audit } = oauthSetup();
    const hostile = `‮evil​\u0007${"x".repeat(200)} `;
    const result = await ik.oauth.register({ body: registration({ client_name: hostile }) });
    const name = String(result.body?.["client_name"]);
    expect(name).toBe(`evil${"x".repeat(96)}`);
    expect(Array.from(name)).toHaveLength(100);
    const view = await ik.oauth.getClient(String(result.body?.["client_id"]));
    expect(view?.name).toBe(name);
    // A name of nothing visible is no name.
    const blank = await ik.oauth.register({ body: registration({ client_name: "‮ ㅤ" }) });
    expect(blank.body).not.toHaveProperty("client_name");
    // The name never reaches an audit event.
    expect(JSON.stringify(audit.events)).not.toContain("evil");
  });
});
