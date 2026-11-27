import { describe, expect, it } from "vitest";
import { InvalidArgumentError, OperationRolledBackError } from "../src/index.js";
import { createOAuthTestClient, type OAuthTestClientOptions } from "../src/testing/index.js";
import { ISSUER, oauthSetup, RESOURCE } from "./oauth-helpers.js";

const ACCESS = /^ikat_[A-Za-z0-9_-]{43}$/;
const REFRESH = /^ikrt_[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;

const compareText = (a: string | undefined, b: string | undefined) =>
  (a ?? "").localeCompare(b ?? "");
const encode = (value: string) => encodeURIComponent(value).replace(/%20/g, "+");
const clientCredentialsForm = () => new URLSearchParams({ grant_type: "client_credentials" });

async function connected(
  setupOptions: Parameters<typeof oauthSetup>[0] = {},
  clientOptions: OAuthTestClientOptions = {},
) {
  const setup = oauthSetup(setupOptions);
  const client = await createOAuthTestClient(setup.ik.oauth, clientOptions);
  const accountId = await setup.account();
  return { ...setup, client, accountId };
}

describe("oauth token endpoint: code exchange", () => {
  it("exchanges a code for a grant with an access and a refresh token", async () => {
    const { ik, client, accountId, audit, clock, store } = await connected();
    const { code, verifier } = await client.authorize(accountId, { optInScopes: ["mcp:events"] });
    const result = await client.exchange(code, verifier);
    expect(result).toEqual({
      httpStatus: 200,
      body: {
        access_token: expect.stringMatching(ACCESS),
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: expect.stringMatching(REFRESH),
        scope: "mcp:read mcp:events",
      },
      headers: { "Cache-Control": "no-store", Pragma: "no-cache" },
    });
    const [grant] = await ik.oauth.listGrants(accountId);
    expect(grant).toEqual({
      id: expect.any(String),
      accountId,
      clientId: client.clientId,
      scopes: ["mcp:read", "mcp:events"],
      resource: RESOURCE,
      createdAt: clock.now(),
      expiresAt: new Date(clock.now().getTime() + 90 * 86_400_000),
      refreshedAt: null,
      source: "created",
    });
    expect(audit.ofType("oauth.grant_created")).toEqual([
      expect.objectContaining({
        accountId,
        clientId: client.clientId,
        grantId: grant?.id,
        scopes: ["mcp:read", "mcp:events"],
      }),
    ]);
    expect((await store.oauth?.findClient(client.clientId))?.lastUsedAt).toEqual(clock.now());
  });

  it("authenticates confidential clients by Basic and by form, and public clients by id", async () => {
    for (const authMethod of ["client_secret_basic", "client_secret_post", "none"] as const) {
      const { client, accountId } = await connected({}, { authMethod });
      const connectedClient = await client.connect(accountId);
      expect(connectedClient.result.httpStatus).toBe(200);
    }
  });

  it("decodes Basic credentials as form-encoded (RFC 6749 section 2.3.1)", async () => {
    const { ik, store, hasher } = oauthSetup();
    // An imported client id and secret with characters that the form encoding changes.
    const id = "legacy+client";
    const secret = "s3cr3t with spaces+plus";
    await store.oauth?.insertClient({
      id,
      secretDigest: await hasher.digest("oauth-client-secret", secret),
      secretDigestAlgorithm: "hmac-sha256",
      authMethod: "client_secret_basic",
      grantTypes: ["authorization_code"],
      redirectUris: ["http://127.0.0.1/callback"],
      name: null,
      source: "import",
      createdAt: new Date(0),
      lastUsedAt: null,
    });
    const encoded = await ik.oauth.token({
      form: clientCredentialsForm(),
      authorization: `Basic ${btoa(`${encode(id)}:${encode(secret)}`)}`,
    });
    // Authenticated: the grant type is the next check.
    expect(encoded.body?.["error"]).toBe("unsupported_grant_type");
    // Not encoded, "+" reads as a space: another id and another secret.
    const raw = await ik.oauth.token({
      form: clientCredentialsForm(),
      authorization: `Basic ${btoa(`${id}:${secret}`)}`,
    });
    expect(raw.body?.["error"]).toBe("invalid_client");
  });

  const unauthenticated: [
    string,
    (c: { clientId: string; clientSecret: string | null }) => {
      form: Record<string, string>;
      authorization: string | null;
    },
    boolean,
  ][] = [
    ["no credentials", () => ({ form: {}, authorization: null }), false],
    [
      "an unknown client",
      () => ({ form: { client_id: "ikc_nobody" }, authorization: null }),
      false,
    ],
    [
      "a wrong secret by form",
      (c) => ({
        form: { client_id: c.clientId, client_secret: "ikcs_wrong" },
        authorization: null,
      }),
      false,
    ],
    [
      "a wrong secret by Basic",
      (c) => ({ form: {}, authorization: `Basic ${btoa(`${c.clientId}:ikcs_wrong`)}` }),
      true,
    ],
    ["a malformed Basic header", () => ({ form: {}, authorization: "Basic !!!" }), true],
    [
      "a Basic header without a colon",
      (c) => ({ form: {}, authorization: `Basic ${btoa(c.clientId)}` }),
      true,
    ],
    ["another scheme", (c) => ({ form: {}, authorization: `Bearer ${c.clientId}` }), true],
    [
      "a confidential client without its secret",
      (c) => ({ form: { client_id: c.clientId }, authorization: null }),
      false,
    ],
  ];
  it.each(unauthenticated)("answers 401 invalid_client for %s", async (_, build, basic) => {
    const { ik, client } = await connected({}, { authMethod: "client_secret_basic" });
    const { form, authorization } = build(client);
    const result = await ik.oauth.token({
      form: new URLSearchParams({ grant_type: "authorization_code", ...form }),
      authorization,
    });
    expect(result.httpStatus).toBe(401);
    expect(result.body).toEqual({ error: "invalid_client", error_description: expect.any(String) });
    if (basic) expect(result.headers["WWW-Authenticate"]).toBe('Basic realm="example.com"');
    else expect(result.headers).not.toHaveProperty("WWW-Authenticate");
  });

  it("refuses missing parameters, an unknown grant type and a code grant the client may not use", async () => {
    const { ik, client, store } = await connected();
    const call = (form: Record<string, string>) => ik.oauth.token(client.credentials(form));
    expect((await call({})).body?.["error"]).toBe("invalid_request");
    expect((await call({ grant_type: "password" })).body?.["error"]).toBe("unsupported_grant_type");
    expect((await call({ grant_type: "authorization_code", code: "x" })).body?.["error"]).toBe(
      "invalid_request",
    );
    await store.oauth?.insertClient({
      id: "refresh-only",
      secretDigest: null,
      secretDigestAlgorithm: null,
      authMethod: "none",
      grantTypes: ["refresh_token"],
      redirectUris: ["http://127.0.0.1/callback"],
      name: null,
      source: "import",
      createdAt: new Date(0),
      lastUsedAt: null,
    });
    const refused = await ik.oauth.token({
      form: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: "refresh-only",
        code: "ikac_x",
        redirect_uri: "http://127.0.0.1/callback",
        code_verifier: "v".repeat(43),
      }),
      authorization: null,
    });
    expect(refused.body?.["error"]).toBe("unauthorized_client");
    await expect(ik.oauth.token({ form: "x" as never, authorization: null })).rejects.toThrow(
      InvalidArgumentError,
    );
  });

  it("needs redirect_uri at the token endpoint only if the authorization request named it", async () => {
    const { ik, client, accountId, audit } = await connected();
    const withoutUri = (code: string, verifier: string) =>
      ik.oauth.token(
        client.credentials({ grant_type: "authorization_code", code, code_verifier: verifier }),
      );
    const omitted = await client.authorize(accountId, { redirectUri: null });
    expect((await withoutUri(omitted.code, omitted.verifier)).httpStatus).toBe(200);
    const omittedThenSent = await client.authorize(accountId, { redirectUri: null });
    expect((await client.exchange(omittedThenSent.code, omittedThenSent.verifier)).httpStatus).toBe(
      200,
    );
    const omittedThenWrong = await client.authorize(accountId, { redirectUri: null });
    const wrong = await client.exchange(omittedThenWrong.code, omittedThenWrong.verifier, {
      redirect_uri: "http://127.0.0.1/other",
    });
    expect(wrong.body?.["error"]).toBe("invalid_grant");
    const named = await client.authorize(accountId);
    const missing = await withoutUri(named.code, named.verifier);
    expect(missing.body?.["error"]).toBe("invalid_grant");
    expect(audit.ofType("oauth.token_failed").map((e) => e.reason)).toEqual([
      "redirect_mismatch",
      "redirect_mismatch",
    ]);
  });

  it("refuses an expired code, a disabled account and a policy refusal, each with token_failed", async () => {
    let verdict = true;
    const { ik, client, accountId, clock, audit } = await connected({
      oauth: { admit: () => verdict },
    });
    const late = await client.authorize(accountId);
    clock.advanceSeconds(300);
    expect((await client.exchange(late.code, late.verifier)).body?.["error"]).toBe("invalid_grant");
    const refusedByPolicy = await client.authorize(accountId);
    verdict = false;
    expect(
      (await client.exchange(refusedByPolicy.code, refusedByPolicy.verifier)).body?.["error"],
    ).toBe("invalid_grant");
    verdict = true;
    const disabled = await client.authorize(accountId);
    await ik.accounts.disable(accountId);
    expect((await client.exchange(disabled.code, disabled.verifier)).body?.["error"]).toBe(
      "invalid_grant",
    );
    expect(audit.ofType("oauth.token_failed").map((e) => e.reason)).toEqual([
      "code_expired",
      "refused_by_policy",
      "account_disabled",
    ]);
    expect(audit.ofType("oauth.token_failed").every((e) => e.clientId === client.clientId)).toBe(
      true,
    );
  });

  it("a second exchange for the same client replaces its grant", async () => {
    const { ik, client, accountId, audit } = await connected();
    const first = await client.connect(accountId);
    const second = await client.connect(accountId);
    expect(await ik.oauth.validateAccessToken(first.accessToken)).toEqual({
      status: "refused",
      reason: "unknown",
    });
    expect((await ik.oauth.validateAccessToken(second.accessToken)).status).toBe("valid");
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["replaced"]);
  });

  it("refuses a new client at the grant cap; the cap counts other clients only", async () => {
    const setup = oauthSetup({ oauth: { maxGrantsPerAccount: 2 } });
    const accountId = await setup.account();
    const clients = await Promise.all(
      Array.from({ length: 3 }, () => createOAuthTestClient(setup.ik.oauth)),
    );
    const [a, b, c] = clients;
    if (!a || !b || !c) throw new Error("no clients");
    await a.connect(accountId);
    await b.connect(accountId);
    const { code, verifier } = await c.authorize(accountId);
    const refused = await c.exchange(code, verifier);
    expect(refused.body).toEqual({
      error: "invalid_grant",
      error_description: "The account has too many connected applications.",
    });
    expect((await a.connect(accountId)).result.httpStatus).toBe(200);
    expect(setup.audit.ofType("oauth.token_failed").map((e) => e.reason)).toEqual(["grant_limit"]);
  });

  it("issues no refresh token under refreshTokens if_registered to a client that did not register it", async () => {
    const { client, accountId } = await connected(
      { oauth: { refreshTokens: "if_registered" } },
      { grantTypes: ["authorization_code"] },
    );
    const { refreshToken, result } = await client.connect(accountId);
    expect(refreshToken).toBeNull();
    expect(result.body).not.toHaveProperty("refresh_token");
    const refused = await client.refresh("ikrt_x");
    expect(refused.body?.["error"]).toBe("unauthorized_client");
  });

  it("caps the access token at the grant's end", async () => {
    const { client, accountId } = await connected({
      oauth: { grantSeconds: 3600, refreshTokenSeconds: 3600, accessTokenSeconds: 3600 },
    });
    const { result } = await client.connect(accountId);
    expect(result.body?.["expires_in"]).toBe(3600);
  });

  it("deletes the grant again if the sink refuses grant_created", async () => {
    const { ik, client, accountId, audit } = await connected();
    const { code, verifier } = await client.authorize(accountId);
    const emit = audit.emit.bind(audit);
    audit.emit = (event) => {
      if (event.type === "oauth.grant_created") throw new Error("sink down");
      return emit(event);
    };
    await expect(client.exchange(code, verifier)).rejects.toThrow(OperationRolledBackError);
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
  });

  it("a refused grant_created on a re-authorization records the replaced grant's end", async () => {
    const { ik, client, accountId, audit } = await connected();
    const first = await client.connect(accountId);
    const [old] = await ik.oauth.listGrants(accountId);
    const { code, verifier } = await client.authorize(accountId);
    const emit = audit.emit.bind(audit);
    audit.emit = (event) => {
      if (event.type === "oauth.grant_created") throw new Error("sink down");
      return emit(event);
    };
    await expect(client.exchange(code, verifier)).rejects.toThrow(OperationRolledBackError);
    expect(await ik.oauth.validateAccessToken(first.accessToken)).toEqual({
      status: "refused",
      reason: "unknown",
    });
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    expect(audit.ofType("oauth.grant_ended")).toEqual([
      expect.objectContaining({ grantId: old?.id, clientId: client.clientId, reason: "replaced" }),
    ]);
  });

  it("a refused grant_ended of the replaced grant rolls the new grant back", async () => {
    const { ik, client, accountId, audit } = await connected();
    await client.connect(accountId);
    const { code, verifier } = await client.authorize(accountId);
    const emit = audit.emit.bind(audit);
    audit.emit = (event) => {
      if (event.type === "oauth.grant_ended") throw new Error("sink down");
      return emit(event);
    };
    await expect(client.exchange(code, verifier)).rejects.toThrow(OperationRolledBackError);
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    expect(audit.ofType("oauth.grant_created")).toHaveLength(1);
  });
});

describe("oauth revocation and administration", () => {
  it("an admin client delete records grant_ended for each grant it ended", async () => {
    const { ik, client, accountId, audit, account } = await connected();
    const otherAccount = await account();
    const a = await client.connect(accountId);
    const b = await client.connect(otherAccount);
    const grantIds = [
      ...(await ik.oauth.listGrants(accountId)),
      ...(await ik.oauth.listGrants(otherAccount)),
    ].map((g) => g.id);
    const emit = audit.emit.bind(audit);
    let refused = false;
    audit.emit = (event) => {
      if (event.type === "oauth.grant_ended" && !refused) {
        refused = true;
        throw new Error("sink down");
      }
      return emit(event);
    };
    await expect(ik.oauth.deleteClient(client.clientId)).rejects.toThrow("sink down");
    expect(await ik.oauth.getClient(client.clientId)).toBeNull();
    for (const tokens of [a, b]) {
      expect((await ik.oauth.validateAccessToken(tokens.accessToken)).status).toBe("refused");
    }
    expect(audit.ofType("oauth.client_deleted")).toHaveLength(1);
    // The first grant_ended was refused; the second was still sent.
    expect(audit.ofType("oauth.grant_ended")).toEqual([
      expect.objectContaining({ clientId: client.clientId, reason: "client_deleted" }),
    ]);
    expect(grantIds).toContain(audit.ofType("oauth.grant_ended")[0]?.grantId);
    audit.emit = emit;
    const fresh = await createOAuthTestClient(ik.oauth);
    await fresh.connect(accountId);
    await fresh.connect(otherAccount);
    expect(await ik.oauth.deleteClient(fresh.clientId)).toBe(true);
    const ended = audit.ofType("oauth.grant_ended").slice(1);
    expect(ended.map((e) => e.accountId).toSorted(compareText)).toEqual(
      [accountId, otherAccount].toSorted(compareText),
    );
    expect(ended.every((e) => e.reason === "client_deleted")).toBe(true);
  });

  it("the client revokes by access or refresh token; the grant ends", async () => {
    const { ik, client, accountId, audit } = await connected();
    for (const pick of ["accessToken", "refreshToken"] as const) {
      const tokens = await client.connect(accountId);
      const token = tokens[pick];
      if (token === null) throw new Error("no token");
      expect(await client.revoke(token)).toEqual({
        httpStatus: 200,
        body: null,
        headers: { "Cache-Control": "no-store", Pragma: "no-cache" },
      });
      expect((await ik.oauth.validateAccessToken(tokens.accessToken)).status).toBe("refused");
      expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    }
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual([
      "revoked_by_client",
      "revoked_by_client",
    ]);
    // Unknown and malformed tokens: 200, nothing happens.
    expect((await client.revoke("ikat_unknown")).httpStatus).toBe(200);
    expect((await client.revoke("garbage")).httpStatus).toBe(200);
    const missing = await ik.oauth.revoke(client.credentials({}));
    expect(missing.body?.["error"]).toBe("invalid_request");
  });

  it("lists, revokes one and revokes all grants of an account", async () => {
    const { ik, client, accountId, audit, clock } = await connected();
    const other = await createOAuthTestClient(ik.oauth);
    await client.connect(accountId);
    clock.advanceSeconds(1);
    const second = await other.connect(accountId);
    const grants = await ik.oauth.listGrants(accountId);
    expect(grants.map((g) => g.clientId)).toEqual([client.clientId, other.clientId]);
    const [first] = grants;
    if (!first) throw new Error("no grant");
    expect(await ik.oauth.revokeGrant({ accountId: "someone-else", grantId: first.id })).toBe(
      false,
    );
    expect(await ik.oauth.revokeGrant({ accountId, grantId: first.id })).toBe(true);
    expect(await ik.oauth.revokeGrant({ accountId, grantId: first.id })).toBe(false);
    expect(await ik.oauth.revokeAll(accountId)).toBe(1);
    expect(await ik.oauth.revokeAll(accountId)).toBe(0);
    expect((await ik.oauth.validateAccessToken(second.accessToken)).status).toBe("refused");
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual([
      "revoked",
      "revoked_all",
    ]);
  });

  it("the metadata issuer is the iss of every flow", async () => {
    const { client, accountId } = await connected();
    const { location } = await client.authorize(accountId);
    expect(location.searchParams.get("iss")).toBe(ISSUER);
  });
});
