import { describe, expect, it } from "vitest";
import { InvalidArgumentError } from "../src/index.js";
import { createOAuthTestClient, createPkcePair } from "../src/testing/index.js";
import { ISSUER, oauthSetup, RESOURCE } from "./oauth-helpers.js";

async function request(
  overrides: Record<string, string | null> = {},
  clientId = "",
  redirectUri = "http://127.0.0.1/callback",
) {
  const { challenge } = await createPkcePair();
  const values: Record<string, string | null> = {
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "st-1",
    ...overrides,
  };
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(values)) if (value !== null) params.set(name, value);
  return params;
}

async function flow(setupOptions: Parameters<typeof oauthSetup>[0] = {}) {
  const setup = oauthSetup(setupOptions);
  const client = await createOAuthTestClient(setup.ik.oauth, { name: "Example client" });
  const accountId = await setup.account();
  return { ...setup, client, accountId };
}

describe("oauth authorize.begin", () => {
  it("returns a consent ticket with the client, the resource and the scopes", async () => {
    const { ik, client, accountId, clock } = await flow();
    const begun = await ik.oauth.authorize.begin({
      params: await request({ scope: "mcp:read mcp:events unknown" }, client.clientId),
      accountId,
    });
    expect(begun).toEqual({
      status: "consent",
      ticket: expect.stringMatching(/^v1\./),
      expiresAt: new Date(clock.now().getTime() + 600_000),
      client: { id: client.clientId, name: "Example client", redirectUri: client.redirectUri },
      resource: RESOURCE,
      scopes: ["mcp:read"],
      optInScopes: ["mcp:events"],
      requestedOptInScopes: ["mcp:events"],
    });
  });

  it("uses the only registered redirect URI when the request names none", async () => {
    const { ik, client, accountId } = await flow();
    const begun = await ik.oauth.authorize.begin({
      params: await request({ redirect_uri: null }, client.clientId),
      accountId,
    });
    expect(begun.status === "consent" && begun.client.redirectUri).toBe(client.redirectUri);

    const two = await ik.oauth.register({
      body: JSON.stringify({
        redirect_uris: ["http://127.0.0.1/a", "http://127.0.0.1/b"],
        token_endpoint_auth_method: "none",
      }),
    });
    const refused = await ik.oauth.authorize.begin({
      params: await request({ redirect_uri: null }, String(two.body?.["client_id"])),
      accountId,
    });
    expect(refused).toMatchObject({ status: "invalid", error: "invalid_redirect_uri" });
  });

  const invalidCases: [string, Record<string, string | null>, string][] = [
    ["a missing client_id", { client_id: null }, "invalid_request"],
    ["an unknown client", { client_id: "ikc_unknown" }, "invalid_client"],
    [
      "an unregistered redirect URI",
      { redirect_uri: "https://evil.example/cb" },
      "invalid_redirect_uri",
    ],
    ["a missing response_type", { response_type: null }, "invalid_request"],
    ["response_type token", { response_type: "token" }, "unsupported_response_type"],
    ["no PKCE method", { code_challenge_method: null }, "invalid_request"],
    ["the plain PKCE method", { code_challenge_method: "plain" }, "invalid_request"],
    ["no code challenge", { code_challenge: null }, "invalid_request"],
    ["a short code challenge", { code_challenge: "abc" }, "invalid_request"],
    ["a state above 1024 characters", { state: "s".repeat(1025) }, "invalid_request"],
    ["an unknown resource", { resource: "https://other.example/mcp" }, "invalid_target"],
  ];
  it.each(invalidCases)("refuses %s without a redirect", async (_, overrides, error) => {
    const { ik, client, accountId } = await flow();
    const params = await request({ client_id: client.clientId, ...overrides });
    const begun = await ik.oauth.authorize.begin({ params, accountId });
    expect(begun).toEqual({ status: "invalid", error, description: expect.any(String) });
  });

  it("refuses two resources as invalid_target and other repeated parameters as invalid_request", async () => {
    const { ik, client, accountId } = await flow();
    const twoResources = await request({}, client.clientId);
    twoResources.append("resource", RESOURCE);
    twoResources.append("resource", ISSUER);
    expect(await ik.oauth.authorize.begin({ params: twoResources, accountId })).toMatchObject({
      status: "invalid",
      error: "invalid_target",
    });
    const record = { client_id: client.clientId, state: ["a", "b"] } as unknown as Record<
      string,
      string
    >;
    expect(await ik.oauth.authorize.begin({ params: record, accountId })).toMatchObject({
      status: "invalid",
      error: "invalid_request",
    });
  });

  it("refuses a client that may not use the code grant", async () => {
    const { ik, store, accountId } = await flow();
    await store.oauth?.insertClient({
      id: "imported-client",
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
    expect(
      await ik.oauth.authorize.begin({ params: await request({}, "imported-client"), accountId }),
    ).toMatchObject({ status: "invalid", error: "unauthorized_client" });
  });

  it("refuses a missing or disabled account, and what the admit policy refuses", async () => {
    const seen: string[] = [];
    let verdict: unknown = true;
    const { ik, client, accountId } = await flow({
      oauth: {
        admit: (requestInfo) => {
          seen.push(`${requestInfo.phase}:${requestInfo.scopes.join(" ")}`);
          return verdict as boolean;
        },
      },
    });
    const params = await request({ scope: "mcp:events" }, client.clientId);
    expect(await ik.oauth.authorize.begin({ params, accountId: "no-such-account" })).toEqual({
      status: "refused",
      reason: "no_account",
    });
    verdict = false;
    expect(await ik.oauth.authorize.begin({ params, accountId })).toEqual({
      status: "refused",
      reason: "refused_by_policy",
    });
    expect(seen).toEqual(["authorize:mcp:read mcp:events"]);
    verdict = "yes";
    await expect(ik.oauth.authorize.begin({ params, accountId })).rejects.toThrow(TypeError);
    verdict = true;
    await ik.accounts.disable(accountId);
    expect(await ik.oauth.authorize.begin({ params, accountId })).toEqual({
      status: "refused",
      reason: "account_disabled",
    });
  });

  it("throws InvalidArgumentError for a call of the wrong shape", async () => {
    const { ik, accountId } = await flow();
    await expect(ik.oauth.authorize.begin({ params: "x" as never, accountId })).rejects.toThrow(
      InvalidArgumentError,
    );
    await expect(
      ik.oauth.authorize.begin({ params: new URLSearchParams(), accountId: "" }),
    ).rejects.toThrow(InvalidArgumentError);
  });
});

async function consent(
  setupOptions: Parameters<typeof oauthSetup>[0] = {},
  overrides: Record<string, string | null> = {},
) {
  const f = await flow(setupOptions);
  const begun = await f.ik.oauth.authorize.begin({
    params: await request(overrides, f.client.clientId),
    accountId: f.accountId,
  });
  if (begun.status !== "consent") throw new Error(begun.status);
  return { ...f, ticket: begun.ticket };
}

describe("oauth authorize.approve and deny", () => {
  it("approve stores a single-use code with the chosen scopes and redirects with code, state and iss", async () => {
    const { ik, store, audit, ticket, accountId, client, hasher } = await consent();
    const approved = await ik.oauth.authorize.approve({
      ticket,
      accountId,
      optInScopes: ["mcp:events"],
    });
    if (approved.status !== "redirect") throw new Error(approved.status);
    const location = new URL(approved.location);
    expect(`${location.origin}${location.pathname}`).toBe(client.redirectUri);
    const code = location.searchParams.get("code") ?? "";
    expect(code).toMatch(/^ikac_[A-Za-z0-9_-]{43}$/);
    expect(location.searchParams.get("state")).toBe("st-1");
    expect(location.searchParams.get("iss")).toBe(ISSUER);
    const stored = await store.oauth?.consumeCode(await hasher.digest("oauth-code", code));
    expect(stored).toMatchObject({
      clientId: client.clientId,
      accountId,
      redirectUri: client.redirectUri,
      resource: RESOURCE,
      scopes: ["mcp:read", "mcp:events"],
    });
    expect(audit.ofType("oauth.consent_approved")).toEqual([
      expect.objectContaining({
        accountId,
        clientId: client.clientId,
        scopes: ["mcp:read", "mcp:events"],
      }),
    ]);
  });

  it("approve without opt-in scopes grants the defaults only, and keeps a query of the redirect URI", async () => {
    const setup = oauthSetup();
    const client = await createOAuthTestClient(setup.ik.oauth, {
      redirectUri: "https://app.example.com/cb?tenant=a",
    });
    const accountId = await setup.account();
    const { code, location } = await client.authorize(accountId, { state: "x y" });
    expect(location.search.startsWith("?tenant=a&")).toBe(true);
    expect(location.searchParams.get("state")).toBe("x y");
    const stored = await setup.store.oauth?.consumeCode(
      await setup.hasher.digest("oauth-code", code),
    );
    expect(stored?.scopes).toEqual(["mcp:read"]);
  });

  it("approve refuses an expired ticket, a disabled account and a policy change; a gone client invalidates", async () => {
    let verdict = true;
    const { ik, ticket, accountId, clock, client } = await consent({
      oauth: { admit: () => verdict },
    });
    verdict = false;
    expect(await ik.oauth.authorize.approve({ ticket, accountId })).toEqual({
      status: "refused",
      reason: "refused_by_policy",
    });
    verdict = true;
    await ik.oauth.deleteClient(client.clientId);
    expect(await ik.oauth.authorize.approve({ ticket, accountId })).toMatchObject({
      status: "invalid",
      error: "invalid_ticket",
    });
    clock.advanceSeconds(600);
    expect(await ik.oauth.authorize.approve({ ticket, accountId })).toMatchObject({
      status: "invalid",
      error: "ticket_expired",
    });

    const other = await consent();
    await other.ik.accounts.disable(other.accountId);
    expect(
      await other.ik.oauth.authorize.approve({ ticket: other.ticket, accountId: other.accountId }),
    ).toEqual({ status: "refused", reason: "account_disabled" });
  });

  it("deny redirects with access_denied, state and iss, and records it", async () => {
    const { ik, audit, ticket, accountId, client } = await consent({}, { scope: "mcp:events" });
    const denied = await ik.oauth.authorize.deny({ ticket, accountId });
    if (denied.status !== "redirect") throw new Error(denied.status);
    const location = new URL(denied.location);
    expect(Object.fromEntries(location.searchParams)).toEqual({
      error: "access_denied",
      state: "st-1",
      iss: ISSUER,
    });
    expect(audit.ofType("oauth.consent_denied")).toEqual([
      expect.objectContaining({
        accountId,
        clientId: client.clientId,
        scopes: ["mcp:read", "mcp:events"],
      }),
    ]);
    expect(audit.ofType("oauth.consent_approved")).toEqual([]);
  });

  it("deny with a gone client renders invalid_ticket and records nothing", async () => {
    const { ik, audit, ticket, accountId, client } = await consent();
    await ik.oauth.deleteClient(client.clientId);
    expect(await ik.oauth.authorize.deny({ ticket, accountId })).toEqual({
      status: "invalid",
      error: "invalid_ticket",
      description: "The request is invalid.",
    });
    expect(audit.ofType("oauth.consent_denied")).toEqual([]);
  });

  it("a request without state redirects without state", async () => {
    const { ik, ticket, accountId } = await consent({}, { state: null });
    const approved = await ik.oauth.authorize.approve({ ticket, accountId });
    if (approved.status !== "redirect") throw new Error(approved.status);
    expect(new URL(approved.location).searchParams.has("state")).toBe(false);
  });
});
