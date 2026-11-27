import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../src/index.js";
import { createOAuthTestClient } from "../src/testing/index.js";
import { oauthSetup } from "./oauth-helpers.js";

async function connected(setupOptions: Parameters<typeof oauthSetup>[0] = {}) {
  const setup = oauthSetup(setupOptions);
  const client = await createOAuthTestClient(setup.ik.oauth);
  const accountId = await setup.account();
  const tokens = await client.connect(accountId, { optInScopes: ["mcp:events"] });
  if (tokens.refreshToken === null) throw new Error("no refresh token");
  return { ...setup, client, accountId, tokens, refreshToken: tokens.refreshToken };
}

const tokensOf = (result: { body: Record<string, unknown> | null }) => ({
  access: String(result.body?.["access_token"]),
  refresh: String(result.body?.["refresh_token"]),
});

describe("oauth refresh", () => {
  it("rotates: a new pair, the same ref, the grant generation and refresh time move on", async () => {
    const { ik, client, refreshToken, tokens, clock, audit, accountId } = await connected();
    clock.advanceSeconds(60);
    const result = await client.refresh(refreshToken);
    expect(result.httpStatus).toBe(200);
    const next = tokensOf(result);
    expect(next.refresh).not.toBe(refreshToken);
    expect(next.refresh.split(".")[0]).toBe(refreshToken.split(".")[0]);
    expect(result.body?.["scope"]).toBe("mcp:read mcp:events");
    // Earlier access tokens stay valid until they expire (another instance may hold one).
    expect((await ik.oauth.validateAccessToken(tokens.accessToken)).status).toBe("valid");
    expect((await ik.oauth.validateAccessToken(next.access)).status).toBe("valid");
    const [grant] = await ik.oauth.listGrants(accountId);
    expect(grant?.refreshedAt).toEqual(clock.now());
    expect(audit.ofType("oauth.token_refreshed")).toEqual([
      expect.objectContaining({ accountId, clientId: client.clientId, grantId: grant?.id }),
    ]);
    // The new refresh token rotates again.
    clock.advanceSeconds(60);
    expect((await client.refresh(next.refresh)).httpStatus).toBe(200);
  });

  it("narrows the scope of the new access token; a wider scope is invalid_scope", async () => {
    const { ik, client, refreshToken } = await connected();
    const narrowed = await client.refresh(refreshToken, { scope: "mcp:read" });
    expect(narrowed.body?.["scope"]).toBe("mcp:read");
    const access = tokensOf(narrowed).access;
    expect(await ik.oauth.validateAccessToken(access)).toMatchObject({ scopes: ["mcp:read"] });
    const wider = await client.refresh(tokensOf(narrowed).refresh, { scope: "mcp:read admin" });
    expect(wider.body?.["error"]).toBe("invalid_scope");
  });

  it("an expired refresh token or grant ends the grant", async () => {
    const { ik, client, refreshToken, clock, accountId, audit } = await connected();
    clock.advanceSeconds(30 * 86_400);
    expect((await client.refresh(refreshToken)).body?.["error"]).toBe("invalid_grant");
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["expired"]);
  });

  it("a refresh token's life is capped at the grant's end", async () => {
    const { client, refreshToken, clock } = await connected({
      oauth: { grantSeconds: 40 * 86_400 },
    });
    clock.advanceSeconds(20 * 86_400);
    const first = await client.refresh(refreshToken);
    expect(first.httpStatus).toBe(200);
    // Refreshed at day 20: 30 more days would pass the grant's end at day 40.
    clock.advanceSeconds(20 * 86_400);
    expect((await client.refresh(tokensOf(first).refresh)).body?.["error"]).toBe("invalid_grant");
  });

  it("a disabled account or a policy refusal refuses the refresh and keeps the grant", async () => {
    let verdict = true;
    const { ik, client, refreshToken, accountId, store } = await connected({
      oauth: { admit: (request) => (request.phase === "refresh" ? verdict : true) },
    });
    verdict = false;
    expect((await client.refresh(refreshToken)).body?.["error"]).toBe("invalid_grant");
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
    verdict = true;
    await store.accounts.setStatus(accountId, "disabled");
    expect((await client.refresh(refreshToken)).body?.["error"]).toBe("invalid_grant");
    await store.accounts.setStatus(accountId, "active");
    // The token was never rotated, so it still works.
    expect((await client.refresh(refreshToken)).httpStatus).toBe(200);
  });

  it("a refused token_refreshed event does not fail the refresh; onAuditError gets it", async () => {
    const reported: AuditEvent[] = [];
    const { client, refreshToken, audit } = await connected({
      oauth: {
        onAuditError: (_error, event) => {
          reported.push(event);
          throw new Error("handler fails too");
        },
      },
    });
    const emit = audit.emit.bind(audit);
    audit.emit = (event) => {
      if (event.type === "oauth.token_refreshed") throw new Error("sink down");
      return emit(event);
    };
    expect((await client.refresh(refreshToken)).httpStatus).toBe(200);
    expect(reported.map((e) => e.type)).toEqual(["oauth.token_refreshed"]);
  });

  it("a failed last-used write fails neither the exchange nor a won refresh; onStoreError gets it", async () => {
    const reported: unknown[] = [];
    const setup = oauthSetup({
      oauth: {
        onStoreError: (error, write) => {
          reported.push([String(error), write]);
          throw new Error("handler fails too");
        },
      },
    });
    const oauthStore = setup.store.oauth;
    if (!oauthStore) throw new Error("no oauth store");
    oauthStore.markClientUsed = () => Promise.reject(new Error("db blip"));
    const client = await createOAuthTestClient(setup.ik.oauth);
    const accountId = await setup.account();
    const tokens = await client.connect(accountId);
    if (tokens.refreshToken === null) throw new Error("no refresh token");
    setup.clock.advanceSeconds(86_401);
    const result = await client.refresh(tokens.refreshToken);
    expect(result.httpStatus).toBe(200);
    const next = tokensOf(result);
    expect((await setup.ik.oauth.validateAccessToken(next.access)).status).toBe("valid");
    expect(await setup.ik.oauth.listGrants(accountId)).toHaveLength(1);
    expect((await client.refresh(next.refresh)).httpStatus).toBe(200);
    const write = { kind: "client_last_used", clientId: client.clientId };
    expect(reported).toEqual([
      ["Error: db blip", write],
      ["Error: db blip", write],
      ["Error: db blip", write],
    ]);
  });

  it("refuses another resource at a refresh with invalid_target and keeps the grant", async () => {
    const { ik, client, refreshToken, audit, accountId } = await connected();
    const other = await client.refresh(refreshToken, { resource: "https://example.com" });
    expect(other.body?.["error"]).toBe("invalid_target");
    expect(audit.ofType("oauth.token_failed").map((e) => e.reason)).toEqual(["resource_mismatch"]);
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
    const same = await client.refresh(refreshToken, { resource: "https://example.com/mcp" });
    expect(same.httpStatus).toBe(200);
  });

  it("records refresh_unknown when a reused token's grant was already ended", async () => {
    const { client, refreshToken, audit, store, clock } = await connected();
    const next = tokensOf(await client.refresh(refreshToken));
    expect(next.refresh).toMatch(/^ikrt_/);
    clock.advanceSeconds(60);
    const oauthStore = store.oauth;
    if (!oauthStore) throw new Error("no oauth store");
    // A concurrent call ends the grant between the read and the delete.
    oauthStore.deleteGrant = () => Promise.resolve(null);
    expect((await client.refresh(refreshToken)).body?.["error"]).toBe("invalid_grant");
    expect(audit.ofType("oauth.token_failed").map((e) => e.reason)).toEqual(["refresh_unknown"]);
    expect(audit.ofType("oauth.grant_ended")).toEqual([]);
  });

  it("refuses a malformed or unknown refresh token without ending anything", async () => {
    const { ik, client, accountId, audit } = await connected();
    for (const token of ["garbage", `ikrt_${"a".repeat(22)}.${"b".repeat(43)}`]) {
      expect((await client.refresh(token)).body?.["error"]).toBe("invalid_grant");
    }
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
    expect(audit.ofType("oauth.token_failed").map((e) => e.reason)).toEqual([
      "refresh_unknown",
      "refresh_unknown",
    ]);
    expect((await client.refresh("")).body?.["error"]).toBe("invalid_grant");
    const missing = await ik.oauth.token(client.credentials({ grant_type: "refresh_token" }));
    expect(missing.body?.["error"]).toBe("invalid_request");
  });
});
