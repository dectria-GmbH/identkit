import { describe, expect, it } from "vitest";
import { createHmacHasher, InvalidArgumentError } from "../src/index.js";
import { createOAuthTestClient } from "../src/testing/index.js";
import { ISSUER, oauthSetup, RESOURCE } from "./oauth-helpers.js";

async function connected(setupOptions: Parameters<typeof oauthSetup>[0] = {}) {
  const setup = oauthSetup(setupOptions);
  const client = await createOAuthTestClient(setup.ik.oauth);
  const accountId = await setup.account();
  const tokens = await client.connect(accountId, { optInScopes: ["mcp:events"] });
  return { ...setup, client, accountId, tokens };
}

describe("oauth validateAccessToken", () => {
  it("returns the account, client, grant, scopes and resource of a live token", async () => {
    const { ik, client, accountId, tokens, clock } = await connected();
    const [grant] = await ik.oauth.listGrants(accountId);
    expect(await ik.oauth.validateAccessToken(tokens.accessToken)).toEqual({
      status: "valid",
      accountId,
      clientId: client.clientId,
      grantId: grant?.id,
      scopes: ["mcp:read", "mcp:events"],
      resource: RESOURCE,
      expiresAt: new Date(clock.now().getTime() + 3_600_000),
    });
    expect(
      (await ik.oauth.validateAccessToken(tokens.accessToken, { resource: RESOURCE })).status,
    ).toBe("valid");
  });

  it("refuses malformed and unknown tokens, and expired tokens and grants", async () => {
    const { ik, tokens, clock } = await connected({
      oauth: { grantSeconds: 7200, refreshTokenSeconds: 3600, accessTokenSeconds: 3600 },
    });
    expect(await ik.oauth.validateAccessToken("garbage")).toEqual({
      status: "refused",
      reason: "malformed",
    });
    expect(await ik.oauth.validateAccessToken(`ikat_${"a".repeat(43)}`)).toEqual({
      status: "refused",
      reason: "unknown",
    });
    expect(await ik.oauth.validateAccessToken(5 as never)).toMatchObject({ reason: "malformed" });
    clock.advanceSeconds(3600);
    expect(await ik.oauth.validateAccessToken(tokens.accessToken)).toEqual({
      status: "refused",
      reason: "expired",
    });
  });

  it("refuses a token of a grant past its end", async () => {
    const { ik, tokens, store, hasher, accountId, clock } = await connected();
    // The grant ends a minute from now, while its access token still has an hour.
    const [view] = await ik.oauth.listGrants(accountId);
    const lookup = await store.oauth?.findGrant(view?.id ?? "");
    if (!lookup) throw new Error("no grant");
    await store.oauth?.deleteGrant(lookup.grant.id, { accountId }, clock.now());
    const shortened = { ...lookup.grant, expiresAt: new Date(clock.now().getTime() + 60_000) };
    await store.oauth?.insertGrant(
      shortened,
      {
        digest: await hasher.digest("oauth-access-token", tokens.accessToken),
        grantId: shortened.id,
        generation: 1,
        scopes: ["mcp:read"],
        createdAt: clock.now(),
        expiresAt: new Date(clock.now().getTime() + 3_600_000),
      },
      { maxOtherGrants: 10, at: clock.now() },
    );
    expect((await ik.oauth.validateAccessToken(tokens.accessToken)).status).toBe("valid");
    clock.advanceSeconds(60);
    expect(await ik.oauth.validateAccessToken(tokens.accessToken)).toEqual({
      status: "refused",
      reason: "grant_expired",
    });
  });

  it("refuses a disabled account, another resource and a token whose scopes are all removed", async () => {
    const { ik, tokens, store, accountId, hasher } = await connected();
    expect(await ik.oauth.validateAccessToken(tokens.accessToken, { resource: ISSUER })).toEqual({
      status: "refused",
      reason: "wrong_resource",
    });
    await expect(
      ik.oauth.validateAccessToken(tokens.accessToken, { resource: "https://other.example" }),
    ).rejects.toThrow(InvalidArgumentError);

    // The same store and key under options that no longer list the scopes or the resource.
    const narrowed = oauthSetup({
      store,
      hasher,
      oauth: { defaultScopes: ["other:scope"], optInScopes: [] },
    });
    expect(await narrowed.ik.oauth.validateAccessToken(tokens.accessToken)).toEqual({
      status: "refused",
      reason: "no_allowed_scope",
    });
    const fewerScopes = oauthSetup({ store, hasher, oauth: { optInScopes: [] } });
    expect(await fewerScopes.ik.oauth.validateAccessToken(tokens.accessToken)).toMatchObject({
      status: "valid",
      scopes: ["mcp:read"],
    });
    const moved = oauthSetup({ store, hasher, oauth: { resources: [ISSUER] } });
    expect(await moved.ik.oauth.validateAccessToken(tokens.accessToken)).toEqual({
      status: "refused",
      reason: "wrong_resource",
    });
    // Another hash key finds nothing.
    const otherKey = oauthSetup({ store, hasher: createHmacHasher(new Uint8Array(32).fill(7)) });
    expect(await otherKey.ik.oauth.validateAccessToken(tokens.accessToken)).toMatchObject({
      reason: "unknown",
    });

    await store.accounts.setStatus(accountId, "disabled");
    expect(await ik.oauth.validateAccessToken(tokens.accessToken)).toEqual({
      status: "refused",
      reason: "account_disabled",
    });
  });
});
