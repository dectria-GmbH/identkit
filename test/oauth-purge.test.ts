import { describe, expect, it } from "vitest";
import { createMemoryStore, type IdentkitStore } from "../src/index.js";
import { createOAuthTestClient, type RecordingAuditSink } from "../src/testing/index.js";
import { oauthSetup } from "./oauth-helpers.js";

const DAY = 86_400;
const byText = (x: string | undefined, y: string | undefined) => (x ?? "").localeCompare(y ?? "");

/** Makes the audit sink throw on every event of `type`. */
function failSink(audit: RecordingAuditSink, type: string) {
  const emit = audit.emit.bind(audit);
  audit.emit = (event) => {
    if (event.type === type) throw new Error("sink down");
    return emit(event);
  };
}

describe("oauth purge", () => {
  it("deletes expired grants, codes and access tokens and old registration counts", async () => {
    const { ik, clock, audit, account } = oauthSetup({
      oauth: { grantSeconds: 3 * DAY, refreshTokenSeconds: 3600, accessTokenSeconds: 600 },
    });
    const client = await createOAuthTestClient(ik.oauth);
    const accountId = await account();
    const connected = await client.connect(accountId);
    await client.authorize(await account());
    const empty = { clients: 0, grants: 0, codes: 0, accessTokens: 0, registrationWindows: 0 };
    expect(await ik.oauth.purge()).toEqual(empty);
    clock.advanceSeconds(DAY);
    // The access token and the code expired; the grant lives; the registration was yesterday.
    expect(await ik.oauth.purge()).toEqual({
      ...empty,
      codes: 1,
      accessTokens: 1,
      registrationWindows: 1,
    });
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
    clock.advanceSeconds(2 * DAY);
    expect(await ik.oauth.purge()).toEqual({ ...empty, grants: 1 });
    expect(audit.ofType("oauth.grant_ended")).toEqual([
      expect.objectContaining({ accountId, clientId: client.clientId, reason: "expired" }),
    ]);
    expect(await ik.oauth.validateAccessToken(connected.accessToken)).toMatchObject({
      reason: "unknown",
    });
    // Used at the exchange three days ago: not idle under the default 180 days.
    expect(await ik.oauth.getClient(client.clientId)).not.toBeNull();
    expect(await ik.oauth.purge()).toEqual(empty);
  });

  it("deletes unused clients after unusedDays and idle clients after idleDays", async () => {
    const { ik, clock, audit, account } = oauthSetup({
      oauth: {
        grantSeconds: 2 * DAY,
        refreshTokenSeconds: DAY,
        clientRetention: { unusedDays: 30, idleDays: 10 },
      },
    });
    const unused = await createOAuthTestClient(ik.oauth);
    const idle = await createOAuthTestClient(ik.oauth);
    await idle.connect(await account());
    clock.advanceSeconds(10 * DAY + 1);
    // The idle client's grant expired, and its last use is more than 10 days ago.
    expect((await ik.oauth.purge()).clients).toBe(1);
    expect(await ik.oauth.getClient(idle.clientId)).toBeNull();
    expect(await ik.oauth.getClient(unused.clientId)).not.toBeNull();
    clock.advanceSeconds(20 * DAY);
    expect((await ik.oauth.purge()).clients).toBe(1);
    expect(await ik.oauth.getClient(unused.clientId)).toBeNull();
    expect(audit.ofType("oauth.client_deleted").map((e) => `${e.clientId} ${e.reason}`)).toEqual([
      `${idle.clientId} idle`,
      `${unused.clientId} unused`,
    ]);
  });

  it("keeps a client in the middle of a code exchange: the approval counts as use", async () => {
    // Review a2 r1 L4: between consumeCode and insertGrant the client holds neither a code nor
    // a grant, so a purge in that gap deleted an old unused client and the exchange failed.
    const inner = createMemoryStore();
    const innerOAuth = inner.oauth;
    if (!innerOAuth) throw new Error("the memory store has oauth");
    let purgeInGap: (() => Promise<unknown>) | null = null;
    const store: IdentkitStore = {
      ...inner,
      oauth: {
        ...innerOAuth,
        insertGrant: async (...args) => {
          const purge = purgeInGap;
          purgeInGap = null;
          if (purge) await purge();
          return innerOAuth.insertGrant(...args);
        },
      },
    };
    const { ik, clock, account } = oauthSetup({
      store,
      oauth: { clientRetention: { unusedDays: 1, idleDays: 1 } },
    });
    const client = await createOAuthTestClient(ik.oauth);
    const accountId = await account();
    clock.advanceSeconds(2 * DAY);
    const { code, verifier } = await client.authorize(accountId);
    clock.advanceSeconds(299);
    purgeInGap = () => ik.oauth.purge();
    const exchanged = await client.exchange(code, verifier);
    expect(purgeInGap).toBeNull();
    expect(exchanged.httpStatus).toBe(200);
    expect(await ik.oauth.getClient(client.clientId)).not.toBeNull();
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
  });

  it("a refused event stops no deletion and no other event; the first error goes up", async () => {
    const { ik, clock, audit, account } = oauthSetup({
      oauth: {
        grantSeconds: 2 * DAY,
        refreshTokenSeconds: DAY,
        clientRetention: { unusedDays: 1, idleDays: 1 },
      },
    });
    const a = await createOAuthTestClient(ik.oauth);
    const b = await createOAuthTestClient(ik.oauth);
    await a.connect(await account());
    await b.connect(await account());
    clock.advanceSeconds(3 * DAY);
    failSink(audit, "oauth.grant_ended");
    await expect(ik.oauth.purge()).rejects.toThrow("sink down");
    expect(
      audit
        .ofType("oauth.client_deleted")
        .map((e) => e.clientId)
        .toSorted(byText),
    ).toEqual([a.clientId, b.clientId].toSorted(byText));
    expect(await ik.oauth.getClient(a.clientId)).toBeNull();
    expect(await ik.oauth.getClient(b.clientId)).toBeNull();
  });
});
