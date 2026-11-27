import { describe, expect, it } from "vitest";
import { createIdentkit, createMemoryStore, type IdentkitStore } from "../src/index.js";
import {
  createFakeClock,
  createOAuthTestClient,
  createRecordingAuditSink,
  createRecordingMailSender,
} from "../src/testing/index.js";
import { emailFirstPolicy, testConfig } from "./helpers.js";
import { oauthSetup } from "./oauth-helpers.js";

/** A memory store whose `deleteGrantsForAccount` throws while `broken.on` is true. */
function brokenGrantStore() {
  const inner = createMemoryStore();
  const oauth = inner.oauth;
  if (!oauth) throw new Error("the memory store has oauth");
  const broken = { on: true };
  const store: IdentkitStore = {
    ...inner,
    oauth: {
      ...oauth,
      deleteGrantsForAccount: async (accountId) => {
        if (broken.on) throw new Error("no such table: identkit_oauth_grants");
        return oauth.deleteGrantsForAccount(accountId);
      },
    },
  };
  return { store, broken };
}

describe("oauth grants end when an account is disabled", () => {
  it("rule: accounts.disable ends every grant and code of the account, and only those", async () => {
    const { ik, account, audit } = oauthSetup();
    const accountId = await account();
    const other = await account();
    const a = await createOAuthTestClient(ik.oauth);
    const b = await createOAuthTestClient(ik.oauth);
    const first = await a.connect(accountId);
    const second = await b.connect(accountId);
    const kept = await a.connect(other);
    // A code in flight: approved, not exchanged yet.
    const pending = await b.authorize(other);
    const pendingOwn = await a.authorize(accountId);

    await ik.accounts.disable(accountId);

    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    for (const token of [first.accessToken, second.accessToken]) {
      // Ending a grant deletes its access tokens, so the token is unknown, not only refused.
      expect(await ik.oauth.validateAccessToken(token)).toEqual({
        status: "refused",
        reason: "unknown",
      });
    }
    const refreshed = await a.refresh(first.refreshToken ?? "");
    expect(refreshed.body).toMatchObject({ error: "invalid_grant" });
    // The account's code is gone; the other account's code still works.
    const ownExchange = await a.exchange(pendingOwn.code, pendingOwn.verifier);
    expect(ownExchange.body).toMatchObject({ error: "invalid_grant" });
    expect((await b.exchange(pending.code, pending.verifier)).httpStatus).toBe(200);
    expect((await ik.oauth.validateAccessToken(kept.accessToken)).status).toBe("valid");

    const ended = audit.ofType("oauth.grant_ended");
    expect(ended.map((e) => `${e.accountId} ${e.clientId} ${e.reason}`).toSorted()).toEqual(
      [
        `${accountId} ${a.clientId} account_disabled`,
        `${accountId} ${b.clientId} account_disabled`,
      ].toSorted(),
    );
    expect(new Set(ended.map((e) => e.grantId)).size).toBe(2);
  });

  it("rule: grants end also when the oauth option is not set, if the store has oauth", async () => {
    const { ik, store, account, hasher, sealer } = oauthSetup();
    const accountId = await account();
    const client = await createOAuthTestClient(ik.oauth);
    const tokens = await client.connect(accountId);
    const audit = createRecordingAuditSink();
    const withoutOAuth = createIdentkit({
      config: testConfig,
      policy: emailFirstPolicy,
      isPrivilegedAccount: () => false,
      store,
      hasher,
      sealer,
      mail: createRecordingMailSender(),
      audit,
      clock: createFakeClock(),
    });
    await withoutOAuth.accounts.disable(accountId);
    expect(await store.oauth?.listGrants(accountId, new Date(0))).toEqual([]);
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["account_disabled"]);
    expect(await ik.oauth.validateAccessToken(tokens.accessToken)).toMatchObject({
      reason: "unknown",
    });
  });

  it("rule: a failed grant store still revokes the sessions, runs the hook and goes up; a retry ends the grants", async () => {
    const { store, broken } = brokenGrantStore();
    const { ik, account, audit } = oauthSetup({ store });
    const accountId = await account();
    const client = await createOAuthTestClient(ik.oauth);
    const tokens = await client.connect(accountId);
    await expect(ik.accounts.disable(accountId)).rejects.toThrow(
      "no such table: identkit_oauth_grants",
    );
    expect((await ik.accounts.get(accountId))?.status).toBe("disabled");
    expect(audit.ofType("account.disabled")).toHaveLength(1);
    expect(audit.ofType("oauth.grant_ended")).toHaveLength(0);
    // The grant still stands, but a disabled account's token is refused.
    expect(await ik.oauth.validateAccessToken(tokens.accessToken)).toEqual({
      status: "refused",
      reason: "account_disabled",
    });
    broken.on = false;
    await ik.accounts.disable(accountId);
    expect(audit.ofType("account.disabled")).toHaveLength(1);
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["account_disabled"]);
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
  });
});
