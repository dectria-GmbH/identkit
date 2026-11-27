import { createHash, randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import type { IdentkitStore } from "../src/storage/types.js";
import { mfaPolicy, otherCode, setup, STEP, testConfig } from "./helpers.js";
import { googleClaims, guid, msClaims, oidcSetup, TENANT } from "./oidc-helpers.js";

/**
 * End-to-end flows against a database store: the services on top of the store, with parallel
 * calls where a single-use or limit rule must hold. Call it inside the describe block whose
 * setup creates the store.
 */
export function runStoreFlows(name: string, store: () => IdentkitStore) {
  it(`flows: e-mail sign-in, attempt limit and single use against ${name}`, async () => {
    const t = setup({ store: store() });
    const first = await t.codeFor("flows-person@example.org");
    const guesses = await Promise.all(
      Array.from({ length: 10 }, () =>
        t.ik.emailSignIn.verifyCode({ flowId: first.flowId, code: otherCode(first.code) }),
      ),
    );
    expect(guesses.every((g) => g.status === "failed")).toBe(true);
    expect((await store().otp.findById(first.flowId))?.attempts).toBe(
      testConfig.emailOtp.maxAttemptsPerCode,
    );

    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const second = await t.codeFor("flows-person@example.org");
    const uses = await Promise.all(
      Array.from({ length: 5 }, () => t.ik.emailSignIn.verifyCode(second)),
    );
    expect(uses.filter((u) => u.status === "signed_in")).toHaveLength(1);
  });

  it(`flows: passkey registration, sign-in, step-up and approval against ${name}`, async () => {
    const t = setup({ store: store() });
    const user = await t.userWithPasskey("flows-passkey@example.org");
    const { options } = await t.ik.passkeys.startSignIn();
    const assertion = t.authenticator.assert(options);
    expect((await t.ik.passkeys.finishSignIn(assertion)).status).toBe("signed_in");
    expect((await t.ik.passkeys.finishSignIn(assertion)).status).toBe("failed");

    const stepUp = await t.ik.stepUp.startPasskey(user.token);
    if (stepUp.status !== "ok") throw new Error("denied");
    const granted = await t.ik.stepUp.finishPasskey(
      user.token,
      t.authenticator.assert(stepUp.options),
    );
    if (granted.status !== "granted") throw new Error("not granted");
    expect((await t.ik.sessions.requireStepUp(granted.token, { methods: ["passkey"] })).ok).toBe(
      true,
    );

    const payloadHash = "b".repeat(64);
    const approval = await t.ik.approvals.start({ sessionToken: granted.token, payloadHash });
    if (approval.status !== "ok" || approval.level !== "signature") throw new Error("denied");
    const response = t.authenticator.assert(approval.options);
    expect(
      (await t.ik.approvals.verify({ sessionToken: granted.token, payloadHash, response })).status,
    ).toBe("approved");
    expect(
      (await t.ik.approvals.verify({ sessionToken: granted.token, payloadHash, response })).status,
    ).toBe("failed");
  });

  it(`flows: TOTP enrolment, second factor, replay and code approval against ${name}`, async () => {
    const t = setup({
      store: store(),
      policy: { ...mfaPolicy, approvalEvidenceLevels: ["signature", "code-confirmation"] },
    });
    const user = await t.signIn("flows-totp@example.org");
    const { secret } = await t.enrolTotp(user.token);
    const row = await store().totp.findActive(user.account.id);
    expect(row?.sealedSecret).not.toContain(secret);

    // Parallel step-ups with one code on five sessions: exactly one wins.
    t.clock.advanceSeconds(STEP);
    const tokens = [user.token];
    for (let i = 0; i < 4; i += 1) {
      const { flowId, code } = await t.codeFor("flows-totp@example.org");
      const pending = await t.ik.emailSignIn.verifyCode({ flowId, code });
      if (pending.status !== "second_factor_required") throw new Error(pending.status);
      t.clock.advanceSeconds(STEP);
      const done = await t.ik.totp.verifySecondFactor(pending.pendingToken, {
        code: t.totpCode(secret),
      });
      if (done.status !== "signed_in") throw new Error(done.status);
      tokens.push(done.token);
    }
    t.clock.advanceSeconds(STEP);
    const code = t.totpCode(secret);
    const results = await Promise.all(
      tokens.map((token) => t.ik.stepUp.verifyTotp(token, { code })),
    );
    expect(results.filter((r) => r.status === "granted")).toHaveLength(1);

    // A code approval consumes its step: the same code cannot approve twice.
    t.clock.advanceSeconds(STEP);
    const live = results.find((r) => r.status === "granted");
    if (live?.status !== "granted") throw new Error("no step-up");
    const payloadHash = "d".repeat(64);
    const approvalCode = t.totpCode(secret);
    const approvals = await Promise.all(
      [0, 1].map(async () => {
        const start = await t.ik.approvals.start({
          sessionToken: live.token,
          payloadHash,
          levels: ["code-confirmation"],
        });
        if (start.status !== "ok" || start.level !== "code-confirmation") {
          throw new Error("denied");
        }
        return t.ik.approvals.verify({
          sessionToken: live.token,
          payloadHash,
          approvalId: start.approvalId,
          code: approvalCode,
        });
      }),
    );
    expect(approvals.filter((a) => a.status === "approved")).toHaveLength(1);
  });

  it(`flows: session idle timeout against ${name}`, async () => {
    const t = setup({ store: store() });
    const { token } = await t.signIn("flows-session@example.org");
    t.clock.advanceSeconds(testConfig.sessions.idleTimeoutSeconds - 1);
    expect(await t.ik.sessions.validate(token)).not.toBeNull();
    t.clock.advanceSeconds(testConfig.sessions.idleTimeoutSeconds);
    expect(await t.ik.sessions.validate(token)).toBeNull();
  });

  it(`flows: OIDC binding, import, one link per account and concurrent first sign-ins against ${name}`, async () => {
    const t = await oidcSetup({ store: store() });
    const tag = guid().slice(-8);
    const claims = msClaims(`flows-oidc-${tag}@contoso.example`);
    const first = await t.signInWith("microsoft", claims);
    if (first.status !== "signed_in") throw new Error(first.status);
    expect(first.session.authMethods).toEqual(["oidc"]);
    expect((await t.ik.sessions.validate(first.token))?.authMethods).toEqual(["oidc"]);
    const again = await t.signInWith("microsoft", claims);
    if (again.status !== "signed_in") throw new Error(again.status);
    expect(again.account.id).toBe(first.account.id);
    expect(await t.signInWith("google", googleClaims(`flows-oidc-${tag}@contoso.example`))).toEqual(
      { status: "refused", reason: "account_has_link" },
    );

    const legacy = await t.ik.accounts.create({ email: `flows-legacy-${tag}@example.org` });
    if (legacy.status !== "created") throw new Error("no account");
    const objectId = guid();
    const imports = await Promise.all(
      [0, 1, 2].map(() =>
        t.ik.oidc.importLink({
          accountId: legacy.account.id,
          provider: "microsoft",
          tenantId: TENANT,
          objectId,
        }),
      ),
    );
    expect(imports.filter((r) => r.status === "imported")).toHaveLength(1);
    expect(imports.filter((r) => r.status === "already_linked")).toHaveLength(2);
    const migrated = await t.signInWith(
      "microsoft",
      msClaims("anything@contoso.example", { oid: objectId, xms_edov: false }),
    );
    if (migrated.status !== "signed_in") throw new Error(migrated.status);
    expect(migrated.account.id).toBe(legacy.account.id);

    const raced = googleClaims(`flows-race-${tag}@example.org`);
    const results = await Promise.all([0, 1, 2].map(() => t.signInWith("google", raced)));
    const accounts = new Set(
      results.map((r) => (r.status === "signed_in" ? r.account.id : r.status)),
    );
    expect(accounts.size).toBe(1);
    expect(await t.ik.oidc.listLinks(String([...accounts][0]))).toHaveLength(1);
  });

  it(`flows: API tokens, cap under parallel creates, verify, lastUsedAt, revoke and disable against ${name}`, async () => {
    const t = setup({
      store: store(),
      apiTokens: {
        prefix: "pat_",
        allowedScopes: ["read", "write"],
        maxActiveTokensPerAccount: 3,
        acceptLegacyDigests: true,
      },
    });
    const tag = randomBytes(6).toString("hex");
    const created = await t.ik.accounts.create({ email: `flows-tokens-${tag}@example.org` });
    if (created.status !== "created") throw new Error(created.status);
    const accountId = created.account.id;
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        t.ik.apiTokens.create({
          accountId,
          name: "ci",
          scopes: ["write", "read"],
          expiresInDays: 7,
        }),
      ),
    );
    const tokens = results.flatMap((r) => (r.status === "created" ? [r] : []));
    expect(tokens).toHaveLength(3);
    expect(results.filter((r) => r.status === "limit_reached")).toHaveLength(5);
    const [first, second] = tokens;
    if (!first || !second) throw new Error("no tokens");

    const verified = await Promise.all([0, 1, 2, 3].map(() => t.ik.apiTokens.verify(first.token)));
    expect(verified.every((v) => v.status === "valid")).toBe(true);
    expect(verified[0]).toEqual({
      status: "valid",
      accountId,
      tokenId: first.apiToken.id,
      scopes: ["write", "read"],
      expiresAt: first.apiToken.expiresAt,
    });
    expect(t.audit.ofType("api_token.used")).toHaveLength(1);
    t.clock.advanceSeconds(3600);
    await t.ik.apiTokens.verify(first.token);
    expect(t.audit.ofType("api_token.used")).toHaveLength(2);
    const listed = await t.ik.apiTokens.list(accountId);
    expect(listed).toHaveLength(3);
    expect(listed.find((v) => v.id === first.apiToken.id)?.lastUsedAt).toEqual(t.clock.now());

    expect(await t.ik.apiTokens.revoke({ accountId, tokenId: first.apiToken.id })).toBe(true);
    expect(await t.ik.apiTokens.verify(first.token)).toEqual({
      status: "refused",
      reason: "revoked",
    });

    // A legacy SHA-256 digest imports, verifies, and counts against the cap.
    const legacyToken = `pat_${randomBytes(32).toString("base64url")}`;
    const imported = await t.ik.apiTokens.import({
      accountId,
      name: "legacy",
      scopes: ["read"],
      expiresAt: new Date(t.clock.now().getTime() + 86_400_000),
      sha256Digest: createHash("sha256").update(legacyToken).digest("hex"),
    });
    expect(imported.status).toBe("imported");
    expect((await t.ik.apiTokens.verify(legacyToken)).status).toBe("valid");
    expect(
      (await t.ik.apiTokens.create({ accountId, name: "x", scopes: ["read"], expiresInDays: 7 }))
        .status,
    ).toBe("limit_reached");

    t.clock.advanceSeconds(7 * 86_400);
    expect(await t.ik.apiTokens.verify(second.token)).toEqual({
      status: "refused",
      reason: "expired",
    });
    await t.ik.accounts.disable(accountId);
    expect(await t.ik.apiTokens.verify(legacyToken)).toEqual({
      status: "refused",
      reason: "revoked",
    });
    expect(await t.ik.apiTokens.list(accountId)).toEqual([]);
  });
}
