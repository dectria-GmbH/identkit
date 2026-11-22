import { describe, expect, it } from "vitest";
import {
  hashPayload,
  MethodNotAllowedError,
  verifyApprovalEvidence,
  type CodeConfirmationEvidence,
} from "../src/index.js";
import { hookedTotpStore, mfaPolicy, ORIGIN, RP_ID, setup, STEP, testConfig } from "./helpers.js";

const payloadA = hashPayload(JSON.stringify({ request: "release", amount: 100 }));
const payloadB = hashPayload(JSON.stringify({ request: "release", amount: 100000 }));

const codePolicy = { ...mfaPolicy, approvalProofLevel: "code-confirmation" as const };

async function userWithTotp(t: ReturnType<typeof setup>, email = "person@example.org") {
  const user = await t.signIn(email);
  const { secret, factorId } = await t.enrolTotp(user.token);
  t.clock.advanceSeconds(STEP);
  return { ...user, secret, factorId };
}

async function startCode(t: ReturnType<typeof setup>, token: string, payloadHash: string) {
  const start = await t.ik.approvals.start({
    sessionToken: token,
    payloadHash,
    level: "code-confirmation",
  });
  if (start.status !== "ok") throw new Error(`denied: ${start.reason}`);
  return start;
}

async function confirmed(
  t: ReturnType<typeof setup>,
  user: Awaited<ReturnType<typeof userWithTotp>>,
) {
  const start = await startCode(t, user.token, payloadA);
  const result = await t.ik.approvals.verify({
    sessionToken: user.token,
    payloadHash: payloadA,
    level: "code-confirmation",
    approvalId: start.approvalId,
    code: t.totpCode(user.secret),
  });
  if (result.status !== "approved" || result.proof.level !== "code-confirmation") {
    throw new Error(`not approved: ${result.status}`);
  }
  return result.proof;
}

describe("approval proofs by code confirmation", () => {
  it("rule: code-confirmation refused under policy signature", async () => {
    const t = setup({ policy: mfaPolicy });
    const user = await userWithTotp(t);
    await expect(
      t.ik.approvals.start({
        sessionToken: user.token,
        payloadHash: payloadA,
        level: "code-confirmation",
      }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
    await expect(
      t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        level: "code-confirmation",
        approvalId: "A".repeat(43),
        code: t.totpCode(user.secret),
      }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
    // The code was not consumed by the refused call.
    expect(
      (await t.ik.stepUp.verifyTotp(user.token, { code: t.totpCode(user.secret) })).status,
    ).toBe("granted");
  });

  it("the level of a verification is explicit, never inferred from the fields", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const start = await startCode(t, user.token, payloadA);
    const untyped: unknown = {
      sessionToken: user.token,
      payloadHash: payloadA,
      approvalId: start.approvalId,
      code: t.totpCode(user.secret),
    };
    await expect(
      t.ik.approvals.verify(untyped as Parameters<typeof t.ik.approvals.verify>[0]),
    ).rejects.toThrow('needs level: "code-confirmation"');
    const mixed: unknown = {
      sessionToken: user.token,
      payloadHash: payloadA,
      level: "code-confirmation",
      response: {},
    };
    await expect(
      t.ik.approvals.verify(mixed as Parameters<typeof t.ik.approvals.verify>[0]),
    ).rejects.toThrow("takes no response");
    // Neither call consumed the pending approval or the code.
    const result = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
      level: "code-confirmation",
      approvalId: start.approvalId,
      code: t.totpCode(user.secret),
    });
    expect(result.status === "approved" && result.proof.level).toBe("code-confirmation");
  });

  it("signature stays acceptable under policy code-confirmation", async () => {
    const t = setup({ policy: codePolicy });
    const user = await t.userWithPasskey("person@example.org");
    const start = await t.ik.approvals.start({ sessionToken: user.token, payloadHash: payloadA });
    if (start.status !== "ok") throw new Error("denied");
    expect(start.level).toBe("signature");
    const result = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
      response: t.authenticator.assert(start.options),
    });
    expect(result.status).toBe("approved");
  });

  it("evidence carries level, account, payload hash, time, time step and HMAC, and no code", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const start = await startCode(t, user.token, payloadA);
    expect(start.expiresAt.getTime() - t.clock.now().getTime()).toBe(
      testConfig.totp.approvalTtlSeconds * 1000,
    );
    const code = t.totpCode(user.secret);
    const result = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
      level: "code-confirmation",
      approvalId: start.approvalId,
      code,
    });
    if (result.status !== "approved" || result.proof.level !== "code-confirmation") {
      throw new Error("not approved");
    }
    expect(Object.keys(result.proof).toSorted()).toEqual(
      ["accountId", "level", "mac", "payloadHash", "recordedAt", "timeStep", "version"].toSorted(),
    );
    expect(result.proof).toMatchObject({
      version: 1,
      level: "code-confirmation",
      accountId: user.account.id,
      payloadHash: payloadA,
      recordedAt: t.clock.now().toISOString(),
      timeStep: Math.floor(t.clock.now().getTime() / 1000 / STEP),
    });
    expect(result.proof.mac).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(result.proof)).not.toContain(code);
    const events = t.audit.ofType("approval.code_confirmation_recorded");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ level: "code-confirmation", payloadHash: payloadA });
    expect(t.audit.ofType("approval.verified")).toHaveLength(0);
  });

  it("rule: code-confirmation evidence never reported as verified", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const proof = await confirmed(t, user);
    const verifier = { credentialPublicKey: new Uint8Array(32), rpId: RP_ID, origins: [ORIGIN] };
    const recorded = {
      status: "recorded_not_independently_verifiable",
      level: "code-confirmation",
    };
    expect(await verifyApprovalEvidence({ evidence: proof })).toEqual(recorded);
    expect(await verifyApprovalEvidence({ evidence: proof, verifier })).toEqual(recorded);
    // An edited record is never "verified" either; only the server can tell it was edited.
    const edited: CodeConfirmationEvidence = { ...proof, payloadHash: payloadB };
    expect((await verifyApprovalEvidence({ evidence: edited, verifier })).status).not.toBe(
      "verified",
    );
    // Relabelled as a signature, it lacks everything a signature check needs.
    const relabelled = { ...proof, level: "signature" } as unknown as CodeConfirmationEvidence;
    expect(await verifyApprovalEvidence({ evidence: relabelled, verifier })).toEqual({
      status: "invalid",
    });

    expect(await t.ik.approvals.checkRecordedEvidence(proof)).toEqual({ status: "intact" });
    for (const changed of [
      edited,
      { ...proof, accountId: "another-account" },
      { ...proof, timeStep: proof.timeStep + 1 },
      { ...proof, recordedAt: new Date(0).toISOString() },
      { ...proof, mac: "0".repeat(64) },
    ]) {
      expect(await t.ik.approvals.checkRecordedEvidence(changed)).toEqual({ status: "invalid" });
    }
    // Another deployment (another hash key) cannot confirm the record.
    const elsewhere = setup({ policy: codePolicy });
    expect(await elsewhere.ik.approvals.checkRecordedEvidence(proof)).toEqual({
      status: "invalid",
    });
  });

  it("rule: one code cannot serve two purposes - an approval code does not then step up or complete a sign-in", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const code = t.totpCode(user.secret);
    const start = await startCode(t, user.token, payloadA);
    expect(
      (
        await t.ik.approvals.verify({
          sessionToken: user.token,
          payloadHash: payloadA,
          level: "code-confirmation",
          approvalId: start.approvalId,
          code,
        })
      ).status,
    ).toBe("approved");
    expect(await t.ik.stepUp.verifyTotp(user.token, { code })).toEqual({
      status: "failed",
      reason: "invalid",
    });
    // userWithTotp waited one time step, which covers the resend cooldown of the e-mail code.
    const { flowId, code: mailCode } = await t.codeFor("person@example.org");
    const pending = await t.ik.emailSignIn.verifyCode({ flowId, code: mailCode });
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    expect(await t.ik.totp.verifySecondFactor(pending.pendingToken, { code })).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("rule: one code cannot serve two purposes - a step-up code does not then approve", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const code = t.totpCode(user.secret);
    const start = await startCode(t, user.token, payloadA);
    const granted = await t.ik.stepUp.verifyTotp(user.token, { code });
    if (granted.status !== "granted") throw new Error("no step-up");
    expect(
      await t.ik.approvals.verify({
        sessionToken: granted.token,
        payloadHash: payloadA,
        level: "code-confirmation",
        approvalId: start.approvalId,
        code,
      }),
    ).toEqual({ status: "failed", reason: "invalid" });
  });

  it("a pending approval works once, for its session, account and payload, until it expires", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const other = await userWithTotp(t, "other@example.org");

    const forPayload = await startCode(t, user.token, payloadA);
    expect(
      await t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadB,
        level: "code-confirmation",
        approvalId: forPayload.approvalId,
        code: t.totpCode(user.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });

    const forUser = await startCode(t, user.token, payloadA);
    expect(
      await t.ik.approvals.verify({
        sessionToken: other.token,
        payloadHash: payloadA,
        level: "code-confirmation",
        approvalId: forUser.approvalId,
        code: t.totpCode(other.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });
    // The failed attempt consumed it.
    expect(
      await t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        level: "code-confirmation",
        approvalId: forUser.approvalId,
        code: t.totpCode(user.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });

    const expiring = await startCode(t, user.token, payloadA);
    t.clock.advanceSeconds(testConfig.totp.approvalTtlSeconds);
    expect(
      await t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        level: "code-confirmation",
        approvalId: expiring.approvalId,
        code: t.totpCode(user.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });

    const fine = await startCode(t, user.token, payloadA);
    const approved = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
      level: "code-confirmation",
      approvalId: fine.approvalId,
      code: t.totpCode(user.secret),
    });
    expect(approved.status).toBe("approved");
  });

  it("a factor removal or session revocation during the check yields no evidence", async () => {
    for (const race of ["factor", "session"] as const) {
      const { inner, store, hooks } = hookedTotpStore();
      const t = setup({ store, policy: codePolicy });
      const user = await userWithTotp(t);
      const start = await startCode(t, user.token, payloadA);
      hooks.afterRecordStep = async () => {
        if (race === "factor") await inner.totp.delete(user.factorId, user.account.id);
        else await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
      };
      expect(
        await t.ik.approvals.verify({
          sessionToken: user.token,
          payloadHash: payloadA,
          level: "code-confirmation",
          approvalId: start.approvalId,
          code: t.totpCode(user.secret),
        }),
        race,
      ).toEqual({ status: "failed", reason: "invalid" });
      expect(t.audit.ofType("approval.code_confirmation_recorded"), race).toHaveLength(0);
    }
  });

  it("needs a full session and an active TOTP factor; a wrong code fails, a lock reports locked", async () => {
    const t = setup({ policy: codePolicy });
    const noTotp = await t.signIn("plain@example.org");
    expect(
      await t.ik.approvals.start({
        sessionToken: noTotp.token,
        payloadHash: payloadA,
        level: "code-confirmation",
      }),
    ).toEqual({ status: "denied", reason: "no_totp" });

    const user = await userWithTotp(t);
    const valid = new Set([-1, 0, 1].map((n) => t.totpCode(user.secret, n * STEP)));
    const wrong = ["000000", "111111", "222222", "333333"].find((c) => !valid.has(c)) ?? "";
    for (let i = 0; i < testConfig.totp.lockout.maxFailures; i += 1) {
      const start = await startCode(t, user.token, payloadA);
      expect(
        await t.ik.approvals.verify({
          sessionToken: user.token,
          payloadHash: payloadA,
          level: "code-confirmation",
          approvalId: start.approvalId,
          code: wrong,
        }),
      ).toEqual({ status: "failed", reason: "invalid" });
    }
    const start = await startCode(t, user.token, payloadA);
    expect(
      await t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        level: "code-confirmation",
        approvalId: start.approvalId,
        code: t.totpCode(user.secret),
      }),
    ).toEqual({ status: "failed", reason: "locked" });

    await t.ik.sessions.revoke(user.token);
    expect(
      await t.ik.approvals.start({
        sessionToken: user.token,
        payloadHash: payloadA,
        level: "code-confirmation",
      }),
    ).toEqual({ status: "denied", reason: "no_session" });
  });
});
