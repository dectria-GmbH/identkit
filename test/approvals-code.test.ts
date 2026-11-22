import { describe, expect, it } from "vitest";
import {
  hashPayload,
  InvalidArgumentError,
  MethodNotAllowedError,
  checkApprovalEvidence,
  type CodeConfirmationEvidence,
} from "../src/index.js";
import { hookedTotpStore, mfaPolicy, ORIGIN, RP_ID, setup, STEP, testConfig } from "./helpers.js";

const payloadA = hashPayload(JSON.stringify({ request: "release", amount: 100 }));
const payloadB = hashPayload(JSON.stringify({ request: "release", amount: 100000 }));

const codePolicy = {
  ...mfaPolicy,
  approvalEvidenceLevels: ["signature" as const, "code-confirmation" as const],
};

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
    levels: ["code-confirmation"],
  });
  if (start.status !== "ok" || start.level !== "code-confirmation") throw new Error("denied");
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
    approvalId: start.approvalId,
    code: t.totpCode(user.secret),
  });
  if (result.status !== "approved" || result.evidence.level !== "code-confirmation") {
    throw new Error(`not approved: ${result.status}`);
  }
  return result.evidence;
}

describe("approval proofs by code confirmation", () => {
  it("rule: code-confirmation refused under policy signature", async () => {
    const t = setup({ policy: mfaPolicy });
    const user = await userWithTotp(t);
    await expect(
      t.ik.approvals.start({
        sessionToken: user.token,
        payloadHash: payloadA,
        levels: ["code-confirmation"],
      }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
    await expect(
      t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        approvalId: "A".repeat(43),
        code: t.totpCode(user.secret),
      }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
    // The code was not consumed by the refused call.
    expect(
      (await t.ik.stepUp.verifyTotp(user.token, { code: t.totpCode(user.secret) })).status,
    ).toBe("granted");
  });

  it("rule: level chosen on the server - start picks the strongest allowed level, verify takes the stored one", async () => {
    const t = setup({ policy: codePolicy });
    const passkeyUser = await t.userWithPasskey("person@example.org");
    const passkeyStepUp = await t.ik.stepUp.startPasskey(passkeyUser.token);
    if (passkeyStepUp.status !== "ok") throw new Error("denied");
    const user = await t.ik.stepUp.finishPasskey(
      passkeyUser.token,
      t.authenticator.assert(passkeyStepUp.options),
    );
    if (user.status !== "granted") throw new Error("no step-up");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    // With a passkey and both levels allowed, no input can make start choose a code.
    const strongest = await t.ik.approvals.start({
      sessionToken: user.token,
      payloadHash: payloadA,
    });
    expect(strongest.status === "ok" && strongest.level).toBe("signature");
    // A code form at verify finds no pending code approval for it.
    expect(
      await t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        approvalId: "A".repeat(43),
        code: t.totpCode(secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });
    // The server can narrow the levels per call; a code approval then needs its filter too.
    const coded = await startCode(t, user.token, payloadA);
    await expect(
      t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        levels: ["signature"],
        approvalId: coded.approvalId,
        code: t.totpCode(secret, STEP),
      }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
    // Malformed filters and mixed forms fail loudly with a coded error.
    for (const levels of [[], ["sms"], "signature"]) {
      await expect(
        t.ik.approvals.start({
          sessionToken: user.token,
          payloadHash: payloadA,
          levels: levels as unknown as ["signature"],
        }),
        JSON.stringify(levels),
      ).rejects.toMatchObject({ code: "invalid_argument" });
    }
    const mixed: unknown = {
      sessionToken: user.token,
      payloadHash: payloadA,
      approvalId: coded.approvalId,
      code: "123456",
      response: {},
    };
    await expect(
      t.ik.approvals.verify(mixed as Parameters<typeof t.ik.approvals.verify>[0]),
    ).rejects.toBeInstanceOf(InvalidArgumentError);
  });

  it("rule: a per-call filter only narrows - it cannot widen the policy", async () => {
    const t = setup({ policy: mfaPolicy }); // approvalEvidenceLevels: ["signature"]
    const user = await userWithTotp(t);
    // The filter names code confirmation, the policy does not: nothing is left.
    await expect(
      t.ik.approvals.start({
        sessionToken: user.token,
        payloadHash: payloadA,
        levels: ["signature", "code-confirmation"],
      }),
    ).resolves.toEqual({ status: "denied", reason: "no_passkey" });
    expect(t.audit.ofType("approval.challenge_created")).toHaveLength(0);
  });

  it("levels are accepted exactly as listed: a code-only policy refuses signatures", async () => {
    const t = setup({ policy: { ...mfaPolicy, approvalEvidenceLevels: ["code-confirmation"] } });
    const user = await t.userWithPasskey("person@example.org");
    await expect(
      t.ik.approvals.start({
        sessionToken: user.token,
        payloadHash: payloadA,
        levels: ["signature"],
      }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
    await expect(
      t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        response: t.authenticator.assert({ challenge: "A".repeat(43), rpId: RP_ID }),
      }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
  });

  it("signature stays acceptable under policy code-confirmation", async () => {
    const t = setup({ policy: codePolicy });
    const user = await t.userWithPasskey("person@example.org");
    const start = await t.ik.approvals.start({ sessionToken: user.token, payloadHash: payloadA });
    if (start.status !== "ok" || start.level !== "signature") throw new Error("denied");
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
      approvalId: start.approvalId,
      code,
    });
    if (result.status !== "approved" || result.evidence.level !== "code-confirmation") {
      throw new Error("not approved");
    }
    expect(Object.keys(result.evidence).toSorted()).toEqual(
      ["accountId", "level", "mac", "payloadHash", "recordedAt", "timeStep", "version"].toSorted(),
    );
    expect(result.evidence).toMatchObject({
      version: 1,
      level: "code-confirmation",
      accountId: user.account.id,
      payloadHash: payloadA,
      recordedAt: t.clock.now().toISOString(),
      timeStep: Math.floor(t.clock.now().getTime() / 1000 / STEP),
    });
    expect(result.evidence.mac).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(result.evidence)).not.toContain(code);
    const events = t.audit.ofType("approval.code_confirmation_recorded");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ level: "code-confirmation", payloadHash: payloadA });
    expect(t.audit.ofType("approval.verified")).toHaveLength(0);
  });

  it("rule: every approval event carries its level", async () => {
    const t = setup({ policy: codePolicy });
    const passkeyUser = await t.userWithPasskey("passkey@example.org");
    const start = await t.ik.approvals.start({
      sessionToken: passkeyUser.token,
      payloadHash: payloadA,
    });
    if (start.status !== "ok" || start.level !== "signature") throw new Error("denied");
    await t.ik.approvals.verify({
      sessionToken: passkeyUser.token,
      payloadHash: payloadA,
      response: t.authenticator.assert(start.options),
    });
    await t.ik.approvals.verify({
      sessionToken: passkeyUser.token,
      payloadHash: payloadA,
      response: t.authenticator.assert(start.options),
    });
    const user = await userWithTotp(t);
    await confirmed(t, user);
    const coded = await startCode(t, user.token, payloadA);
    await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadB,
      approvalId: coded.approvalId,
      code: t.totpCode(user.secret),
    });
    const events = t.audit.events.filter((e) => e.type.startsWith("approval."));
    expect(new Set(events.map((e) => e.type))).toEqual(
      new Set([
        "approval.challenge_created",
        "approval.verified",
        "approval.failed",
        "approval.code_confirmation_recorded",
      ]),
    );
    for (const event of events) {
      expect(["signature", "code-confirmation"], event.type).toContain(event.level);
    }
  });

  it("rule: code-confirmation evidence never reported as verified", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const evidence = await confirmed(t, user);
    const verifier = { credentialPublicKey: new Uint8Array(32), rpId: RP_ID, origins: [ORIGIN] };
    const recorded = {
      status: "recorded_not_independently_verifiable",
      level: "code-confirmation",
    };
    expect(await checkApprovalEvidence({ evidence, hasher: t.hasher })).toEqual(recorded);
    expect(await checkApprovalEvidence({ evidence, hasher: t.hasher, verifier })).toEqual(recorded);
    // Relabelled as a signature, it lacks everything a signature check needs.
    const relabelled = { ...evidence, level: "signature" } as unknown as CodeConfirmationEvidence;
    expect(await checkApprovalEvidence({ evidence: relabelled, verifier })).toEqual({
      status: "invalid",
    });
  });

  it("rule: forged code-confirmation evidence rejected - the HMAC decides, never the shape", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const evidence = await confirmed(t, user);
    const forged: CodeConfirmationEvidence = {
      version: 1,
      level: "code-confirmation",
      accountId: user.account.id,
      payloadHash: payloadB,
      recordedAt: t.clock.now().toISOString(),
      timeStep: evidence.timeStep,
      mac: "0".repeat(64),
    };
    for (const changed of [
      forged,
      { ...evidence, payloadHash: payloadB },
      { ...evidence, accountId: "another-account" },
      { ...evidence, timeStep: evidence.timeStep + 1 },
      { ...evidence, recordedAt: new Date(0).toISOString() },
      { ...evidence, mac: "0".repeat(64) },
      { ...evidence, timeStep: String(evidence.timeStep) } as unknown as CodeConfirmationEvidence,
    ]) {
      expect(await checkApprovalEvidence({ evidence: changed, hasher: t.hasher })).toEqual({
        status: "invalid",
      });
    }
    // Another deployment (another hash key) cannot confirm the record.
    const elsewhere = setup({ policy: codePolicy });
    expect(await checkApprovalEvidence({ evidence, hasher: elsewhere.hasher })).toEqual({
      status: "invalid",
    });
    // Without the key there is nothing to check: the call fails instead of answering.
    await expect(checkApprovalEvidence({ evidence })).rejects.toBeInstanceOf(InvalidArgumentError);
  });

  it("rule: evidence check fails closed for untyped callers - a wrong argument shape throws a coded error", async () => {
    const t = setup({ policy: codePolicy });
    const user = await userWithTotp(t);
    const evidence = await confirmed(t, user);
    const check = checkApprovalEvidence as unknown as (...args: unknown[]) => Promise<unknown>;
    const shapes: unknown[][] = [
      [evidence, { credentialPublicKey: new Uint8Array(32), rpId: RP_ID, origins: [ORIGIN] }],
      [evidence],
      [{ evidence, hasher: t.hasher }, "extra"],
      [{}],
      [null],
      [],
      [{ evidence: "not an object", hasher: t.hasher }],
    ];
    for (const args of shapes) {
      await expect(check(...args), JSON.stringify(args.length)).rejects.toMatchObject({
        name: "InvalidArgumentError",
        code: "invalid_argument",
      });
    }
    // The earlier name is gone, so an old import fails instead of returning a truthy object.
    const exported: Record<string, unknown> = await import("../src/index.js");
    expect(exported["verifyApprovalEvidence"]).toBeUndefined();
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
        approvalId: forPayload.approvalId,
        code: t.totpCode(user.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });

    const forUser = await startCode(t, user.token, payloadA);
    expect(
      await t.ik.approvals.verify({
        sessionToken: other.token,
        payloadHash: payloadA,
        approvalId: forUser.approvalId,
        code: t.totpCode(other.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });
    // The failed attempt consumed it.
    expect(
      await t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
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
        approvalId: expiring.approvalId,
        code: t.totpCode(user.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });

    const fine = await startCode(t, user.token, payloadA);
    const approved = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
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
        levels: ["code-confirmation"],
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
        approvalId: start.approvalId,
        code: t.totpCode(user.secret),
      }),
    ).toEqual({ status: "failed", reason: "locked" });

    await t.ik.sessions.revoke(user.token);
    expect(
      await t.ik.approvals.start({
        sessionToken: user.token,
        payloadHash: payloadA,
        levels: ["code-confirmation"],
      }),
    ).toEqual({ status: "denied", reason: "no_session" });
  });
});
