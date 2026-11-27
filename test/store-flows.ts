import { expect, it } from "vitest";
import type { IdentkitStore } from "../src/storage/types.js";
import { mfaPolicy, otherCode, setup, STEP, testConfig } from "./helpers.js";

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
}
