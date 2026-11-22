import { describe, expect, it } from "vitest";
import { setup, testConfig } from "./helpers.js";

const { idleTimeoutSeconds, absoluteTimeoutSeconds } = testConfig.sessions;

describe("sessions", () => {
  it("rule: idle timeout - a session expires after the idle time without use", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    t.clock.advanceSeconds(idleTimeoutSeconds - 1);
    expect(await t.ik.sessions.validate(token)).not.toBeNull();
    t.clock.advanceSeconds(idleTimeoutSeconds);
    expect(await t.ik.sessions.validate(token)).toBeNull();
    expect(t.audit.ofType("session.expired")).toHaveLength(1);
  });

  it("rule: idle timeout - use extends the session, and an expired session stays expired", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    t.clock.advanceSeconds(idleTimeoutSeconds - 10);
    expect(await t.ik.sessions.validate(token)).not.toBeNull();
    t.clock.advanceSeconds(idleTimeoutSeconds - 10);
    expect(await t.ik.sessions.validate(token)).not.toBeNull();
    t.clock.advanceSeconds(idleTimeoutSeconds);
    expect(await t.ik.sessions.validate(token)).toBeNull();
    t.clock.advanceSeconds(-idleTimeoutSeconds);
    expect(await t.ik.sessions.validate(token)).toBeNull();
  });

  it("rule: absolute timeout - a session in constant use ends at the absolute limit", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    const step = idleTimeoutSeconds - 1;
    let elapsed = 0;
    while (elapsed + step < absoluteTimeoutSeconds) {
      t.clock.advanceSeconds(step);
      elapsed += step;
      expect(await t.ik.sessions.validate(token)).not.toBeNull();
    }
    t.clock.advanceSeconds(absoluteTimeoutSeconds - elapsed);
    expect(await t.ik.sessions.validate(token)).toBeNull();
  });

  it("rule: rotation - rotating issues a new token and invalidates the old one", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    const rotated = await t.ik.sessions.rotate(token);
    expect(rotated).not.toBeNull();
    expect(rotated?.token).not.toBe(token);
    expect(await t.ik.sessions.validate(token)).toBeNull();
    expect(await t.ik.sessions.validate(rotated?.token ?? "")).not.toBeNull();
  });

  it("rule: rotation - a step-up changes the token", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    const stepUp = await t.ik.stepUp.requestEmailCode(token);
    if (stepUp.status !== "sent") throw new Error("not sent");
    const granted = await t.ik.stepUp.verifyEmailCode(token, {
      flowId: stepUp.flowId,
      code: t.mail.last()?.code ?? "",
    });
    expect(granted.status).toBe("granted");
    if (granted.status !== "granted") return;
    expect(granted.token).not.toBe(token);
    expect(await t.ik.sessions.validate(token)).toBeNull();
    expect(await t.ik.sessions.validate(granted.token)).not.toBeNull();
  });

  it("rule: revocation - a revoked token no longer validates", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    expect(await t.ik.sessions.revoke(token)).toBe(true);
    expect(await t.ik.sessions.validate(token)).toBeNull();
    expect(t.audit.ofType("session.revoked")).toHaveLength(1);
  });

  it("rule: revocation - revokeAll ends every session of the account except the named one", async () => {
    const t = setup();
    const a = await t.signIn("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const b = await t.signIn("person@example.org");
    expect(await t.ik.sessions.revokeAll(a.account.id, { exceptSessionId: b.session.id })).toBe(1);
    expect(await t.ik.sessions.validate(a.token)).toBeNull();
    expect(await t.ik.sessions.validate(b.token)).not.toBeNull();
  });

  it("a session of a disabled account does not validate, even if it was created late", async () => {
    const t = setup();
    const { token, account } = await t.signIn("person@example.org");
    // Simulates a session written after the disable revoked all sessions.
    await t.store.accounts.setStatus(account.id, "disabled");
    expect(await t.ik.sessions.validate(token)).toBeNull();
  });

  it("rejects tokens that are malformed or unknown", async () => {
    const t = setup();
    for (const token of ["", "x", "a".repeat(43), "a".repeat(200)]) {
      expect(await t.ik.sessions.validate(token)).toBeNull();
    }
  });

  it("rule: step-up window - a step-up is valid only for the configured time", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    // A fresh sign-in counts as a step-up by its own method.
    expect((await t.ik.sessions.requireStepUp(token)).ok).toBe(true);
    t.clock.advanceSeconds(testConfig.stepUp.validitySeconds - 1);
    expect((await t.ik.sessions.requireStepUp(token)).ok).toBe(true);
    t.clock.advanceSeconds(1);
    expect(await t.ik.sessions.requireStepUp(token)).toEqual({
      ok: false,
      reason: "step_up_required",
    });
  });

  it("rule: step-up window - a step-up by e-mail code does not satisfy a passkey-only requirement", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    expect(await t.ik.sessions.requireStepUp(token, { methods: ["passkey"] })).toEqual({
      ok: false,
      reason: "step_up_required",
    });
  });

  it("rule: step-up window - a call cannot widen the methods beyond the policy", async () => {
    const t = setup();
    t.policy.current = { ...t.policy.current, stepUpMethods: ["passkey"] };
    const { token } = await t.signIn("person@example.org");
    expect(await t.ik.sessions.requireStepUp(token, { methods: ["email_otp"] })).toEqual({
      ok: false,
      reason: "step_up_required",
    });
  });
});
