import { describe, expect, it } from "vitest";
import { createMemoryStore, InvalidEmailError, MethodNotAllowedError } from "../src/index.js";
import type { IdentkitStore } from "../src/storage/types.js";
import { otherCode, setup, testConfig } from "./helpers.js";

describe("e-mail code sign-in", () => {
  it("signs in with the mailed code and creates the account on first sign-in", async () => {
    const t = setup();
    const { flowId, code } = await t.codeFor("Person@Example.org ");
    expect(t.mail.last()?.to).toBe("person@example.org");
    const result = await t.ik.emailSignIn.verifyCode({ flowId, code });
    expect(result.status).toBe("signed_in");
    if (result.status !== "signed_in") return;
    expect(result.accountCreated).toBe(true);
    expect(result.account.email).toBe("person@example.org");
    expect(await t.ik.sessions.validate(result.token)).not.toBeNull();

    const again = await (async () => {
      t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
      return t.signIn("person@example.org");
    })();
    expect(again.accountCreated).toBe(false);
    expect(again.account.id).toBe(result.account.id);
  });

  it("passes only recipient, code, purpose and lifetime to the mail sender", async () => {
    const t = setup();
    await t.codeFor("person@example.org");
    const message = t.mail.last();
    expect(Object.keys(message ?? {}).toSorted()).toEqual([
      "code",
      "expiresInMinutes",
      "purpose",
      "to",
    ]);
    expect(message?.code).toMatch(/^[0-9]{6}$/);
    expect(message?.expiresInMinutes).toBe(10);
  });

  it("rule: code expiry - rejects a code after its lifetime", async () => {
    const t = setup();
    const { flowId, code } = await t.codeFor("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.codeTtlSeconds);
    const result = await t.ik.emailSignIn.verifyCode({ flowId, code });
    expect(result).toEqual({ status: "failed", reason: "expired" });
  });

  it("rule: code expiry - accepts a code one second before its lifetime ends", async () => {
    const t = setup();
    const { flowId, code } = await t.codeFor("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.codeTtlSeconds - 1);
    expect((await t.ik.emailSignIn.verifyCode({ flowId, code })).status).toBe("signed_in");
  });

  it("rule: attempt limit - locks the code after the configured number of wrong attempts", async () => {
    const t = setup();
    const { flowId, code } = await t.codeFor("person@example.org");
    const max = testConfig.emailOtp.maxAttemptsPerCode;
    const results = [];
    for (let i = 0; i < max; i += 1) {
      results.push(await t.ik.emailSignIn.verifyCode({ flowId, code: otherCode(code) }));
    }
    expect(
      results.slice(0, max - 1).every((r) => r.status === "failed" && r.reason === "invalid"),
    ).toBe(true);
    expect(results[max - 1]).toEqual({ status: "failed", reason: "locked" });
    // The right code no longer works for this flow.
    expect(await t.ik.emailSignIn.verifyCode({ flowId, code })).toEqual({
      status: "failed",
      reason: "locked",
    });
    expect(t.audit.ofType("otp.locked")).toHaveLength(1);
  });

  it("rule: attempt limit - concurrent guesses cannot exceed the limit", async () => {
    const t = setup();
    const { flowId, code } = await t.codeFor("person@example.org");
    const guesses = Array.from({ length: 20 }, () =>
      t.ik.emailSignIn.verifyCode({ flowId, code: otherCode(code) }),
    );
    await Promise.all(guesses);
    const flow = await t.store.otp.findById(flowId);
    expect(flow?.attempts).toBe(testConfig.emailOtp.maxAttemptsPerCode);
  });

  it("rule: address lockout - locks the address after the configured failures across flows", async () => {
    const t = setup();
    const email = "person@example.org";
    const { maxFailures } = testConfig.emailOtp.addressLockout;
    let failures = 0;
    let last;
    while (failures <= maxFailures) {
      const { flowId, code } = await t.codeFor(email);
      for (
        let i = 0;
        i < testConfig.emailOtp.maxAttemptsPerCode - 1 && failures <= maxFailures;
        i += 1
      ) {
        last = await t.ik.emailSignIn.verifyCode({ flowId, code: otherCode(code) });
        failures += 1;
      }
      t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    }
    expect(last).toEqual({ status: "failed", reason: "locked" });
    expect(t.audit.ofType("address.locked")).toHaveLength(1);
    // While locked, no new code goes out, for this address.
    const blocked = await t.ik.emailSignIn.requestCode({ email });
    expect(blocked.status).toBe("locked");
    // After the lock time, sign-in works again.
    t.clock.advanceSeconds(testConfig.emailOtp.addressLockout.lockSeconds);
    expect((await t.signIn(email)).status).toBe("signed_in");
  });

  it("rule: address lockout - each further lock lasts twice as long until a success", async () => {
    const t = setup();
    const email = "person@example.org";
    const { maxFailures, lockSeconds } = testConfig.emailOtp.addressLockout;
    async function failUntilLocked() {
      let failures = 0;
      while (failures <= maxFailures) {
        t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
        const { flowId, code } = await t.codeFor(email);
        for (
          let i = 0;
          i < testConfig.emailOtp.maxAttemptsPerCode - 1 && failures <= maxFailures;
          i += 1
        ) {
          await t.ik.emailSignIn.verifyCode({ flowId, code: otherCode(code) });
          failures += 1;
        }
      }
    }
    await failUntilLocked();
    t.clock.advanceSeconds(lockSeconds);
    await failUntilLocked();
    // Second lock: twice the base lock time.
    t.clock.advanceSeconds(lockSeconds);
    expect((await t.ik.emailSignIn.requestCode({ email })).status).toBe("locked");
    t.clock.advanceSeconds(lockSeconds);
    expect((await t.signIn(email)).status).toBe("signed_in");
    // The success reset the count: the next lock is back to the base time.
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    await failUntilLocked();
    t.clock.advanceSeconds(lockSeconds);
    expect((await t.ik.emailSignIn.requestCode({ email })).status).toBe("sent");
  });

  it("rule: address lockout - sign-in and step-up failures are counted apart", async () => {
    const t = setup();
    const session = await t.signIn("person@example.org");
    const { maxFailures } = testConfig.emailOtp.addressLockout;
    let failures = 0;
    while (failures <= maxFailures) {
      t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
      const requested = await t.ik.stepUp.requestEmailCode(session.token);
      if (requested.status !== "sent") break;
      const code = t.mail.last()?.code ?? "";
      for (
        let i = 0;
        i < testConfig.emailOtp.maxAttemptsPerCode - 1 && failures <= maxFailures;
        i += 1
      ) {
        await t.ik.stepUp.verifyEmailCode(session.token, {
          flowId: requested.flowId,
          code: otherCode(code),
        });
        failures += 1;
      }
      // Keep the session alive while failing step-ups.
      await t.ik.sessions.validate(session.token);
    }
    expect((await t.ik.stepUp.requestEmailCode(session.token)).status).toBe("locked");
    expect((await t.ik.emailSignIn.requestCode({ email: "person@example.org" })).status).toBe(
      "sent",
    );
  });

  it("rule: resend cooldown - refuses a second code inside the cooldown", async () => {
    const t = setup();
    await t.codeFor("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds - 1);
    const second = await t.ik.emailSignIn.requestCode({ email: "person@example.org" });
    expect(second).toEqual({ status: "cooldown", retryAfterSeconds: 1 });
    expect(t.mail.sent).toHaveLength(1);
    t.clock.advanceSeconds(1);
    expect((await t.ik.emailSignIn.requestCode({ email: "person@example.org" })).status).toBe(
      "sent",
    );
    expect(t.mail.sent).toHaveLength(2);
  });

  it("a new code supersedes the previous code of the same address", async () => {
    const t = setup();
    const first = await t.codeFor("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    await t.codeFor("person@example.org");
    expect(await t.ik.emailSignIn.verifyCode(first)).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("rule: single use - a code works only once", async () => {
    const t = setup();
    const { flowId, code } = await t.codeFor("person@example.org");
    expect((await t.ik.emailSignIn.verifyCode({ flowId, code })).status).toBe("signed_in");
    expect(await t.ik.emailSignIn.verifyCode({ flowId, code })).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("rule: single use - concurrent use of one code yields one session", async () => {
    const t = setup();
    const { flowId, code } = await t.codeFor("person@example.org");
    const results = await Promise.all(
      Array.from({ length: 5 }, () => t.ik.emailSignIn.verifyCode({ flowId, code })),
    );
    expect(results.filter((r) => r.status === "signed_in")).toHaveLength(1);
  });

  it("rule: code binding - a code does not verify another flow", async () => {
    const t = setup();
    const a = await t.codeFor("a@example.org");
    const b = await t.codeFor("b@example.org");
    expect(await t.ik.emailSignIn.verifyCode({ flowId: b.flowId, code: a.code })).toMatchObject({
      status: "failed",
    });
  });

  it("rule: code binding - a stored code hash moved to another flow does not verify", async () => {
    // Simulates an attacker who can write the store: the digest of flow A, copied into flow
    // B, must not accept A's code, because the digest covers flow id and address.
    const inner = createMemoryStore();
    let flowA: Awaited<ReturnType<IdentkitStore["otp"]["findById"]>> = null;
    const store: IdentkitStore = {
      ...inner,
      otp: {
        ...inner.otp,
        findById: async (id) => {
          const flow = await inner.otp.findById(id);
          if (flow && flowA && flow.id !== flowA.id)
            return { ...flow, codeDigest: flowA.codeDigest };
          return flow;
        },
      },
    };
    const t = setup({ store });
    const a = await t.codeFor("a@example.org");
    flowA = await inner.otp.findById(a.flowId);
    const b = await t.codeFor("b@example.org");
    expect(await t.ik.emailSignIn.verifyCode({ flowId: b.flowId, code: a.code })).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("rule: code binding - a sign-in code does not satisfy a step-up and the reverse", async () => {
    const t = setup();
    const session = await t.signIn("person@example.org");
    const stepUp = await t.ik.stepUp.requestEmailCode(session.token);
    if (stepUp.status !== "sent") throw new Error("step-up code not sent");
    const stepUpCode = t.mail.last()?.code ?? "";
    // The step-up flow cannot be redeemed as a sign-in.
    expect(await t.ik.emailSignIn.verifyCode({ flowId: stepUp.flowId, code: stepUpCode })).toEqual({
      status: "failed",
      reason: "invalid",
    });

    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const signInFlow = await t.codeFor("person@example.org");
    expect(await t.ik.stepUp.verifyEmailCode(session.token, signInFlow)).toMatchObject({
      status: "failed",
    });
  });

  it("rule: code binding - a step-up code works only in the session that requested it", async () => {
    const t = setup();
    const first = await t.signIn("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const second = await t.signIn("person@example.org");
    const stepUp = await t.ik.stepUp.requestEmailCode(first.token);
    if (stepUp.status !== "sent") throw new Error("not sent");
    const code = t.mail.last()?.code ?? "";
    expect(
      await t.ik.stepUp.verifyEmailCode(second.token, { flowId: stepUp.flowId, code }),
    ).toMatchObject({ status: "failed" });
  });

  it("rejects a malformed address before any work, independent of accounts", async () => {
    const t = setup();
    for (const email of [
      "",
      "not-an-address",
      "a".repeat(10_000) + "@example.org",
      42,
      ["a@example.org"],
    ]) {
      await expect(t.ik.emailSignIn.requestCode({ email: email as string })).rejects.toBeInstanceOf(
        InvalidEmailError,
      );
    }
    expect(t.mail.sent).toHaveLength(0);
  });

  it("rejects malformed codes and unknown flows with the generic failure", async () => {
    const t = setup();
    const { flowId } = await t.codeFor("person@example.org");
    for (const input of [
      { flowId, code: "12345" },
      { flowId, code: "abcdef" },
      { flowId: "unknown", code: "123456" },
      { flowId: "../../etc", code: "123456" },
    ]) {
      expect(await t.ik.emailSignIn.verifyCode(input)).toEqual({
        status: "failed",
        reason: "invalid",
      });
    }
  });

  it("refuses e-mail codes when the policy does not allow them", async () => {
    const t = setup({
      policy: {
        signInMethods: ["passkey"],
        secondFactor: "none",
        stepUpMethods: ["passkey"],
        secondFactorMethods: ["passkey"],
        approvalProofLevel: "signature",
        createAccountOnFirstSignIn: false,
      },
    });
    await expect(
      t.ik.emailSignIn.requestCode({ email: "person@example.org" }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
  });

  it("closed registration: an unknown address fails like a wrong code, after the code", async () => {
    const t = setup({ policy: { ...setup().policy.current, createAccountOnFirstSignIn: false } });
    const { flowId, code } = await t.codeFor("nobody@example.org");
    expect(await t.ik.emailSignIn.verifyCode({ flowId, code })).toEqual({
      status: "failed",
      reason: "invalid",
    });
    expect(await t.ik.accounts.findByEmail("nobody@example.org")).toBeNull();
  });

  it("a disabled account cannot sign in", async () => {
    const t = setup();
    const session = await t.signIn("person@example.org");
    await t.ik.accounts.disable(session.account.id);
    expect(await t.ik.sessions.validate(session.token)).toBeNull();
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const { flowId, code } = await t.codeFor("person@example.org");
    expect(await t.ik.emailSignIn.verifyCode({ flowId, code })).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });
});

/** Records every store method that a call reaches, in order. */
function tracingStore() {
  const inner = createMemoryStore();
  const calls: string[] = [];
  const wrap = <T extends object>(name: string, part: T): T =>
    new Proxy(part, {
      get(target, prop, receiver) {
        const value: unknown = Reflect.get(target, prop, receiver);
        if (typeof value !== "function") return value;
        return (...args: unknown[]) => {
          calls.push(`${name}.${String(prop)}`);
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      },
    });
  const store = Object.fromEntries(
    Object.entries(inner).map(([name, part]) => [name, wrap(name, part as object)]),
  ) as unknown as IdentkitStore;
  return { store, calls };
}

describe("rule: no account enumeration", () => {
  it("requesting a code gives the same response shape for a known and an unknown address", async () => {
    const t = setup();
    await t.signIn("known@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const known = await t.ik.emailSignIn.requestCode({ email: "known@example.org" });
    const unknown = await t.ik.emailSignIn.requestCode({ email: "unknown@example.org" });
    const shape = (r: typeof known) =>
      r.status === "sent"
        ? {
            status: r.status,
            ttl: r.expiresAt.getTime() - t.clock.now().getTime(),
            keys: Object.keys(r).toSorted(),
          }
        : r;
    expect(shape(known)).toEqual(shape(unknown));
    // Both addresses get a code.
    expect(t.mail.sent.map((m) => m.to).slice(-2)).toEqual([
      "known@example.org",
      "unknown@example.org",
    ]);
  });

  it("requesting a code runs the same store calls and the same mail call for known and unknown", async () => {
    const { store, calls } = tracingStore();
    const t = setup({ store });
    await t.signIn("known@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);

    calls.length = 0;
    const mailBefore = t.mail.sent.length;
    await t.ik.emailSignIn.requestCode({ email: "known@example.org" });
    const knownCalls = [...calls];
    const knownMails = t.mail.sent.length - mailBefore;

    calls.length = 0;
    await t.ik.emailSignIn.requestCode({ email: "unknown@example.org" });
    expect(calls).toEqual(knownCalls);
    expect(t.mail.sent.length - mailBefore - knownMails).toBe(knownMails);
    expect(knownCalls.some((c) => c.startsWith("accounts."))).toBe(false);
  });

  it("a wrong code gives the same failure for a known and an unknown address", async () => {
    const t = setup();
    await t.signIn("known@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const known = await t.codeFor("known@example.org");
    const unknown = await t.codeFor("unknown@example.org");
    expect(
      await t.ik.emailSignIn.verifyCode({ flowId: known.flowId, code: otherCode(known.code) }),
    ).toEqual(
      await t.ik.emailSignIn.verifyCode({ flowId: unknown.flowId, code: otherCode(unknown.code) }),
    );
  });

  it("a wrong code runs the same store calls for a known and an unknown address", async () => {
    const { store, calls } = tracingStore();
    const t = setup({ store });
    await t.signIn("known@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const known = await t.codeFor("known@example.org");
    const unknown = await t.codeFor("unknown@example.org");

    calls.length = 0;
    await t.ik.emailSignIn.verifyCode({ flowId: known.flowId, code: otherCode(known.code) });
    const knownCalls = [...calls];
    calls.length = 0;
    await t.ik.emailSignIn.verifyCode({ flowId: unknown.flowId, code: otherCode(unknown.code) });
    expect(calls).toEqual(knownCalls);
  });

  it("cooldown and lockout answers do not depend on whether the address has an account", async () => {
    const t = setup();
    await t.signIn("known@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    await t.ik.emailSignIn.requestCode({ email: "known@example.org" });
    await t.ik.emailSignIn.requestCode({ email: "unknown@example.org" });
    expect(await t.ik.emailSignIn.requestCode({ email: "known@example.org" })).toEqual(
      await t.ik.emailSignIn.requestCode({ email: "unknown@example.org" }),
    );
  });

  it("audit events never contain the code, the address or a token", async () => {
    const t = setup();
    const { flowId, code } = await t.codeFor("person@example.org");
    await t.ik.emailSignIn.verifyCode({ flowId, code: otherCode(code) });
    const result = await t.ik.emailSignIn.verifyCode({ flowId, code });
    if (result.status !== "signed_in") throw new Error("not signed in");
    const serialized = JSON.stringify(t.audit.events);
    expect(serialized).not.toContain(code);
    expect(serialized).not.toContain("person@example.org");
    expect(serialized).not.toContain(result.token);
    expect(t.audit.ofType("otp.sent")).toHaveLength(1);
    expect(t.audit.ofType("otp.verify_failed")).toHaveLength(1);
  });
});
