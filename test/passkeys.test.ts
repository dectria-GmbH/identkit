import { describe, expect, it } from "vitest";
import { createMemoryStore, MethodNotAllowedError } from "../src/index.js";
import type { IdentkitStore } from "../src/storage/types.js";
import { createSoftwareAuthenticator } from "../src/testing/index.js";
import { ORIGIN, setup, testConfig } from "./helpers.js";

const staffPolicy = {
  signInMethods: ["passkey" as const],
  secondFactor: "none" as const,
  stepUpMethods: ["passkey" as const],
  secondFactorMethods: ["passkey" as const],
  approvalProofLevel: "signature" as const,
  createAccountOnFirstSignIn: false,
};

async function passkeySignIn(t: ReturnType<typeof setup>, overrides = {}) {
  const { options } = await t.ik.passkeys.startSignIn();
  return t.ik.passkeys.finishSignIn(t.authenticator.assert(options, overrides));
}

describe("passkey registration", () => {
  it("registers a passkey and signs in with it", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    expect(await t.ik.passkeys.list(user.account.id)).toHaveLength(1);
    const result = await passkeySignIn(t);
    expect(result.status).toBe("signed_in");
    if (result.status === "signed_in") expect(result.account.id).toBe(user.account.id);
  });

  it("asks the authenticator for user verification, a discoverable key and no attestation", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: token });
    if (start.status !== "ok") throw new Error("denied");
    expect(start.options.authenticatorSelection).toMatchObject({
      residentKey: "required",
      userVerification: "required",
    });
    expect(start.options.attestation).toBe("none");
    expect(start.options.user.id).not.toContain("person");
  });

  it("refuses an attestation format other than none", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options, { fmt: "packed" });
    expect(await t.ik.passkeys.finishRegistration({ sessionToken: token }, response)).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("refuses a registration without user verification", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options, { userVerified: false });
    expect((await t.ik.passkeys.finishRegistration({ sessionToken: token }, response)).status).toBe(
      "failed",
    );
  });

  it("rule: origin check - refuses a registration from another origin", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options, { origin: "https://evil.example" });
    expect((await t.ik.passkeys.finishRegistration({ sessionToken: token }, response)).status).toBe(
      "failed",
    );
  });

  it("a second passkey needs a fresh passkey step-up", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    // The e-mail sign-in step-up is still fresh, but it is not a passkey step-up.
    expect(await t.ik.passkeys.startRegistration({ sessionToken: user.token })).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
  });

  it("the first passkey needs a fresh step-up too", async () => {
    const t = setup();
    const { token } = await t.signIn("person@example.org");
    t.clock.advanceSeconds(testConfig.stepUp.validitySeconds);
    expect(await t.ik.passkeys.startRegistration({ sessionToken: token })).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
  });

  it("registering a passkey revokes the other sessions of the account", async () => {
    const t = setup();
    const other = await t.signIn("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const current = await t.signIn("person@example.org");
    await t.registerPasskey(current.token);
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
    expect(await t.ik.sessions.validate(current.token)).not.toBeNull();
  });

  it("enrollment token: registers once, then is spent", async () => {
    const t = setup({ policy: staffPolicy });
    const created = await t.ik.accounts.create({ email: "staff@example.org" });
    if (created.status !== "created") throw new Error("not created");
    const { token } = await t.ik.passkeys.issueEnrollmentToken(created.account.id);
    const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    expect(
      (await t.ik.passkeys.finishRegistration({ enrollmentToken: token }, response)).status,
    ).toBe("registered");
    expect(await t.ik.passkeys.startRegistration({ enrollmentToken: token })).toEqual({
      status: "denied",
      reason: "invalid_enrollment",
    });
    expect((await passkeySignIn(t)).status).toBe("signed_in");
  });

  it("enrollment token: expires", async () => {
    const t = setup({ policy: staffPolicy });
    const created = await t.ik.accounts.create({ email: "staff@example.org" });
    if (created.status !== "created") throw new Error("not created");
    const { token } = await t.ik.passkeys.issueEnrollmentToken(created.account.id);
    t.clock.advanceSeconds(testConfig.enrollment.tokenTtlSeconds);
    expect(await t.ik.passkeys.startRegistration({ enrollmentToken: token })).toEqual({
      status: "denied",
      reason: "invalid_enrollment",
    });
  });

  it("one address, one account: a second account for the same address is refused", async () => {
    const t = setup();
    expect((await t.ik.accounts.create({ email: "person@example.org" })).status).toBe("created");
    expect(await t.ik.accounts.create({ email: " PERSON@example.org" })).toEqual({
      status: "email_taken",
    });
  });
});

describe("passkey sign-in", () => {
  it("is refused when the policy does not allow passkey sign-in", async () => {
    const t = setup();
    t.policy.current = { ...t.policy.current, signInMethods: ["email_otp"] };
    await expect(t.ik.passkeys.startSignIn()).rejects.toBeInstanceOf(MethodNotAllowedError);
  });

  it("rule: challenge single use - an assertion cannot be replayed", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    const { options } = await t.ik.passkeys.startSignIn();
    const assertion = t.authenticator.assert(options);
    expect((await t.ik.passkeys.finishSignIn(assertion)).status).toBe("signed_in");
    expect(await t.ik.passkeys.finishSignIn(assertion)).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("rule: challenge single use - a replay fails also for an authenticator without a counter", async () => {
    const t = setup({ counterStep: 0 });
    await t.userWithPasskey("person@example.org");
    const { options } = await t.ik.passkeys.startSignIn();
    const assertion = t.authenticator.assert(options);
    expect((await t.ik.passkeys.finishSignIn(assertion)).status).toBe("signed_in");
    expect(await t.ik.passkeys.finishSignIn(assertion)).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("rule: challenge single use - a failed attempt spends the challenge", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    const { options } = await t.ik.passkeys.startSignIn();
    const bad = t.authenticator.assert(options, { origin: "https://evil.example" });
    expect((await t.ik.passkeys.finishSignIn(bad)).status).toBe("failed");
    expect((await t.ik.passkeys.finishSignIn(t.authenticator.assert(options))).status).toBe(
      "failed",
    );
  });

  it("rejects an assertion over a challenge the server did not issue", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    const { options } = await t.ik.passkeys.startSignIn();
    const forged = t.authenticator.assert(options, { challenge: "A".repeat(43) });
    expect((await t.ik.passkeys.finishSignIn(forged)).status).toBe("failed");
  });

  it("rejects an assertion after the challenge lifetime", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    const { options } = await t.ik.passkeys.startSignIn();
    t.clock.advanceSeconds(testConfig.webauthn.challengeTtlSeconds);
    expect((await t.ik.passkeys.finishSignIn(t.authenticator.assert(options))).status).toBe(
      "failed",
    );
  });

  it("rule: origin check - rejects an assertion from another origin", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    expect(await passkeySignIn(t, { origin: "https://portal.example.evil.example" })).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("rule: origin check - rejects an assertion made in a cross-origin frame", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    expect(await passkeySignIn(t, { crossOrigin: true })).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("rejects an assertion for another RP ID", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    expect((await passkeySignIn(t, { rpId: "evil.example" })).status).toBe("failed");
  });

  it("rejects an assertion without user verification", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    expect((await passkeySignIn(t, { userVerified: false })).status).toBe("failed");
  });

  it("rejects an assertion with a wrong ceremony type", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    expect((await passkeySignIn(t, { type: "webauthn.create" })).status).toBe("failed");
  });

  it("rejects a user handle that does not belong to the credential", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    expect((await passkeySignIn(t, { userHandle: "b3RoZXI" })).status).toBe("failed");
  });

  it("rejects a credential that is not registered", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    const stranger = createSoftwareAuthenticator({ origin: ORIGIN });
    const { options } = await t.ik.passkeys.startSignIn();
    const fake = stranger.register({
      rp: { id: "portal.example", name: "x" },
      user: { id: "dXNlcg", name: "u", displayName: "u" },
      challenge: options.challenge,
      pubKeyCredParams: [],
    });
    void fake;
    expect(
      (await t.ik.passkeys.finishSignIn(stranger.assert({ ...options, rpId: "portal.example" })))
        .status,
    ).toBe("failed");
  });

  it("rule: signature counter - rejects an assertion whose counter does not increase", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    expect((await passkeySignIn(t, { counter: 5 })).status).toBe("signed_in");
    expect(await passkeySignIn(t, { counter: 5 })).toEqual({ status: "failed", reason: "invalid" });
    expect(await passkeySignIn(t, { counter: 3 })).toEqual({ status: "failed", reason: "invalid" });
    expect(t.audit.ofType("passkey.counter_regression")).toHaveLength(2);
    expect((await passkeySignIn(t, { counter: 6 })).status).toBe("signed_in");
  });

  it("rule: signature counter - accepts authenticators that always report zero", async () => {
    const t = setup({ counterStep: 0 });
    await t.userWithPasskey("person@example.org");
    expect((await passkeySignIn(t)).status).toBe("signed_in");
    expect((await passkeySignIn(t)).status).toBe("signed_in");
  });

  it("rule: signature counter - a counter of zero after a non-zero counter is rejected", async () => {
    const t = setup();
    await t.userWithPasskey("person@example.org");
    expect((await passkeySignIn(t, { counter: 2 })).status).toBe("signed_in");
    expect((await passkeySignIn(t, { counter: 0 })).status).toBe("failed");
  });

  it("a passkey revoked while its sign-in is in flight yields no session", async () => {
    const inner = createMemoryStore();
    let revokeDuringInsert: (() => Promise<void>) | null = null;
    const store: IdentkitStore = {
      ...inner,
      sessions: {
        ...inner.sessions,
        insert: async (session) => {
          // The revocation runs completely between the assertion check and the insert.
          if (revokeDuringInsert) await revokeDuringInsert();
          return inner.sessions.insert(session);
        },
      },
    };
    const t = setup({ store });
    const user = await t.userWithPasskey("person@example.org");
    const { options } = await t.ik.passkeys.startSignIn();
    const assertion = t.authenticator.assert(options);
    revokeDuringInsert = async () => {
      revokeDuringInsert = null;
      await t.ik.passkeys.revoke(user.account.id, user.credentialId);
    };
    expect(await t.ik.passkeys.finishSignIn(assertion)).toEqual({
      status: "failed",
      reason: "invalid",
    });
    const live = (await inner.sessions.revokeAllForAccount(user.account.id, t.clock.now(), "probe"))
      .length;
    expect(live).toBe(0);
  });

  it("a disabled account cannot sign in with its passkey", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    await t.ik.accounts.disable(user.account.id);
    expect((await passkeySignIn(t)).status).toBe("failed");
  });
});

const mfaPolicy = {
  signInMethods: ["email_otp" as const, "passkey" as const],
  secondFactor: "if_enrolled" as const,
  stepUpMethods: ["passkey" as const],
  secondFactorMethods: ["passkey" as const],
  approvalProofLevel: "signature" as const,
  createAccountOnFirstSignIn: true,
};

async function pendingSignIn(t: ReturnType<typeof setup>) {
  t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
  const { flowId, code } = await t.codeFor("person@example.org");
  const result = await t.ik.emailSignIn.verifyCode({ flowId, code });
  if (result.status !== "second_factor_required") throw new Error(`unexpected ${result.status}`);
  return result.pendingToken;
}

describe("passkey as second factor", () => {
  it("asks for the passkey after the e-mail code, and the pending token is no session", async () => {
    const t = setup({ policy: mfaPolicy });
    await t.userWithPasskey("person@example.org");
    const pendingToken = await pendingSignIn(t);
    expect(await t.ik.sessions.validate(pendingToken)).toBeNull();
    expect(await t.ik.sessions.rotate(pendingToken)).toBeNull();
    expect(
      await t.ik.approvals.start({ sessionToken: pendingToken, payloadHash: "a".repeat(64) }),
    ).toEqual({
      status: "denied",
      reason: "no_session",
    });

    const start = await t.ik.passkeys.startSecondFactor(pendingToken);
    if (start.status !== "ok") throw new Error("denied");
    const done = await t.ik.passkeys.finishSecondFactor(
      pendingToken,
      t.authenticator.assert(start.options),
    );
    expect(done.status).toBe("signed_in");
    if (done.status !== "signed_in") return;
    expect(done.token).not.toBe(pendingToken);
    expect(done.session.authMethods).toEqual(["email_otp", "passkey"]);
    expect(await t.ik.sessions.validate(done.token)).not.toBeNull();
    expect(await t.ik.passkeys.startSecondFactor(pendingToken)).toEqual({
      status: "denied",
      reason: "no_pending_session",
    });
  });

  it("the pending state expires", async () => {
    const t = setup({ policy: mfaPolicy });
    await t.userWithPasskey("person@example.org");
    const pendingToken = await pendingSignIn(t);
    const start = await t.ik.passkeys.startSecondFactor(pendingToken);
    if (start.status !== "ok") throw new Error("denied");
    t.clock.advanceSeconds(testConfig.sessions.pendingTimeoutSeconds);
    expect(
      (await t.ik.passkeys.finishSecondFactor(pendingToken, t.authenticator.assert(start.options)))
        .status,
    ).toBe("failed");
  });

  it("a passkey of another account does not complete the sign-in", async () => {
    const t = setup({ policy: mfaPolicy });
    await t.userWithPasskey("person@example.org");
    // A second person with their own passkey on the same authenticator instance.
    await t.userWithPasskey("other@example.org");
    const otherCredential = t.authenticator.credentialIds()[1];
    const pendingToken = await pendingSignIn(t);
    const start = await t.ik.passkeys.startSecondFactor(pendingToken);
    if (start.status !== "ok") throw new Error("denied");
    const assertion = t.authenticator.assert(
      { ...start.options, allowCredentials: [] },
      { credentialId: otherCredential ?? "" },
    );
    expect((await t.ik.passkeys.finishSecondFactor(pendingToken, assertion)).status).toBe("failed");
  });

  it("a sign-in challenge cannot complete a second factor", async () => {
    const t = setup({ policy: mfaPolicy });
    await t.userWithPasskey("person@example.org");
    const pendingToken = await pendingSignIn(t);
    const { options } = await t.ik.passkeys.startSignIn();
    expect(
      (await t.ik.passkeys.finishSecondFactor(pendingToken, t.authenticator.assert(options)))
        .status,
    ).toBe("failed");
  });
});

describe("passkey step-up and removal", () => {
  it("a passkey step-up rotates the token and satisfies a passkey requirement", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const start = await t.ik.stepUp.startPasskey(user.token);
    if (start.status !== "ok") throw new Error("denied");
    const granted = await t.ik.stepUp.finishPasskey(
      user.token,
      t.authenticator.assert(start.options),
    );
    expect(granted.status).toBe("granted");
    if (granted.status !== "granted") return;
    expect(await t.ik.sessions.validate(user.token)).toBeNull();
    expect((await t.ik.sessions.requireStepUp(granted.token, { methods: ["passkey"] })).ok).toBe(
      true,
    );
  });

  it("a step-up challenge of one session does not work in another session", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const other = await t.signIn("person@example.org");
    const start = await t.ik.stepUp.startPasskey(user.token);
    if (start.status !== "ok") throw new Error("denied");
    expect(
      (await t.ik.stepUp.finishPasskey(other.token, t.authenticator.assert(start.options))).status,
    ).toBe("failed");
  });

  it("removing a passkey needs a fresh passkey step-up", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    expect(await t.ik.passkeys.remove(user.token, user.credentialId)).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
    const start = await t.ik.stepUp.startPasskey(user.token);
    if (start.status !== "ok") throw new Error("denied");
    const granted = await t.ik.stepUp.finishPasskey(
      user.token,
      t.authenticator.assert(start.options),
    );
    if (granted.status !== "granted") throw new Error("not granted");
    expect(await t.ik.passkeys.remove(granted.token, user.credentialId)).toEqual({
      status: "removed",
    });
    expect(await t.ik.passkeys.list(user.account.id)).toHaveLength(0);
    expect((await passkeySignIn(t)).status).toBe("failed");
  });

  it("an administrative revoke removes the passkey and ends all sessions", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    expect(await t.ik.passkeys.revoke(user.account.id, user.credentialId)).toBe(true);
    expect(await t.ik.sessions.validate(user.token)).toBeNull();
    expect((await passkeySignIn(t)).status).toBe("failed");
  });
});
