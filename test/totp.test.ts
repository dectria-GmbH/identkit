import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createAesGcmSealer,
  createMemoryStore,
  MethodNotAllowedError,
  NotConfiguredError,
  OperationRolledBackError,
  SealedSecretError,
  type IdentkitStore,
  type SecretSealer,
} from "../src/index.js";
import { createOAuthTestClient } from "../src/testing/index.js";
import { base32Decode } from "../src/totp-core.js";
import {
  emailFirstPolicy,
  hookedTotpStore,
  mfaPolicy,
  setup,
  STEP,
  testConfig,
} from "./helpers.js";
import { baseOAuthOptions } from "./oauth-helpers.js";

type T = ReturnType<typeof setup>;

/** Everything a value shows when it is logged or serialised. */
function render(value: unknown): string {
  return value instanceof Error
    ? `${value.name} ${value.message} ${value.stack ?? ""} ${JSON.stringify(value)}`
    : JSON.stringify(value);
}

/** A well-formed code that is valid at none of the steps in the drift window. */
function wrongCode(t: T, secret: string): string {
  const valid = new Set([-1, 0, 1].map((n) => t.totpCode(secret, n * STEP)));
  for (let i = 0; ; i += 1) {
    const candidate = String(i).padStart(6, "0");
    if (!valid.has(candidate)) return candidate;
  }
}

async function stepUpTotp(t: T, token: string, code: string) {
  return t.ik.stepUp.verifyTotp(token, { code });
}

/** Signs in by e-mail after the resend cooldown. */
async function signInAgain(t: T, email: string) {
  t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
  const { flowId, code } = await t.codeFor(email);
  return t.ik.emailSignIn.verifyCode({ flowId, code });
}

describe("TOTP enrolment", () => {
  it("rule: enrolment inactive before confirmation - a pending factor cannot step up, complete a sign-in or approve", async () => {
    const t = setup({
      policy: { ...mfaPolicy, approvalEvidenceLevels: ["signature", "code-confirmation"] },
    });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");
    expect(await t.ik.totp.get(user.account.id)).toBeNull();
    expect(await t.store.totp.findActive(user.account.id)).toBeNull();
    expect(await stepUpTotp(t, user.token, t.totpCode(start.secret))).toEqual({
      status: "failed",
      reason: "invalid",
    });
    expect(
      await t.ik.approvals.start({
        sessionToken: user.token,
        payloadHash: "a".repeat(64),
        levels: ["code-confirmation"],
      }),
    ).toEqual({ status: "denied", reason: "no_totp" });
    // With only a pending factor, the account has no second factor: the e-mail code suffices.
    expect((await signInAgain(t, "person@example.org")).status).toBe("signed_in");
  });

  it("rule: enrolment confirmation - a wrong code does not activate; a valid code activates and is consumed", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");
    expect(start).toMatchObject({ algorithm: "SHA1", digits: 6, periodSeconds: 30 });
    expect(base32Decode(start.secret)).toHaveLength(20);
    expect(start.provisioningUri.startsWith("otpauth://totp/")).toBe(true);
    expect(
      await t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: wrongCode(t, start.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });
    expect(await t.ik.totp.get(user.account.id)).toBeNull();

    const code = t.totpCode(start.secret);
    const confirmed = await t.ik.totp.confirmEnrolment(user.token, {
      factorId: start.factorId,
      code,
    });
    expect(confirmed).toEqual({ status: "enrolled", factorId: start.factorId, revokedSessions: 0 });
    expect((await t.ik.totp.get(user.account.id))?.id).toBe(start.factorId);
    // The confirming code is consumed: it cannot step up in the same time step.
    expect((await stepUpTotp(t, user.token, code)).status).toBe("failed");
    t.clock.advanceSeconds(STEP);
    expect((await stepUpTotp(t, user.token, t.totpCode(start.secret))).status).toBe("granted");
  });

  it("enrolment: expires, and only the session that started it can confirm", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");

    const other = await signInAgain(t, "person@example.org");
    if (other.status !== "signed_in") throw new Error("no session");
    expect(
      await t.ik.totp.confirmEnrolment(other.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });

    t.clock.advanceSeconds(
      testConfig.totp.enrolmentTtlSeconds - testConfig.emailOtp.resendCooldownSeconds,
    );
    // The step-up of the session is stale by now as well; refresh it to test the expiry alone.
    const flow = await t.ik.stepUp.requestEmailCode(user.token);
    if (flow.status !== "sent") throw new Error("not sent");
    const refreshed = await t.ik.stepUp.verifyEmailCode(user.token, {
      flowId: flow.flowId,
      code: t.mail.last()?.code ?? "",
    });
    if (refreshed.status !== "granted") throw new Error("no step-up");
    expect(
      await t.ik.totp.confirmEnrolment(refreshed.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).toEqual({ status: "failed", reason: "expired" });
  });

  it("enrolment: needs a fresh step-up; with a passkey, a passkey step-up; a second factor is refused", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    expect(await t.ik.totp.startEnrolment(user.token)).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
    const passkeyStart = await t.ik.stepUp.startPasskey(user.token);
    if (passkeyStart.status !== "ok") throw new Error("denied");
    const granted = await t.ik.stepUp.finishPasskey(
      user.token,
      t.authenticator.assert(passkeyStart.options),
    );
    if (granted.status !== "granted") throw new Error("no step-up");
    await t.enrolTotp(granted.token);
    expect(await t.ik.totp.startEnrolment(granted.token)).toEqual({
      status: "denied",
      reason: "already_enrolled",
    });

    const fresh = setup();
    const stale = await fresh.signIn("person@example.org");
    fresh.clock.advanceSeconds(testConfig.stepUp.validitySeconds);
    expect(await fresh.ik.totp.startEnrolment(stale.token)).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
  });

  it("a first passkey on an account with only TOTP needs a TOTP step-up", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    expect(await t.ik.passkeys.startRegistration({ sessionToken: user.token })).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
    t.clock.advanceSeconds(STEP);
    const granted = await stepUpTotp(t, user.token, t.totpCode(secret));
    if (granted.status !== "granted") throw new Error("no step-up");
    await t.registerPasskey(granted.token);
  });

  it("rule: factor change revokes sessions - enrolment, removal and administrative revocation end other sessions", async () => {
    const t = setup();
    const a = await t.signIn("person@example.org");
    const b = await signInAgain(t, "person@example.org");
    if (b.status !== "signed_in") throw new Error("no session");
    const { secret } = await t.enrolTotp(a.token);
    expect(await t.ik.sessions.validate(b.token)).toBeNull();
    expect(await t.ik.sessions.validate(a.token)).not.toBeNull();

    const c = await signInAgain(t, "person@example.org");
    if (c.status !== "signed_in") throw new Error("no session");
    // Removal needs a fresh step-up with the strongest factor: here TOTP.
    expect(await t.ik.totp.remove(a.token)).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
    t.clock.advanceSeconds(STEP);
    const granted = await stepUpTotp(t, a.token, t.totpCode(secret));
    if (granted.status !== "granted") throw new Error("no step-up");
    expect(await t.ik.totp.remove(granted.token)).toEqual({ status: "removed" });
    expect(await t.ik.sessions.validate(c.token)).toBeNull();
    expect(await t.ik.sessions.validate(granted.token)).not.toBeNull();
    expect(await t.ik.totp.get(a.account.id)).toBeNull();

    await t.enrolTotp(granted.token);
    expect(await t.ik.totp.revoke(a.account.id)).toBe(true);
    expect(await t.ik.sessions.validate(granted.token)).toBeNull();
    expect(t.audit.ofType("totp.removed")).toHaveLength(2);
  });

  it("enrolment: a revocation between the check and the activation leaves no factor", async () => {
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    expect(
      await t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).toEqual({ status: "denied", reason: "no_session" });
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
  });

  it("a failed session revocation after the factor write is retried or undone", async () => {
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const a = await t.signIn("person@example.org");
    const b = await signInAgain(t, "person@example.org");
    if (b.status !== "signed_in") throw new Error("no session");

    // Enrolment: the revocation of the other sessions fails, so the factor goes and every
    // session ends.
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error("denied");
    hooks.failRevokeAll = 1;
    const rolledBack = await t.ik.totp
      .confirmEnrolment(a.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      })
      .catch((error: unknown) => error);
    expect(rolledBack).toBeInstanceOf(OperationRolledBackError);
    expect((rolledBack as Error).cause).toEqual(new Error("store unavailable"));
    expect(await inner.totp.findActive(a.account.id)).toBeNull();
    expect(await t.ik.sessions.validate(b.token)).toBeNull();
    expect(await t.ik.sessions.validate(a.token)).toBeNull();

    // Removal: one failure is retried.
    const c = await signInAgain(t, "person@example.org");
    if (c.status !== "signed_in") throw new Error("no session");
    const { secret } = await t.enrolTotp(c.token);
    const d = await signInAgain(t, "person@example.org");
    if (d.status !== "signed_in") throw new Error("no session");
    t.clock.advanceSeconds(STEP);
    const granted = await stepUpTotp(t, c.token, t.totpCode(secret));
    if (granted.status !== "granted") throw new Error("no step-up");
    hooks.failRevokeAll = 1;
    expect(await t.ik.totp.remove(granted.token)).toEqual({ status: "removed" });
    expect(await t.ik.sessions.validate(d.token)).toBeNull();

    // Administrative revocation: a retry after a failure still ends the sessions.
    await t.enrolTotp(granted.token);
    hooks.failRevokeAll = 1;
    await expect(t.ik.totp.revoke(c.account.id)).rejects.toThrow("store unavailable");
    expect(await t.ik.totp.revoke(c.account.id)).toBe(false);
    expect(await t.ik.sessions.validate(granted.token)).toBeNull();
  });

  it("administrative revocation also deletes a pending enrolment, so it cannot be confirmed later", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");
    expect(await t.ik.totp.revoke(user.account.id)).toBe(true);
    expect(await t.store.totp.findPending(start.factorId)).toBeNull();
    const again = await signInAgain(t, "person@example.org");
    if (again.status !== "signed_in") throw new Error(again.status);
    expect(
      await t.ik.totp.confirmEnrolment(again.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });
    expect(await t.store.totp.findActive(user.account.id)).toBeNull();
  });

  it("a privileged hook that returns no boolean fails the sign-in", async () => {
    const t = setup({ policy: emailFirstPolicy });
    const { createIdentkit, createHmacHasher } = await import("../src/index.js");
    const { createRecordingAuditSink, createRecordingMailSender } =
      await import("../src/testing/index.js");
    const mail = createRecordingMailSender();
    const ik = createIdentkit({
      config: testConfig,
      store: createMemoryStore(),
      hasher: createHmacHasher(randomBytes(32)),
      mail,
      audit: createRecordingAuditSink(),
      sealer: t.sealer,
      policy: emailFirstPolicy,
      isPrivilegedAccount: (() => undefined) as unknown as () => boolean,
    });
    const requested = await ik.emailSignIn.requestCode({ email: "x@example.org" });
    if (requested.status !== "sent") throw new Error("not sent");
    await expect(
      ik.emailSignIn.verifyCode({ flowId: requested.flowId, code: mail.last()?.code ?? "" }),
    ).rejects.toThrow("isPrivilegedAccount must return a boolean");
  });

  it("a TOTP step-up stops changing factors once the policy drops TOTP from step-up", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    const granted = await stepUpTotp(t, user.token, t.totpCode(secret));
    if (granted.status !== "granted") throw new Error("no step-up");
    t.policy.current = { ...t.policy.current, stepUpMethods: ["passkey", "email_otp"] };
    expect(await t.ik.passkeys.startRegistration({ sessionToken: granted.token })).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
    expect(await t.ik.totp.remove(granted.token)).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
  });

  it("rule: a store error after activation cannot skip the second check - a revoked session leaves no factor", async () => {
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const other = await signInAgain(t, "person@example.org");
    if (other.status !== "signed_in") throw new Error("no session");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");
    // The owner revokes the enrolling session while the confirmation runs, and the store
    // fails on the next throttle write.
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    hooks.failThrottleReset = 1;
    expect(
      await t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).toEqual({ status: "denied", reason: "no_session" });
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
    // The denied path wrote no throttle reset at all.
    expect(hooks.failThrottleReset).toBe(1);
    hooks.failThrottleReset = 0;

    // On the success path a failing reset comes after the check and the revocation.
    const fresh = await signInAgain(t, "person@example.org");
    const bystander = await signInAgain(t, "person@example.org");
    if (fresh.status !== "signed_in" || bystander.status !== "signed_in") throw new Error("no");
    const again = await t.ik.totp.startEnrolment(fresh.token);
    if (again.status !== "ok") throw new Error("denied");
    hooks.failThrottleReset = 1;
    await expect(
      t.ik.totp.confirmEnrolment(fresh.token, {
        factorId: again.factorId,
        code: t.totpCode(again.secret),
      }),
    ).rejects.toThrow("store unavailable");
    expect(await t.ik.sessions.validate(bystander.token)).toBeNull();
  });

  it("rule: enrolment cleanup fails closed - if the factor cannot be deleted, the account is disabled", async () => {
    for (const failures of [2, 3]) {
      const { inner, store, hooks } = hookedTotpStore();
      const t = setup({ store });
      const user = await t.signIn("person@example.org");
      const start = await t.ik.totp.startEnrolment(user.token);
      if (start.status !== "ok") throw new Error("denied");
      hooks.beforeActivate = async () => {
        await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
      };
      hooks.failTotpDelete = failures;
      const result = t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      });
      if (failures === 2) {
        // The per-account delete still removes it.
        expect(await result, "2").toEqual({ status: "denied", reason: "no_session" });
        expect(await inner.totp.findActive(user.account.id)).toBeNull();
        expect((await inner.accounts.findById(user.account.id))?.status).toBe("active");
      } else {
        await expect(result, "3").rejects.toThrow("store unavailable");
        // The factor survived every delete, so nobody can sign in to the account any more.
        expect(await inner.totp.findActive(user.account.id)).not.toBeNull();
        expect((await inner.accounts.findById(user.account.id))?.status).toBe("disabled");
        expect(t.audit.ofType("totp.enrolment_failed").map((e) => e.reason)).toContain(
          "cleanup_failed_account_disabled",
        );
      }
    }
  });

  it("rule: a cleanup that disables the account also revokes its API tokens", async () => {
    for (const label of ["token store works", "token store fails", "grant store fails once"]) {
      const tokenStoreFails = label === "token store fails";
      const hooked = hookedTotpStore();
      const { inner, hooks } = hooked;
      const tokens = inner.apiTokens;
      const grants = inner.oauth;
      if (!tokens || !grants) throw new Error("memory store has apiTokens and oauth");
      let tokenFailures = 0;
      let grantFailures = 0;
      const store: IdentkitStore = {
        ...hooked.store,
        oauth: {
          ...grants,
          deleteGrantsForAccount: async (...args) => {
            if (grantFailures > 0) {
              grantFailures -= 1;
              throw new Error("no such table: identkit_oauth_grants");
            }
            return grants.deleteGrantsForAccount(...args);
          },
        },
        apiTokens: {
          ...tokens,
          revokeAllForAccount: async (...args) => {
            if (tokenFailures > 0) {
              tokenFailures -= 1;
              throw new Error("no such table: identkit_api_tokens");
            }
            return tokens.revokeAllForAccount(...args);
          },
        },
      };
      const t = setup({
        store,
        apiTokens: { prefix: "pat_", allowedScopes: ["read:items"] },
        oauth: baseOAuthOptions,
      });
      const user = await t.signIn("person@example.org");
      const apiToken = await t.ik.apiTokens.create({
        accountId: user.account.id,
        name: "ci",
        scopes: ["read:items"],
        expiresInDays: 30,
      });
      if (apiToken.status !== "created") throw new Error(apiToken.status);
      const oauthClient = await createOAuthTestClient(t.ik.oauth);
      const connected = await oauthClient.connect(user.account.id);
      const start = await t.ik.totp.startEnrolment(user.token);
      if (start.status !== "ok") throw new Error("denied");
      hooks.beforeActivate = async () => {
        await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
      };
      hooks.failTotpDelete = 3;
      tokenFailures = tokenStoreFails ? 2 : 0;
      grantFailures = label === "grant store fails once" ? 1 : 0;
      await expect(
        t.ik.totp.confirmEnrolment(user.token, {
          factorId: start.factorId,
          code: t.totpCode(start.secret),
        }),
        label,
      ).rejects.toThrow("store unavailable");
      expect((await inner.accounts.findById(user.account.id))?.status, label).toBe("disabled");
      const reasons = t.audit.ofType("totp.enrolment_failed").map((e) => e.reason);
      if (tokenStoreFails) {
        // The token revocation failed twice: the disable counts as failed, and the audit
        // trail says so.
        expect(reasons, label).toContain("cleanup_failed_disable_failed");
        expect(t.audit.ofType("account.disabled"), label).toHaveLength(0);
        expect(t.audit.ofType("api_token.revoked"), label).toHaveLength(0);
        expect(t.audit.ofType("oauth.grant_ended"), label).toHaveLength(0);
        // The operator step from the README: call accounts.disable before the re-enable.
        await t.ik.accounts.disable(user.account.id);
      } else {
        expect(reasons, label).toContain("cleanup_failed_account_disabled");
      }
      // Review r3: the cleanup disabled the account with a bare status write, so enabling it
      // again in the store brought its API tokens back.
      await inner.accounts.setStatus(user.account.id, "active");
      expect(await t.ik.apiTokens.verify(apiToken.token), label).toEqual({
        status: "refused",
        reason: "revoked",
      });
      // The cleanup ends the OAuth grants as well, so the re-enable brings no grant back.
      expect(await t.ik.oauth.validateAccessToken(connected.accessToken), label).toEqual({
        status: "refused",
        reason: "unknown",
      });
      expect(
        t.audit.ofType("oauth.grant_ended").map((e) => `${e.clientId} ${e.reason}`),
        label,
      ).toEqual([`${oauthClient.clientId} account_disabled`]);
      if (!tokenStoreFails) {
        // Review a2 B r1 L4: also after a grant store error, the retry finds the tokens revoked
        // already; their event comes from the first attempt.
        expect(
          t.audit.ofType("api_token.revoked").map((e) => `${e.tokenId} ${e.reason}`),
          label,
        ).toEqual([`${apiToken.apiToken.id} account_disabled`]);
      }
    }
  });

  it("rule: an activation that commits and then throws runs the cleanup", async () => {
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    hooks.activateThrowsAfterCommit = true;
    const rolledBack = await t.ik.totp
      .confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      })
      .catch((error: unknown) => error);
    expect(rolledBack).toBeInstanceOf(OperationRolledBackError);
    expect((rolledBack as Error).cause).toEqual(new Error("connection lost"));
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
  });

  it("a cleanup whose disable also fails says so in the audit event", async () => {
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    hooks.failTotpDelete = 3;
    hooks.failSetStatus = 1;
    // One disable failure is retried.
    await expect(
      t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).rejects.toThrow("store unavailable");
    expect((await inner.accounts.findById(user.account.id))?.status).toBe("disabled");
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);

    const second = hookedTotpStore();
    const u = setup({ store: second.store });
    const person = await u.signIn("person@example.org");
    const begun = await u.ik.totp.startEnrolment(person.token);
    if (begun.status !== "ok") throw new Error("denied");
    second.hooks.beforeActivate = async () => {
      await second.inner.sessions.revoke(person.session.id, u.clock.now(), "test");
    };
    second.hooks.failTotpDelete = 3;
    second.hooks.failSetStatus = 2;
    await expect(
      u.ik.totp.confirmEnrolment(person.token, {
        factorId: begun.factorId,
        code: u.totpCode(begun.secret),
      }),
    ).rejects.toThrow("store unavailable");
    expect((await second.inner.accounts.findById(person.account.id))?.status).toBe("active");
    expect(u.audit.ofType("totp.enrolment_failed").map((e) => e.reason)).toContain(
      "cleanup_failed_disable_failed",
    );
    expect(u.audit.ofType("account.disabled")).toHaveLength(0);
  });

  it("the TOTP secret is stored only sealed", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret, factorId } = await t.enrolTotp(user.token);
    const row = await t.store.totp.findActive(user.account.id);
    expect(row?.id).toBe(factorId);
    const stored = JSON.stringify(row);
    expect(stored).not.toContain(secret);
    expect(stored).not.toContain(Buffer.from(base32Decode(secret)).toString("hex"));
    expect(stored).not.toContain(Buffer.from(base32Decode(secret)).toString("base64url"));
  });
});

describe("TOTP verification", () => {
  it("rule: drift window - codes within driftSteps are accepted, codes outside are refused", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(10 * STEP);
    let token = user.token;
    expect((await stepUpTotp(t, token, t.totpCode(secret, -2 * STEP))).status).toBe("failed");
    expect((await stepUpTotp(t, token, t.totpCode(secret, 2 * STEP))).status).toBe("failed");
    const early = await stepUpTotp(t, token, t.totpCode(secret, -STEP));
    if (early.status !== "granted") throw new Error(`early: ${early.status}`);
    token = early.token;
    expect((await stepUpTotp(t, token, t.totpCode(secret, STEP))).status).toBe("granted");

    const strict = setup({
      config: { ...testConfig, totp: { ...testConfig.totp, driftSteps: 0 } },
    });
    const other = await strict.signIn("person@example.org");
    const enrolled = await strict.enrolTotp(other.token);
    strict.clock.advanceSeconds(10 * STEP);
    expect(
      (await stepUpTotp(strict, other.token, strict.totpCode(enrolled.secret, -STEP))).status,
    ).toBe("failed");
    expect((await stepUpTotp(strict, other.token, strict.totpCode(enrolled.secret))).status).toBe(
      "granted",
    );
  });

  it("rule: replay - a time step accepted once is not accepted again, also for an older step", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    const code = t.totpCode(secret);
    const first = await stepUpTotp(t, user.token, code);
    if (first.status !== "granted") throw new Error("no step-up");
    expect(await stepUpTotp(t, first.token, code)).toEqual({ status: "failed", reason: "invalid" });
    // Still inside the drift window, but older than the accepted step.
    t.clock.advanceSeconds(STEP);
    expect((await stepUpTotp(t, first.token, t.totpCode(secret, -STEP))).status).toBe("failed");
    expect(t.audit.ofType("totp.verify_failed").map((e) => e.reason)).toEqual([
      "replayed",
      "replayed",
    ]);
  });

  it("rule: replay - parallel requests with the same code: exactly one succeeds", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    const tokens: string[] = [user.token];
    for (let i = 0; i < 4; i += 1) {
      const next = await signInAgain(t, "person@example.org");
      if (next.status !== "signed_in") throw new Error("no session");
      tokens.push(next.token);
    }
    t.clock.advanceSeconds(STEP);
    const code = t.totpCode(secret);
    const results = await Promise.all(tokens.map((token) => stepUpTotp(t, token, code)));
    expect(results.filter((r) => r.status === "granted")).toHaveLength(1);
  });

  it("rule: attempt limit and lockout - failures lock TOTP for the account across purposes; the lock ends; a success resets", async () => {
    const t = setup({ policy: mfaPolicy });
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    const { maxFailures, lockSeconds } = testConfig.totp.lockout;
    t.clock.advanceSeconds(STEP);
    const wrong = wrongCode(t, secret);
    for (let i = 0; i < maxFailures; i += 1) {
      expect(await stepUpTotp(t, user.token, wrong)).toEqual({
        status: "failed",
        reason: "invalid",
      });
    }
    expect(await stepUpTotp(t, user.token, t.totpCode(secret))).toEqual({
      status: "failed",
      reason: "locked",
    });
    expect(t.audit.ofType("totp.locked")).toHaveLength(1);
    // The lock is per account, so the second factor of a new sign-in is locked too.
    const pending = await signInAgain(t, "person@example.org");
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    expect(pending.methods).toEqual(["totp"]);
    expect(
      await t.ik.totp.verifySecondFactor(pending.pendingToken, { code: t.totpCode(secret) }),
    ).toEqual({ status: "failed", reason: "locked" });

    t.clock.advanceSeconds(lockSeconds);
    const after = await signInAgain(t, "person@example.org");
    if (after.status !== "second_factor_required") throw new Error(after.status);
    expect(
      (await t.ik.totp.verifySecondFactor(after.pendingToken, { code: t.totpCode(secret) })).status,
    ).toBe("signed_in");
  });

  it("rule: attempt limit and lockout - a guesser who stays at the window limit is locked at the consecutive limit", async () => {
    const lockout = {
      maxFailures: 10,
      windowSeconds: 60,
      maxConsecutiveFailures: 30,
      lockSeconds: 300,
      maxLockSeconds: 86_400,
    };
    const t = setup({ config: { ...testConfig, totp: { ...testConfig.totp, lockout } } });
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    const compared = () =>
      t.audit.ofType("totp.verify_failed").filter((e) => e.reason === "wrong_code").length;
    for (let window = 1; window <= 5; window += 1) {
      t.clock.advanceSeconds(lockout.windowSeconds);
      const wrong = wrongCode(t, secret);
      for (let i = 0; i < lockout.maxFailures; i += 1) {
        await stepUpTotp(t, user.token, wrong);
      }
      // The window limit is never passed, so only the consecutive limit can lock.
      if (window === 3) expect(t.audit.ofType("totp.locked")).toHaveLength(0);
    }
    expect(compared()).toBe(lockout.maxConsecutiveFailures);
    expect(t.audit.ofType("totp.locked")).toHaveLength(1);
    expect(await stepUpTotp(t, user.token, t.totpCode(secret))).toEqual({
      status: "failed",
      reason: "locked",
    });
    // After the lock, one code is compared; a right one succeeds and resets the counts.
    t.clock.advanceSeconds(lockout.lockSeconds);
    expect((await stepUpTotp(t, user.token, t.totpCode(secret))).status).toBe("granted");
  });

  it("rule: attempt limit and lockout - an operator unlock lets the owner use TOTP while the lock runs", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    const wrong = wrongCode(t, secret);
    for (let i = 0; i <= testConfig.totp.lockout.maxFailures; i += 1) {
      await stepUpTotp(t, user.token, wrong);
    }
    expect(t.audit.ofType("totp.locked")).toHaveLength(1);
    expect(await stepUpTotp(t, user.token, t.totpCode(secret))).toEqual({
      status: "failed",
      reason: "locked",
    });
    expect(await t.ik.accounts.unlock(user.account.id)).toBe(true);
    t.clock.advanceSeconds(STEP);
    expect((await stepUpTotp(t, user.token, t.totpCode(secret))).status).toBe("granted");
  });

  it("rule: attempt limit and lockout - parallel guesses cannot exceed the limit", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    const wrong = wrongCode(t, secret);
    await Promise.all(Array.from({ length: 25 }, () => stepUpTotp(t, user.token, wrong)));
    const compared = t.audit.ofType("totp.verify_failed").filter((e) => e.reason === "wrong_code");
    expect(compared).toHaveLength(testConfig.totp.lockout.maxFailures);
  });

  it("refuses malformed codes without opening the secret", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    await t.enrolTotp(user.token);
    const opened = t.testSealer.opened();
    for (const code of ["12345", "1234567", "12a456", "", " 123456"]) {
      expect((await stepUpTotp(t, user.token, code)).status).toBe("failed");
    }
    expect(t.testSealer.opened()).toBe(opened);
  });

  it("an unreadable sealed secret fails closed with a SealedSecretError", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    t.testSealer.failNextOpen();
    await expect(stepUpTotp(t, user.token, t.totpCode(secret))).rejects.toBeInstanceOf(
      SealedSecretError,
    );
    expect((await t.ik.sessions.validate(user.token))?.stepUp?.method).toBe("email_otp");
  });

  it("TOTP needs a sealer: a static policy fails at construction, a dynamic one per call", async () => {
    const { createIdentkit, createHmacHasher } = await import("../src/index.js");
    const { createRecordingAuditSink, createRecordingMailSender } =
      await import("../src/testing/index.js");
    const base = {
      config: testConfig,
      store: createMemoryStore(),
      hasher: createHmacHasher(randomBytes(32)),
      mail: createRecordingMailSender(),
      audit: createRecordingAuditSink(),
      isPrivilegedAccount: () => false,
    };
    expect(() => createIdentkit({ ...base, policy: mfaPolicy })).toThrow(NotConfiguredError);
    // A policy function is read per call, so the missing sealer shows only then.
    const ik = createIdentkit({ ...base, policy: () => mfaPolicy });
    await expect(ik.totp.startEnrolment("A".repeat(43))).rejects.toBeInstanceOf(NotConfiguredError);
  });
});

describe("TOTP as second factor and step-up", () => {
  it("e-mail code then TOTP gives a full session with both methods", async () => {
    const t = setup({ policy: mfaPolicy });
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    const pending = await signInAgain(t, "person@example.org");
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    expect(await t.ik.sessions.validate(pending.pendingToken)).toBeNull();
    const done = await t.ik.totp.verifySecondFactor(pending.pendingToken, {
      code: t.totpCode(secret),
    });
    if (done.status !== "signed_in") throw new Error(done.status);
    expect(done.session.authMethods).toEqual(["email_otp", "totp"]);
    expect(done.session.stepUp?.method).toBe("totp");
    expect((await t.ik.sessions.requireStepUp(done.token, { methods: ["totp"] })).ok).toBe(true);
  });

  it("a removal during the second-factor check leaves no session", async () => {
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, policy: mfaPolicy });
    const user = await t.signIn("person@example.org");
    const { secret, factorId } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    const pending = await signInAgain(t, "person@example.org");
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    hooks.afterRecordStep = async () => {
      await inner.totp.delete(factorId, user.account.id);
    };
    expect(
      await t.ik.totp.verifySecondFactor(pending.pendingToken, { code: t.totpCode(secret) }),
    ).toEqual({ status: "failed", reason: "invalid" });
    expect(
      (await inner.sessions.revokeAllForAccount(user.account.id, t.clock.now(), "probe")).length,
    ).toBe(1); // only the enrolling session was still live
  });

  it("a removal during the step-up check leaves no step-up", async () => {
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const { secret, factorId } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    hooks.afterRecordStep = async () => {
      await inner.totp.delete(factorId, user.account.id);
    };
    expect(await stepUpTotp(t, user.token, t.totpCode(secret))).toEqual({
      status: "failed",
      reason: "invalid",
    });
    expect(await inner.sessions.findById(user.session.id)).toMatchObject({
      revokeReason: "factor_removed",
    });
  });

  it("rule: policy refuses a disallowed factor - enrolment, second factor and step-up by TOTP throw", async () => {
    const t = setup({ policy: mfaPolicy });
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    t.clock.advanceSeconds(STEP);
    const pending = await signInAgain(t, "person@example.org");
    if (pending.status !== "second_factor_required") throw new Error(pending.status);

    t.policy.current = {
      ...mfaPolicy,
      secondFactorMethods: ["passkey"],
      stepUpMethods: ["passkey", "email_otp"],
    };
    await expect(
      t.ik.totp.verifySecondFactor(pending.pendingToken, { code: t.totpCode(secret) }),
    ).rejects.toBeInstanceOf(MethodNotAllowedError);
    await expect(stepUpTotp(t, user.token, t.totpCode(secret))).rejects.toBeInstanceOf(
      MethodNotAllowedError,
    );
    await expect(t.ik.totp.startEnrolment(user.token)).rejects.toBeInstanceOf(
      MethodNotAllowedError,
    );
    // The account has a factor the policy does not allow: no session from the e-mail code.
    expect(await signInAgain(t, "person@example.org")).toEqual({
      status: "second_factor_unavailable",
      reason: "method_not_allowed",
    });
  });

  it("a passkey second factor is refused when the policy allows only TOTP", async () => {
    const t = setup({ policy: { ...mfaPolicy, secondFactorMethods: ["totp"] } });
    await t.userWithPasskey("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const { flowId, code } = await t.codeFor("person@example.org");
    expect(await t.ik.emailSignIn.verifyCode({ flowId, code })).toEqual({
      status: "second_factor_unavailable",
      reason: "method_not_allowed",
    });
  });

  it("rule: privileged accounts need a second factor - secondFactor none does not apply to them", async () => {
    const t = setup({ policy: emailFirstPolicy, privilegedEmails: ["admin@example.org"] });
    // A privileged account without a second factor gets no session from an e-mail code.
    const before = t.audit.ofType("session.created").length;
    t.clock.advanceSeconds(1);
    const { flowId, code } = await t.codeFor("admin@example.org");
    expect(await t.ik.emailSignIn.verifyCode({ flowId, code })).toEqual({
      status: "second_factor_unavailable",
      reason: "enrolment_required",
    });
    expect(t.audit.ofType("session.created")).toHaveLength(before);

    // A non-privileged account under the same policy signs in with the code alone.
    const plain = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(plain.token);
    expect((await signInAgain(t, "person@example.org")).status).toBe("signed_in");

    // Marked privileged, the same account must use its factor.
    t.privileged.add("person@example.org");
    t.clock.advanceSeconds(STEP);
    const pending = await signInAgain(t, "person@example.org");
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    expect(pending.methods).toEqual(["totp"]);
    expect(
      (await t.ik.totp.verifySecondFactor(pending.pendingToken, { code: t.totpCode(secret) }))
        .status,
    ).toBe("signed_in");
  });

  it("the privileged hook is required and fails closed", async () => {
    const { createIdentkit, createHmacHasher } = await import("../src/index.js");
    const { createRecordingAuditSink, createRecordingMailSender, createTestSealer } =
      await import("../src/testing/index.js");
    const base = {
      config: testConfig,
      sealer: createTestSealer(),
      store: createMemoryStore(),
      hasher: createHmacHasher(randomBytes(32)),
      mail: createRecordingMailSender(),
      audit: createRecordingAuditSink(),
      policy: emailFirstPolicy,
    };
    expect(() => createIdentkit(base as unknown as Parameters<typeof createIdentkit>[0])).toThrow(
      TypeError,
    );
    const mail = createRecordingMailSender();
    const throwing = createIdentkit({
      ...base,
      mail,
      isPrivilegedAccount: () => {
        throw new Error("directory unavailable");
      },
    });
    const requested = await throwing.emailSignIn.requestCode({ email: "x@example.org" });
    if (requested.status !== "sent") throw new Error("not sent");
    await expect(
      throwing.emailSignIn.verifyCode({ flowId: requested.flowId, code: mail.last()?.code ?? "" }),
    ).rejects.toThrow("directory unavailable");
  });
});

describe("TOTP secrets", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rule: secret never leaves - audit events, errors, console output and later results hold no secret", async () => {
    const consoleCalls: unknown[][] = [];
    for (const method of ["log", "info", "warn", "error", "debug", "trace"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        consoleCalls.push(args);
      });
    }
    const t = setup({
      policy: { ...mfaPolicy, approvalEvidenceLevels: ["signature", "code-confirmation"] },
    });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error("denied");
    const secretBytes = Buffer.from(base32Decode(start.secret));
    const codes: string[] = [];
    const code = (offset = 0) => {
      const value = t.totpCode(start.secret, offset);
      codes.push(value);
      return value;
    };
    const later: unknown[] = [];
    const errors: unknown[] = [];

    later.push(
      await t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: wrongCode(t, start.secret),
      }),
    );
    later.push(
      await t.ik.totp.confirmEnrolment(user.token, { factorId: start.factorId, code: code() }),
    );
    const row = await t.store.totp.findActive(user.account.id);
    const sealed = row?.sealedSecret ?? "missing";
    later.push(await t.ik.totp.get(user.account.id));
    t.clock.advanceSeconds(STEP);
    later.push(await stepUpTotp(t, user.token, wrongCode(t, start.secret)));
    const granted = await stepUpTotp(t, user.token, code());
    later.push(granted);
    if (granted.status !== "granted") throw new Error("no step-up");
    later.push(await stepUpTotp(t, granted.token, codes.at(-1) ?? ""));

    t.clock.advanceSeconds(STEP);
    const pending = await signInAgain(t, "person@example.org");
    later.push(pending);
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    later.push(await t.ik.totp.verifySecondFactor(pending.pendingToken, { code: code() }));

    t.clock.advanceSeconds(STEP);
    const approval = await t.ik.approvals.start({
      sessionToken: granted.token,
      payloadHash: "c".repeat(64),
      levels: ["code-confirmation"],
    });
    later.push(approval);
    if (approval.status !== "ok" || approval.level !== "code-confirmation") {
      throw new Error("denied");
    }
    later.push(
      await t.ik.approvals.verify({
        sessionToken: granted.token,
        payloadHash: "c".repeat(64),
        approvalId: approval.approvalId,
        code: code(),
      }),
    );

    t.clock.advanceSeconds(STEP);
    t.testSealer.failNextOpen();
    errors.push(await stepUpTotp(t, granted.token, code()).catch((e: unknown) => e));
    errors.push(
      await t.ik.totp
        .confirmEnrolment(granted.token, { factorId: "x".repeat(65), code: "1" })
        .catch((e: unknown) => e),
    );
    later.push(await t.ik.totp.reseal(user.account.id));
    later.push(await t.ik.totp.get(user.account.id));

    const forbidden = [
      start.secret,
      start.secret.toLowerCase(),
      secretBytes.toString("hex"),
      secretBytes.toString("base64"),
      secretBytes.toString("base64url"),
      start.provisioningUri,
      "otpauth",
      sealed,
      sealed.split(".")[3] ?? "missing",
    ];
    const surfaces = {
      audit: t.audit.events.map(render).join("\n"),
      errors: errors.map(render).join("\n"),
      console: consoleCalls.map(render).join("\n"),
      later: later.map(render).join("\n"),
    };
    expect(errors[0]).toBeInstanceOf(SealedSecretError);
    expect(t.audit.events.length).toBeGreaterThan(20);
    for (const [surface, text] of Object.entries(surfaces)) {
      for (const value of forbidden) {
        expect(text.includes(value), `${surface} contains a secret form`).toBe(false);
      }
    }
    for (const value of codes) {
      expect(surfaces.audit.includes(value), "audit contains a code").toBe(false);
    }
  });

  it("reseal: moves a factor to the active key, so the old key can be dropped", async () => {
    const oldKey = randomBytes(32);
    const nextKey = randomBytes(32);
    let current: SecretSealer = createAesGcmSealer({ keys: { old: oldKey }, activeKeyId: "old" });
    const sealer: SecretSealer = {
      seal: (plaintext, context) => current.seal(plaintext, context),
      open: (sealed, context) => current.open(sealed, context),
    };
    const t = setup({ sealer });
    const user = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(user.token);
    expect((await t.store.totp.findActive(user.account.id))?.sealedSecret).toMatch(/^v1\.old\./);

    current = createAesGcmSealer({ keys: { old: oldKey, next: nextKey }, activeKeyId: "next" });
    expect(await t.ik.totp.reseal(user.account.id)).toBe(true);
    expect((await t.store.totp.findActive(user.account.id))?.sealedSecret).toMatch(/^v1\.next\./);
    expect(t.audit.ofType("totp.resealed")).toHaveLength(1);

    current = createAesGcmSealer({ keys: { next: nextKey }, activeKeyId: "next" });
    t.clock.advanceSeconds(STEP);
    expect((await stepUpTotp(t, user.token, t.totpCode(secret))).status).toBe("granted");
  });

  it("a sealed secret moved to another account does not open", async () => {
    const t = setup();
    const a = await t.signIn("a@example.org");
    const b = await t.signIn("b@example.org");
    const { secret } = await t.enrolTotp(a.token);
    await t.enrolTotp(b.token);
    const rowA = await t.store.totp.findActive(a.account.id);
    const rowB = await t.store.totp.findActive(b.account.id);
    if (!rowA || !rowB) throw new Error("missing");
    // Someone with write access copies A's sealed secret into B's row.
    expect(
      await t.store.totp.replaceSealedSecret(rowB.id, rowB.sealedSecret, rowA.sealedSecret),
    ).toBe(true);
    t.clock.advanceSeconds(STEP);
    await expect(stepUpTotp(t, b.token, t.totpCode(secret))).rejects.toBeInstanceOf(
      SealedSecretError,
    );
  });
});
