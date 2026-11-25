/**
 * Races between a ceremony and a concurrent change (revocation, registration, store error).
 * A wrapped store runs the concurrent change at the exact point where it would hurt.
 */
import { describe, expect, it } from "vitest";
import { createMemoryStore, hashPayload } from "../src/index.js";
import type { IdentkitStore, SessionRecord } from "../src/storage/types.js";
import { emailFirstPolicy, setup, testConfig } from "./helpers.js";

interface Hooks {
  /** Runs once, right after the signature counter of an assertion was written. */
  afterCounterUpdate: (() => Promise<void>) | null;
  /** Runs once, right before a session is inserted. */
  beforeSessionInsert: ((session: SessionRecord) => Promise<void>) | null;
  /** If set, the next linkPerson call throws once. */
  failNextLink: boolean;
  /** Runs once, right before a credential is inserted. */
  beforeCredentialInsert: (() => Promise<void>) | null;
  /** Runs once, right after a credential was inserted. */
  afterCredentialInsert: (() => Promise<void>) | null;
  /** Runs once, right before a pending credential is activated. */
  beforeActivate: (() => Promise<void>) | null;
}

function hookedStore() {
  const inner = createMemoryStore();
  const hooks: Hooks = {
    afterCounterUpdate: null,
    beforeSessionInsert: null,
    failNextLink: false,
    beforeCredentialInsert: null,
    afterCredentialInsert: null,
    beforeActivate: null,
  };
  const store: IdentkitStore = {
    ...inner,
    credentials: {
      ...inner.credentials,
      insert: async (credential) => {
        const hook = hooks.beforeCredentialInsert;
        hooks.beforeCredentialInsert = null;
        if (hook) await hook();
        const result = await inner.credentials.insert(credential);
        const after = hooks.afterCredentialInsert;
        hooks.afterCredentialInsert = null;
        if (after) await after();
        return result;
      },
      activate: async (...args) => {
        const hook = hooks.beforeActivate;
        hooks.beforeActivate = null;
        if (hook) await hook();
        return inner.credentials.activate(...args);
      },
      updateCounter: async (...args) => {
        const result = await inner.credentials.updateCounter(...args);
        const hook = hooks.afterCounterUpdate;
        hooks.afterCounterUpdate = null;
        if (hook) await hook();
        return result;
      },
    },
    sessions: {
      ...inner.sessions,
      insert: async (session) => {
        const hook = hooks.beforeSessionInsert;
        hooks.beforeSessionInsert = null;
        if (hook) await hook(session);
        return inner.sessions.insert(session);
      },
    },
    accounts: {
      ...inner.accounts,
      linkPerson: async (...args) => {
        if (hooks.failNextLink) {
          hooks.failNextLink = false;
          throw new Error("store unavailable");
        }
        return inner.accounts.linkPerson(...args);
      },
    },
  };
  return { inner, store, hooks };
}

async function liveSessions(inner: IdentkitStore, accountId: string, at: Date) {
  return (await inner.sessions.revokeAllForAccount(accountId, at, "probe")).length;
}

describe("races with a concurrent revocation", () => {
  it("passkey sign-in: a credential id re-registered by another account does not save the session", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const victim = await t.userWithPasskey("victim@example.org");
    const other = await t.signIn("other@example.org");
    const victimCredential = await inner.credentials.findById(victim.credentialId);
    if (!victimCredential) throw new Error("no credential");
    const { options } = await t.ik.passkeys.startSignIn();
    const assertion = t.authenticator.assert(options);
    hooks.beforeSessionInsert = async () => {
      await t.ik.passkeys.revoke(victim.account.id, victim.credentialId);
      // Same id, another account and another key.
      await inner.credentials.insert({
        ...victimCredential,
        accountId: other.account.id,
        publicKey: new Uint8Array([9, 9, 9]),
      });
    };
    expect(await t.ik.passkeys.finishSignIn(assertion)).toEqual({
      status: "failed",
      reason: "invalid",
    });
    expect(await liveSessions(inner, victim.account.id, t.clock.now())).toBe(0);
  });

  it("passkey step-up: a revocation during the ceremony leaves no step-up", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.userWithPasskey("person@example.org");
    const start = await t.ik.stepUp.startPasskey(user.token);
    if (start.status !== "ok") throw new Error("denied");
    const assertion = t.authenticator.assert(start.options);
    hooks.afterCounterUpdate = async () => {
      await inner.credentials.delete(user.credentialId, user.account.id);
    };
    expect((await t.ik.stepUp.finishPasskey(user.token, assertion)).status).toBe("failed");
    expect(await liveSessions(inner, user.account.id, t.clock.now())).toBe(0);
  });

  it("second factor: a revocation during the ceremony leaves no session", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({
      store,
      policy: {
        signInMethods: ["email_otp", "passkey"],
        secondFactor: "if_enrolled",
        stepUpMethods: ["passkey"],
        secondFactorMethods: ["passkey"],
        approvalEvidenceLevels: ["signature"],
        createAccountOnFirstSignIn: true,
      },
    });
    const user = await t.userWithPasskey("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const { flowId, code } = await t.codeFor("person@example.org");
    const pending = await t.ik.emailSignIn.verifyCode({ flowId, code });
    if (pending.status !== "second_factor_required") throw new Error(pending.status);
    const start = await t.ik.passkeys.startSecondFactor(pending.pendingToken);
    if (start.status !== "ok") throw new Error("denied");
    const assertion = t.authenticator.assert(start.options);
    hooks.afterCounterUpdate = async () => {
      await inner.credentials.delete(user.credentialId, user.account.id);
    };
    expect((await t.ik.passkeys.finishSecondFactor(pending.pendingToken, assertion)).status).toBe(
      "failed",
    );
    // Only the session that registered the passkey is left; the completed one was revoked.
    expect(await liveSessions(inner, user.account.id, t.clock.now())).toBe(1);
  });

  it("approval: a revocation during the ceremony yields no proof", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.userWithPasskey("person@example.org");
    const payloadHash = hashPayload("release 1");
    const start = await t.ik.approvals.start({ sessionToken: user.token, payloadHash });
    if (start.status !== "ok" || start.level !== "signature") throw new Error("denied");
    const response = t.authenticator.assert(start.options);
    hooks.afterCounterUpdate = async () => {
      await inner.credentials.delete(user.credentialId, user.account.id);
    };
    expect(
      await t.ik.approvals.verify({ sessionToken: user.token, payloadHash, response }),
    ).toEqual({
      status: "failed",
      reason: "invalid",
    });
  });

  it("e-mail sign-in: a first passkey registered meanwhile makes the second factor due", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({
      store,
      policy: {
        signInMethods: ["email_otp", "passkey"],
        secondFactor: "if_enrolled",
        stepUpMethods: ["passkey"],
        secondFactorMethods: ["passkey"],
        approvalEvidenceLevels: ["signature"],
        createAccountOnFirstSignIn: true,
      },
    });
    const first = await t.signIn("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const { flowId, code } = await t.codeFor("person@example.org");
    hooks.beforeSessionInsert = async (session) => {
      if (session.state !== "complete") return;
      // The owner registers a first passkey in another session at this moment.
      await inner.credentials.insert({
        id: "concurrent-credential",
        accountId: first.account.id,
        publicKey: new Uint8Array([1]),
        counter: 0,
        transports: [],
        deviceType: "multiDevice",
        backedUp: true,
        createdAt: t.clock.now(),
        lastUsedAt: null,
        activatedAt: t.clock.now(),
      });
    };
    const result = await t.ik.emailSignIn.verifyCode({ flowId, code });
    expect(result.status).toBe("second_factor_required");
    // Only the first session and the pending one exist; no extra full session.
    const sessions = await inner.sessions.revokeAllForAccount(
      first.account.id,
      t.clock.now(),
      "probe",
    );
    expect(sessions).toHaveLength(2);
  });
});

describe("passkey registration races", () => {
  it("a session revoked during the registration leaves no new passkey", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    hooks.beforeCredentialInsert = async () => {
      await t.ik.sessions.revokeAll(user.account.id);
    };
    expect(await t.ik.passkeys.finishRegistration({ sessionToken: user.token }, response)).toEqual({
      status: "denied",
      reason: "no_session",
    });
    expect(await inner.credentials.listByAccount(user.account.id)).toHaveLength(0);
  });

  it("a session revoked between the re-check and the activation leaves no passkey", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    hooks.beforeActivate = async () => {
      await t.ik.sessions.revokeAll(user.account.id);
    };
    expect(await t.ik.passkeys.finishRegistration({ sessionToken: user.token }, response)).toEqual({
      status: "denied",
      reason: "no_session",
    });
    expect(await inner.credentials.listByAccount(user.account.id)).toHaveLength(0);
    const { options } = await t.ik.passkeys.startSignIn();
    expect((await t.ik.passkeys.finishSignIn(t.authenticator.assert(options))).status).toBe(
      "failed",
    );
  });

  it("an error in the check after the activation still removes the passkey", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    const sink = { ...t.audit };
    hooks.beforeActivate = () => {
      // The session idles out now; the check after the activation revokes it, and the audit
      // event for that fails.
      t.clock.advanceSeconds(testConfig.sessions.idleTimeoutSeconds);
      t.audit.emit = (event) => {
        if (event.type === "session.expired") throw new Error("audit sink down");
        return sink.emit(event);
      };
      return Promise.resolve();
    };
    await expect(
      t.ik.passkeys.finishRegistration({ sessionToken: user.token }, response),
    ).rejects.toThrow("audit sink down");
    expect(await inner.credentials.listByAccount(user.account.id)).toHaveLength(0);
    expect(await liveSessions(inner, user.account.id, t.clock.now())).toBe(0);
  });

  it("an error in the activation removes the passkey, ends the sessions and keeps the error", async () => {
    const inner = createMemoryStore();
    let deleteFailures = 1;
    const store: IdentkitStore = {
      ...inner,
      credentials: {
        ...inner.credentials,
        activate: async (...args) => {
          // The row is activated, then the connection drops before the answer arrives.
          await inner.credentials.activate(...args);
          throw new Error("connection lost");
        },
        delete: async (...args) => {
          if (deleteFailures > 0) {
            deleteFailures -= 1;
            throw new Error("delete failed once");
          }
          return inner.credentials.delete(...args);
        },
      },
    };
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    await expect(
      t.ik.passkeys.finishRegistration({ sessionToken: user.token }, response),
    ).rejects.toThrow("connection lost");
    expect(await inner.credentials.listByAccount(user.account.id)).toHaveLength(0);
    expect(await liveSessions(inner, user.account.id, t.clock.now())).toBe(0);
  });

  it("an enrollment token revoked while its registration runs leaves no passkey", async () => {
    for (const point of ["afterCredentialInsert", "beforeActivate"] as const) {
      const { store, hooks } = hookedStore();
      const t = setup({ store });
      const created = await t.ik.accounts.create({ email: "staff@example.org" });
      if (created.status !== "created") throw new Error("not created");
      const { token } = await t.ik.passkeys.issueEnrollmentToken(created.account.id);
      const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
      if (start.status !== "ok") throw new Error("denied");
      hooks[point] = async () => {
        await t.ik.passkeys.issueEnrollmentToken(created.account.id);
      };
      const finish = await t.ik.passkeys.finishRegistration(
        { enrollmentToken: token },
        t.authenticator.register(start.options),
      );
      expect(finish, point).toEqual({ status: "denied", reason: "invalid_enrollment" });
      expect(await t.ik.passkeys.list(created.account.id), point).toHaveLength(0);
    }
  });

  it("a revoked token whose cleanup fails twice disables the account", async () => {
    const inner = createMemoryStore();
    let deleteFailures = 0;
    let afterActivate: (() => Promise<void>) | null = null;
    const store: IdentkitStore = {
      ...inner,
      credentials: {
        ...inner.credentials,
        activate: async (...args) => {
          const result = await inner.credentials.activate(...args);
          const hook = afterActivate;
          afterActivate = null;
          if (hook) await hook();
          return result;
        },
        delete: async (...args) => {
          if (deleteFailures > 0) {
            deleteFailures -= 1;
            throw new Error("connection reset");
          }
          return inner.credentials.delete(...args);
        },
      },
    };
    const t = setup({ store, policy: { ...emailFirstPolicy, createAccountOnFirstSignIn: false } });
    const created = await t.ik.accounts.create({ email: "staff@example.org" });
    if (created.status !== "created") throw new Error("not created");
    const { token } = await t.ik.passkeys.issueEnrollmentToken(created.account.id);
    const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
    if (start.status !== "ok") throw new Error("denied");
    afterActivate = async () => {
      await t.ik.passkeys.revokeEnrollmentTokens(created.account.id);
      deleteFailures = 2;
    };
    await expect(
      t.ik.passkeys.finishRegistration(
        { enrollmentToken: token },
        t.authenticator.register(start.options),
      ),
    ).rejects.toThrow("connection reset");
    // The passkey survived both deletes, so the account is disabled and the passkey is useless.
    expect(await inner.credentials.listByAccount(created.account.id)).toHaveLength(1);
    expect((await t.ik.accounts.get(created.account.id))?.status).toBe("disabled");
    expect(t.audit.ofType("passkey.registration_failed").map((e) => e.reason)).toContain(
      "cleanup_failed_account_disabled",
    );
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    const { options } = await t.ik.passkeys.startSignIn();
    expect((await t.ik.passkeys.finishSignIn(t.authenticator.assert(options))).status).toBe(
      "failed",
    );
  });

  it("a session revocation that fails in the cleanup is recorded", async () => {
    const inner = createMemoryStore();
    let revokeFailures = 0;
    let afterActivate: (() => Promise<void>) | null = null;
    const store: IdentkitStore = {
      ...inner,
      credentials: {
        ...inner.credentials,
        activate: async (...args) => {
          const result = await inner.credentials.activate(...args);
          const hook = afterActivate;
          afterActivate = null;
          if (hook) await hook();
          return result;
        },
      },
      sessions: {
        ...inner.sessions,
        revokeAllForAccount: async (...args) => {
          if (revokeFailures > 0) {
            revokeFailures -= 1;
            throw new Error("store unavailable");
          }
          return inner.sessions.revokeAllForAccount(...args);
        },
      },
    };
    const t = setup({ store });
    const created = await t.ik.accounts.create({ email: "staff@example.org" });
    if (created.status !== "created") throw new Error("not created");
    const { token } = await t.ik.passkeys.issueEnrollmentToken(created.account.id);
    const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
    if (start.status !== "ok") throw new Error("denied");
    afterActivate = async () => {
      await t.ik.passkeys.revokeEnrollmentTokens(created.account.id);
      revokeFailures = 1;
    };
    await expect(
      t.ik.passkeys.finishRegistration(
        { enrollmentToken: token },
        t.authenticator.register(start.options),
      ),
    ).rejects.toThrow("store unavailable");
    expect(await inner.credentials.listByAccount(created.account.id)).toHaveLength(0);
    expect(t.audit.ofType("passkey.registration_failed").map((e) => e.reason)).toContain(
      "cleanup_failed",
    );
  });

  it("a pending row removed before its activation ends no session", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    hooks.beforeActivate = async () => {
      await inner.credentials.delete(response.id, user.account.id);
    };
    expect(await t.ik.passkeys.finishRegistration({ sessionToken: user.token }, response)).toEqual({
      status: "denied",
      reason: "no_session",
    });
    expect(await t.ik.sessions.validate(user.token)).not.toBeNull();
  });

  it("a token rotation in another tab does not cancel the registration", async () => {
    const { store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    let rotated: string | null = null;
    hooks.beforeActivate = async () => {
      rotated = (await t.ik.sessions.rotate(user.token))?.token ?? null;
    };
    expect(
      (await t.ik.passkeys.finishRegistration({ sessionToken: user.token }, response)).status,
    ).toBe("registered");
    expect(rotated).not.toBeNull();
    expect(await t.ik.sessions.validate(rotated ?? "")).not.toBeNull();
  });

  it("a passkey cannot sign in before its registration completed", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    const { options } = await t.ik.passkeys.startSignIn();
    let midway: unknown = null;
    // Runs right after the insert, while the registration re-checks its grant.
    hooks.afterCredentialInsert = async () => {
      midway = await t.ik.passkeys.finishSignIn(t.authenticator.assert(options));
      await t.ik.sessions.revokeAll(user.account.id);
    };
    expect(
      (await t.ik.passkeys.finishRegistration({ sessionToken: user.token }, response)).status,
    ).toBe("denied");
    expect(midway).toEqual({ status: "failed", reason: "invalid" });
    expect(await liveSessions(inner, user.account.id, t.clock.now())).toBe(0);
  });

  it("a concurrent first registration makes a passkey step-up due for the other one", async () => {
    const { inner, store, hooks } = hookedStore();
    const t = setup({ store });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: user.token });
    if (start.status !== "ok") throw new Error("denied");
    const response = t.authenticator.register(start.options);
    hooks.beforeCredentialInsert = async () => {
      await inner.credentials.insert({
        id: "owner-first-passkey",
        accountId: user.account.id,
        publicKey: new Uint8Array([1]),
        counter: 0,
        transports: [],
        deviceType: "multiDevice",
        backedUp: true,
        createdAt: t.clock.now(),
        lastUsedAt: null,
        activatedAt: t.clock.now(),
      });
    };
    expect(await t.ik.passkeys.finishRegistration({ sessionToken: user.token }, response)).toEqual({
      status: "denied",
      reason: "step_up_required",
    });
    const ids = (await inner.credentials.listByAccount(user.account.id)).map((c) => c.id);
    expect(ids).toEqual(["owner-first-passkey"]);
  });
});

describe("a failing audit sink does not skip session revocation", () => {
  it("removing a passkey revokes the other sessions before the audit event", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const other = await t.signIn("person@example.org");
    const start = await t.ik.stepUp.startPasskey(user.token);
    if (start.status !== "ok") throw new Error("denied");
    const granted = await t.ik.stepUp.finishPasskey(
      user.token,
      t.authenticator.assert(start.options),
    );
    if (granted.status !== "granted") throw new Error("not granted");
    const sink = { ...t.audit };
    t.audit.emit = (event) => {
      if (event.type === "passkey.removed") throw new Error("audit sink down");
      return sink.emit(event);
    };
    await expect(t.ik.passkeys.remove(granted.token, user.credentialId)).rejects.toThrow(
      "audit sink down",
    );
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
  });
});

describe("challenges of one purpose cannot be destroyed through another", () => {
  it("a sign-in attempt with an approval challenge leaves the approval usable", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const payloadHash = hashPayload("release 2");
    const start = await t.ik.approvals.start({ sessionToken: user.token, payloadHash });
    if (start.status !== "ok" || start.level !== "signature") throw new Error("denied");
    const response = t.authenticator.assert(start.options);
    expect((await t.ik.passkeys.finishSignIn(response)).status).toBe("failed");
    expect(
      (await t.ik.approvals.verify({ sessionToken: user.token, payloadHash, response })).status,
    ).toBe("approved");
  });
});

describe("identity verification links before it reports success", () => {
  it("a failed link leaves the verification pending, and a retry completes it", async () => {
    const { store, hooks } = hookedStore();
    const t = setup({ store, idv: { outcome: "succeed", personKey: "person-x" } });
    const user = await t.signIn("person@example.org");
    const { verificationId } = await t.ik.identityVerification.start({
      accountId: user.account.id,
    });
    hooks.failNextLink = true;
    await expect(t.ik.identityVerification.refresh(verificationId)).rejects.toThrow(
      "store unavailable",
    );
    expect((await t.ik.identityVerification.get(verificationId))?.status).toBe("pending");
    expect((await t.ik.identityVerification.refresh(verificationId))?.status).toBe("verified");
    expect((await t.ik.accounts.get(user.account.id))?.identityVerified).toBe(true);
  });
});
