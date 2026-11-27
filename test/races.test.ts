/**
 * Races between a ceremony and a concurrent change (revocation, registration, store error).
 * A wrapped store runs the concurrent change at the exact point where it would hurt.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createMemoryStore,
  hashPayload,
  OperationRolledBackError,
  PasskeyCleanupError,
} from "../src/index.js";
import type { IdentkitStore, SessionRecord } from "../src/storage/types.js";
import { createOAuthTestClient } from "../src/testing/index.js";
import { emailFirstPolicy, setup, testConfig } from "./helpers.js";
import { baseOAuthOptions, oauthSetup } from "./oauth-helpers.js";

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
    const rolledBack = await t.ik.passkeys
      .finishRegistration({ sessionToken: user.token }, response)
      .catch((error: unknown) => error);
    expect(rolledBack).toBeInstanceOf(OperationRolledBackError);
    expect((rolledBack as Error).cause).toEqual(new Error("audit sink down"));
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
    const rolledBack = await t.ik.passkeys
      .finishRegistration({ sessionToken: user.token }, response)
      .catch((error: unknown) => error);
    expect(rolledBack).toBeInstanceOf(OperationRolledBackError);
    expect((rolledBack as Error).cause).toEqual(new Error("connection lost"));
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

  it("a cleanup that disables the account also revokes its API tokens", async () => {
    for (const tokenStoreFails of [false, true]) {
      const label = tokenStoreFails ? "token store fails" : "token store works";
      const inner = createMemoryStore();
      const tokens = inner.apiTokens;
      if (!tokens) throw new Error("memory store has apiTokens");
      const fail = { delete: 0, tokens: 0 };
      let afterActivate: (() => Promise<void>) | null = null;
      const store: IdentkitStore = {
        ...inner,
        apiTokens: {
          ...tokens,
          revokeAllForAccount: async (...args) => {
            if (fail.tokens > 0) {
              fail.tokens -= 1;
              throw new Error("no such table: identkit_api_tokens");
            }
            return tokens.revokeAllForAccount(...args);
          },
        },
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
            if (fail.delete > 0) {
              fail.delete -= 1;
              throw new Error("connection reset");
            }
            return inner.credentials.delete(...args);
          },
        },
      };
      const t = setup({
        store,
        policy: { ...emailFirstPolicy, createAccountOnFirstSignIn: false },
        apiTokens: { prefix: "pat_", allowedScopes: ["read:items"] },
        oauth: baseOAuthOptions,
      });
      const created = await t.ik.accounts.create({ email: "staff@example.org" });
      if (created.status !== "created") throw new Error("not created");
      const accountId = created.account.id;
      const apiToken = await t.ik.apiTokens.create({
        accountId,
        name: "ci",
        scopes: ["read:items"],
        expiresInDays: 30,
      });
      if (apiToken.status !== "created") throw new Error(apiToken.status);
      const oauthClient = await createOAuthTestClient(t.ik.oauth);
      const connected = await oauthClient.connect(accountId);
      const { token } = await t.ik.passkeys.issueEnrollmentToken(accountId);
      const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
      if (start.status !== "ok") throw new Error("denied");
      afterActivate = async () => {
        await t.ik.passkeys.revokeEnrollmentTokens(accountId);
        fail.delete = 2;
        fail.tokens = tokenStoreFails ? 2 : 0;
      };
      const error: unknown = await t.ik.passkeys
        .finishRegistration({ enrollmentToken: token }, t.authenticator.register(start.options))
        .then(
          () => null,
          (e: unknown) => e,
        );
      expect((await t.ik.accounts.get(accountId))?.status, label).toBe("disabled");
      const reasons = t.audit.ofType("passkey.registration_failed").map((e) => e.reason);
      if (tokenStoreFails) {
        // The token revocation failed twice: the disable counts as failed, so the caller and
        // the audit trail learn that the account's tokens may still be live.
        expect(error, label).toBeInstanceOf(PasskeyCleanupError);
        expect(reasons, label).toContain("cleanup_failed_disable_failed");
        expect(t.audit.ofType("api_token.revoked"), label).toHaveLength(0);
        expect(t.audit.ofType("oauth.grant_ended"), label).toHaveLength(0);
        // The operator step from the README: call accounts.disable before the re-enable.
        await t.ik.accounts.disable(accountId);
      } else {
        expect(error, label).toEqual(new Error("connection reset"));
        expect(reasons, label).toContain("cleanup_failed_account_disabled");
      }
      // Review r3: the cleanup disabled the account with a bare status write, so enabling it
      // again in the store brought its API tokens back.
      await inner.accounts.setStatus(accountId, "active");
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
        expect(
          t.audit.ofType("api_token.revoked").map((e) => `${e.tokenId} ${e.reason}`),
          label,
        ).toEqual([`${apiToken.apiToken.id} account_disabled`]);
      }
    }
  });

  it("a cleanup whose deletes and disables all fail throws PasskeyCleanupError", async () => {
    for (const scenario of ["grant lost", "grant lost, revokeAll fails", "activate throws"]) {
      const inner = createMemoryStore();
      const fail = { delete: 0, setStatus: 0, revokeAll: 0 };
      let afterActivate: (() => Promise<void>) | null = null;
      const store: IdentkitStore = {
        ...inner,
        accounts: {
          ...inner.accounts,
          setStatus: async (...args) => {
            if (fail.setStatus > 0) {
              fail.setStatus -= 1;
              throw new Error("connection reset");
            }
            return inner.accounts.setStatus(...args);
          },
        },
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
            if (fail.delete > 0) {
              fail.delete -= 1;
              throw new Error("connection reset");
            }
            return inner.credentials.delete(...args);
          },
        },
        sessions: {
          ...inner.sessions,
          revokeAllForAccount: async (...args) => {
            if (fail.revokeAll > 0) {
              fail.revokeAll -= 1;
              throw new Error("store unavailable");
            }
            return inner.sessions.revokeAllForAccount(...args);
          },
        },
      };
      const t = setup({ store });
      const created = await t.ik.accounts.create({ email: "staff@example.org" });
      if (created.status !== "created") throw new Error("not created");
      const accountId = created.account.id;
      const { token } = await t.ik.passkeys.issueEnrollmentToken(accountId);
      const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
      if (start.status !== "ok") throw new Error("denied");
      afterActivate = async () => {
        await t.ik.passkeys.revokeEnrollmentTokens(accountId);
        fail.delete = 2;
        fail.setStatus = 2;
        fail.revokeAll = scenario === "grant lost, revokeAll fails" ? 1 : 0;
        // A committed activation whose reply is lost.
        if (scenario === "activate throws") throw new Error("connection lost");
      };
      const error: unknown = await t.ik.passkeys
        .finishRegistration({ enrollmentToken: token }, t.authenticator.register(start.options))
        .then(
          () => null,
          (e: unknown) => e,
        );
      const label = scenario;
      // The store error, a failed session revocation and an activation error do not hide the
      // surviving passkey.
      expect(error, label).toBeInstanceOf(PasskeyCleanupError);
      if (!(error instanceof PasskeyCleanupError)) return;
      const [credential] = await inner.credentials.listByAccount(accountId);
      expect(error, label).toMatchObject({
        code: "passkey_cleanup_failed",
        accountId,
        credentialId: credential?.id,
      });
      expect((error.cause as Error).message, label).toBe("connection reset");
      // The residual: an active passkey on an active account, and only a best-effort event.
      expect((await t.ik.accounts.get(accountId))?.status, label).toBe("active");
      expect(
        t.audit.ofType("passkey.registration_failed").map((e) => e.reason),
        label,
      ).toContain("cleanup_failed_disable_failed");
      expect(t.audit.ofType("account.disabled"), label).toHaveLength(0);
      const signIn = await t.ik.passkeys.startSignIn();
      expect(
        (await t.ik.passkeys.finishSignIn(t.authenticator.assert(signIn.options))).status,
        label,
      ).toBe("signed_in");
      // The operator step the error names removes it.
      expect(await t.ik.passkeys.revoke(accountId, error.credentialId), label).toBe(true);
      const again = await t.ik.passkeys.startSignIn();
      expect(
        (await t.ik.passkeys.finishSignIn(t.authenticator.assert(again.options))).status,
        label,
      ).toBe("failed");
    }
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
    const rolledBack = await t.ik.passkeys
      .finishRegistration({ enrollmentToken: token }, t.authenticator.register(start.options))
      .catch((error: unknown) => error);
    expect(rolledBack).toBeInstanceOf(OperationRolledBackError);
    expect((rolledBack as Error).cause).toEqual(new Error("store unavailable"));
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

/** A memory store whose OAuth writes can run a concurrent call at the point it would hurt. */
function hookedOAuthStore() {
  const inner = createMemoryStore();
  const oauth = inner.oauth;
  if (!oauth) throw new Error("memory store has no oauth");
  const hooks: {
    beforeConsume: (() => Promise<void>) | null;
    beforeRotate: (() => Promise<void>) | null;
    beforeInsertGrant: (() => Promise<void>) | null;
    afterInsertGrant: (() => Promise<void>) | null;
    beforeUpgradeSecret: (() => Promise<void>) | null;
    beforeImportGrant: (() => Promise<void>) | null;
    beforeInsertClient: (() => Promise<void>) | null;
  } = {
    beforeConsume: null,
    beforeRotate: null,
    beforeInsertGrant: null,
    afterInsertGrant: null,
    beforeUpgradeSecret: null,
    beforeImportGrant: null,
    beforeInsertClient: null,
  };
  const once = async (name: keyof typeof hooks) => {
    const hook = hooks[name];
    hooks[name] = null;
    if (hook) await hook();
  };
  const store: IdentkitStore = {
    ...inner,
    oauth: {
      ...oauth,
      consumeCode: async (digest) => {
        await once("beforeConsume");
        return oauth.consumeCode(digest);
      },
      rotateGrant: async (...args) => {
        await once("beforeRotate");
        return oauth.rotateGrant(...args);
      },
      insertGrant: async (...args) => {
        await once("beforeInsertGrant");
        const result = await oauth.insertGrant(...args);
        await once("afterInsertGrant");
        return result;
      },
      upgradeClientSecret: async (...args) => {
        await once("beforeUpgradeSecret");
        return oauth.upgradeClientSecret(...args);
      },
      importGrant: async (...args) => {
        await once("beforeImportGrant");
        return oauth.importGrant(...args);
      },
      insertClient: async (...args) => {
        await once("beforeInsertClient");
        return oauth.insertClient(...args);
      },
    },
  };
  return { store, hooks };
}

describe("oauth races", () => {
  it("a code exchanged by a concurrent call first is gone for this one, and its grant ends", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik, account } = oauthSetup({ store });
    const client = await createOAuthTestClient(ik.oauth);
    const accountId = await account();
    const { code, verifier } = await client.authorize(accountId);
    let concurrent: Awaited<ReturnType<typeof client.exchange>> | null = null;
    hooks.beforeConsume = async () => {
      concurrent = await client.exchange(code, verifier);
    };
    const late = await client.exchange(code, verifier);
    expect(concurrent).toMatchObject({ httpStatus: 200 });
    expect(late.body?.["error"]).toBe("invalid_grant");
    // The late call saw the code again: the grant of the first exchange ended (code reuse).
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
  });

  it("a rotation that loses to a concurrent one issues nothing and keeps the grant", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik, account } = oauthSetup({ store });
    const client = await createOAuthTestClient(ik.oauth);
    const accountId = await account();
    const tokens = await client.connect(accountId);
    const refreshToken = tokens.refreshToken ?? "";
    let concurrent: Awaited<ReturnType<typeof client.refresh>> | null = null;
    hooks.beforeRotate = async () => {
      concurrent = await client.refresh(refreshToken);
    };
    const late = await client.refresh(refreshToken);
    expect(concurrent).toMatchObject({ httpStatus: 200 });
    expect(late.body?.["error"]).toBe("invalid_grant");
    expect(late.body).not.toHaveProperty("access_token");
    expect(await ik.oauth.listGrants(accountId)).toHaveLength(1);
  });

  it("a grant insert after a concurrent one filled the cap is refused", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik, account } = oauthSetup({ store, oauth: { maxGrantsPerAccount: 1 } });
    const accountId = await account();
    const first = await createOAuthTestClient(ik.oauth);
    const second = await createOAuthTestClient(ik.oauth);
    const firstCode = await first.authorize(accountId);
    const secondCode = await second.authorize(accountId);
    let concurrent: Awaited<ReturnType<typeof first.exchange>> | null = null;
    hooks.beforeInsertGrant = async () => {
      concurrent = await second.exchange(secondCode.code, secondCode.verifier);
    };
    const late = await first.exchange(firstCode.code, firstCode.verifier);
    expect(concurrent).toMatchObject({ httpStatus: 200 });
    expect(late.body?.["error"]).toBe("invalid_grant");
    expect((await ik.oauth.listGrants(accountId)).map((g) => g.clientId)).toEqual([
      second.clientId,
    ]);
  });

  it("parallel registrations at the limit never pass it", async () => {
    const { ik } = oauthSetup({
      oauth: { registration: { maxPerAddressPerDay: 5, maxPerDay: 8 } },
    });
    const body = JSON.stringify({
      redirect_uris: ["http://127.0.0.1/cb"],
      token_endpoint_auth_method: "none",
    });
    const sameAddress = await Promise.all(
      Array.from({ length: 20 }, () => ik.oauth.register({ body, addressKey: "192.0.2.1" })),
    );
    expect(sameAddress.filter((r) => r.httpStatus === 201)).toHaveLength(5);
    const spread = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        ik.oauth.register({ body, addressKey: `192.0.2.${i + 10}` }),
      ),
    );
    expect(spread.filter((r) => r.httpStatus === 201)).toHaveLength(3);
  });

  it("a disable between the code and the grant insert leaves no grant", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik, account } = oauthSetup({ store });
    const client = await createOAuthTestClient(ik.oauth);
    const accountId = await account();
    const { code, verifier } = await client.authorize(accountId);
    hooks.beforeInsertGrant = () => ik.accounts.disable(accountId);
    expect((await client.exchange(code, verifier)).body?.["error"]).toBe("invalid_grant");
    expect(await store.oauth?.listGrants(accountId, new Date(0))).toEqual([]);
  });

  it("a disable right after the grant insert ends the new grant; its tokens never work", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik, account, audit } = oauthSetup({ store });
    const client = await createOAuthTestClient(ik.oauth);
    const accountId = await account();
    const { code, verifier } = await client.authorize(accountId);
    hooks.afterInsertGrant = () => ik.accounts.disable(accountId);
    const result = await client.exchange(code, verifier);
    // The exchange had won already, so it answers with tokens; the disable ended their grant.
    expect(result.httpStatus).toBe(200);
    const accessToken = String(result.body?.["access_token"]);
    await store.accounts.setStatus(accountId, "active");
    expect(await ik.oauth.validateAccessToken(accessToken)).toMatchObject({ reason: "unknown" });
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    expect(audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["account_disabled"]);
  });

  it("a client deleted mid-exchange: no grant survives, its tokens never work (review a2 r2 N-c)", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik, account, audit } = oauthSetup({ store });
    const client = await createOAuthTestClient(ik.oauth);
    const accountId = await account();
    const { code, verifier } = await client.authorize(accountId);
    hooks.afterInsertGrant = async () => {
      await ik.oauth.deleteClient(client.clientId);
    };
    const result = await client.exchange(code, verifier);
    expect(result.httpStatus).toBe(200);
    expect(await ik.oauth.validateAccessToken(String(result.body?.["access_token"]))).toMatchObject(
      { reason: "unknown" },
    );
    expect(await ik.oauth.listGrants(accountId)).toEqual([]);
    // The audit order is inverted: the end of the grant is recorded before its creation. Both
    // records exist; the README names this order.
    expect(
      audit.events
        .filter((e) => e.type === "oauth.grant_ended" || e.type === "oauth.grant_created")
        .map((e) => e.type),
    ).toEqual(["oauth.grant_ended", "oauth.grant_created"]);
  });

  it("a legacy secret upgrade that loses to a concurrent one still authenticates", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik } = oauthSetup({ store, oauth: { acceptLegacyClientSecrets: true } });
    const secretSha256 = createHash("sha256").update("old secret").digest("hex");
    await ik.oauth.importClient({
      id: "legacy-client",
      redirectUris: ["http://127.0.0.1/callback"],
      grantTypes: ["authorization_code"],
      authMethod: "client_secret_post",
      secretSha256,
    });
    const call = () =>
      ik.oauth.token({
        form: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: "x",
          client_id: "legacy-client",
          client_secret: "old secret",
        }),
        authorization: null,
      });
    let concurrent: Awaited<ReturnType<typeof call>> | null = null;
    hooks.beforeUpgradeSecret = async () => {
      concurrent = await call();
    };
    const late = await call();
    // Both authenticated (an unauthenticated call would answer 401, not invalid_grant).
    expect(concurrent).toMatchObject({ httpStatus: 400 });
    expect(late).toMatchObject({ httpStatus: 400 });
    const stored = await store.oauth?.findClient("legacy-client");
    expect(stored?.secretDigestAlgorithm).toBe("hmac-sha256");
  });

  it("a grant import that loses to a concurrent import of the same grant answers already_imported", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik, account, clock, audit } = oauthSetup({ store });
    const accountId = await account();
    await ik.oauth.importClient({
      id: "legacy-client",
      redirectUris: ["http://127.0.0.1/callback"],
      grantTypes: ["authorization_code", "refresh_token"],
      authMethod: "none",
    });
    const now = clock.now().getTime();
    const input = {
      id: "legacy-grant",
      accountId,
      clientId: "legacy-client",
      scopes: ["mcp:read"],
      resource: "https://example.com/mcp",
      createdAt: new Date(now - 1000),
      expiresAt: new Date(now + 86_400_000),
      generation: 1,
      refreshExpiresAt: new Date(now + 86_400_000),
      refreshSha256: "a".repeat(64),
    };
    let concurrent: Awaited<ReturnType<typeof ik.oauth.importGrant>> | null = null;
    hooks.beforeImportGrant = async () => {
      concurrent = await ik.oauth.importGrant(input);
    };
    const late = await ik.oauth.importGrant(input);
    expect(concurrent).toEqual({ status: "imported" });
    expect(late).toEqual({ status: "already_imported" });
    expect(audit.ofType("oauth.grant_imported")).toHaveLength(1);
  });

  it("a client import that loses to a concurrent import of the same client answers already_imported", async () => {
    const { store, hooks } = hookedOAuthStore();
    const { ik, audit } = oauthSetup({ store });
    const input = {
      id: "legacy-client",
      redirectUris: ["http://127.0.0.1/callback"],
      grantTypes: ["authorization_code"],
      authMethod: "none" as const,
    };
    let concurrent: Awaited<ReturnType<typeof ik.oauth.importClient>> | null = null;
    hooks.beforeInsertClient = async () => {
      concurrent = await ik.oauth.importClient(input);
    };
    const late = await ik.oauth.importClient(input);
    expect(concurrent).toMatchObject({ status: "imported" });
    expect(late).toMatchObject({ status: "already_imported" });
    const other = await ik.oauth.importClient({
      ...input,
      grantTypes: ["authorization_code", "refresh_token"],
    });
    expect(other).toEqual({ status: "id_taken" });
    expect(audit.ofType("oauth.client_imported")).toHaveLength(1);
  });
});
