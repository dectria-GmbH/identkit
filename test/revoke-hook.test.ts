import { describe, expect, it } from "vitest";
import {
  AllSessionsRevokedHookError,
  createMemoryStore,
  OperationRolledBackError,
  SessionsNotRevokedError,
  type AllSessionsRevokedEvent,
  type AuditEventType,
} from "../src/index.js";
import type { IdentkitStore } from "../src/storage/types.js";
import { createOAuthTestClient, type RecordingAuditSink } from "../src/testing/index.js";
import { googleClaims, oidcSetup } from "./oidc-helpers.js";
import { baseOAuthOptions } from "./oauth-helpers.js";
import { emailFirstPolicy, hookedTotpStore, setup, STEP, testConfig } from "./helpers.js";

/** A hook that throws while `failing` is true and records every call. */
function toggledHook() {
  const state = { failing: false, calls: [] as AllSessionsRevokedEvent[] };
  const hook = (event: AllSessionsRevokedEvent) => {
    state.calls.push(event);
    if (state.failing) throw new Error("application store down");
  };
  return { state, hook };
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected the call to throw");
}

function expectHookError(error: unknown, accountId: string, exceptSessionId: string | null) {
  expect(error).toBeInstanceOf(AllSessionsRevokedHookError);
  expect(error).toMatchObject({ accountId, exceptSessionId });
  expect((error as Error).cause).toEqual(new Error("application store down"));
}

/** Asserts the error of an operation that identkit rolled back. */
function expectRolledBack(
  error: unknown,
  expected: { accountId: string; cause: unknown; hookFailed: boolean },
) {
  expect(error).toBeInstanceOf(OperationRolledBackError);
  expect(error).not.toBeInstanceOf(AllSessionsRevokedHookError);
  const rolledBack = error as OperationRolledBackError;
  expect(rolledBack.accountId).toBe(expected.accountId);
  expect(rolledBack.cause).toEqual(expected.cause);
  expect(rolledBack.hookFailed).toBe(expected.hookFailed);
  expect(rolledBack.revokeAllOptions).toEqual({});
}

const hookDown = new Error("application store down");
const sinkDown = new Error("sink down");

/** Makes the audit sink throw once, on the next event of `type`. */
function failSinkOnce(audit: RecordingAuditSink, type: AuditEventType) {
  const emit = audit.emit.bind(audit);
  audit.emit = (event) => {
    if (event.type !== type) return emit(event);
    audit.emit = emit;
    throw new Error("sink down");
  };
}

type T = ReturnType<typeof setup>;

async function signInAgain(t: T, email: string) {
  t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
  const { flowId, code } = await t.codeFor(email);
  const result = await t.ik.emailSignIn.verifyCode({ flowId, code });
  if (result.status !== "signed_in") throw new Error(result.status);
  return result;
}

describe("revoke-all hook failures", () => {
  it("rule: hook last - accounts.disable writes its audit event before a failing hook; a retry reaches the hook", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    state.failing = true;
    expectHookError(await caught(t.ik.accounts.disable(a.account.id)), a.account.id, null);
    expect((await t.ik.accounts.get(a.account.id))?.status).toBe("disabled");
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    expect(await t.ik.sessions.validate(a.token)).toBeNull();
    state.failing = false;
    await t.ik.accounts.disable(a.account.id);
    expect(state.calls).toHaveLength(2);
  });

  it("rule: hook last - a passkey registration records the passkey before a failing hook; revokeAll re-runs it", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: a.token });
    if (start.status !== "ok") throw new Error(start.reason);
    const response = t.authenticator.register(start.options);
    state.failing = true;
    const error = await caught(
      t.ik.passkeys.finishRegistration({ sessionToken: a.token }, response),
    );
    expectHookError(error, a.account.id, a.session.id);
    expect(t.audit.ofType("passkey.registered")).toHaveLength(1);
    expect(await t.ik.passkeys.list(a.account.id)).toHaveLength(1);

    state.failing = false;
    const { accountId, revokeAllOptions } = error as AllSessionsRevokedHookError;
    await t.ik.sessions.revokeAll(accountId, revokeAllOptions);
    expect(state.calls.at(-1)).toEqual({
      accountId: a.account.id,
      exceptSessionId: a.session.id,
      revokedSessionIds: [],
    });
    expect(await t.ik.sessions.validate(a.token)).not.toBeNull();
  });

  it("rule: hook last - passkeys.revoke records the removal before a failing hook; a retry reaches the hook", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const user = await t.userWithPasskey("person@example.org");
    state.failing = true;
    expectHookError(
      await caught(t.ik.passkeys.revoke(user.account.id, user.credentialId)),
      user.account.id,
      null,
    );
    expect(t.audit.ofType("passkey.removed")).toHaveLength(1);
    expect(await t.ik.passkeys.list(user.account.id)).toEqual([]);
    const before = state.calls.length;
    state.failing = false;
    expect(await t.ik.passkeys.revoke(user.account.id, user.credentialId)).toBe(false);
    expect(state.calls).toHaveLength(before + 1);
  });

  it("rule: hook last - a TOTP enrolment records the factor before a failing hook", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error(start.reason);
    state.failing = true;
    expectHookError(
      await caught(
        t.ik.totp.confirmEnrolment(a.token, {
          factorId: start.factorId,
          code: t.totpCode(start.secret),
        }),
      ),
      a.account.id,
      a.session.id,
    );
    expect(t.audit.ofType("totp.enrolled")).toHaveLength(1);
    expect(await t.ik.totp.get(a.account.id)).not.toBeNull();
  });

  it("rule: hook last - totp.remove records the removal before a failing hook; revokeAll re-runs it", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(a.token);
    const other = await signInAgain(t, "person@example.org");
    t.clock.advanceSeconds(STEP);
    const granted = await t.ik.stepUp.verifyTotp(a.token, { code: t.totpCode(secret) });
    if (granted.status !== "granted") throw new Error(granted.status);
    state.failing = true;
    const error = await caught(t.ik.totp.remove(granted.token));
    expectHookError(error, a.account.id, a.session.id);
    expect(t.audit.ofType("totp.removed")).toHaveLength(1);
    expect(await t.ik.totp.get(a.account.id)).toBeNull();
    expect(await t.ik.sessions.validate(other.token)).toBeNull();

    // A retried remove answers not_found; the error names the call that re-runs the hook.
    state.failing = false;
    const before = state.calls.length;
    expect(await t.ik.totp.remove(granted.token)).toEqual({
      status: "denied",
      reason: "not_found",
    });
    const { accountId, revokeAllOptions } = error as AllSessionsRevokedHookError;
    await t.ik.sessions.revokeAll(accountId, revokeAllOptions);
    expect(state.calls).toHaveLength(before + 1);
    expect(await t.ik.sessions.validate(granted.token)).not.toBeNull();
  });

  it("rule: hook last - totp.revoke records the removal before a failing hook; a retry reaches the hook", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    await t.enrolTotp(a.token);
    state.failing = true;
    expectHookError(await caught(t.ik.totp.revoke(a.account.id)), a.account.id, null);
    expect(t.audit.ofType("totp.removed")).toHaveLength(1);
    expect(await t.ik.totp.get(a.account.id)).toBeNull();
    const before = state.calls.length;
    state.failing = false;
    expect(await t.ik.totp.revoke(a.account.id)).toBe(false);
    expect(state.calls).toHaveLength(before + 1);
  });

  it("rule: hook last - a TOTP enrolment that loses its grant records grant_changed before a failing hook and reports the rollback", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    state.failing = true;
    expectRolledBack(
      await caught(
        t.ik.totp.confirmEnrolment(user.token, {
          factorId: start.factorId,
          code: t.totpCode(start.secret),
        }),
      ),
      { accountId: user.account.id, cause: hookDown, hookFailed: true },
    );
    expect(t.audit.ofType("totp.enrolment_failed")).toEqual([
      expect.objectContaining({ reason: "grant_changed" }),
    ]);
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
  });

  it("rule: hook does not mask - a failed TOTP rollback keeps its store error when the hook also throws", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    hooks.failTotpDelete = 3;
    state.failing = true;
    const before = state.calls.length;
    await expect(
      t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).rejects.toThrow("store unavailable");
    // The hook still ran, best effort.
    expect(state.calls).toHaveLength(before + 1);
    expect((await inner.accounts.findById(user.account.id))?.status).toBe("disabled");
  });

  it("rule: hook last - oidc.removeLink records the removal before a failing hook; a retry reaches the hook", async () => {
    const { state, hook } = toggledHook();
    const t = await oidcSetup({ onAllSessionsRevoked: hook });
    const first = await t.signInWith("google", googleClaims("reset@example.org"));
    if (first.status !== "signed_in") throw new Error(first.status);
    const [link] = await t.ik.oidc.listLinks(first.account.id);
    if (!link) throw new Error("no link");
    state.failing = true;
    expectHookError(
      await caught(t.ik.oidc.removeLink(first.account.id, link.id)),
      first.account.id,
      null,
    );
    expect(t.audit.ofType("oidc.link_removed")).toHaveLength(1);
    expect(await t.ik.oidc.listLinks(first.account.id)).toEqual([]);
    expect(await t.ik.sessions.validate(first.token)).toBeNull();
    const before = state.calls.length;
    state.failing = false;
    expect(await t.ik.oidc.removeLink(first.account.id, link.id)).toBe(false);
    expect(state.calls).toHaveLength(before + 1);
    expect(t.audit.ofType("oidc.link_removed")).toHaveLength(1);
  });
});

describe("revoke-all hook with a failing audit sink", () => {
  it("rule: sink cannot skip hook - a TOTP enrolment runs the hook when the sink refuses totp.enrolled", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error(start.reason);
    failSinkOnce(t.audit, "totp.enrolled");
    const before = state.calls.length;
    await expect(
      t.ik.totp.confirmEnrolment(a.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).rejects.toThrow("sink down");
    expect(state.calls.slice(before)).toEqual([
      { accountId: a.account.id, exceptSessionId: a.session.id, revokedSessionIds: [] },
    ]);
    expect(await t.ik.totp.get(a.account.id)).not.toBeNull();
  });

  it("rule: sink cannot skip hook - a TOTP enrolment that loses its grant runs the hook when the sink refuses grant_changed", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    failSinkOnce(t.audit, "totp.enrolment_failed");
    const before = state.calls.length;
    expectRolledBack(
      await caught(
        t.ik.totp.confirmEnrolment(user.token, {
          factorId: start.factorId,
          code: t.totpCode(start.secret),
        }),
      ),
      { accountId: user.account.id, cause: sinkDown, hookFailed: false },
    );
    expect(state.calls.slice(before)).toEqual([
      expect.objectContaining({ accountId: user.account.id, exceptSessionId: null }),
    ]);
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
  });

  it("rule: sink cannot skip hook - totp.remove runs the hook when the sink refuses totp.removed", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(a.token);
    const other = await signInAgain(t, "person@example.org");
    t.clock.advanceSeconds(STEP);
    const granted = await t.ik.stepUp.verifyTotp(a.token, { code: t.totpCode(secret) });
    if (granted.status !== "granted") throw new Error(granted.status);
    failSinkOnce(t.audit, "totp.removed");
    const before = state.calls.length;
    await expect(t.ik.totp.remove(granted.token)).rejects.toThrow("sink down");
    expect(state.calls.slice(before)).toEqual([
      {
        accountId: a.account.id,
        exceptSessionId: a.session.id,
        revokedSessionIds: [other.session.id],
      },
    ]);
    expect(await t.ik.totp.get(a.account.id)).toBeNull();
  });

  it("rule: sink cannot skip hook - a passkey registration runs the hook when the sink refuses passkey.registered", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: a.token });
    if (start.status !== "ok") throw new Error(start.reason);
    const response = t.authenticator.register(start.options);
    failSinkOnce(t.audit, "passkey.registered");
    const before = state.calls.length;
    await expect(
      t.ik.passkeys.finishRegistration({ sessionToken: a.token }, response),
    ).rejects.toThrow("sink down");
    expect(state.calls.slice(before)).toEqual([
      { accountId: a.account.id, exceptSessionId: a.session.id, revokedSessionIds: [] },
    ]);
    expect(await t.ik.passkeys.list(a.account.id)).toHaveLength(1);
  });

  it("rule: sink cannot skip hook - a passkey registration that loses its grant runs the hook when the sink refuses grant_changed", async () => {
    const { state, hook } = toggledHook();
    const inner = createMemoryStore();
    let afterActivate: (() => Promise<void>) | null = null;
    const store: IdentkitStore = {
      ...inner,
      credentials: {
        ...inner.credentials,
        activate: async (...args) => {
          const result = await inner.credentials.activate(...args);
          const run = afterActivate;
          afterActivate = null;
          if (run) await run();
          return result;
        },
      },
    };
    const t = setup({
      store,
      policy: { ...emailFirstPolicy, createAccountOnFirstSignIn: false },
      onAllSessionsRevoked: hook,
    });
    const created = await t.ik.accounts.create({ email: "staff@example.org" });
    if (created.status !== "created") throw new Error("not created");
    const { token } = await t.ik.passkeys.issueEnrollmentToken(created.account.id);
    const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
    if (start.status !== "ok") throw new Error(start.reason);
    afterActivate = async () => {
      await t.ik.passkeys.revokeEnrollmentTokens(created.account.id);
    };
    failSinkOnce(t.audit, "passkey.registration_failed");
    const before = state.calls.length;
    expectRolledBack(
      await caught(
        t.ik.passkeys.finishRegistration(
          { enrollmentToken: token },
          t.authenticator.register(start.options),
        ),
      ),
      { accountId: created.account.id, cause: sinkDown, hookFailed: false },
    );
    expect(state.calls.slice(before)).toEqual([
      expect.objectContaining({ accountId: created.account.id, exceptSessionId: null }),
    ]);
    expect(await inner.credentials.listByAccount(created.account.id)).toEqual([]);
  });

  it("rule: sink cannot skip hook - sessions.revokeAll runs the hook when the sink refuses session.revoked", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    failSinkOnce(t.audit, "session.revoked");
    await expect(t.ik.sessions.revokeAll(a.account.id)).rejects.toThrow("sink down");
    expect(state.calls).toEqual([
      { accountId: a.account.id, exceptSessionId: null, revokedSessionIds: [a.session.id] },
    ]);
    expect(await t.ik.sessions.validate(a.token)).toBeNull();
  });

  it("rule: hook error wins - if sink and hook both throw, AllSessionsRevokedHookError carries the sink error", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(a.token);
    t.clock.advanceSeconds(STEP);
    const granted = await t.ik.stepUp.verifyTotp(a.token, { code: t.totpCode(secret) });
    if (granted.status !== "granted") throw new Error(granted.status);
    failSinkOnce(t.audit, "totp.removed");
    state.failing = true;
    const error = await caught(t.ik.totp.remove(granted.token));
    expectHookError(error, a.account.id, a.session.id);
    expect((error as AllSessionsRevokedHookError).auditError).toEqual(new Error("sink down"));
  });

  it("rule: hook error wins - auditError stays undefined when only the hook throws", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    state.failing = true;
    const error = await caught(t.ik.sessions.revokeAll(a.account.id));
    expectHookError(error, a.account.id, null);
    expect((error as AllSessionsRevokedHookError).auditError).toBeUndefined();
  });
});

/** Asserts a hook error with the sink's error as `auditError`. */
function expectHookErrorWithSink(
  error: unknown,
  expected: { accountId: string; revokeAllOptions: object },
) {
  expect(error).toBeInstanceOf(AllSessionsRevokedHookError);
  expect(error).not.toBeInstanceOf(OperationRolledBackError);
  const hookError = error as AllSessionsRevokedHookError;
  expect(hookError.cause).toEqual(hookDown);
  expect(hookError.accountId).toBe(expected.accountId);
  expect(hookError.revokeAllOptions).toEqual(expected.revokeAllOptions);
  expect(hookError.auditError).toEqual(sinkDown);
}

/** A store whose next passkey activation commits and then throws, as a lost reply would. */
function activationLosesReply() {
  const inner = createMemoryStore();
  const state = { armed: false };
  const store: IdentkitStore = {
    ...inner,
    credentials: {
      ...inner.credentials,
      activate: async (...args) => {
        const result = await inner.credentials.activate(...args);
        if (state.armed) {
          state.armed = false;
          throw new Error("connection lost");
        }
        return result;
      },
    },
  };
  return { inner, store, state };
}

/** Sets up a passkey registration through an enrollment token that is revoked on activation. */
async function passkeyGrantChanges(hook: (event: AllSessionsRevokedEvent) => void) {
  const inner = createMemoryStore();
  let afterActivate: (() => Promise<void>) | null = null;
  const store: IdentkitStore = {
    ...inner,
    credentials: {
      ...inner.credentials,
      activate: async (...args) => {
        const result = await inner.credentials.activate(...args);
        const run = afterActivate;
        afterActivate = null;
        if (run) await run();
        return result;
      },
    },
  };
  const t = setup({
    store,
    policy: { ...emailFirstPolicy, createAccountOnFirstSignIn: false },
    onAllSessionsRevoked: hook,
  });
  const created = await t.ik.accounts.create({ email: "staff@example.org" });
  if (created.status !== "created") throw new Error("not created");
  // A live session, so the rollback's revocation emits a `session.revoked` event.
  const live = await t.signIn("staff@example.org");
  const { token } = await t.ik.passkeys.issueEnrollmentToken(created.account.id);
  const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
  if (start.status !== "ok") throw new Error(start.reason);
  afterActivate = async () => {
    await t.ik.passkeys.revokeEnrollmentTokens(created.account.id);
  };
  const finish = () =>
    t.ik.passkeys.finishRegistration(
      { enrollmentToken: token },
      t.authenticator.register(start.options),
    );
  return { t, inner, accountId: created.account.id, live, finish };
}

describe("a sink that refuses session.revoked inside an operation", () => {
  // Rollbacks: the caller never gets a hook error that reads as "done".

  it("rule: rollback is marked - a TOTP enrolment that fails after the activation throws OperationRolledBackError with the original error, also when sink and hook fail", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const user = await t.signIn("person@example.org");
    const other = await signInAgain(t, "person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.activateThrowsAfterCommit = true;
    failSinkOnce(t.audit, "session.revoked");
    state.failing = true;
    const before = state.calls.length;
    const error = await caught(
      t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    expectRolledBack(error, {
      accountId: user.account.id,
      cause: new Error("connection lost"),
      hookFailed: true,
    });
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
    expect(await t.ik.sessions.validate(user.token)).toBeNull();
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
    // The hook ran once, for the full revocation of the rollback.
    expect(state.calls.slice(before)).toEqual([
      expect.objectContaining({ accountId: user.account.id, exceptSessionId: null }),
    ]);
  });

  it("rule: rollback is marked - a passkey registration that fails at the activation throws OperationRolledBackError with the original error, also when sink and hook fail", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, state: activation } = activationLosesReply();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: a.token });
    if (start.status !== "ok") throw new Error(start.reason);
    const response = t.authenticator.register(start.options);
    activation.armed = true;
    failSinkOnce(t.audit, "session.revoked");
    state.failing = true;
    const error = await caught(
      t.ik.passkeys.finishRegistration({ sessionToken: a.token }, response),
    );
    expectRolledBack(error, {
      accountId: a.account.id,
      cause: new Error("connection lost"),
      hookFailed: true,
    });
    expect(await inner.credentials.listByAccount(a.account.id)).toEqual([]);
    expect(await t.ik.sessions.validate(a.token)).toBeNull();
    // The sessions were revoked: no cleanup failure is recorded.
    expect(t.audit.ofType("passkey.registration_failed")).toEqual([]);
  });

  it("rule: rollback is marked - a TOTP enrolment that loses its grant throws OperationRolledBackError when sink and hook fail", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const user = await t.signIn("person@example.org");
    const other = await signInAgain(t, "person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    failSinkOnce(t.audit, "session.revoked");
    state.failing = true;
    const error = await caught(
      t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    // The first error is the sink's; the hook still needs a re-run.
    expectRolledBack(error, { accountId: user.account.id, cause: sinkDown, hookFailed: true });
    expect(t.audit.ofType("totp.enrolment_failed")).toEqual([
      expect.objectContaining({ reason: "grant_changed" }),
    ]);
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
  });

  it("rule: rollback is marked - a TOTP enrolment that loses its grant throws OperationRolledBackError when only the sink fails", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const user = await t.signIn("person@example.org");
    await signInAgain(t, "person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    failSinkOnce(t.audit, "session.revoked");
    const before = state.calls.length;
    expectRolledBack(
      await caught(
        t.ik.totp.confirmEnrolment(user.token, {
          factorId: start.factorId,
          code: t.totpCode(start.secret),
        }),
      ),
      { accountId: user.account.id, cause: sinkDown, hookFailed: false },
    );
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
    expect(state.calls.slice(before)).toEqual([
      expect.objectContaining({ accountId: user.account.id, exceptSessionId: null }),
    ]);
    expect(t.audit.ofType("totp.enrolment_failed")).toEqual([
      expect.objectContaining({ reason: "grant_changed" }),
    ]);
  });

  it("rule: rollback is marked - a TOTP enrolment that loses its grant throws OperationRolledBackError when only the hook fails", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const user = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    state.failing = true;
    const error = await caught(
      t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    expectRolledBack(error, { accountId: user.account.id, cause: hookDown, hookFailed: true });
  });

  it("rule: rollback is marked - a passkey registration that loses its grant throws OperationRolledBackError when sink and hook fail", async () => {
    const { state, hook } = toggledHook();
    const { t, inner, accountId, live, finish } = await passkeyGrantChanges(hook);
    failSinkOnce(t.audit, "session.revoked");
    state.failing = true;
    const error = await caught(finish());
    expectRolledBack(error, { accountId, cause: sinkDown, hookFailed: true });
    // The grant change is recorded; the sessions were revoked, so no cleanup failure is.
    expect(t.audit.ofType("passkey.registration_failed").map((e) => e.reason)).toEqual([
      "grant_changed",
    ]);
    expect(await inner.credentials.listByAccount(accountId)).toEqual([]);
    expect(await t.ik.sessions.validate(live.token)).toBeNull();
  });

  it("rule: rollback is marked - a passkey registration that loses its grant throws OperationRolledBackError when only the sink fails", async () => {
    const { state, hook } = toggledHook();
    const { t, inner, accountId, finish } = await passkeyGrantChanges(hook);
    failSinkOnce(t.audit, "session.revoked");
    const before = state.calls.length;
    expectRolledBack(await caught(finish()), { accountId, cause: sinkDown, hookFailed: false });
    expect(await inner.credentials.listByAccount(accountId)).toEqual([]);
    expect(state.calls.slice(before)).toEqual([
      expect.objectContaining({ accountId, exceptSessionId: null }),
    ]);
    expect(t.audit.ofType("passkey.registration_failed").map((e) => e.reason)).toEqual([
      "grant_changed",
    ]);
  });

  it("rule: rollback is marked - a TOTP enrolment that stands throws the plain sink error, never OperationRolledBackError", async () => {
    const t = setup({ onAllSessionsRevoked: () => undefined });
    const a = await t.signIn("person@example.org");
    await signInAgain(t, "person@example.org");
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error(start.reason);
    failSinkOnce(t.audit, "session.revoked");
    const error = await caught(
      t.ik.totp.confirmEnrolment(a.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    expect(error).not.toBeInstanceOf(OperationRolledBackError);
    expect(error).toEqual(sinkDown);
    expect(await t.ik.totp.get(a.account.id)).not.toBeNull();
  });

  // Success paths: the operation stands and its own event is still offered to the sink.

  it("rule: sink cannot skip events - a TOTP enrolment stands and records totp.enrolled", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const other = await signInAgain(t, "person@example.org");
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error(start.reason);
    failSinkOnce(t.audit, "session.revoked");
    const before = state.calls.length;
    await expect(
      t.ik.totp.confirmEnrolment(a.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).rejects.toThrow("sink down");
    expect(state.calls.slice(before)).toEqual([
      {
        accountId: a.account.id,
        exceptSessionId: a.session.id,
        revokedSessionIds: [other.session.id],
      },
    ]);
    expect(t.audit.ofType("totp.enrolled")).toHaveLength(1);
    expect(await t.ik.totp.get(a.account.id)).not.toBeNull();
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
    expect(await t.ik.sessions.validate(a.token)).not.toBeNull();
  });

  it("rule: sink cannot skip events - a TOTP enrolment that stands offers the hook re-run for the enrolling session", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    await signInAgain(t, "person@example.org");
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error(start.reason);
    failSinkOnce(t.audit, "session.revoked");
    state.failing = true;
    const error = await caught(
      t.ik.totp.confirmEnrolment(a.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    expectHookErrorWithSink(error, {
      accountId: a.account.id,
      revokeAllOptions: { exceptSessionId: a.session.id },
    });
    expect(t.audit.ofType("totp.enrolled")).toHaveLength(1);
    expect(await t.ik.totp.get(a.account.id)).not.toBeNull();
  });

  it("rule: sink cannot skip events - a passkey registration stands and records passkey.registered", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const other = await signInAgain(t, "person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: a.token });
    if (start.status !== "ok") throw new Error(start.reason);
    const response = t.authenticator.register(start.options);
    failSinkOnce(t.audit, "session.revoked");
    const before = state.calls.length;
    await expect(
      t.ik.passkeys.finishRegistration({ sessionToken: a.token }, response),
    ).rejects.toThrow("sink down");
    expect(state.calls.slice(before)).toHaveLength(1);
    expect(t.audit.ofType("passkey.registered")).toHaveLength(1);
    expect(await t.ik.passkeys.list(a.account.id)).toHaveLength(1);
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
  });

  it("rule: sink cannot skip events - accounts.disable records account.disabled", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    failSinkOnce(t.audit, "session.revoked");
    await expect(t.ik.accounts.disable(a.account.id)).rejects.toThrow("sink down");
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    expect(state.calls).toHaveLength(1);
  });

  it("rule: sink cannot skip events - totp.revoke records totp.removed", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    await t.enrolTotp(a.token);
    failSinkOnce(t.audit, "session.revoked");
    const before = state.calls.length;
    await expect(t.ik.totp.revoke(a.account.id)).rejects.toThrow("sink down");
    expect(t.audit.ofType("totp.removed")).toEqual([
      expect.objectContaining({ reason: "administrative" }),
    ]);
    expect(state.calls.slice(before)).toHaveLength(1);
  });

  it("rule: no swallowed error - totp.remove throws the sink error and records totp.removed", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(a.token);
    const other = await signInAgain(t, "person@example.org");
    t.clock.advanceSeconds(STEP);
    const granted = await t.ik.stepUp.verifyTotp(a.token, { code: t.totpCode(secret) });
    if (granted.status !== "granted") throw new Error(granted.status);
    failSinkOnce(t.audit, "session.revoked");
    const before = state.calls.length;
    await expect(t.ik.totp.remove(granted.token)).rejects.toThrow("sink down");
    expect(state.calls.slice(before)).toEqual([
      {
        accountId: a.account.id,
        exceptSessionId: a.session.id,
        revokedSessionIds: [other.session.id],
      },
    ]);
    expect(t.audit.ofType("totp.removed")).toHaveLength(1);
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
  });

  it("rule: no swallowed error - totp.remove keeps a hook error and the sink error", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(a.token);
    await signInAgain(t, "person@example.org");
    t.clock.advanceSeconds(STEP);
    const granted = await t.ik.stepUp.verifyTotp(a.token, { code: t.totpCode(secret) });
    if (granted.status !== "granted") throw new Error(granted.status);
    failSinkOnce(t.audit, "session.revoked");
    state.failing = true;
    const before = state.calls.length;
    const error = await caught(t.ik.totp.remove(granted.token));
    expectHookErrorWithSink(error, {
      accountId: a.account.id,
      revokeAllOptions: { exceptSessionId: a.session.id },
    });
    // One revocation, one hook call: no retry after the sink error.
    expect(state.calls.slice(before)).toHaveLength(1);
  });
});

describe("a store that fails the session revocation of an operation that cannot be retried", () => {
  it("rule: event not lost - totp.remove records totp.removed when both revocation attempts fail", async () => {
    const { store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const a = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(a.token);
    t.clock.advanceSeconds(STEP);
    const granted = await t.ik.stepUp.verifyTotp(a.token, { code: t.totpCode(secret) });
    if (granted.status !== "granted") throw new Error(granted.status);
    hooks.failRevokeAll = 2;
    const error = await caught(t.ik.totp.remove(granted.token));
    expect(error).toBeInstanceOf(SessionsNotRevokedError);
    expect((error as Error).cause).toEqual(new Error("store unavailable"));
    expect(t.audit.ofType("totp.removed")).toHaveLength(1);
  });

  it("rule: no dead end - after SessionsNotRevokedError from totp.remove, revokeAll finishes the revocation", async () => {
    const { state, hook } = toggledHook();
    const { store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const { secret } = await t.enrolTotp(a.token);
    const other = await signInAgain(t, "person@example.org");
    t.clock.advanceSeconds(STEP);
    const granted = await t.ik.stepUp.verifyTotp(a.token, { code: t.totpCode(secret) });
    if (granted.status !== "granted") throw new Error(granted.status);
    hooks.failRevokeAll = 2;
    const before = state.calls.length;
    const error = await caught(t.ik.totp.remove(granted.token));
    expect(error).toBeInstanceOf(SessionsNotRevokedError);
    const { accountId, revokeAllOptions } = error as SessionsNotRevokedError;
    expect(revokeAllOptions).toEqual({ exceptSessionId: a.session.id });
    expect(state.calls.slice(before)).toEqual([]);
    expect(await t.ik.sessions.validate(other.token)).not.toBeNull();
    // A retried remove is a dead end; the error's revokeAll call is not.
    expect(await t.ik.totp.remove(granted.token)).toEqual({
      status: "denied",
      reason: "not_found",
    });
    expect(await t.ik.sessions.revokeAll(accountId, revokeAllOptions)).toBe(1);
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
    expect(await t.ik.sessions.validate(granted.token)).not.toBeNull();
    expect(state.calls.slice(before)).toEqual([
      {
        accountId: a.account.id,
        exceptSessionId: a.session.id,
        revokedSessionIds: [other.session.id],
      },
    ]);
  });

  it("rule: event not lost - totp.revoke records totp.removed once across a retry", async () => {
    const { store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const a = await t.signIn("person@example.org");
    await t.enrolTotp(a.token);
    hooks.failRevokeAll = 1;
    await expect(t.ik.totp.revoke(a.account.id)).rejects.toThrow("store unavailable");
    expect(t.audit.ofType("totp.removed")).toHaveLength(1);
    expect(await t.ik.totp.revoke(a.account.id)).toBe(false);
    expect(t.audit.ofType("totp.removed")).toHaveLength(1);
  });

  it("rule: rollback is marked - a passkey registration rolls back like a TOTP enrolment", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const other = await signInAgain(t, "person@example.org");
    const start = await t.ik.passkeys.startRegistration({ sessionToken: a.token });
    if (start.status !== "ok") throw new Error(start.reason);
    const response = t.authenticator.register(start.options);
    hooks.failRevokeAll = 1;
    const before = state.calls.length;
    const error = await caught(
      t.ik.passkeys.finishRegistration({ sessionToken: a.token }, response),
    );
    expectRolledBack(error, {
      accountId: a.account.id,
      cause: new Error("store unavailable"),
      hookFailed: false,
    });
    expect(t.audit.ofType("passkey.registered")).toEqual([]);
    expect(await inner.credentials.listByAccount(a.account.id)).toEqual([]);
    // The rollback's own revocation ends every session, the enrolling one too.
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
    expect(await t.ik.sessions.validate(a.token)).toBeNull();
    expect(state.calls.slice(before)).toEqual([
      expect.objectContaining({ accountId: a.account.id, exceptSessionId: null }),
    ]);
  });
});

describe("a throttle store that fails after a successful TOTP enrolment", () => {
  it("rule: event not lost - totp.enrolled is recorded and the store error goes up as auditError", async () => {
    const { state, hook } = toggledHook();
    const { store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.failThrottleReset = 1;
    state.failing = true;
    const error = await caught(
      t.ik.totp.confirmEnrolment(a.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    expect(error).toBeInstanceOf(AllSessionsRevokedHookError);
    expect((error as AllSessionsRevokedHookError).auditError).toEqual(
      new Error("store unavailable"),
    );
    expect(t.audit.ofType("totp.enrolled")).toHaveLength(1);
    expect(await t.ik.totp.get(a.account.id)).not.toBeNull();
  });
});

describe("the error class tells whether an operation took effect", () => {
  it("rule: rollback is marked - a TOTP enrolment whose rollback cannot revoke the sessions throws OperationRolledBackError with hookFailed", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const user = await t.signIn("person@example.org");
    const other = await signInAgain(t, "person@example.org");
    const start = await t.ik.totp.startEnrolment(user.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.beforeActivate = async () => {
      await inner.sessions.revoke(user.session.id, t.clock.now(), "test");
    };
    hooks.failRevokeAll = 1;
    const before = state.calls.length;
    const error = await caught(
      t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    expectRolledBack(error, {
      accountId: user.account.id,
      cause: new Error("store unavailable"),
      hookFailed: true,
    });
    expect(await inner.totp.findActive(user.account.id)).toBeNull();
    expect(t.audit.ofType("totp.enrolment_failed")).toEqual([
      expect.objectContaining({ reason: "grant_changed" }),
    ]);
    expect(state.calls.slice(before)).toEqual([]);
    expect(await t.ik.sessions.validate(other.token)).not.toBeNull();
    // The error names the call that finishes the revocation and runs the hook.
    const { accountId, revokeAllOptions } = error as OperationRolledBackError;
    await t.ik.sessions.revokeAll(accountId, revokeAllOptions);
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
    expect(state.calls.slice(before)).toEqual([
      expect.objectContaining({ accountId: user.account.id, exceptSessionId: null }),
    ]);
  });

  it("rule: rollback is marked - a TOTP enrolment whose revocation of the other sessions fails throws OperationRolledBackError", async () => {
    const { state, hook } = toggledHook();
    const { inner, store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    const other = await signInAgain(t, "person@example.org");
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.failRevokeAll = 1;
    const error = await caught(
      t.ik.totp.confirmEnrolment(a.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    expectRolledBack(error, {
      accountId: a.account.id,
      cause: new Error("store unavailable"),
      hookFailed: false,
    });
    expect(await inner.totp.findActive(a.account.id)).toBeNull();
    expect(t.audit.ofType("totp.enrolled")).toEqual([]);
    expect(await t.ik.sessions.validate(other.token)).toBeNull();
    expect(await t.ik.sessions.validate(a.token)).toBeNull();
    expect(state.calls).toHaveLength(1);
  });

  it("rule: rollback is marked - a passkey registration that loses its grant before the activation throws OperationRolledBackError when the sink fails", async () => {
    const inner = createMemoryStore();
    let afterInsert: (() => Promise<void>) | null = null;
    const store: IdentkitStore = {
      ...inner,
      credentials: {
        ...inner.credentials,
        insert: async (...args) => {
          const result = await inner.credentials.insert(...args);
          const run = afterInsert;
          afterInsert = null;
          if (run) await run();
          return result;
        },
      },
    };
    const t = setup({
      store,
      policy: { ...emailFirstPolicy, createAccountOnFirstSignIn: false },
      onAllSessionsRevoked: () => undefined,
    });
    const created = await t.ik.accounts.create({ email: "staff@example.org" });
    if (created.status !== "created") throw new Error("not created");
    const { token } = await t.ik.passkeys.issueEnrollmentToken(created.account.id);
    const start = await t.ik.passkeys.startRegistration({ enrollmentToken: token });
    if (start.status !== "ok") throw new Error(start.reason);
    afterInsert = async () => {
      await t.ik.passkeys.revokeEnrollmentTokens(created.account.id);
    };
    failSinkOnce(t.audit, "passkey.registration_failed");
    const error = await caught(
      t.ik.passkeys.finishRegistration(
        { enrollmentToken: token },
        t.authenticator.register(start.options),
      ),
    );
    expectRolledBack(error, { accountId: created.account.id, cause: sinkDown, hookFailed: false });
    expect(await inner.credentials.listByAccount(created.account.id)).toEqual([]);
  });

  it("rule: first error - the sink error on totp.enrolled wins over a later throttle reset error", async () => {
    const { store, hooks } = hookedTotpStore();
    const t = setup({ store, onAllSessionsRevoked: () => undefined });
    const a = await t.signIn("person@example.org");
    const start = await t.ik.totp.startEnrolment(a.token);
    if (start.status !== "ok") throw new Error(start.reason);
    hooks.failThrottleReset = 1;
    failSinkOnce(t.audit, "totp.enrolled");
    const error = await caught(
      t.ik.totp.confirmEnrolment(a.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    );
    expect(error).toEqual(sinkDown);
    // The reset was attempted after the refused event.
    expect(hooks.failThrottleReset).toBe(0);
    expect(await t.ik.totp.get(a.account.id)).not.toBeNull();
  });
});

describe("a retried accounts.disable", () => {
  it("rule: no duplicate event - a retry after a session.revoked sink error does not record account.disabled again", async () => {
    const { state, hook } = toggledHook();
    const t = setup({ onAllSessionsRevoked: hook });
    const a = await t.signIn("person@example.org");
    failSinkOnce(t.audit, "session.revoked");
    await expect(t.ik.accounts.disable(a.account.id)).rejects.toThrow("sink down");
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    await t.ik.accounts.disable(a.account.id);
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    // The retry still runs the hook.
    expect(state.calls).toHaveLength(2);
  });

  it("rule: event not lost - a store error on the revocation records account.disabled once across a retry", async () => {
    const { store, hooks } = hookedTotpStore();
    const t = setup({ store });
    const a = await t.signIn("person@example.org");
    hooks.failRevokeAll = 1;
    await expect(t.ik.accounts.disable(a.account.id)).rejects.toThrow("store unavailable");
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    expect(await t.ik.sessions.validate(a.token)).toBeNull();
    await t.ik.accounts.disable(a.account.id);
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
  });
});

/**
 * A memory store whose API token revocation and OAuth grant end throw while their flag is on.
 * Both are on at the start.
 */
function brokenRevocationStores() {
  const memory = createMemoryStore();
  const tokens = memory.apiTokens;
  const oauth = memory.oauth;
  if (!tokens || !oauth) throw new Error("memory store has apiTokens and oauth");
  const broken = { tokens: true, grants: true };
  const store: IdentkitStore = {
    ...memory,
    apiTokens: {
      ...tokens,
      revokeAllForAccount: (...args) =>
        broken.tokens
          ? Promise.reject(new Error("no such table: identkit_api_tokens"))
          : tokens.revokeAllForAccount(...args),
    },
    oauth: {
      ...oauth,
      deleteGrantsForAccount: (...args) =>
        broken.grants
          ? Promise.reject(new Error("no such table: identkit_oauth_grants"))
          : oauth.deleteGrantsForAccount(...args),
    },
  };
  return { store, broken };
}

/** identkit with OAuth over a broken store, an account and one connected client. */
async function disableSetup(onAllSessionsRevoked?: (event: AllSessionsRevokedEvent) => void) {
  const { store, broken } = brokenRevocationStores();
  const t = setup({
    store,
    oauth: baseOAuthOptions,
    ...(onAllSessionsRevoked ? { onAllSessionsRevoked } : {}),
  });
  const user = await t.signIn(`disable-${Math.random().toString(36).slice(2)}@example.org`);
  const client = await createOAuthTestClient(t.ik.oauth);
  const tokens = await client.connect(user.account.id);
  return { t, store, broken, accountId: user.account.id, tokens };
}

describe("accounts.disable with a failing OAuth grant store", () => {
  it("rule: hook error wins - it carries the grant store error, and the message names the retry", async () => {
    const { t, broken, accountId } = await disableSetup(() => {
      throw hookDown;
    });
    broken.tokens = false;
    const error = await caught(t.ik.accounts.disable(accountId));
    expect(error).toBeInstanceOf(AllSessionsRevokedHookError);
    const hookError = error as AllSessionsRevokedHookError;
    expect(hookError.cause).toEqual(hookDown);
    expect(hookError.tokenRevocationError).toBeUndefined();
    expect(hookError.grantRevocationError).toEqual(
      new Error("no such table: identkit_oauth_grants"),
    );
    expect(hookError.message).toBe(
      "onAllSessionsRevoked failed after the revocation, and the end of the OAuth grants failed " +
        "(no such table: identkit_oauth_grants); call accounts.disable again",
    );
    expect(t.audit.ofType("account.disabled")).toHaveLength(1);
    expect(t.audit.ofType("session.revoked")).toHaveLength(1);
  });

  it("rule: hook error wins - with both store errors it carries both and names both", async () => {
    const { t, accountId } = await disableSetup(() => {
      throw hookDown;
    });
    failSinkOnce(t.audit, "account.disabled");
    const error = await caught(t.ik.accounts.disable(accountId));
    expect(error).toBeInstanceOf(AllSessionsRevokedHookError);
    const hookError = error as AllSessionsRevokedHookError;
    expect(hookError.auditError).toEqual(sinkDown);
    expect(hookError.tokenRevocationError).toEqual(new Error("no such table: identkit_api_tokens"));
    expect(hookError.grantRevocationError).toEqual(
      new Error("no such table: identkit_oauth_grants"),
    );
    expect(hookError.message).toBe(
      "onAllSessionsRevoked failed after the revocation, and the revocation of the API tokens " +
        "failed (no such table: identkit_api_tokens) and the end of the OAuth grants failed " +
        "(no such table: identkit_oauth_grants); call accounts.disable again",
    );
  });

  it("rule: sink error before store errors - the sink error goes up unchanged; the retry shows and fixes the grant error", async () => {
    const { t, broken, accountId, tokens } = await disableSetup();
    broken.tokens = false;
    failSinkOnce(t.audit, "account.disabled");
    const error = await caught(t.ik.accounts.disable(accountId));
    expect(error).toEqual(sinkDown);
    expect(Object.getOwnPropertyNames(error)).not.toContain("grantRevocationError");
    await expect(t.ik.accounts.disable(accountId)).rejects.toThrow(
      "no such table: identkit_oauth_grants",
    );
    broken.grants = false;
    await t.ik.accounts.disable(accountId);
    expect(t.audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["account_disabled"]);
    expect(await t.ik.oauth.validateAccessToken(tokens.accessToken)).toMatchObject({
      reason: "unknown",
    });
  });

  it("rule: token store error before grant store error - without hook and sink errors the token error goes up", async () => {
    const { t, broken, accountId, tokens } = await disableSetup();
    await expect(t.ik.accounts.disable(accountId)).rejects.toThrow(
      "no such table: identkit_api_tokens",
    );
    broken.tokens = false;
    await expect(t.ik.accounts.disable(accountId)).rejects.toThrow(
      "no such table: identkit_oauth_grants",
    );
    // The grant still stands, but the disabled account's token is refused.
    expect(await t.ik.oauth.validateAccessToken(tokens.accessToken)).toMatchObject({
      reason: "account_disabled",
    });
    broken.grants = false;
    await t.ik.accounts.disable(accountId);
    expect(await t.ik.oauth.listGrants(accountId)).toEqual([]);
  });

  it("rule: event not lost - a failed session revocation still records the ended grants", async () => {
    const { store, broken } = brokenRevocationStores();
    broken.tokens = false;
    broken.grants = false;
    const failing: IdentkitStore = {
      ...store,
      sessions: {
        ...store.sessions,
        revokeAllForAccount: () => Promise.reject(new Error("store unavailable")),
      },
    };
    const t = setup({ store: failing, oauth: baseOAuthOptions });
    const user = await t.signIn("revoke-fails@example.org");
    const client = await createOAuthTestClient(t.ik.oauth);
    await client.connect(user.account.id);
    await expect(t.ik.accounts.disable(user.account.id)).rejects.toThrow("store unavailable");
    expect(t.audit.ofType("oauth.grant_ended").map((e) => e.reason)).toEqual(["account_disabled"]);
  });
});
