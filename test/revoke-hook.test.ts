import { describe, expect, it } from "vitest";
import {
  AllSessionsRevokedHookError,
  createMemoryStore,
  type AllSessionsRevokedEvent,
  type AuditEventType,
} from "../src/index.js";
import type { IdentkitStore } from "../src/storage/types.js";
import type { RecordingAuditSink } from "../src/testing/index.js";
import { googleClaims, oidcSetup } from "./oidc-helpers.js";
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

  it("rule: hook last - a TOTP enrolment that loses its grant records grant_changed before a failing hook", async () => {
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
    expectHookError(
      await caught(
        t.ik.totp.confirmEnrolment(user.token, {
          factorId: start.factorId,
          code: t.totpCode(start.secret),
        }),
      ),
      user.account.id,
      null,
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
    await expect(
      t.ik.totp.confirmEnrolment(user.token, {
        factorId: start.factorId,
        code: t.totpCode(start.secret),
      }),
    ).rejects.toThrow("sink down");
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
    await expect(
      t.ik.passkeys.finishRegistration(
        { enrollmentToken: token },
        t.authenticator.register(start.options),
      ),
    ).rejects.toThrow("sink down");
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
