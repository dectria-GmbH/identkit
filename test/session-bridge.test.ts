import { describe, expect, it } from "vitest";
import {
  AllSessionsRevokedHookError,
  parseConfig,
  type AllSessionsRevokedEvent,
} from "../src/index.js";
import { setup, testConfig } from "./helpers.js";

const TWELVE_HOURS = 43_200;

/** A session that ends only at its absolute limit: idle timeout equal to the absolute one. */
const noIdleConfig = {
  ...testConfig,
  sessions: {
    idleTimeoutSeconds: TWELVE_HOURS,
    absoluteTimeoutSeconds: TWELVE_HOURS,
    pendingTimeoutSeconds: 300,
  },
};

describe("session bridge", () => {
  it("rule: idle equal to absolute - a session unused for 12 hours less a second still validates", async () => {
    expect(parseConfig(noIdleConfig).sessions.idleTimeoutSeconds).toBe(TWELVE_HOURS);
    const t = setup({ config: noIdleConfig });
    const { token, session } = await t.signIn("person@example.org");
    expect(session.expiresAt.getTime() - session.createdAt.getTime()).toBe(TWELVE_HOURS * 1000);
    t.clock.advanceSeconds(TWELVE_HOURS - 1);
    const view = await t.ik.sessions.validate(token);
    expect(view).not.toBeNull();
    // Use does not extend it: the absolute end stays the earlier one.
    expect(view?.expiresAt.getTime()).toBe(session.createdAt.getTime() + TWELVE_HOURS * 1000);
    t.clock.advanceSeconds(1);
    expect(await t.ik.sessions.validate(token)).toBeNull();
    expect(t.audit.ofType("session.expired")).toHaveLength(1);
  });

  it("rule: idle equal to absolute - an untouched session never ends before the absolute limit", async () => {
    const t = setup({ config: noIdleConfig });
    const { token } = await t.signIn("person@example.org");
    // The default test config ends an unused session after 900 seconds; this one does not.
    t.clock.advanceSeconds(testConfig.sessions.idleTimeoutSeconds * 10);
    expect(await t.ik.sessions.validate(token)).not.toBeNull();
  });

  it("rule: an idle timeout above the absolute one is still refused", () => {
    expect(() =>
      parseConfig({
        ...testConfig,
        sessions: { ...noIdleConfig.sessions, idleTimeoutSeconds: TWELVE_HOURS + 1 },
      }),
    ).toThrow(/absoluteTimeoutSeconds/);
  });

  it("rule: revoke-all hook - every revokeAll reports to the hook, also from other services", async () => {
    const events: AllSessionsRevokedEvent[] = [];
    const t = setup({ onAllSessionsRevoked: (event) => void events.push(event) });
    const a = await t.signIn("person@example.org");
    t.clock.advanceSeconds(30);
    const b = await t.signIn("person@example.org");

    expect(await t.ik.sessions.revokeAll(a.account.id, { exceptSessionId: b.session.id })).toBe(1);
    expect(events).toEqual([
      {
        accountId: a.account.id,
        exceptSessionId: b.session.id,
        revokedSessionIds: [a.session.id],
      },
    ]);

    // Through a passkey registration (revokes the other sessions) and a disable (all of them).
    t.clock.advanceSeconds(30);
    const c = await t.signIn("person@example.org");
    await t.registerPasskey(c.token);
    expect(events.at(-1)).toMatchObject({ accountId: a.account.id, exceptSessionId: c.session.id });
    expect(events.at(-1)?.revokedSessionIds).toContain(b.session.id);
    await t.ik.accounts.disable(a.account.id);
    expect(events.at(-1)).toEqual({
      accountId: a.account.id,
      exceptSessionId: null,
      revokedSessionIds: [c.session.id],
    });

    // Also with no live session left, so the application can end its own sessions.
    await t.ik.sessions.revokeAll(a.account.id);
    expect(events.at(-1)).toEqual({
      accountId: a.account.id,
      exceptSessionId: null,
      revokedSessionIds: [],
    });
  });

  it("rule: revoke-all hook - a failing hook fails the call, the sessions stay revoked, a retry reaches it", async () => {
    let fail = true;
    const calls: AllSessionsRevokedEvent[] = [];
    const t = setup({
      onAllSessionsRevoked: (event) => {
        calls.push(event);
        if (fail) throw new Error("application store down");
      },
    });
    const a = await t.signIn("person@example.org");
    const error: unknown = await t.ik.sessions.revokeAll(a.account.id).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AllSessionsRevokedHookError);
    expect(error).toMatchObject({ accountId: a.account.id, exceptSessionId: null });
    expect((error as Error).cause).toEqual(new Error("application store down"));
    expect(await t.ik.sessions.validate(a.token)).toBeNull();
    expect(t.audit.ofType("session.revoked")).toHaveLength(1);
    fail = false;
    expect(await t.ik.sessions.revokeAll(a.account.id)).toBe(0);
    expect(calls).toHaveLength(2);
  });
});
