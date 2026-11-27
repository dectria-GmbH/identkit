import { addSeconds } from "./clock.js";
import type { AuthMethod, StepUpMethod } from "./config.js";
import type { Context } from "./context.js";
import { isTokenShaped, randomId, randomToken } from "./crypto.js";
import { AllSessionsRevokedHookError, OperationRolledBackError } from "./errors.js";
import type { SessionRecord, SessionState, StepUpRecord } from "./storage/types.js";

/** What a consumer sees of a valid session. Never contains the token. */
export interface SessionView {
  id: string;
  accountId: string;
  authMethods: AuthMethod[];
  createdAt: Date;
  /** The earlier of the idle and the absolute expiry, as of this validation. */
  expiresAt: Date;
  stepUp: StepUpRecord | null;
}

export interface IssuedSession {
  /** Bearer token for the client. identkit stores only its keyed hash. */
  token: string;
  session: SessionView;
}

export type StepUpCheck =
  { ok: true; session: SessionView } | { ok: false; reason: "no_session" | "step_up_required" };

export interface Sessions {
  /** Returns the session for a token, or null if it is unknown, revoked, pending or expired. */
  validate(token: string): Promise<SessionView | null>;
  /**
   * Like `validate`, and also requires a step-up within the configured validity window by
   * one of `methods` (default: the policy's step-up methods). Use it before sensitive actions.
   */
  requireStepUp(token: string, options?: { methods?: StepUpMethod[] }): Promise<StepUpCheck>;
  /** Issues a new token for the session and invalidates the old one. */
  rotate(token: string): Promise<IssuedSession | null>;
  revoke(token: string): Promise<boolean>;
  /** Administrative: takes a bare id. Do not pass client input without your own check. */
  revokeById(sessionId: string, reason?: string): Promise<boolean>;
  /**
   * Administrative: revokes all sessions of an account, for example on sign-out everywhere.
   * Takes a bare id. Do not pass client input without your own check. Calls the option
   * `onAllSessionsRevoked` after the revocation and its audit events, also when no session was
   * live and also when the audit sink throws (its error then goes up after the hook). If the hook
   * throws, this call throws `AllSessionsRevokedHookError` and the sessions stay revoked. The
   * call is idempotent: call it again to re-run the hook.
   */
  revokeAll(accountId: string, options?: { exceptSessionId?: string }): Promise<number>;
}

export interface SessionInternals {
  create(input: {
    accountId: string;
    state: SessionState;
    authMethods: AuthMethod[];
    stepUp: StepUpRecord | null;
  }): Promise<IssuedSession>;
  /** Loads a live session in the given state, applying timeouts. Does not touch it. */
  load(
    token: string,
    state: SessionState,
  ): Promise<{ record: SessionRecord; digest: string } | null>;
  /** Like `load`, by session id. The session may have rotated its token since. */
  loadById(sessionId: string, state: SessionState): Promise<SessionRecord | null>;
  /** Replaces the token of a live session with a new one and applies the change. */
  elevate(
    loaded: { record: SessionRecord; digest: string },
    change: { state?: SessionState; addMethod?: AuthMethod; stepUp?: StepUpRecord },
    reason: string,
  ): Promise<IssuedSession | null>;
  view(record: SessionRecord): SessionView;
  /**
   * Revokes like `sessions.revokeAll` but does not call the hook. The caller finishes its own
   * writes and audit events first and then calls the hook, so a throwing hook cannot leave
   * identkit's state half-written or skip an audit event. Use `finishThenRunHook` for the
   * caller's events, so a throwing audit sink cannot skip the hook or the caller's events.
   * Throws only when the store revocation throws. If the sink throws on a `session.revoked`
   * event, the other events are still emitted and the first sink error is returned as
   * `auditFailure`; `finishThenRunHook` throws it after the hook. A rollback uses
   * `finishRollback` instead.
   */
  revokeAllDeferringHook(
    accountId: string,
    options?: { exceptSessionId?: string },
  ): Promise<Revocation>;
}

/**
 * Runs the deferred `onAllSessionsRevoked` hook. `auditError` is the error of the same
 * operation's audit events, if one threw; a hook failure then carries it.
 */
export type RunHook = (options?: { auditError: unknown }) => Promise<void>;

/** A revocation whose hook has not run yet. */
export interface Revocation {
  /** The number of sessions revoked. */
  count: number;
  runHook: RunHook;
  /** The first error of the audit sink on a `session.revoked` event, or null. */
  auditFailure: { error: unknown } | null;
}

/** For paths that revoked nothing: no hook, no error. */
export const noRevocation: Revocation = {
  count: 0,
  runHook: async () => undefined,
  auditFailure: null,
};

/**
 * Runs `events`, the caller's own audit events (and the writes that belong to them), then the
 * hook. `events` runs also after a sink failure on a `session.revoked` event of `revocation`,
 * and the hook runs also when `events` throws: a throwing audit sink skips neither. The first
 * error (of the revocation's events, then of `events`) goes up after the hook ran. If the hook
 * throws, its `AllSessionsRevokedHookError` goes up instead and carries that first error as
 * `auditError`.
 */
export async function finishThenRunHook(
  revocation: Revocation,
  events: () => Promise<void>,
): Promise<void> {
  let failure = revocation.auditFailure;
  try {
    await events();
  } catch (error) {
    failure ??= { error };
  }
  if (!failure) {
    await revocation.runHook();
    return;
  }
  await revocation.runHook({ auditError: failure.error });
  throw failure.error;
}

/**
 * Finishes an operation that identkit rolled back. `revocation` is the rollback's revocation of
 * every session, or null if the store failed on it. `failure` is the first error so far: the
 * error that caused the rollback, or the store's error on the revocation. Runs `events` (the
 * rollback's own audit events) and then the hook, each also after an earlier failure. Returns
 * null if nothing failed, so the caller can return its `denied` outcome. Otherwise it returns
 * `OperationRolledBackError` with the first error as `cause`, for the caller to throw: the
 * caller can tell that the operation did not take effect, and `hookFailed` says whether the
 * hook still needs to run.
 */
export async function finishRollback(
  accountId: string,
  revocation: Revocation | null,
  failure: { error: unknown } | null,
  events: () => Promise<void> = async () => undefined,
): Promise<OperationRolledBackError | null> {
  let first = failure ?? revocation?.auditFailure ?? null;
  try {
    await events();
  } catch (error) {
    first ??= { error };
  }
  // Without a revocation the hook never ran: `sessions.revokeAll` must finish it.
  let hookFailed = revocation === null;
  if (revocation) {
    try {
      await revocation.runHook();
    } catch (error) {
      hookFailed = true;
      first ??= { error: error instanceof AllSessionsRevokedHookError ? error.cause : error };
    }
  }
  return first ? new OperationRolledBackError(accountId, { cause: first.error, hookFailed }) : null;
}

/** What `onAllSessionsRevoked` receives after `sessions.revokeAll`. */
export interface AllSessionsRevokedEvent {
  accountId: string;
  /** The session that stayed live, or null if every session of the account ended. */
  exceptSessionId: string | null;
  /** Sessions this call revoked. Empty if none was live, for example on a retry. */
  revokedSessionIds: string[];
}

/** Called after every `sessions.revokeAll`, also when it is called from another service. */
export type AllSessionsRevokedHook = (event: AllSessionsRevokedEvent) => void | Promise<void>;

export function createSessions(
  ctx: Context,
  onAllSessionsRevoked: AllSessionsRevokedHook | null = null,
): { sessions: Sessions; internals: SessionInternals } {
  const { config, store, hasher, clock } = ctx;

  const digestOf = (token: string) => hasher.digest("session-token", token);

  function idleExpiry(record: SessionRecord): Date {
    if (record.state === "pending_second_factor") return record.absoluteExpiresAt;
    return addSeconds(record.lastSeenAt, config.sessions.idleTimeoutSeconds);
  }

  function view(record: SessionRecord): SessionView {
    const idle = idleExpiry(record);
    const expiresAt = idle < record.absoluteExpiresAt ? idle : record.absoluteExpiresAt;
    return {
      id: record.id,
      accountId: record.accountId,
      authMethods: [...record.authMethods],
      createdAt: record.createdAt,
      expiresAt,
      stepUp: record.stepUp,
    };
  }

  async function load(token: string, state: SessionState) {
    if (!isTokenShaped(token)) return null;
    const digest = await digestOf(token);
    const record = await store.sessions.findByTokenDigest(digest);
    const live = await checkLive(record, state);
    return live ? { record: live, digest } : null;
  }

  async function loadById(sessionId: string, state: SessionState) {
    return checkLive(await store.sessions.findById(sessionId), state);
  }

  /** Applies revocation, state, timeouts and account status to a stored session. */
  async function checkLive(
    record: SessionRecord | null,
    state: SessionState,
  ): Promise<SessionRecord | null> {
    if (!record || record.revokedAt !== null || record.state !== state) return null;
    const now = clock.now();
    const expired =
      now.getTime() >= record.absoluteExpiresAt.getTime() ||
      now.getTime() >= idleExpiry(record).getTime();
    if (expired) {
      if (await store.sessions.revoke(record.id, now, "expired")) {
        await ctx.emit({
          type: "session.expired",
          accountId: record.accountId,
          sessionId: record.id,
        });
      }
      return null;
    }
    // A session created while the account was being disabled must not outlive the disable.
    const account = await store.accounts.findById(record.accountId);
    if (!account || account.status !== "active") {
      if (await store.sessions.revoke(record.id, now, "account_disabled")) {
        await ctx.emit({
          type: "session.revoked",
          accountId: record.accountId,
          sessionId: record.id,
          reason: "account_disabled",
        });
      }
      return null;
    }
    return record;
  }

  async function create(input: Parameters<SessionInternals["create"]>[0]): Promise<IssuedSession> {
    const now = clock.now();
    const token = randomToken();
    const lifetime =
      input.state === "pending_second_factor"
        ? config.sessions.pendingTimeoutSeconds
        : config.sessions.absoluteTimeoutSeconds;
    const record: SessionRecord = {
      id: randomId(),
      accountId: input.accountId,
      tokenDigest: await digestOf(token),
      state: input.state,
      authMethods: input.authMethods,
      createdAt: now,
      lastSeenAt: now,
      absoluteExpiresAt: addSeconds(now, lifetime),
      stepUp: input.stepUp,
      revokedAt: null,
      revokeReason: null,
    };
    await store.sessions.insert(record);
    await ctx.emit({
      type: "session.created",
      accountId: record.accountId,
      sessionId: record.id,
      method: record.authMethods.join("+"),
      reason: record.state,
    });
    return { token, session: view(record) };
  }

  async function elevate(
    loaded: { record: SessionRecord; digest: string },
    change: { state?: SessionState; addMethod?: AuthMethod; stepUp?: StepUpRecord },
    reason: string,
  ): Promise<IssuedSession | null> {
    const now = clock.now();
    const { record } = loaded;
    const state = change.state ?? record.state;
    const authMethods =
      change.addMethod && !record.authMethods.includes(change.addMethod)
        ? [...record.authMethods, change.addMethod]
        : [...record.authMethods];
    // A pending session that completes gets the full absolute lifetime from now.
    const absoluteExpiresAt =
      record.state === "pending_second_factor" && state === "complete"
        ? addSeconds(now, config.sessions.absoluteTimeoutSeconds)
        : record.absoluteExpiresAt;
    const token = randomToken();
    const newDigest = await digestOf(token);
    const update = {
      state,
      authMethods,
      stepUp: change.stepUp ?? record.stepUp,
      lastSeenAt: now,
      absoluteExpiresAt,
    };
    const rotated = await store.sessions.rotate(record.id, loaded.digest, newDigest, update);
    if (!rotated) return null;
    await ctx.emit({
      type: "session.rotated",
      accountId: record.accountId,
      sessionId: record.id,
      reason,
    });
    return { token, session: view({ ...record, ...update, tokenDigest: newDigest }) };
  }

  const sessions: Sessions = {
    async validate(token) {
      const loaded = await load(token, "complete");
      if (!loaded) return null;
      const now = clock.now();
      await store.sessions.touch(loaded.record.id, now);
      return view({ ...loaded.record, lastSeenAt: now });
    },

    async requireStepUp(token, options) {
      const session = await sessions.validate(token);
      if (!session) return { ok: false, reason: "no_session" };
      const policy = await ctx.getPolicy();
      const methods = (options?.methods ?? policy.stepUpMethods).filter((m) =>
        policy.stepUpMethods.includes(m),
      );
      const stepUp = session.stepUp;
      const fresh =
        stepUp !== null &&
        methods.includes(stepUp.method) &&
        clock.now().getTime() < addSeconds(stepUp.at, config.stepUp.validitySeconds).getTime();
      return fresh ? { ok: true, session } : { ok: false, reason: "step_up_required" };
    },

    async rotate(token) {
      const loaded = await load(token, "complete");
      if (!loaded) return null;
      return elevate(loaded, {}, "requested");
    },

    async revoke(token) {
      if (!isTokenShaped(token)) return false;
      const record = await store.sessions.findByTokenDigest(await digestOf(token));
      if (!record) return false;
      return sessions.revokeById(record.id, "signed_out");
    },

    async revokeById(sessionId, reason = "revoked") {
      const record = await store.sessions.findById(sessionId);
      if (!record) return false;
      const revoked = await store.sessions.revoke(sessionId, clock.now(), reason);
      if (revoked) {
        await ctx.emit({
          type: "session.revoked",
          accountId: record.accountId,
          sessionId,
          reason,
        });
      }
      return revoked;
    },

    async revokeAll(accountId, options) {
      const revocation = await revokeAllDeferringHook(
        accountId,
        options?.exceptSessionId === undefined
          ? undefined
          : { exceptSessionId: options.exceptSessionId },
      );
      await finishThenRunHook(revocation, async () => undefined);
      return revocation.count;
    },
  };

  async function revokeAllDeferringHook(
    accountId: string,
    options?: { exceptSessionId?: string },
  ): Promise<Revocation> {
    const ids = await store.sessions.revokeAllForAccount(
      accountId,
      clock.now(),
      "revoked_all",
      options?.exceptSessionId,
    );
    const exceptSessionId = options?.exceptSessionId ?? null;
    // Called also when no session was live, so a repeated `revokeAll` re-runs the hook.
    const runHook: RunHook = async (hookOptions) => {
      if (!onAllSessionsRevoked) return;
      try {
        await onAllSessionsRevoked({ accountId, exceptSessionId, revokedSessionIds: [...ids] });
      } catch (error) {
        throw new AllSessionsRevokedHookError(accountId, exceptSessionId, {
          cause: error,
          ...(hookOptions ? { auditError: hookOptions.auditError } : {}),
        });
      }
    };
    // The sessions are revoked: a throwing audit sink must not skip the other events, the
    // caller's own events or the hook. `finishThenRunHook` throws the error after all of them.
    let auditFailure: { error: unknown } | null = null;
    for (const sessionId of ids) {
      try {
        await ctx.emit({ type: "session.revoked", accountId, sessionId, reason: "revoked_all" });
      } catch (error) {
        auditFailure ??= { error };
      }
    }
    return { count: ids.length, runHook, auditFailure };
  }

  return {
    sessions,
    internals: { create, load, loadById, elevate, view, revokeAllDeferringHook },
  };
}
