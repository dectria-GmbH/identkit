import { addSeconds } from "./clock.js";
import type { AuthMethod, StepUpMethod } from "./config.js";
import type { Context } from "./context.js";
import { isTokenShaped, randomId, randomToken } from "./crypto.js";
import { AllSessionsRevokedHookError } from "./errors.js";
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
   * writes and audit events first and then calls `runHook`, so a throwing hook cannot leave
   * identkit's state half-written or skip an audit event. Use `finishThenRunHook` for the
   * caller's events, so a throwing audit sink cannot skip the hook either. `runHook` throws
   * `AllSessionsRevokedHookError`. If the sink throws on a `session.revoked` event here, this
   * call runs the hook and then throws.
   */
  revokeAllDeferringHook(
    accountId: string,
    options?: { exceptSessionId?: string },
  ): Promise<{ count: number; runHook: RunHook }>;
}

/**
 * Runs the deferred `onAllSessionsRevoked` hook. `auditError` is the audit sink's error if the
 * sink threw on an event of the same operation; a hook failure then carries it.
 */
export type RunHook = (options?: { auditError: unknown }) => Promise<void>;

/**
 * Runs `events`, the caller's own audit events (and the writes that follow them), then
 * `runHook`, also when `events` throws: a throwing audit sink cannot skip the hook. If only
 * `events` throws, its error goes up after the hook ran. If the hook throws, its
 * `AllSessionsRevokedHookError` goes up and carries the error of `events` as `auditError`.
 */
export async function finishThenRunHook(
  runHook: RunHook,
  events: () => Promise<void>,
): Promise<void> {
  try {
    await events();
  } catch (error) {
    await runHook({ auditError: error });
    throw error;
  }
  await runHook();
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
      const { count, runHook } = await revokeAllDeferringHook(accountId, options);
      await runHook();
      return count;
    },
  };

  async function revokeAllDeferringHook(
    accountId: string,
    options?: { exceptSessionId?: string },
  ): Promise<{ count: number; runHook: RunHook }> {
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
    // The sessions are revoked: a throwing audit sink must not skip the hook.
    try {
      for (const sessionId of ids) {
        await ctx.emit({ type: "session.revoked", accountId, sessionId, reason: "revoked_all" });
      }
    } catch (error) {
      await runHook({ auditError: error });
      throw error;
    }
    return { count: ids.length, runHook };
  }

  return {
    sessions,
    internals: { create, load, loadById, elevate, view, revokeAllDeferringHook },
  };
}
