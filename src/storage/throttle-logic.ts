import { addSeconds } from "../clock.js";
import type { ThrottleResult, ThrottleRule } from "./types.js";

export interface ThrottleState {
  windowStart: Date;
  attempts: number;
  lockedUntil: Date | null;
  /** Locks since the last reset. Each further lock lasts twice as long, up to the maximum. */
  lockCount: number;
  /**
   * Allowed attempts since the last reset (a success), across windows and locks. Callers
   * count an attempt before the comparison and reset on a success, so this is the number of
   * consecutive failures, plus the attempt that is in progress.
   */
  consecutiveFailures: number;
}

/** Lock duration for the next lock: `lockSeconds * 2^lockCount`, at most `maxLockSeconds`. */
export function lockDuration(rule: ThrottleRule, lockCount: number): number {
  const factor = 2 ** Math.min(lockCount, 30);
  return Math.min(rule.lockSeconds * factor, rule.maxLockSeconds);
}

/**
 * Counts one attempt. A store calls this inside its own atomic section and saves `next`.
 *
 * Two limits lock the key:
 * - Within one window, the attempt after `maxFailures` attempts. A new window or the end of a
 *   lock starts this count again.
 * - The attempt after `maxConsecutiveFailures` attempts since the last reset. A new window
 *   does not start this count again. When the count is at the limit, the end of each lock
 *   lets exactly one attempt through, and the attempt after it locks again.
 *
 * Only `reset` (a success) clears the lock count and the consecutive count, so repeated locks
 * grow longer.
 */
export function applyThrottle(
  state: ThrottleState | null,
  at: Date,
  rule: ThrottleRule,
): { next: ThrottleState; result: ThrottleResult } {
  const now = at.getTime();
  if (state?.lockedUntil && now < state.lockedUntil.getTime()) {
    return {
      next: state,
      result: { allowed: false, lockedUntil: state.lockedUntil, lockedNow: false },
    };
  }
  const lockCount = state?.lockCount ?? 0;
  const consecutiveFailures = state?.consecutiveFailures ?? 0;
  // A lock ended before this attempt.
  const released = state !== null && state.lockedUntil !== null;
  const fresh =
    !state || released || now >= addSeconds(state.windowStart, rule.windowSeconds).getTime();
  const base: ThrottleState = fresh
    ? { windowStart: at, attempts: 0, lockedUntil: null, lockCount, consecutiveFailures }
    : state;
  const attempts = base.attempts + 1;
  const consecutiveLimitReached = consecutiveFailures >= rule.maxConsecutiveFailures && !released;
  if (attempts > rule.maxFailures || consecutiveLimitReached) {
    const lockedUntil = addSeconds(at, lockDuration(rule, lockCount));
    return {
      next: {
        windowStart: base.windowStart,
        attempts,
        lockedUntil,
        lockCount: lockCount + 1,
        consecutiveFailures,
      },
      result: { allowed: false, lockedUntil, lockedNow: true },
    };
  }
  return {
    next: {
      windowStart: base.windowStart,
      attempts,
      lockedUntil: null,
      lockCount,
      consecutiveFailures: consecutiveFailures + 1,
    },
    result: { allowed: true, lockedUntil: null, lockedNow: false },
  };
}
