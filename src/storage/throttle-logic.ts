import { addSeconds } from "../clock.js";
import type { ThrottleResult, ThrottleRule } from "./types.js";

export interface ThrottleState {
  windowStart: Date;
  attempts: number;
  lockedUntil: Date | null;
  /** Locks since the last reset. Each further lock lasts twice as long, up to the maximum. */
  lockCount: number;
}

/** Lock duration for the next lock: `lockSeconds * 2^lockCount`, at most `maxLockSeconds`. */
export function lockDuration(rule: ThrottleRule, lockCount: number): number {
  const factor = 2 ** Math.min(lockCount, 30);
  return Math.min(rule.lockSeconds * factor, rule.maxLockSeconds);
}

/**
 * Counts one attempt. A store calls this inside its own atomic section and saves `next`.
 * Within one window, the attempt after `maxFailures` attempts locks the key. A new window or
 * the end of a lock starts the attempt count again, but not the lock count: only `reset`
 * (a success) clears that, so repeated locks grow longer.
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
  const fresh =
    !state ||
    state.lockedUntil !== null ||
    now >= addSeconds(state.windowStart, rule.windowSeconds).getTime();
  const base: ThrottleState = fresh
    ? { windowStart: at, attempts: 0, lockedUntil: null, lockCount }
    : state;
  const attempts = base.attempts + 1;
  if (attempts > rule.maxFailures) {
    const lockedUntil = addSeconds(at, lockDuration(rule, lockCount));
    return {
      next: { windowStart: base.windowStart, attempts, lockedUntil, lockCount: lockCount + 1 },
      result: { allowed: false, lockedUntil, lockedNow: true },
    };
  }
  return {
    next: { windowStart: base.windowStart, attempts, lockedUntil: null, lockCount },
    result: { allowed: true, lockedUntil: null, lockedNow: false },
  };
}
