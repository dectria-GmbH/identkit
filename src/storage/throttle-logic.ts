import { addSeconds } from "../clock.js";
import type { ThrottleResult, ThrottleRule } from "./types.js";

export interface ThrottleState {
  windowStart: Date;
  attempts: number;
  lockedUntil: Date | null;
}

/**
 * Counts one attempt. A store calls this inside its own atomic section and saves `next`.
 * Within one window, the attempt after `maxFailures` attempts locks the key for
 * `lockSeconds`; a new window or the end of a lock starts the count again.
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
  const fresh =
    !state ||
    state.lockedUntil !== null ||
    now >= addSeconds(state.windowStart, rule.windowSeconds).getTime();
  const base: ThrottleState = fresh ? { windowStart: at, attempts: 0, lockedUntil: null } : state;
  const attempts = base.attempts + 1;
  if (attempts > rule.maxFailures) {
    const lockedUntil = addSeconds(at, rule.lockSeconds);
    return {
      next: { windowStart: base.windowStart, attempts, lockedUntil },
      result: { allowed: false, lockedUntil, lockedNow: true },
    };
  }
  return {
    next: { windowStart: base.windowStart, attempts, lockedUntil: null },
    result: { allowed: true, lockedUntil: null, lockedNow: false },
  };
}
