/**
 * Source of the current time. Every time-dependent rule in identkit reads the time
 * through this interface, so tests and consumers can control it.
 */
export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export function addSeconds(date: Date, seconds: number): Date {
  return new Date(date.getTime() + seconds * 1000);
}

/** Whole seconds from `from` until `to`, rounded up, never negative. */
export function secondsUntil(from: Date, to: Date): number {
  return Math.max(0, Math.ceil((to.getTime() - from.getTime()) / 1000));
}
