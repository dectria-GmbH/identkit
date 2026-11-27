import { describe, expect, it } from "vitest";
import { newAccountRecord } from "../src/accounts.js";
import { createMemoryStore } from "../src/index.js";
import { throttleKey as otpThrottleKey } from "../src/email-otp.js";
import type { IdentkitStore, ThrottleRule } from "../src/storage/types.js";
import { totpEnrolmentThrottleKey, totpThrottleKey } from "../src/throttle-keys.js";
import { setup } from "./helpers.js";

/** Small limits, so a few calls reach the consecutive limit. */
const rule: ThrottleRule = {
  maxFailures: 100,
  windowSeconds: 900,
  maxConsecutiveFailures: 3,
  lockSeconds: 900,
  maxLockSeconds: 900,
};

type Setup = ReturnType<typeof setup>;

/** Every throttle key that `accounts.unlock` must clear for the account and its address. */
async function accountKeys(t: Setup, accountId: string, email: string) {
  const addressDigest = await t.hasher.digest("address", email);
  return {
    "otp:sign_in": otpThrottleKey("sign_in", addressDigest),
    "otp:step_up": otpThrottleKey("step_up", addressDigest),
    totp: totpThrottleKey(accountId),
    "totp-enrolment": totpEnrolmentThrottleKey(accountId),
  };
}

/** Counts failures until the consecutive limit locks the key. */
async function lock(store: IdentkitStore, key: string, at: Date) {
  for (let i = 0; i < rule.maxConsecutiveFailures; i += 1) {
    expect((await store.throttle.reserve(key, at, rule)).allowed).toBe(true);
  }
  expect((await store.throttle.reserve(key, at, rule)).lockedNow).toBe(true);
}

/** True if the key allows `maxConsecutiveFailures` attempts in a row, as after a success. */
async function countsCleared(store: IdentkitStore, key: string, at: Date) {
  if ((await store.throttle.peek(key, at)) !== null) return false;
  for (let i = 0; i < rule.maxConsecutiveFailures; i += 1) {
    if (!(await store.throttle.reserve(key, at, rule)).allowed) return false;
  }
  return true;
}

async function createAccount(t: Setup, email: string) {
  const created = await t.ik.accounts.create({ email });
  if (created.status !== "created") throw new Error("not created");
  return created.account;
}

describe("accounts.unlock", () => {
  it("clears the running lock of every key: sign-in and step-up codes, TOTP checks and enrolment", async () => {
    const t = setup();
    const account = await createAccount(t, "person@example.org");
    const keys = await accountKeys(t, account.id, account.email);
    for (const key of Object.values(keys)) await lock(t.store, key, t.clock.now());
    expect(await t.ik.accounts.unlock(account.id)).toBe(true);
    for (const [name, key] of Object.entries(keys)) {
      expect(await countsCleared(t.store, key, t.clock.now()), name).toBe(true);
    }
  });

  it("clears the consecutive count also after the lock ended", async () => {
    const t = setup();
    const account = await createAccount(t, "person@example.org");
    const keys = await accountKeys(t, account.id, account.email);
    for (const key of Object.values(keys)) await lock(t.store, key, t.clock.now());
    // The lock ended, but the count is still at the limit: the next two attempts would lock.
    t.clock.advanceSeconds(rule.lockSeconds);
    for (const key of Object.values(keys)) {
      expect(await t.store.throttle.peek(key, t.clock.now())).toBeNull();
    }
    expect(await t.ik.accounts.unlock(account.id)).toBe(true);
    for (const [name, key] of Object.entries(keys)) {
      expect(await countsCleared(t.store, key, t.clock.now()), name).toBe(true);
    }
  });

  it("normalizes a stored address that was written outside identkit", async () => {
    const t = setup();
    const record = newAccountRecord(" Person@Example.org", t.clock.now());
    expect(await t.store.accounts.insert(record)).toBe("inserted");
    // A code request normalizes the address, so the lock sits on the normalized digest.
    const keys = await accountKeys(t, record.id, "person@example.org");
    await lock(t.store, keys["otp:sign_in"], t.clock.now());
    expect(await t.ik.accounts.unlock(record.id)).toBe(true);
    expect(await countsCleared(t.store, keys["otp:sign_in"], t.clock.now())).toBe(true);
  });

  it("writes lockout.released before the resets, so a reset that fails part-way leaves its record", async () => {
    const inner = createMemoryStore();
    // Number of resets that pass before the next one throws; null: none throws.
    let failAfter: number | null = null;
    const store: IdentkitStore = {
      ...inner,
      throttle: {
        ...inner.throttle,
        reset: async (key) => {
          if (failAfter !== null) {
            if (failAfter === 0) {
              failAfter = null;
              throw new Error("connection reset");
            }
            failAfter -= 1;
          }
          return inner.throttle.reset(key);
        },
      },
    };
    const t = setup({ store });
    const account = await createAccount(t, "person@example.org");
    const keys = await accountKeys(t, account.id, account.email);
    for (const key of Object.values(keys)) await lock(store, key, t.clock.now());

    // The sign-in lock is lifted, then the step-up reset fails.
    failAfter = 1;
    await expect(t.ik.accounts.unlock(account.id)).rejects.toThrow("connection reset");
    expect(await inner.throttle.peek(keys["otp:sign_in"], t.clock.now())).toBeNull();
    expect(t.audit.ofType("lockout.released")).toMatchObject([
      { accountId: account.id, reason: "administrative" },
    ]);

    // A retry completes the unlock and records it again.
    expect(await t.ik.accounts.unlock(account.id)).toBe(true);
    expect(t.audit.ofType("lockout.released")).toHaveLength(2);
    for (const [name, key] of Object.entries(keys)) {
      expect(await countsCleared(inner, key, t.clock.now()), name).toBe(true);
    }

    // unlockAddress writes its event first too.
    failAfter = 0;
    await expect(t.ik.accounts.unlockAddress(account.email)).rejects.toThrow("connection reset");
    expect(t.audit.ofType("lockout.released")).toHaveLength(3);
  });

  it("keeps every lock when the audit sink refuses lockout.released", async () => {
    const t = setup();
    const account = await createAccount(t, "person@example.org");
    const keys = await accountKeys(t, account.id, account.email);
    for (const key of Object.values(keys)) await lock(t.store, key, t.clock.now());

    const recording = t.audit;
    const emit = (event: Parameters<typeof recording.emit>[0]) => recording.events.push(event);
    t.audit.emit = (event) => {
      if (event.type === "lockout.released") throw new Error("audit sink down");
      emit(event);
    };
    await expect(t.ik.accounts.unlock(account.id)).rejects.toThrow("audit sink down");
    await expect(t.ik.accounts.unlockAddress(account.email)).rejects.toThrow("audit sink down");
    for (const [name, key] of Object.entries(keys)) {
      expect(await t.store.throttle.peek(key, t.clock.now()), name).not.toBeNull();
    }
  });
});
