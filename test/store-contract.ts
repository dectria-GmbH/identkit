import { describe, expect, it } from "vitest";
import { addSeconds } from "../src/clock.js";
import type { IdentkitStore, OtpFlowRecord, SessionRecord } from "../src/storage/types.js";

const T0 = new Date("2030-01-01T00:00:00.000Z");
let seq = 0;
const uid = (prefix: string) =>
  `${prefix}-${process.pid}-${(seq += 1)}-${Math.random().toString(36).slice(2, 8)}`;

function account(email = `${uid("a")}@example.org`) {
  return {
    id: uid("acc"),
    email,
    webauthnUserId: uid("wu"),
    status: "active" as const,
    createdAt: T0,
    personKeyDigest: null,
    assuranceLevel: null,
    identityVerifiedAt: null,
  };
}

function flow(overrides: Partial<OtpFlowRecord> = {}): OtpFlowRecord {
  return {
    id: uid("flow"),
    purpose: "sign_in",
    email: "x@example.org",
    addressDigest: uid("addr"),
    sessionId: null,
    codeDigest: "c",
    createdAt: T0,
    expiresAt: addSeconds(T0, 600),
    attempts: 0,
    maxAttempts: 3,
    consumedAt: null,
    supersededAt: null,
    ...overrides,
  };
}

function session(accountId: string, overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    id: uid("ses"),
    accountId,
    tokenDigest: uid("tok"),
    state: "complete",
    authMethods: ["email_otp"],
    createdAt: T0,
    lastSeenAt: T0,
    absoluteExpiresAt: addSeconds(T0, 3600),
    stepUp: { method: "email_otp", at: T0 },
    revokedAt: null,
    revokeReason: null,
    ...overrides,
  };
}

/** Behaviour every `IdentkitStore` implementation must show. */
export function runStoreContract(
  name: string,
  factory: () => Promise<IdentkitStore> | IdentkitStore,
) {
  describe(`store contract: ${name}`, () => {
    it("accounts: one account per address, and one person per account", async () => {
      const store = await factory();
      const a = account();
      expect(await store.accounts.insert(a)).toBe("inserted");
      expect(await store.accounts.insert({ ...account(), email: a.email })).toBe("email_taken");
      expect((await store.accounts.findByEmail(a.email))?.id).toBe(a.id);
      const b = account();
      await store.accounts.insert(b);
      const person = uid("person");
      expect(await store.accounts.linkPerson(a.id, person, "high", T0)).toBe("linked");
      expect(await store.accounts.linkPerson(a.id, person, "high", T0)).toBe("already_linked");
      expect(await store.accounts.linkPerson(b.id, person, "high", T0)).toBe(
        "person_linked_elsewhere",
      );
      expect(await store.accounts.linkPerson(a.id, uid("person"), "high", T0)).toBe(
        "account_has_other_person",
      );
      expect((await store.accounts.findById(a.id))?.assuranceLevel).toBe("high");
      await store.accounts.setStatus(a.id, "disabled");
      expect((await store.accounts.findById(a.id))?.status).toBe("disabled");
    });

    it("otp: send slot honours the cooldown", async () => {
      const store = await factory();
      const key = uid("gate");
      expect((await store.otp.claimSendSlot(key, T0, 30)).claimed).toBe(true);
      const blocked = await store.otp.claimSendSlot(key, addSeconds(T0, 29), 30);
      expect(blocked.claimed).toBe(false);
      expect(blocked.nextAllowedAt.getTime()).toBe(addSeconds(T0, 30).getTime());
      expect((await store.otp.claimSendSlot(key, addSeconds(T0, 30), 30)).claimed).toBe(true);
    });

    it("otp: attempts are capped, also under concurrency", async () => {
      const store = await factory();
      const f = flow({ maxAttempts: 3 });
      await store.otp.insert(f);
      const results = await Promise.all(
        Array.from({ length: 10 }, () => store.otp.reserveAttempt(f.id, T0)),
      );
      expect(results.filter((r) => r.status === "reserved")).toHaveLength(3);
      expect(results.filter((r) => r.status === "exhausted")).toHaveLength(7);
      expect((await store.otp.findById(f.id))?.attempts).toBe(3);
    });

    it("otp: expired, consumed and superseded flows are unavailable", async () => {
      const store = await factory();
      const f = flow();
      await store.otp.insert(f);
      expect(await store.otp.reserveAttempt(f.id, f.expiresAt)).toEqual({ status: "unavailable" });
      expect(await store.otp.consume(f.id, f.expiresAt)).toBe(false);
      const g = flow();
      await store.otp.insert(g);
      await store.otp.supersedeOpen(g.addressDigest, "step_up", T0);
      expect((await store.otp.reserveAttempt(g.id, T0)).status).toBe("reserved");
      await store.otp.supersedeOpen(g.addressDigest, "sign_in", T0);
      expect(await store.otp.reserveAttempt(g.id, T0)).toEqual({ status: "unavailable" });
      expect(await store.otp.reserveAttempt("missing", T0)).toEqual({ status: "unavailable" });
    });

    it("otp: a flow is consumed once, also under concurrency", async () => {
      const store = await factory();
      const f = flow();
      await store.otp.insert(f);
      const results = await Promise.all(
        Array.from({ length: 10 }, () => store.otp.consume(f.id, T0)),
      );
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(await store.otp.reserveAttempt(f.id, T0)).toEqual({ status: "unavailable" });
    });

    it("throttle: locks after the limit, unlocks after the lock time, resets", async () => {
      const store = await factory();
      const key = uid("thr");
      const rule = { maxFailures: 2, windowSeconds: 60, lockSeconds: 120, maxLockSeconds: 600 };
      expect((await store.throttle.reserve(key, T0, rule)).allowed).toBe(true);
      expect((await store.throttle.reserve(key, T0, rule)).allowed).toBe(true);
      const locked = await store.throttle.reserve(key, T0, rule);
      expect(locked).toMatchObject({ allowed: false, lockedNow: true });
      expect((await store.throttle.peek(key, addSeconds(T0, 119)))?.getTime()).toBe(
        addSeconds(T0, 120).getTime(),
      );
      expect(await store.throttle.reserve(key, addSeconds(T0, 60), rule)).toMatchObject({
        allowed: false,
        lockedNow: false,
      });
      expect(await store.throttle.peek(key, addSeconds(T0, 120))).toBeNull();
      expect((await store.throttle.reserve(key, addSeconds(T0, 120), rule)).allowed).toBe(true);
      await store.throttle.reset(key);
      expect(await store.throttle.peek(key, T0)).toBeNull();
    });

    it("throttle: repeated locks double up to the maximum, a reset clears the count", async () => {
      const store = await factory();
      const key = uid("thr");
      const rule = { maxFailures: 1, windowSeconds: 60, lockSeconds: 100, maxLockSeconds: 300 };
      let at = T0;
      const lockLengths: number[] = [];
      for (let i = 0; i < 4; i += 1) {
        await store.throttle.reserve(key, at, rule);
        const locked = await store.throttle.reserve(key, at, rule);
        if (!locked.lockedUntil) throw new Error("not locked");
        lockLengths.push((locked.lockedUntil.getTime() - at.getTime()) / 1000);
        at = locked.lockedUntil;
      }
      expect(lockLengths).toEqual([100, 200, 300, 300]);
      await store.throttle.reset(key);
      await store.throttle.reserve(key, at, rule);
      const again = await store.throttle.reserve(key, at, rule);
      expect(((again.lockedUntil?.getTime() ?? 0) - at.getTime()) / 1000).toBe(100);
    });

    it("throttle: concurrent attempts cannot exceed the limit", async () => {
      const store = await factory();
      const key = uid("thr");
      const rule = { maxFailures: 3, windowSeconds: 60, lockSeconds: 60, maxLockSeconds: 60 };
      const results = await Promise.all(
        Array.from({ length: 10 }, () => store.throttle.reserve(key, T0, rule)),
      );
      expect(results.filter((r) => r.allowed)).toHaveLength(3);
    });

    it("sessions: rotation is compare-and-set, revocation happens once", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const s = session(a.id);
      await store.sessions.insert(s);
      expect((await store.sessions.findByTokenDigest(s.tokenDigest))?.id).toBe(s.id);
      const update = {
        state: "complete" as const,
        authMethods: ["email_otp" as const, "passkey" as const],
        stepUp: { method: "passkey" as const, at: addSeconds(T0, 5) },
        lastSeenAt: addSeconds(T0, 5),
        absoluteExpiresAt: s.absoluteExpiresAt,
      };
      const results = await Promise.all([
        store.sessions.rotate(s.id, s.tokenDigest, "new-1", update),
        store.sessions.rotate(s.id, s.tokenDigest, "new-2", update),
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(await store.sessions.findByTokenDigest(s.tokenDigest)).toBeNull();
      const after = await store.sessions.findById(s.id);
      expect(after?.stepUp?.method).toBe("passkey");
      expect(after?.authMethods).toEqual(["email_otp", "passkey"]);
      await store.sessions.touch(s.id, addSeconds(T0, 2));
      expect((await store.sessions.findById(s.id))?.lastSeenAt.getTime()).toBe(
        addSeconds(T0, 5).getTime(),
      );
      expect(await store.sessions.revoke(s.id, T0, "test")).toBe(true);
      expect(await store.sessions.revoke(s.id, T0, "test")).toBe(false);
      expect(await store.sessions.rotate(s.id, after?.tokenDigest ?? "", "new-3", update)).toBe(
        false,
      );
    });

    it("sessions: revokeAllForAccount spares the named session and other accounts", async () => {
      const store = await factory();
      const a = account();
      const b = account();
      await store.accounts.insert(a);
      await store.accounts.insert(b);
      const s1 = session(a.id);
      const s2 = session(a.id);
      const s3 = session(b.id);
      for (const s of [s1, s2, s3]) await store.sessions.insert(s);
      expect(await store.sessions.revokeAllForAccount(a.id, T0, "test", s2.id)).toEqual([s1.id]);
      expect((await store.sessions.findById(s2.id))?.revokedAt).toBeNull();
      expect((await store.sessions.findById(s3.id))?.revokedAt).toBeNull();
    });

    it("credentials: unique id, counter compare-and-set, delete scoped to the account", async () => {
      const store = await factory();
      const a = account();
      const b = account();
      await store.accounts.insert(a);
      await store.accounts.insert(b);
      const c = {
        id: uid("cred"),
        accountId: a.id,
        publicKey: new Uint8Array([1, 2, 3]),
        counter: 0,
        transports: ["internal"],
        deviceType: "multiDevice" as const,
        backedUp: true,
        createdAt: T0,
        lastUsedAt: null,
      };
      expect(await store.credentials.insert(c)).toBe("inserted");
      expect(await store.credentials.insert({ ...c, accountId: b.id })).toBe("duplicate");
      expect(Array.from((await store.credentials.findById(c.id))?.publicKey ?? [])).toEqual([
        1, 2, 3,
      ]);
      const results = await Promise.all([
        store.credentials.updateCounter(c.id, 0, 5, T0),
        store.credentials.updateCounter(c.id, 0, 6, T0),
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(await store.credentials.updateCounter(c.id, 0, 7, T0)).toBe(false);
      expect(await store.credentials.updateCounter(c.id, 4_294_967_294, 4_294_967_295, T0)).toBe(
        false,
      );
      expect(await store.credentials.listByAccount(a.id)).toHaveLength(1);
      expect(await store.credentials.delete(c.id, b.id)).toBe(false);
      expect(await store.credentials.delete(c.id, a.id)).toBe(true);
      expect(await store.credentials.findById(c.id)).toBeNull();
    });

    it("challenges: consumed once, also under concurrency", async () => {
      const store = await factory();
      const digest = uid("chal");
      await store.challenges.insert({
        id: uid("cid"),
        challengeDigest: digest,
        purpose: "approval",
        accountId: null,
        sessionId: null,
        enrollmentTokenDigest: null,
        payloadHash: "a".repeat(64),
        nonce: "n",
        createdAt: T0,
        expiresAt: addSeconds(T0, 60),
      });
      // Another purpose does not consume it.
      expect(await store.challenges.consumeByDigest(digest, "sign_in")).toBeNull();
      const results = await Promise.all(
        Array.from({ length: 5 }, () => store.challenges.consumeByDigest(digest, "approval")),
      );
      const found = results.filter((r) => r !== null);
      expect(found).toHaveLength(1);
      expect(found[0]?.payloadHash).toBe("a".repeat(64));
    });

    it("enrollment: consumed once, not after expiry", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const digest = uid("enr");
      await store.enrollment.insert({
        tokenDigest: digest,
        accountId: a.id,
        createdAt: T0,
        expiresAt: addSeconds(T0, 60),
        consumedAt: null,
      });
      expect(await store.enrollment.consume(digest, addSeconds(T0, 60))).toBeNull();
      const results = await Promise.all([
        store.enrollment.consume(digest, T0),
        store.enrollment.consume(digest, T0),
      ]);
      expect(results.filter((r) => r !== null)).toHaveLength(1);
      expect((await store.enrollment.findByDigest(digest))?.consumedAt).not.toBeNull();
    });

    it("verifications: a pending verification completes once", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const id = uid("ver");
      await store.verifications.insert({
        id,
        accountId: a.id,
        vendorReference: null,
        status: "pending",
        assuranceLevel: null,
        evidenceReference: null,
        failureReason: null,
        createdAt: T0,
        expiresAt: addSeconds(T0, 60),
        completedAt: null,
      });
      const ref = uid("ref");
      await store.verifications.setVendorReference(id, ref);
      expect((await store.verifications.findByVendorReference(ref))?.id).toBe(id);
      const done = {
        status: "verified" as const,
        assuranceLevel: "low" as const,
        evidenceReference: "e",
        failureReason: null,
        completedAt: T0,
      };
      // A pending verification is claimed once, then finalized once.
      expect(await store.verifications.finalize(id, done)).toBe(false);
      const claims = await Promise.all([
        store.verifications.claim(id),
        store.verifications.claim(id),
      ]);
      expect(claims.filter(Boolean)).toHaveLength(1);
      expect((await store.verifications.findById(id))?.status).toBe("processing");
      expect(await store.verifications.complete(id, { ...done, status: "expired" })).toBe(false);
      expect(await store.verifications.finalize(id, { ...done, status: "conflict" })).toBe(true);
      expect(await store.verifications.finalize(id, done)).toBe(false);
      expect((await store.verifications.findById(id))?.status).toBe("conflict");

      const other = uid("ver");
      await store.verifications.insert({
        id: other,
        accountId: a.id,
        vendorReference: null,
        status: "pending",
        assuranceLevel: null,
        evidenceReference: null,
        failureReason: null,
        createdAt: T0,
        expiresAt: addSeconds(T0, 60),
        completedAt: null,
      });
      expect(await store.verifications.complete(other, { ...done, status: "expired" })).toBe(true);
      expect(await store.verifications.claim(other)).toBe(false);
    });
  });
}
