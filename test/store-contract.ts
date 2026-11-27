import { describe, expect, it } from "vitest";
import { addSeconds } from "../src/clock.js";
import type {
  ApiTokenRecord,
  IdentkitStore,
  OAuthAccessTokenRecord,
  OAuthClientRecord,
  OAuthCodeRecord,
  OAuthGrantRecord,
  OidcLinkRecord,
  OtpFlowRecord,
  SessionRecord,
  TotpFactorRecord,
} from "../src/storage/types.js";

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

function totpFactor(
  accountId: string,
  overrides: Partial<TotpFactorRecord> = {},
): TotpFactorRecord {
  return {
    id: uid("totp"),
    accountId,
    sealedSecret: `v1.k.${uid("sealed")}`,
    algorithm: "SHA1",
    digits: 6,
    createdAt: T0,
    enrolmentSessionId: null,
    activatedAt: null,
    lastUsedStep: null,
    lastUsedAt: null,
    ...overrides,
  };
}

function oidcLink(accountId: string, overrides: Partial<OidcLinkRecord> = {}): OidcLinkRecord {
  const subject = uid("sub");
  return {
    id: uid("link"),
    accountId,
    linkKey: JSON.stringify(["google", subject]),
    provider: "google",
    issuer: "https://accounts.google.com",
    subject,
    tenantId: null,
    source: "sign_in",
    createdAt: T0,
    ...overrides,
  };
}

function apiToken(accountId: string, overrides: Partial<ApiTokenRecord> = {}): ApiTokenRecord {
  return {
    id: uid("tok"),
    accountId,
    name: "deploy script",
    scopes: ["read:items", "write:items"],
    digest: uid("digest"),
    digestAlgorithm: "hmac-sha256",
    source: "created",
    createdAt: T0,
    expiresAt: addSeconds(T0, 30 * 86_400),
    lastUsedAt: null,
    revokedAt: null,
    revokeReason: null,
    ...overrides,
  };
}

function oauthClient(overrides: Partial<OAuthClientRecord> = {}): OAuthClientRecord {
  return {
    id: uid("client"),
    secretDigest: uid("secret"),
    secretDigestAlgorithm: "hmac-sha256",
    authMethod: "client_secret_basic",
    grantTypes: ["authorization_code", "refresh_token"],
    redirectUris: ["https://app.example.com/cb", "http://127.0.0.1/cb"],
    name: "Example client",
    source: "dynamic",
    createdAt: T0,
    lastUsedAt: null,
    ...overrides,
  };
}

function oauthGrant(
  accountId: string,
  clientId: string,
  overrides: Partial<OAuthGrantRecord> = {},
): OAuthGrantRecord {
  return {
    id: uid("grant"),
    accountId,
    clientId,
    scopes: ["mcp:read", "mcp:events"],
    resource: "https://example.com/mcp",
    createdAt: T0,
    expiresAt: addSeconds(T0, 90 * 86_400),
    generation: 1,
    refreshRefDigest: uid("ref"),
    refreshDigest: uid("refresh"),
    refreshDigestAlgorithm: "hmac-sha256",
    previousRefreshDigest: null,
    refreshedAt: null,
    refreshExpiresAt: addSeconds(T0, 30 * 86_400),
    codeDigest: uid("code"),
    source: "created",
    ...overrides,
  };
}

function oauthAccessToken(
  grantId: string,
  overrides: Partial<OAuthAccessTokenRecord> = {},
): OAuthAccessTokenRecord {
  return {
    digest: uid("access"),
    grantId,
    generation: 1,
    scopes: ["mcp:read"],
    createdAt: T0,
    expiresAt: addSeconds(T0, 3600),
    ...overrides,
  };
}

function oauthCode(
  clientId: string,
  accountId: string,
  overrides: Partial<OAuthCodeRecord> = {},
): OAuthCodeRecord {
  return {
    digest: uid("code"),
    clientId,
    accountId,
    redirectUri: "http://127.0.0.1:5000/cb",
    redirectUriExplicit: true,
    codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    resource: "https://example.com/mcp",
    scopes: ["mcp:read"],
    createdAt: T0,
    expiresAt: addSeconds(T0, 300),
    ...overrides,
  };
}

const byId = (a: { id: string }, b: { id: string }) => (a.id < b.id ? -1 : 1);

/** Behaviour every `IdentkitStore` implementation must show. */
export function runStoreContract(
  name: string,
  factory: () => Promise<IdentkitStore> | IdentkitStore,
) {
  /** The store's `oauth` member, with an active account and a client in it. */
  async function oauthFixture() {
    const store = await factory();
    const oauth = store.oauth;
    if (!oauth) throw new Error("store has no oauth");
    const a = account();
    await store.accounts.insert(a);
    const client = oauthClient();
    expect(await oauth.insertClient(client)).toBe("inserted");
    return { store, oauth, accountId: a.id, client };
  }

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
      const rule = {
        maxFailures: 2,
        windowSeconds: 60,
        maxConsecutiveFailures: 100,
        lockSeconds: 120,
        maxLockSeconds: 600,
      };
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
      const rule = {
        maxFailures: 1,
        windowSeconds: 60,
        maxConsecutiveFailures: 100,
        lockSeconds: 100,
        maxLockSeconds: 300,
      };
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
      const rule = {
        maxFailures: 3,
        windowSeconds: 60,
        maxConsecutiveFailures: 100,
        lockSeconds: 60,
        maxLockSeconds: 60,
      };
      const results = await Promise.all(
        Array.from({ length: 10 }, () => store.throttle.reserve(key, T0, rule)),
      );
      expect(results.filter((r) => r.allowed)).toHaveLength(3);
    });

    it("throttle: the consecutive limit holds across windows; past it, each lock lets one attempt through", async () => {
      const store = await factory();
      const key = uid("thr");
      const rule = {
        maxFailures: 2,
        windowSeconds: 60,
        maxConsecutiveFailures: 5,
        lockSeconds: 100,
        maxLockSeconds: 400,
      };
      // Exactly `maxFailures` attempts per window: the window limit never locks.
      let at = T0;
      let allowed = 0;
      let locked = null;
      for (let window = 0; window < 10 && !locked; window += 1) {
        at = addSeconds(T0, window * rule.windowSeconds);
        for (let i = 0; i < rule.maxFailures && !locked; i += 1) {
          const result = await store.throttle.reserve(key, at, rule);
          if (result.allowed) allowed += 1;
          else locked = result;
        }
      }
      expect(allowed).toBe(rule.maxConsecutiveFailures);
      expect(locked).toMatchObject({ allowed: false, lockedNow: true });
      expect(locked?.lockedUntil?.getTime()).toBe(addSeconds(at, 100).getTime());
      // A new window does not release the lock.
      expect((await store.throttle.reserve(key, addSeconds(at, 99), rule)).allowed).toBe(false);

      // Past the limit: one attempt per lock end, and each lock lasts twice as long.
      const lockLengths: number[] = [];
      for (let i = 0; i < 3; i += 1) {
        at = locked?.lockedUntil ?? at;
        expect((await store.throttle.reserve(key, at, rule)).allowed).toBe(true);
        locked = await store.throttle.reserve(key, at, rule);
        expect(locked).toMatchObject({ allowed: false, lockedNow: true });
        lockLengths.push(((locked.lockedUntil?.getTime() ?? 0) - at.getTime()) / 1000);
      }
      expect(lockLengths).toEqual([200, 400, 400]);

      // A success clears both counts.
      await store.throttle.reset(key);
      for (let i = 0; i < rule.maxFailures; i += 1) {
        expect((await store.throttle.reserve(key, at, rule)).allowed).toBe(true);
      }
    });

    it("throttle: concurrent attempts cannot exceed the consecutive limit in a new window", async () => {
      const store = await factory();
      const key = uid("thr");
      const rule = {
        maxFailures: 10,
        windowSeconds: 60,
        maxConsecutiveFailures: 12,
        lockSeconds: 60,
        maxLockSeconds: 60,
      };
      for (let i = 0; i < 8; i += 1) {
        expect((await store.throttle.reserve(key, T0, rule)).allowed).toBe(true);
      }
      const next = addSeconds(T0, rule.windowSeconds);
      const results = await Promise.all(
        Array.from({ length: 10 }, () => store.throttle.reserve(key, next, rule)),
      );
      expect(results.filter((r) => r.allowed)).toHaveLength(4);
      expect(results.filter((r) => r.lockedNow)).toHaveLength(1);
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
        activatedAt: T0,
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

    it("credentials: a pending credential is invisible and unusable until activated", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const pending = {
        id: uid("cred"),
        accountId: a.id,
        publicKey: new Uint8Array([4]),
        counter: 0,
        transports: [],
        deviceType: "singleDevice" as const,
        backedUp: false,
        createdAt: T0,
        lastUsedAt: null,
        activatedAt: null,
      };
      expect(await store.credentials.insert(pending)).toBe("inserted");
      expect(await store.credentials.insert(pending)).toBe("duplicate");
      expect(await store.credentials.findById(pending.id)).toBeNull();
      expect(await store.credentials.listByAccount(a.id)).toHaveLength(0);
      expect(await store.credentials.updateCounter(pending.id, 0, 1, T0)).toBe(false);
      expect(
        await store.credentials.activate(pending.id, "other-account", pending.publicKey, T0),
      ).toBe(false);
      expect(await store.credentials.activate(pending.id, a.id, new Uint8Array([5]), T0)).toBe(
        false,
      );
      expect(await store.credentials.delete(pending.id, a.id, new Uint8Array([5]))).toBe(false);
      expect(await store.credentials.activate(pending.id, a.id, pending.publicKey, T0)).toBe(true);
      expect((await store.credentials.findById(pending.id))?.activatedAt?.getTime()).toBe(
        T0.getTime(),
      );
      expect(await store.credentials.listByAccount(a.id)).toHaveLength(1);
      expect(await store.credentials.delete(pending.id, a.id, pending.publicKey)).toBe(true);
      expect(await store.credentials.activate(pending.id, a.id, pending.publicKey, T0)).toBe(false);
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

    it("totp: a pending factor is invisible; one active factor per account, also under concurrency", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const pending = [totpFactor(a.id), totpFactor(a.id), totpFactor(a.id)];
      for (const f of pending) await store.totp.insert(f);
      expect(await store.totp.findActive(a.id)).toBeNull();
      expect((await store.totp.findPending(pending[0]?.id ?? ""))?.id).toBe(pending[0]?.id);
      // A pending factor cannot record a step.
      expect(await store.totp.recordStep(pending[0]?.id ?? "", a.id, 5, T0)).toBe(false);
      expect(await store.totp.activate(pending[0]?.id ?? "", "other-account", 5, T0)).toBe(false);
      const results = await Promise.all(
        pending.map((f, i) => store.totp.activate(f.id, a.id, 10 + i, addSeconds(T0, i))),
      );
      expect(results.filter(Boolean)).toHaveLength(1);
      const active = await store.totp.findActive(a.id);
      const winner = pending[results.indexOf(true)];
      expect(active?.id).toBe(winner?.id);
      expect(active?.lastUsedStep).toBe(10 + results.indexOf(true));
      expect(await store.totp.findPending(active?.id ?? "")).toBeNull();
      expect(await store.totp.activate(active?.id ?? "", a.id, 99, T0)).toBe(false);
    });

    it("totp: a time step is recorded once and only upwards, also under concurrency", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const f = totpFactor(a.id);
      await store.totp.insert(f);
      expect(await store.totp.activate(f.id, a.id, 100, T0)).toBe(true);
      expect(await store.totp.recordStep(f.id, a.id, 100, T0)).toBe(false);
      expect(await store.totp.recordStep(f.id, a.id, 99, T0)).toBe(false);
      const results = await Promise.all(
        Array.from({ length: 10 }, () => store.totp.recordStep(f.id, a.id, 101, T0)),
      );
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(await store.totp.recordStep(f.id, "other-account", 102, T0)).toBe(false);
      expect(await store.totp.recordStep(f.id, a.id, 102, addSeconds(T0, 30))).toBe(true);
      const after = await store.totp.findActive(a.id);
      expect(after?.lastUsedStep).toBe(102);
      expect(after?.lastUsedAt?.getTime()).toBe(addSeconds(T0, 30).getTime());
    });

    it("totp: delete is scoped to the account; the sealed secret changes by compare-and-set", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const f = totpFactor(a.id);
      await store.totp.insert(f);
      await store.totp.activate(f.id, a.id, 1, T0);
      expect(await store.totp.replaceSealedSecret(f.id, "wrong", "next")).toBe(false);
      const swaps = await Promise.all([
        store.totp.replaceSealedSecret(f.id, f.sealedSecret, "next-1"),
        store.totp.replaceSealedSecret(f.id, f.sealedSecret, "next-2"),
      ]);
      expect(swaps.filter(Boolean)).toHaveLength(1);
      expect(await store.totp.delete(f.id, "other-account")).toBe(false);
      expect(await store.totp.delete(f.id, a.id)).toBe(true);
      expect(await store.totp.findActive(a.id)).toBeNull();
      const pendingOne = totpFactor(a.id);
      await store.totp.insert(pendingOne);
      const activeOne = totpFactor(a.id);
      await store.totp.insert(activeOne);
      await store.totp.activate(activeOne.id, a.id, 3, T0);
      const otherAccount = account();
      await store.accounts.insert(otherAccount);
      const foreign = totpFactor(otherAccount.id);
      await store.totp.insert(foreign);
      expect(await store.totp.deleteAllForAccount(a.id)).toBe(2);
      expect(await store.totp.activate(pendingOne.id, a.id, 4, T0)).toBe(false);
      expect(await store.totp.findPending(foreign.id)).not.toBeNull();
      // A new factor can be activated after the removal.
      const g = totpFactor(a.id);
      await store.totp.insert(g);
      expect(await store.totp.activate(g.id, a.id, 2, T0)).toBe(true);
    });

    it("sessions: store a TOTP step-up and auth method", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const s = session(a.id, {
        authMethods: ["email_otp", "totp"],
        stepUp: { method: "totp", at: T0 },
      });
      await store.sessions.insert(s);
      const found = await store.sessions.findById(s.id);
      expect(found?.authMethods).toEqual(["email_otp", "totp"]);
      expect(found?.stepUp?.method).toBe("totp");
    });

    it("sessions: a method written by a later release is dropped on read, not an error", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      // As a later release would write it: a method this release does not know.
      const later = session(a.id, {
        authMethods: ["oidc", "later_method" as never],
        stepUp: null,
      });
      const only = session(a.id, { authMethods: ["later_method" as never], stepUp: null });
      await store.sessions.insert(later);
      await store.sessions.insert(only);
      expect((await store.sessions.findById(later.id))?.authMethods).toEqual(["oidc"]);
      expect((await store.sessions.findByTokenDigest(later.tokenDigest))?.authMethods).toEqual([
        "oidc",
      ]);
      expect((await store.sessions.findById(only.id))?.authMethods).toEqual([]);
    });

    it("challenges: a pending code approval is consumed once, only for its purpose", async () => {
      const store = await factory();
      const digest = uid("chal");
      await store.challenges.insert({
        id: uid("cid"),
        challengeDigest: digest,
        purpose: "approval_code",
        accountId: null,
        sessionId: null,
        enrollmentTokenDigest: null,
        payloadHash: "b".repeat(64),
        nonce: null,
        createdAt: T0,
        expiresAt: addSeconds(T0, 60),
      });
      expect(await store.challenges.consumeByDigest(digest, "approval")).toBeNull();
      const results = await Promise.all(
        Array.from({ length: 5 }, () => store.challenges.consumeByDigest(digest, "approval_code")),
      );
      expect(results.filter((r) => r !== null)).toHaveLength(1);
    });

    it("enrollment: consumed once, not after expiry", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const digest = uid("enr");
      await store.enrollment.issue({
        tokenDigest: digest,
        accountId: a.id,
        createdAt: T0,
        expiresAt: addSeconds(T0, 60),
        consumedAt: null,
        revokedAt: null,
      });
      expect(await store.enrollment.consume(digest, addSeconds(T0, 60))).toBeNull();
      const results = await Promise.all([
        store.enrollment.consume(digest, T0),
        store.enrollment.consume(digest, T0),
      ]);
      expect(results.filter((r) => r !== null)).toHaveLength(1);
      expect((await store.enrollment.findByDigest(digest))?.consumedAt).not.toBeNull();
    });

    it("enrollment: a new token revokes the earlier ones of the account; revocation is per account", async () => {
      const store = await factory();
      const a = account();
      const b = account();
      await store.accounts.insert(a);
      await store.accounts.insert(b);
      const token = (accountId: string, digest: string) => ({
        tokenDigest: digest,
        accountId,
        createdAt: T0,
        expiresAt: addSeconds(T0, 600),
        consumedAt: null,
        revokedAt: null,
      });
      const [first, used, second, other] = [uid("enr"), uid("enr"), uid("enr"), uid("enr")];
      await store.enrollment.issue(token(a.id, first));
      await store.enrollment.issue(token(a.id, used));
      expect(await store.enrollment.consume(first, T0)).toBeNull();
      expect((await store.enrollment.findByDigest(first))?.revokedAt).not.toBeNull();
      expect(await store.enrollment.consume(used, T0)).not.toBeNull();
      await store.enrollment.issue(token(b.id, other));
      await store.enrollment.issue(token(a.id, second));
      // Also a consumed token is marked, so a registration that is using it can see it.
      expect((await store.enrollment.findByDigest(used))?.revokedAt).not.toBeNull();
      expect(await store.enrollment.revokeAllForAccount(a.id, T0)).toBe(1);
      expect(await store.enrollment.revokeAllForAccount(a.id, T0)).toBe(0);
      expect(await store.enrollment.consume(second, T0)).toBeNull();
      expect(await store.enrollment.consume(other, T0)).not.toBeNull();
    });

    it("enrollment: concurrent issues leave at most one usable token", async () => {
      const store = await factory();
      const a = account();
      await store.accounts.insert(a);
      const digests = Array.from({ length: 5 }, () => uid("enr"));
      await Promise.all(
        digests.map((digest) =>
          store.enrollment.issue({
            tokenDigest: digest,
            accountId: a.id,
            createdAt: T0,
            expiresAt: addSeconds(T0, 600),
            consumedAt: null,
            revokedAt: null,
          }),
        ),
      );
      const usable = await Promise.all(digests.map((d) => store.enrollment.consume(d, T0)));
      expect(usable.filter((r) => r !== null)).toHaveLength(1);
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

    it("oidc links: one account per subject, exclusive inserts, list and delete", async () => {
      const store = await factory();
      const links = store.oidcLinks;
      if (!links) throw new Error("store has no oidcLinks");
      const a = account();
      const b = account();
      await store.accounts.insert(a);
      await store.accounts.insert(b);
      const first = oidcLink(a.id, {
        provider: "microsoft",
        linkKey: JSON.stringify(["microsoft", uid("tid"), uid("oid")]),
        tenantId: "tid",
        source: "import",
      });
      expect(await links.insert(first, { exclusive: true })).toBe("inserted");
      expect(await links.findByKey(first.linkKey)).toEqual(first);
      expect(await links.findByKey(JSON.stringify(["google", uid("none")]))).toBeNull();

      // The same subject cannot link a second time, for this or another account.
      expect(
        await links.insert({ ...oidcLink(b.id), linkKey: first.linkKey }, { exclusive: false }),
      ).toBe("link_taken");
      expect(
        await links.insert({ ...oidcLink(a.id), linkKey: first.linkKey }, { exclusive: true }),
      ).toBe("link_taken");
      // Exclusive: an account with a link gets no second one; non-exclusive: it does.
      expect(await links.insert(oidcLink(a.id), { exclusive: true })).toBe("account_has_link");
      const second = oidcLink(a.id, { createdAt: addSeconds(T0, 1) });
      expect(await links.insert(second, { exclusive: false })).toBe("inserted");
      expect((await links.listByAccount(a.id)).map((l) => l.id)).toEqual([first.id, second.id]);
      expect(await links.listByAccount(b.id)).toEqual([]);

      expect(await links.delete(first.id, b.id)).toBe(false);
      expect(await links.delete(first.id, a.id)).toBe(true);
      expect(await links.delete(first.id, a.id)).toBe(false);
      expect(await links.findByKey(first.linkKey)).toBeNull();
      expect(
        await links.insert({ ...oidcLink(b.id), linkKey: first.linkKey }, { exclusive: true }),
      ).toBe("inserted");
    });

    it("oidc links: concurrent exclusive inserts leave one link per account and per subject", async () => {
      const store = await factory();
      const links = store.oidcLinks;
      if (!links) throw new Error("store has no oidcLinks");
      const a = account();
      await store.accounts.insert(a);
      const perAccount = await Promise.all(
        Array.from({ length: 8 }, () => links.insert(oidcLink(a.id), { exclusive: true })),
      );
      expect(perAccount.filter((r) => r === "inserted")).toHaveLength(1);
      expect(perAccount.filter((r) => r === "account_has_link")).toHaveLength(7);
      expect(await links.listByAccount(a.id)).toHaveLength(1);

      const others = Array.from({ length: 8 }, () => account());
      for (const other of others) await store.accounts.insert(other);
      const key = JSON.stringify(["oidc", "https://idp.example", uid("sub")]);
      const perSubject = await Promise.all(
        others.map((other) =>
          links.insert(oidcLink(other.id, { provider: "oidc", linkKey: key }), {
            exclusive: false,
          }),
        ),
      );
      expect(perSubject.filter((r) => r === "inserted")).toHaveLength(1);
      expect(perSubject.filter((r) => r === "link_taken")).toHaveLength(7);
    });

    it("api tokens: insert, unique digest, lookup with the account status, list, revoke, delete", async () => {
      const store = await factory();
      const tokens = store.apiTokens;
      if (!tokens) throw new Error("store has no apiTokens");
      const a = account();
      const b = account();
      await store.accounts.insert(a);
      await store.accounts.insert(b);
      const limit = { maxActive: 5, at: T0 };
      const first = apiToken(a.id, { scopes: ["z:last", "a:first"] });
      expect(await tokens.insert(first, limit)).toBe("inserted");
      expect(await tokens.insert({ ...apiToken(b.id), digest: first.digest }, limit)).toBe(
        "digest_taken",
      );
      const legacy = apiToken(a.id, {
        digestAlgorithm: "sha256",
        source: "import",
        createdAt: addSeconds(T0, 1),
        lastUsedAt: addSeconds(T0, 1),
      });
      expect(await tokens.insert(legacy, limit)).toBe("inserted");

      // Scopes keep their order; one read returns both digests with the account status.
      expect(await tokens.findByDigests([first.digest])).toEqual([
        { record: first, accountStatus: "active" },
      ]);
      const both = await tokens.findByDigests([first.digest, legacy.digest]);
      expect(both.map((l) => l.record.id).toSorted()).toEqual([first.id, legacy.id].toSorted());
      expect(both.find((l) => l.record.id === legacy.id)?.record).toEqual(legacy);
      expect(await tokens.findByDigests([uid("none")])).toEqual([]);
      expect(await tokens.findByDigests([])).toEqual([]);
      expect((await tokens.listByAccount(a.id)).map((t) => t.id)).toEqual([first.id, legacy.id]);
      expect(await tokens.listByAccount(b.id)).toEqual([]);

      await store.accounts.setStatus(a.id, "disabled");
      expect((await tokens.findByDigests([first.digest]))[0]?.accountStatus).toBe("disabled");

      // Revocation is scoped to the account and happens once; a revoked token is still found.
      expect(await tokens.revoke(first.id, b.id, T0, "revoked")).toBe(false);
      expect(await tokens.revoke(first.id, a.id, addSeconds(T0, 5), "revoked")).toBe(true);
      expect(await tokens.revoke(first.id, a.id, T0, "revoked")).toBe(false);
      const revoked = (await tokens.findByDigests([first.digest]))[0]?.record;
      expect(revoked?.revokedAt).toEqual(addSeconds(T0, 5));
      expect(revoked?.revokeReason).toBe("revoked");
      expect((await tokens.listByAccount(a.id)).map((t) => t.id)).toEqual([legacy.id]);

      const third = apiToken(a.id);
      await tokens.insert(third, limit);
      expect((await tokens.revokeAllForAccount(a.id, T0, "revoked_all")).toSorted()).toEqual(
        [legacy.id, third.id].toSorted(),
      );
      expect(await tokens.revokeAllForAccount(a.id, T0, "revoked_all")).toEqual([]);
      expect(await tokens.listByAccount(a.id)).toEqual([]);

      expect(await tokens.delete(third.id, b.id)).toBe(false);
      expect(await tokens.delete(third.id, a.id)).toBe(true);
      expect(await tokens.delete(third.id, a.id)).toBe(false);
      expect(await tokens.findByDigests([third.digest])).toEqual([]);
      // A deleted digest can be inserted again.
      expect(await tokens.insert({ ...apiToken(b.id), digest: third.digest }, limit)).toBe(
        "inserted",
      );
    });

    it("api tokens: the active limit holds under concurrency; revoked and expired do not count", async () => {
      const store = await factory();
      const tokens = store.apiTokens;
      if (!tokens) throw new Error("store has no apiTokens");
      const a = account();
      await store.accounts.insert(a);
      const limit = { maxActive: 3, at: T0 };
      const results = await Promise.all(
        Array.from({ length: 10 }, () => tokens.insert(apiToken(a.id), limit)),
      );
      expect(results.filter((r) => r === "inserted")).toHaveLength(3);
      expect(results.filter((r) => r === "limit_reached")).toHaveLength(7);
      expect(await tokens.listByAccount(a.id)).toHaveLength(3);

      const [oldest] = await tokens.listByAccount(a.id);
      if (!oldest) throw new Error("no token");
      await tokens.revoke(oldest.id, a.id, T0, "revoked");
      expect(await tokens.insert(apiToken(a.id), limit)).toBe("inserted");
      expect(await tokens.insert(apiToken(a.id), limit)).toBe("limit_reached");
      // At the expiry of a token, it no longer counts.
      const later = { maxActive: 3, at: addSeconds(T0, 30 * 86_400) };
      const parallel = await Promise.all(
        Array.from({ length: 6 }, () =>
          tokens.insert(apiToken(a.id, { expiresAt: addSeconds(T0, 60 * 86_400) }), later),
        ),
      );
      expect(parallel.filter((r) => r === "inserted")).toHaveLength(3);
    });

    it("api tokens: markUsed writes once per interval, also under concurrency, never after a revoke", async () => {
      const store = await factory();
      const tokens = store.apiTokens;
      if (!tokens) throw new Error("store has no apiTokens");
      const a = account();
      await store.accounts.insert(a);
      const t = apiToken(a.id);
      await tokens.insert(t, { maxActive: 5, at: T0 });
      const at = addSeconds(T0, 10);
      const writes = await Promise.all(
        Array.from({ length: 6 }, () => tokens.markUsed(t.id, at, addSeconds(at, -3600))),
      );
      expect(writes.filter(Boolean)).toHaveLength(1);
      const lastUsed = async () => (await tokens.findByDigests([t.digest]))[0]?.record.lastUsedAt;
      expect(await lastUsed()).toEqual(at);
      const soon = addSeconds(at, 3599);
      expect(await tokens.markUsed(t.id, soon, addSeconds(soon, -3600))).toBe(false);
      const due = addSeconds(at, 3600);
      expect(await tokens.markUsed(t.id, due, addSeconds(due, -3600))).toBe(true);
      expect(await lastUsed()).toEqual(due);
      await tokens.revoke(t.id, a.id, due, "revoked");
      const after = addSeconds(due, 7200);
      expect(await tokens.markUsed(t.id, after, addSeconds(after, -3600))).toBe(false);
      expect(await tokens.markUsed(uid("none"), after, after)).toBe(false);
    });

    it("oauth clients: unique id, lists keep order, last use once per interval, secret compare-and-set", async () => {
      const { oauth, client } = await oauthFixture();
      expect(await oauth.insertClient({ ...oauthClient(), id: client.id })).toBe("id_taken");
      expect(await oauth.findClient(client.id)).toEqual(client);
      expect(await oauth.findClient(uid("none"))).toBeNull();
      const pub = oauthClient({
        secretDigest: null,
        secretDigestAlgorithm: null,
        authMethod: "none",
        name: null,
        source: "import",
        redirectUris: ["https://z.example.com/cb", "https://a.example.com/cb"],
      });
      expect(await oauth.insertClient(pub)).toBe("inserted");
      expect(await oauth.findClient(pub.id)).toEqual(pub);

      const at = addSeconds(T0, 10);
      const writes = await Promise.all(
        Array.from({ length: 6 }, () =>
          oauth.markClientUsed(client.id, at, addSeconds(at, -86_400)),
        ),
      );
      expect(writes.filter(Boolean)).toHaveLength(1);
      expect((await oauth.findClient(client.id))?.lastUsedAt).toEqual(at);
      const soon = addSeconds(at, 3600);
      expect(await oauth.markClientUsed(client.id, soon, addSeconds(soon, -86_400))).toBe(false);
      expect(await oauth.markClientUsed(uid("none"), soon, soon)).toBe(false);

      const legacy = oauthClient({ secretDigestAlgorithm: "sha256", source: "import" });
      await oauth.insertClient(legacy);
      const keyed = uid("keyed");
      const upgrades = await Promise.all(
        Array.from({ length: 4 }, () =>
          oauth.upgradeClientSecret(legacy.id, legacy.secretDigest ?? "", keyed),
        ),
      );
      expect(upgrades.filter(Boolean)).toHaveLength(1);
      const upgraded = await oauth.findClient(legacy.id);
      expect(upgraded?.secretDigest).toBe(keyed);
      expect(upgraded?.secretDigestAlgorithm).toBe("hmac-sha256");
      expect(await oauth.upgradeClientSecret(legacy.id, legacy.secretDigest ?? "", uid("x"))).toBe(
        false,
      );
    });

    it("oauth registration counts: each key stops at its max, in order, also under concurrency", async () => {
      const { oauth } = await oauthFixture();
      const day = new Date("2030-01-01T00:00:00.000Z");
      const address = uid("address");
      const deployment = uid("deployment");
      const keys = [
        { key: address, max: 2 },
        { key: deployment, max: 3 },
      ];
      expect(await oauth.reserveRegistration({ keys, windowStart: day })).toBe("reserved");
      expect(await oauth.reserveRegistration({ keys, windowStart: day })).toBe("reserved");
      // The address refuses first, so the deployment key is not counted.
      expect(await oauth.reserveRegistration({ keys, windowStart: day })).toEqual({
        limitReached: address,
      });
      const other = { key: uid("address"), max: 2 };
      expect(
        await oauth.reserveRegistration({ keys: [other, keys[1] ?? other], windowStart: day }),
      ).toBe("reserved");
      // The deployment refuses; the earlier key keeps its count (counts high, never low).
      expect(
        await oauth.reserveRegistration({ keys: [other, keys[1] ?? other], windowStart: day }),
      ).toEqual({ limitReached: deployment });
      expect(
        await oauth.reserveRegistration({ keys: [other, keys[1] ?? other], windowStart: day }),
      ).toEqual({ limitReached: other.key });
      // A new window starts at zero.
      const next = new Date("2030-01-02T00:00:00.000Z");
      expect(await oauth.reserveRegistration({ keys, windowStart: next })).toBe("reserved");

      const burst = { key: uid("burst"), max: 5 };
      const results = await Promise.all(
        Array.from({ length: 20 }, () =>
          oauth.reserveRegistration({ keys: [burst], windowStart: day }),
        ),
      );
      expect(results.filter((r) => r === "reserved")).toHaveLength(5);
      expect(results.filter((r) => r !== "reserved")).toHaveLength(15);
    });

    it("oauth codes: consumed once, also under concurrency; the grant of a code ends by it", async () => {
      const { oauth, accountId, client } = await oauthFixture();
      const code = oauthCode(client.id, accountId, { scopes: ["z:last", "a:first"] });
      await oauth.insertCode(code);
      const consumed = await Promise.all(
        Array.from({ length: 10 }, () => oauth.consumeCode(code.digest)),
      );
      expect(consumed.filter((c) => c !== null)).toEqual([code]);
      expect(await oauth.consumeCode(code.digest)).toBeNull();
      // The flag round-trips both ways (review a2 r2 N-a: every case used true).
      const implicit = oauthCode(client.id, accountId, { redirectUriExplicit: false });
      await oauth.insertCode(implicit);
      expect(await oauth.consumeCode(implicit.digest)).toEqual(implicit);

      const grant = oauthGrant(accountId, client.id, { codeDigest: code.digest });
      const token = oauthAccessToken(grant.id);
      expect(await oauth.insertGrant(grant, token, { maxOtherGrants: 10, at: T0 })).toEqual({
        status: "inserted",
        replaced: null,
      });
      const ended = await Promise.all(
        Array.from({ length: 4 }, () => oauth.endGrantByCode(code.digest)),
      );
      expect(ended.filter((g) => g !== null)).toEqual([grant]);
      expect(await oauth.findGrant(grant.id)).toBeNull();
      expect(await oauth.findAccessToken(token.digest)).toBeNull();
    });

    it("oauth grants: insert with its first token, one per account and client, joined lookups", async () => {
      const { store, oauth, accountId, client } = await oauthFixture();
      const limit = { maxOtherGrants: 10, at: T0 };
      const first = oauthGrant(accountId, client.id, { scopes: ["z:last", "a:first"] });
      const firstToken = oauthAccessToken(first.id, { scopes: ["z:last"] });
      expect(await oauth.insertGrant(first, firstToken, limit)).toEqual({
        status: "inserted",
        replaced: null,
      });
      expect(await oauth.findGrant(first.id)).toEqual({ grant: first, accountStatus: "active" });
      expect(await oauth.findGrantByRefreshRef(first.refreshRefDigest ?? "")).toEqual({
        grant: first,
        accountStatus: "active",
      });
      expect(await oauth.findGrantByRefreshRef(uid("none"))).toBeNull();
      expect(await oauth.findAccessToken(firstToken.digest)).toEqual({
        token: firstToken,
        grant: first,
        accountStatus: "active",
      });
      expect(await oauth.findAccessToken(uid("none"))).toBeNull();

      // A second grant of the same client replaces the first, and the first's tokens go.
      const second = oauthGrant(accountId, client.id, { createdAt: addSeconds(T0, 5) });
      const secondToken = oauthAccessToken(second.id);
      expect(await oauth.insertGrant(second, secondToken, limit)).toEqual({
        status: "inserted",
        replaced: first,
      });
      expect(await oauth.findGrant(first.id)).toBeNull();
      expect(await oauth.findAccessToken(firstToken.digest)).toBeNull();
      expect((await oauth.listGrants(accountId, T0)).map((g) => g.id)).toEqual([second.id]);

      // A grant without a refresh token, and the account status in every joined read.
      const other = oauthClient();
      await oauth.insertClient(other);
      const bare = oauthGrant(accountId, other.id, {
        refreshRefDigest: null,
        refreshDigest: null,
        refreshDigestAlgorithm: null,
        refreshExpiresAt: null,
        createdAt: addSeconds(T0, 9),
      });
      await oauth.insertGrant(bare, oauthAccessToken(bare.id), limit);
      expect((await oauth.findGrant(bare.id))?.grant).toEqual(bare);
      await store.accounts.setStatus(accountId, "disabled");
      expect((await oauth.findGrant(second.id))?.accountStatus).toBe("disabled");
      expect((await oauth.findAccessToken(secondToken.digest))?.accountStatus).toBe("disabled");
      expect(
        (await oauth.findGrantByRefreshRef(second.refreshRefDigest ?? ""))?.accountStatus,
      ).toBe("disabled");
      // A disabled account gets no grant, and its grant of this client stays.
      expect(
        await oauth.insertGrant(
          oauthGrant(accountId, client.id),
          oauthAccessToken(uid("g")),
          limit,
        ),
      ).toEqual({ status: "account_inactive" });
      expect(
        await oauth.insertGrant(
          oauthGrant(uid("none"), client.id),
          oauthAccessToken(uid("g")),
          limit,
        ),
      ).toEqual({ status: "account_inactive" });
      expect(await oauth.findGrant(second.id)).not.toBeNull();
    });

    it("oauth grants: the cap counts live grants of other clients, also under concurrency", async () => {
      const { oauth, accountId } = await oauthFixture();
      const clients = Array.from({ length: 20 }, () => oauthClient());
      for (const c of clients) await oauth.insertClient(c);
      const limit = { maxOtherGrants: 10, at: T0 };
      const results = await Promise.all(
        clients.map((c) => {
          const grant = oauthGrant(accountId, c.id);
          return oauth.insertGrant(grant, oauthAccessToken(grant.id), limit);
        }),
      );
      expect(results.filter((r) => r.status === "inserted")).toHaveLength(10);
      expect(results.filter((r) => r.status === "limit_reached")).toHaveLength(10);
      const live = await oauth.listGrants(accountId, T0);
      expect(live).toHaveLength(10);

      // Replacing the grant of a client that holds one passes at the cap.
      const held = live[0];
      if (!held) throw new Error("no grant");
      const again = oauthGrant(accountId, held.clientId);
      expect((await oauth.insertGrant(again, oauthAccessToken(again.id), limit)).status).toBe(
        "inserted",
      );
      const outsider = clients.find((c) => !live.some((g) => g.clientId === c.id));
      if (!outsider) throw new Error("no outsider");
      const refused = oauthGrant(accountId, outsider.id, {
        expiresAt: addSeconds(T0, 120 * 86_400),
      });
      expect(await oauth.insertGrant(refused, oauthAccessToken(refused.id), limit)).toEqual({
        status: "limit_reached",
      });
      expect(await oauth.findGrant(refused.id)).toBeNull();
      // At their expiry, grants no longer count, and listGrants no longer returns them.
      const later = { maxOtherGrants: 10, at: addSeconds(T0, 90 * 86_400) };
      expect((await oauth.insertGrant(refused, oauthAccessToken(refused.id), later)).status).toBe(
        "inserted",
      );
      expect((await oauth.listGrants(accountId, later.at)).map((g) => g.id)).toEqual([refused.id]);
    });

    it("oauth grants: rotation is compare-and-set; only the winner's token exists; expired tokens are pruned", async () => {
      const { oauth, accountId, client } = await oauthFixture();
      const grant = oauthGrant(accountId, client.id);
      const firstToken = oauthAccessToken(grant.id, { expiresAt: addSeconds(T0, 60) });
      await oauth.insertGrant(grant, firstToken, { maxOtherGrants: 10, at: T0 });
      const at = addSeconds(T0, 120);
      const attempts = Array.from({ length: 10 }, () => {
        const refreshDigest = uid("refresh");
        return {
          update: {
            generation: 2,
            refreshRefDigest: grant.refreshRefDigest ?? "",
            refreshDigest,
            refreshDigestAlgorithm: "hmac-sha256" as const,
            previousRefreshDigest: grant.refreshDigest,
            refreshedAt: at,
            refreshExpiresAt: addSeconds(at, 30 * 86_400),
          },
          token: oauthAccessToken(grant.id, {
            generation: 2,
            createdAt: at,
            expiresAt: addSeconds(at, 3600),
          }),
        };
      });
      const won = await Promise.all(
        attempts.map((a) => oauth.rotateGrant(grant.id, 1, a.update, a.token, at)),
      );
      expect(won.filter(Boolean)).toHaveLength(1);
      const winner = attempts[won.indexOf(true)];
      if (!winner) throw new Error("no winner");
      const found = await oauth.findGrant(grant.id);
      expect(found?.grant).toEqual({ ...grant, ...winner.update });
      for (const a of attempts) {
        const lookup = await oauth.findAccessToken(a.token.digest);
        if (a === winner) expect(lookup?.token).toEqual(a.token);
        else expect(lookup).toBeNull();
      }
      // A late rotation of the old generation, with its own new digest, loses.
      const stale = { ...winner.update, refreshDigest: uid("refresh") };
      // The expired first token was pruned with the rotation.
      expect(await oauth.findAccessToken(firstToken.digest)).toBeNull();
      expect(await oauth.rotateGrant(grant.id, 1, stale, oauthAccessToken(grant.id), at)).toBe(
        false,
      );
      expect(await oauth.rotateGrant(uid("none"), 1, stale, oauthAccessToken(grant.id), at)).toBe(
        false,
      );
    });

    it("oauth grants: deletes are scoped to the client or the account; an account delete takes its codes", async () => {
      const { oauth, accountId, client } = await oauthFixture();
      const limit = { maxOtherGrants: 10, at: T0 };
      const grant = oauthGrant(accountId, client.id);
      const token = oauthAccessToken(grant.id);
      await oauth.insertGrant(grant, token, limit);
      const stranger = oauthClient();
      await oauth.insertClient(stranger);
      expect(await oauth.deleteGrant(grant.id, { clientId: stranger.id })).toBeNull();
      expect(await oauth.deleteGrant(grant.id, { accountId: uid("acc") })).toBeNull();
      expect(await oauth.deleteGrant(grant.id, { clientId: client.id })).toEqual(grant);
      expect(await oauth.deleteGrant(grant.id, { clientId: client.id })).toBeNull();
      expect(await oauth.findAccessToken(token.digest)).toBeNull();

      const again = oauthGrant(accountId, client.id);
      await oauth.insertGrant(again, oauthAccessToken(again.id), limit);
      expect(await oauth.deleteGrant(again.id, { accountId })).toEqual(again);

      const g1 = oauthGrant(accountId, client.id);
      const g2 = oauthGrant(accountId, stranger.id);
      const t1 = oauthAccessToken(g1.id);
      await oauth.insertGrant(g1, t1, limit);
      await oauth.insertGrant(g2, oauthAccessToken(g2.id), limit);
      const code = oauthCode(client.id, accountId);
      await oauth.insertCode(code);
      const ended = await oauth.deleteGrantsForAccount(accountId);
      expect(ended.map((g) => g.id).toSorted()).toEqual([g1.id, g2.id].toSorted());
      expect(await oauth.deleteGrantsForAccount(accountId)).toEqual([]);
      expect(await oauth.consumeCode(code.digest)).toBeNull();
      expect(await oauth.findAccessToken(t1.digest)).toBeNull();
    });

    it("oauth clients: a client delete takes and returns its grants, their tokens and its codes", async () => {
      const { store, oauth, accountId, client } = await oauthFixture();
      const limit = { maxOtherGrants: 10, at: T0 };
      const other = account();
      await store.accounts.insert(other);
      const stranger = oauthClient();
      await oauth.insertClient(stranger);
      const grant = oauthGrant(accountId, client.id);
      const token = oauthAccessToken(grant.id);
      await oauth.insertGrant(grant, token, limit);
      const second = oauthGrant(other.id, client.id);
      await oauth.insertGrant(second, oauthAccessToken(second.id), limit);
      const kept = oauthGrant(accountId, stranger.id);
      await oauth.insertGrant(kept, oauthAccessToken(kept.id), limit);
      const code = oauthCode(client.id, accountId);
      await oauth.insertCode(code);
      const ended = await oauth.deleteClient(client.id);
      expect(ended?.toSorted(byId)).toEqual([grant, second].toSorted(byId));
      expect(await oauth.deleteClient(client.id)).toBeNull();
      expect(await oauth.findClient(client.id)).toBeNull();
      expect(await oauth.findGrant(grant.id)).toBeNull();
      expect(await oauth.findAccessToken(token.digest)).toBeNull();
      expect(await oauth.consumeCode(code.digest)).toBeNull();
      expect((await oauth.findGrant(kept.id))?.grant).toEqual(kept);
      const empty = oauthClient();
      await oauth.insertClient(empty);
      expect(await oauth.deleteClient(empty.id)).toEqual([]);
    });

    it("oauth grants: an import never replaces and names why it did not insert", async () => {
      const { store, oauth, accountId, client } = await oauthFixture();
      const limit = { maxOtherGrants: 1, at: T0 };
      const imported = oauthGrant(accountId, client.id, {
        source: "import",
        refreshRefDigest: null,
        refreshDigestAlgorithm: "sha256",
        codeDigest: null,
        generation: 7,
      });
      expect(await oauth.importGrant(imported, limit)).toBe("inserted");
      expect((await oauth.findGrant(imported.id))?.grant).toEqual(imported);
      expect(await oauth.importGrant(imported, limit)).toBe("id_taken");
      expect(
        await oauth.importGrant(
          oauthGrant(accountId, client.id, { refreshRefDigest: null, codeDigest: null }),
          limit,
        ),
      ).toBe("account_client_taken");
      const other = oauthClient();
      await oauth.insertClient(other);
      const third = oauthClient();
      await oauth.insertClient(third);
      expect(
        await oauth.importGrant(oauthGrant(accountId, other.id, { refreshRefDigest: null }), {
          maxOtherGrants: 2,
          at: T0,
        }),
      ).toBe("inserted");
      expect(
        await oauth.importGrant(oauthGrant(accountId, third.id, { refreshRefDigest: null }), {
          maxOtherGrants: 2,
          at: T0,
        }),
      ).toBe("limit_reached");
      await store.accounts.setStatus(accountId, "disabled");
      expect(
        await oauth.importGrant(oauthGrant(accountId, third.id, { refreshRefDigest: null }), limit),
      ).toBe("account_inactive");
    });

    it("oauth purge: expired rows go; a client with a live grant or code stays", async () => {
      const { oauth, accountId } = await oauthFixture();
      const day = 86_400;
      const at = addSeconds(T0, 200 * day);
      const limit = { maxOtherGrants: 10, at: T0 };
      // Unused: created long ago, never used, nothing live.
      const unused = oauthClient();
      // Idle: used long ago; its grant expired.
      const idle = oauthClient({ lastUsedAt: addSeconds(T0, day) });
      // Idle by date, but a live grant keeps it.
      const busy = oauthClient({ lastUsedAt: addSeconds(T0, day) });
      // Unused by date, but a live code keeps it.
      const pending = oauthClient();
      // Recent: kept.
      const recent = oauthClient({ createdAt: addSeconds(at, -day) });
      for (const c of [unused, idle, busy, pending, recent]) await oauth.insertClient(c);
      const expired = oauthGrant(accountId, idle.id, { expiresAt: addSeconds(T0, 90 * day) });
      const expiredToken = oauthAccessToken(expired.id);
      await oauth.insertGrant(expired, expiredToken, limit);
      const live = oauthGrant(accountId, busy.id, { expiresAt: addSeconds(at, day) });
      const liveToken = oauthAccessToken(live.id, { expiresAt: addSeconds(at, 3600) });
      const oldToken = oauthAccessToken(live.id);
      await oauth.insertGrant(live, liveToken, limit);
      await oauth.rotateGrant(
        live.id,
        1,
        {
          generation: 2,
          refreshRefDigest: live.refreshRefDigest ?? "",
          refreshDigest: uid("refresh"),
          refreshDigestAlgorithm: "hmac-sha256",
          previousRefreshDigest: live.refreshDigest,
          refreshedAt: T0,
          refreshExpiresAt: addSeconds(at, day),
        },
        oldToken,
        T0,
      );
      const liveCode = oauthCode(pending.id, accountId, { expiresAt: addSeconds(at, 300) });
      const oldCode = oauthCode(busy.id, accountId);
      await oauth.insertCode(liveCode);
      await oauth.insertCode(oldCode);
      await oauth.reserveRegistration({
        keys: [{ key: uid("old"), max: 5 }],
        windowStart: T0,
      });

      const result = await oauth.purge({
        at,
        unusedBefore: addSeconds(at, -30 * day),
        idleBefore: addSeconds(at, -180 * day),
        windowBefore: addSeconds(at, -day),
      });
      // A shared database holds rows of earlier cases too: look only at this case's rows.
      const mine = new Set([unused, idle, busy, pending, recent].map((c) => c.id));
      expect(result.clients.filter((c) => mine.has(c.id)).toSorted(byId)).toEqual(
        [
          { id: unused.id, reason: "unused" },
          { id: idle.id, reason: "idle" },
        ].toSorted(byId),
      );
      expect(result.grants.filter((g) => g.accountId === accountId)).toEqual([expired]);
      expect(result.codes).toBeGreaterThanOrEqual(1);
      expect(result.accessTokens).toBeGreaterThanOrEqual(1);
      expect(result.registrationWindows).toBeGreaterThanOrEqual(1);
      for (const kept of [busy, pending, recent]) {
        expect(await oauth.findClient(kept.id)).not.toBeNull();
      }
      expect(await oauth.findGrant(live.id)).not.toBeNull();
      expect(await oauth.findAccessToken(liveToken.digest)).not.toBeNull();
      expect(await oauth.findAccessToken(oldToken.digest)).toBeNull();
      expect(await oauth.consumeCode(oldCode.digest)).toBeNull();
      expect(await oauth.consumeCode(liveCode.digest)).toEqual(liveCode);
    });
  });
}
