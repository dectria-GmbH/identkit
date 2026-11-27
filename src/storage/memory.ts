import { addSeconds } from "../clock.js";
import { knownAuthMethods } from "./auth-methods.js";
import { applyThrottle, type ThrottleState } from "./throttle-logic.js";
import type {
  AccountRecord,
  ChallengeRecord,
  CredentialRecord,
  EnrollmentTokenRecord,
  IdentkitStore,
  OidcLinkRecord,
  OtpFlowRecord,
  SessionRecord,
  TotpFactorRecord,
  VerificationRecord,
} from "./types.js";

const copy = <T>(value: T): T => structuredClone(value);

/** As the database stores read it: methods this release does not know are dropped. */
const readSession = (session: SessionRecord): SessionRecord => ({
  ...copy(session),
  authMethods: knownAuthMethods(session.authMethods),
});

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.byteLength === b.byteLength && a.every((byte, i) => byte === b[i]);

function isFlowOpen(flow: OtpFlowRecord, at: Date): boolean {
  return (
    flow.consumedAt === null &&
    flow.supersededAt === null &&
    at.getTime() < flow.expiresAt.getTime()
  );
}

/**
 * In-memory store for tests, demos and single-process prototypes. JavaScript runs each
 * method body without interruption, so every method is atomic. Data is lost on exit.
 */
export function createMemoryStore(): IdentkitStore {
  const accounts = new Map<string, AccountRecord>();
  const flows = new Map<string, OtpFlowRecord>();
  const sendGates = new Map<string, Date>();
  const throttles = new Map<string, ThrottleState>();
  const sessions = new Map<string, SessionRecord>();
  const credentials = new Map<string, CredentialRecord>();
  const challenges = new Map<string, ChallengeRecord>();
  const enrollment = new Map<string, EnrollmentTokenRecord>();
  const totpFactors = new Map<string, TotpFactorRecord>();
  const verifications = new Map<string, VerificationRecord>();
  const oidcLinks = new Map<string, OidcLinkRecord>();

  function revokeEnrollment(accountId: string, at: Date): number {
    let revoked = 0;
    for (const token of enrollment.values()) {
      if (token.accountId === accountId && token.revokedAt === null) {
        token.revokedAt = at;
        revoked += 1;
      }
    }
    return revoked;
  }

  return {
    accounts: {
      insert(account) {
        for (const existing of accounts.values()) {
          if (existing.email === account.email) return Promise.resolve("email_taken");
        }
        accounts.set(account.id, copy(account));
        return Promise.resolve("inserted");
      },
      findById(id) {
        const found = accounts.get(id);
        return Promise.resolve(found ? copy(found) : null);
      },
      findByEmail(email) {
        for (const account of accounts.values()) {
          if (account.email === email) return Promise.resolve(copy(account));
        }
        return Promise.resolve(null);
      },
      setStatus(id, status) {
        const found = accounts.get(id);
        if (found) found.status = status;
        return Promise.resolve();
      },
      linkPerson(id, personKeyDigest, assuranceLevel, at) {
        for (const account of accounts.values()) {
          if (account.personKeyDigest === personKeyDigest) {
            return Promise.resolve(
              account.id === id ? "already_linked" : "person_linked_elsewhere",
            );
          }
        }
        const found = accounts.get(id);
        if (!found) throw new Error("account not found");
        if (found.personKeyDigest !== null) return Promise.resolve("account_has_other_person");
        found.personKeyDigest = personKeyDigest;
        found.assuranceLevel = assuranceLevel;
        found.identityVerifiedAt = at;
        return Promise.resolve("linked");
      },
    },
    otp: {
      claimSendSlot(gateKey, at, cooldownSeconds) {
        const last = sendGates.get(gateKey);
        if (last && at.getTime() < addSeconds(last, cooldownSeconds).getTime()) {
          return Promise.resolve({
            claimed: false,
            nextAllowedAt: addSeconds(last, cooldownSeconds),
          });
        }
        sendGates.set(gateKey, at);
        return Promise.resolve({ claimed: true, nextAllowedAt: addSeconds(at, cooldownSeconds) });
      },
      supersedeOpen(addressDigest, purpose, at) {
        for (const flow of flows.values()) {
          if (
            flow.addressDigest === addressDigest &&
            flow.purpose === purpose &&
            flow.consumedAt === null &&
            flow.supersededAt === null
          ) {
            flow.supersededAt = at;
          }
        }
        return Promise.resolve();
      },
      insert(flow) {
        flows.set(flow.id, copy(flow));
        return Promise.resolve();
      },
      findById(id) {
        const found = flows.get(id);
        return Promise.resolve(found ? copy(found) : null);
      },
      reserveAttempt(id, at) {
        const flow = flows.get(id);
        if (!flow || !isFlowOpen(flow, at)) return Promise.resolve({ status: "unavailable" });
        if (flow.attempts >= flow.maxAttempts) return Promise.resolve({ status: "exhausted" });
        flow.attempts += 1;
        return Promise.resolve({ status: "reserved", attempts: flow.attempts });
      },
      consume(id, at) {
        const flow = flows.get(id);
        if (!flow || !isFlowOpen(flow, at)) return Promise.resolve(false);
        flow.consumedAt = at;
        return Promise.resolve(true);
      },
    },
    throttle: {
      reserve(key, at, rule) {
        const { next, result } = applyThrottle(throttles.get(key) ?? null, at, rule);
        throttles.set(key, next);
        return Promise.resolve(result);
      },
      peek(key, at) {
        const state = throttles.get(key);
        if (state?.lockedUntil && at.getTime() < state.lockedUntil.getTime()) {
          return Promise.resolve(state.lockedUntil);
        }
        return Promise.resolve(null);
      },
      reset(key) {
        throttles.delete(key);
        return Promise.resolve();
      },
    },
    sessions: {
      insert(session) {
        sessions.set(session.id, copy(session));
        return Promise.resolve();
      },
      findByTokenDigest(digest) {
        for (const session of sessions.values()) {
          if (session.tokenDigest === digest) return Promise.resolve(readSession(session));
        }
        return Promise.resolve(null);
      },
      findById(id) {
        const found = sessions.get(id);
        return Promise.resolve(found ? readSession(found) : null);
      },
      touch(id, at) {
        const found = sessions.get(id);
        if (found && found.revokedAt === null && at.getTime() > found.lastSeenAt.getTime()) {
          found.lastSeenAt = at;
        }
        return Promise.resolve();
      },
      rotate(id, oldDigest, newDigest, update) {
        const found = sessions.get(id);
        if (!found || found.revokedAt !== null || found.tokenDigest !== oldDigest) {
          return Promise.resolve(false);
        }
        Object.assign(found, copy(update), { tokenDigest: newDigest });
        return Promise.resolve(true);
      },
      revoke(id, at, reason) {
        const found = sessions.get(id);
        if (!found || found.revokedAt !== null) return Promise.resolve(false);
        found.revokedAt = at;
        found.revokeReason = reason;
        return Promise.resolve(true);
      },
      revokeAllForAccount(accountId, at, reason, exceptId) {
        const revoked: string[] = [];
        for (const session of sessions.values()) {
          if (
            session.accountId === accountId &&
            session.revokedAt === null &&
            session.id !== exceptId
          ) {
            session.revokedAt = at;
            session.revokeReason = reason;
            revoked.push(session.id);
          }
        }
        return Promise.resolve(revoked);
      },
    },
    credentials: {
      insert(credential) {
        if (credentials.has(credential.id)) return Promise.resolve("duplicate");
        credentials.set(credential.id, copy(credential));
        return Promise.resolve("inserted");
      },
      activate(id, accountId, publicKey, at) {
        const found = credentials.get(id);
        if (!found || found.accountId !== accountId || !sameBytes(found.publicKey, publicKey)) {
          return Promise.resolve(false);
        }
        found.activatedAt ??= at;
        return Promise.resolve(true);
      },
      findById(id) {
        const found = credentials.get(id);
        return Promise.resolve(found && found.activatedAt !== null ? copy(found) : null);
      },
      listByAccount(accountId) {
        return Promise.resolve(
          [...credentials.values()]
            .filter((c) => c.accountId === accountId && c.activatedAt !== null)
            .map(copy),
        );
      },
      updateCounter(id, expected, next, usedAt) {
        const found = credentials.get(id);
        if (!found || found.activatedAt === null || found.counter !== expected) {
          return Promise.resolve(false);
        }
        found.counter = next;
        found.lastUsedAt = usedAt;
        return Promise.resolve(true);
      },
      delete(id, accountId, publicKey) {
        const found = credentials.get(id);
        if (!found || found.accountId !== accountId) return Promise.resolve(false);
        if (publicKey && !sameBytes(found.publicKey, publicKey)) return Promise.resolve(false);
        credentials.delete(id);
        return Promise.resolve(true);
      },
    },
    challenges: {
      insert(challenge) {
        challenges.set(challenge.challengeDigest, copy(challenge));
        return Promise.resolve();
      },
      consumeByDigest(digest, purpose) {
        const found = challenges.get(digest);
        if (!found || found.purpose !== purpose) return Promise.resolve(null);
        challenges.delete(digest);
        return Promise.resolve(found);
      },
    },
    totp: {
      insert(factor) {
        if (totpFactors.has(factor.id)) throw new Error("duplicate totp factor id");
        totpFactors.set(factor.id, copy(factor));
        return Promise.resolve();
      },
      findPending(id) {
        const found = totpFactors.get(id);
        return Promise.resolve(found && found.activatedAt === null ? copy(found) : null);
      },
      findActive(accountId) {
        for (const factor of totpFactors.values()) {
          if (factor.accountId === accountId && factor.activatedAt !== null) {
            return Promise.resolve(copy(factor));
          }
        }
        return Promise.resolve(null);
      },
      activate(id, accountId, step, at) {
        const found = totpFactors.get(id);
        if (!found || found.accountId !== accountId || found.activatedAt !== null) {
          return Promise.resolve(false);
        }
        for (const other of totpFactors.values()) {
          if (other.accountId === accountId && other.activatedAt !== null) {
            return Promise.resolve(false);
          }
        }
        found.activatedAt = at;
        found.lastUsedStep = step;
        found.lastUsedAt = at;
        return Promise.resolve(true);
      },
      recordStep(id, accountId, step, at) {
        const found = totpFactors.get(id);
        if (
          !found ||
          found.accountId !== accountId ||
          found.activatedAt === null ||
          (found.lastUsedStep !== null && found.lastUsedStep >= step)
        ) {
          return Promise.resolve(false);
        }
        found.lastUsedStep = step;
        found.lastUsedAt = at;
        return Promise.resolve(true);
      },
      delete(id, accountId) {
        const found = totpFactors.get(id);
        if (!found || found.accountId !== accountId) return Promise.resolve(false);
        totpFactors.delete(id);
        return Promise.resolve(true);
      },
      deleteAllForAccount(accountId) {
        let count = 0;
        for (const [id, factor] of totpFactors) {
          if (factor.accountId === accountId) {
            totpFactors.delete(id);
            count += 1;
          }
        }
        return Promise.resolve(count);
      },
      replaceSealedSecret(id, expected, next) {
        const found = totpFactors.get(id);
        if (!found || found.sealedSecret !== expected) return Promise.resolve(false);
        found.sealedSecret = next;
        return Promise.resolve(true);
      },
    },
    enrollment: {
      issue(token) {
        revokeEnrollment(token.accountId, token.createdAt);
        enrollment.set(token.tokenDigest, copy(token));
        return Promise.resolve();
      },
      revokeAllForAccount(accountId, at) {
        return Promise.resolve(revokeEnrollment(accountId, at));
      },
      findByDigest(digest) {
        const found = enrollment.get(digest);
        return Promise.resolve(found ? copy(found) : null);
      },
      consume(digest, at) {
        const found = enrollment.get(digest);
        if (
          !found ||
          found.consumedAt !== null ||
          found.revokedAt !== null ||
          at.getTime() >= found.expiresAt.getTime()
        ) {
          return Promise.resolve(null);
        }
        found.consumedAt = at;
        return Promise.resolve(copy(found));
      },
    },
    verifications: {
      insert(record) {
        verifications.set(record.id, copy(record));
        return Promise.resolve();
      },
      findById(id) {
        const found = verifications.get(id);
        return Promise.resolve(found ? copy(found) : null);
      },
      findByVendorReference(reference) {
        for (const record of verifications.values()) {
          if (record.vendorReference === reference) return Promise.resolve(copy(record));
        }
        return Promise.resolve(null);
      },
      setVendorReference(id, reference) {
        const found = verifications.get(id);
        if (found) found.vendorReference = reference;
        return Promise.resolve();
      },
      claim(id) {
        const found = verifications.get(id);
        if (found?.status !== "pending") return Promise.resolve(false);
        found.status = "processing";
        return Promise.resolve(true);
      },
      finalize(id, update) {
        const found = verifications.get(id);
        if (found?.status !== "processing") return Promise.resolve(false);
        Object.assign(found, copy(update));
        return Promise.resolve(true);
      },
      complete(id, update) {
        const found = verifications.get(id);
        if (!found || found.status !== "pending") return Promise.resolve(false);
        Object.assign(found, copy(update));
        return Promise.resolve(true);
      },
    },
    oidcLinks: {
      insert(link, options) {
        const links = [...oidcLinks.values()];
        if (links.some((l) => l.linkKey === link.linkKey)) return Promise.resolve("link_taken");
        if (options.exclusive && links.some((l) => l.accountId === link.accountId)) {
          return Promise.resolve("account_has_link");
        }
        if (!accounts.has(link.accountId)) throw new Error("account not found");
        oidcLinks.set(link.id, copy(link));
        return Promise.resolve("inserted");
      },
      findByKey(linkKey) {
        for (const link of oidcLinks.values()) {
          if (link.linkKey === linkKey) return Promise.resolve(copy(link));
        }
        return Promise.resolve(null);
      },
      listByAccount(accountId) {
        return Promise.resolve(
          [...oidcLinks.values()]
            .filter((l) => l.accountId === accountId)
            .toSorted((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
            .map(copy),
        );
      },
      delete(id, accountId) {
        const found = oidcLinks.get(id);
        if (!found || found.accountId !== accountId) return Promise.resolve(false);
        oidcLinks.delete(id);
        return Promise.resolve(true);
      },
    },
  };
}
