import { addSeconds } from "../clock.js";
import { knownAuthMethods } from "./auth-methods.js";
import { applyThrottle, type ThrottleState } from "./throttle-logic.js";
import type {
  AccountRecord,
  ApiTokenRecord,
  ChallengeRecord,
  CredentialRecord,
  EnrollmentTokenRecord,
  IdentkitStore,
  OAuthAccessTokenRecord,
  OAuthClientRecord,
  OAuthCodeRecord,
  OAuthGrantRecord,
  OAuthPurgeStoreResult,
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
  const apiTokens = new Map<string, ApiTokenRecord>();
  const oauthClients = new Map<string, OAuthClientRecord>();
  const oauthGrants = new Map<string, OAuthGrantRecord>();
  const oauthAccessTokens = new Map<string, OAuthAccessTokenRecord>();
  const oauthCodes = new Map<string, OAuthCodeRecord>();
  /** Registration counts by key and window start (ms). */
  const registrationCounts = new Map<string, number>();

  /** Deletes the grant and its access tokens, as the foreign key cascade does. */
  function dropGrant(id: string): OAuthGrantRecord | null {
    const grant = oauthGrants.get(id);
    if (!grant) return null;
    oauthGrants.delete(id);
    for (const [digest, token] of oauthAccessTokens) {
      if (token.grantId === id) oauthAccessTokens.delete(digest);
    }
    return grant;
  }

  /** Live grants of the account, other than those of `exceptClientId`. */
  function liveOtherGrants(accountId: string, exceptClientId: string, at: Date): number {
    let count = 0;
    for (const grant of oauthGrants.values()) {
      if (
        grant.accountId === accountId &&
        grant.clientId !== exceptClientId &&
        grant.expiresAt.getTime() > at.getTime()
      ) {
        count += 1;
      }
    }
    return count;
  }

  function findGrantBy(match: (grant: OAuthGrantRecord) => boolean) {
    for (const grant of oauthGrants.values()) {
      if (!match(grant)) continue;
      const account = accounts.get(grant.accountId);
      if (!account) return null;
      return { grant: copy(grant), accountStatus: account.status };
    }
    return null;
  }

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
        if (!accounts.has(link.accountId)) return Promise.reject(new Error("account not found"));
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
    apiTokens: {
      insert(token, limit) {
        const tokens = [...apiTokens.values()];
        if (tokens.some((t) => t.digest === token.digest)) return Promise.resolve("digest_taken");
        const active = tokens.filter(
          (t) =>
            t.accountId === token.accountId &&
            t.revokedAt === null &&
            t.expiresAt.getTime() > limit.at.getTime(),
        );
        if (active.length >= limit.maxActive) return Promise.resolve("limit_reached");
        if (!accounts.has(token.accountId)) return Promise.reject(new Error("account not found"));
        if (apiTokens.has(token.id)) return Promise.reject(new Error("duplicate api token id"));
        apiTokens.set(token.id, copy(token));
        return Promise.resolve("inserted");
      },
      findByDigests(digests) {
        const found = [...apiTokens.values()].flatMap((record) => {
          const account = accounts.get(record.accountId);
          if (!digests.includes(record.digest) || !account) return [];
          return [{ record: copy(record), accountStatus: account.status }];
        });
        return Promise.resolve(found);
      },
      listByAccount(accountId) {
        return Promise.resolve(
          [...apiTokens.values()]
            .filter((t) => t.accountId === accountId && t.revokedAt === null)
            .toSorted(
              (a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : 1),
            )
            .map(copy),
        );
      },
      markUsed(id, at, notAfter) {
        const found = apiTokens.get(id);
        if (
          !found ||
          found.revokedAt !== null ||
          (found.lastUsedAt !== null && found.lastUsedAt.getTime() > notAfter.getTime())
        ) {
          return Promise.resolve(false);
        }
        found.lastUsedAt = at;
        return Promise.resolve(true);
      },
      revoke(id, accountId, at, reason) {
        const found = apiTokens.get(id);
        if (!found || found.accountId !== accountId || found.revokedAt !== null) {
          return Promise.resolve(false);
        }
        found.revokedAt = at;
        found.revokeReason = reason;
        return Promise.resolve(true);
      },
      revokeAllForAccount(accountId, at, reason) {
        const revoked: string[] = [];
        for (const token of apiTokens.values()) {
          if (token.accountId === accountId && token.revokedAt === null) {
            token.revokedAt = at;
            token.revokeReason = reason;
            revoked.push(token.id);
          }
        }
        return Promise.resolve(revoked);
      },
      delete(id, accountId) {
        const found = apiTokens.get(id);
        if (!found || found.accountId !== accountId) return Promise.resolve(false);
        apiTokens.delete(id);
        return Promise.resolve(true);
      },
    },
    oauth: {
      insertClient(client) {
        if (oauthClients.has(client.id)) return Promise.resolve("id_taken");
        oauthClients.set(client.id, copy(client));
        return Promise.resolve("inserted");
      },
      findClient(id) {
        const found = oauthClients.get(id);
        return Promise.resolve(found ? copy(found) : null);
      },
      markClientUsed(id, at, notAfter) {
        const found = oauthClients.get(id);
        if (
          !found ||
          (found.lastUsedAt !== null && found.lastUsedAt.getTime() > notAfter.getTime())
        ) {
          return Promise.resolve(false);
        }
        found.lastUsedAt = at;
        return Promise.resolve(true);
      },
      upgradeClientSecret(id, oldDigest, newDigest) {
        const found = oauthClients.get(id);
        if (!found || found.secretDigest !== oldDigest) return Promise.resolve(false);
        found.secretDigest = newDigest;
        found.secretDigestAlgorithm = "hmac-sha256";
        return Promise.resolve(true);
      },
      deleteClient(id) {
        if (!oauthClients.delete(id)) return Promise.resolve(null);
        const ended: OAuthGrantRecord[] = [];
        for (const grant of oauthGrants.values()) {
          if (grant.clientId !== id) continue;
          const dropped = dropGrant(grant.id);
          if (dropped) ended.push(dropped);
        }
        for (const [digest, code] of oauthCodes) {
          if (code.clientId === id) oauthCodes.delete(digest);
        }
        return Promise.resolve(ended);
      },
      reserveRegistration({ keys, windowStart }) {
        for (const { key, max } of keys) {
          const slot = `${windowStart.getTime()}\u0000${key}`;
          const count = registrationCounts.get(slot) ?? 0;
          if (count >= max) return Promise.resolve({ limitReached: key });
          registrationCounts.set(slot, count + 1);
        }
        return Promise.resolve("reserved");
      },
      insertCode(code) {
        if (oauthCodes.has(code.digest)) return Promise.reject(new Error("duplicate oauth code"));
        if (!oauthClients.has(code.clientId) || !accounts.has(code.accountId)) {
          return Promise.reject(new Error("oauth code references a missing row"));
        }
        oauthCodes.set(code.digest, copy(code));
        return Promise.resolve();
      },
      consumeCode(digest) {
        const found = oauthCodes.get(digest);
        if (!found) return Promise.resolve(null);
        oauthCodes.delete(digest);
        return Promise.resolve(found);
      },
      endGrantByCode(codeDigest) {
        for (const grant of oauthGrants.values()) {
          if (grant.codeDigest === codeDigest) return Promise.resolve(dropGrant(grant.id));
        }
        return Promise.resolve(null);
      },
      insertGrant(grant, firstAccessToken, limit) {
        const account = accounts.get(grant.accountId);
        if (!account || account.status !== "active") {
          return Promise.resolve({ status: "account_inactive" });
        }
        if (liveOtherGrants(grant.accountId, grant.clientId, limit.at) >= limit.maxOtherGrants) {
          return Promise.resolve({ status: "limit_reached" });
        }
        if (!oauthClients.has(grant.clientId)) {
          return Promise.reject(new Error("oauth grant references a missing client"));
        }
        const clash = [...oauthGrants.values()].some(
          (g) =>
            g.id === grant.id ||
            (grant.codeDigest !== null && g.codeDigest === grant.codeDigest) ||
            (grant.refreshRefDigest !== null && g.refreshRefDigest === grant.refreshRefDigest),
        );
        if (clash || oauthAccessTokens.has(firstAccessToken.digest)) {
          return Promise.reject(new Error("duplicate oauth grant or token"));
        }
        let replaced: OAuthGrantRecord | null = null;
        for (const existing of oauthGrants.values()) {
          if (existing.accountId === grant.accountId && existing.clientId === grant.clientId) {
            replaced = dropGrant(existing.id);
          }
        }
        oauthGrants.set(grant.id, copy(grant));
        oauthAccessTokens.set(firstAccessToken.digest, copy(firstAccessToken));
        return Promise.resolve({ status: "inserted", replaced });
      },
      importGrant(grant, limit) {
        if (oauthGrants.has(grant.id)) return Promise.resolve("id_taken");
        const account = accounts.get(grant.accountId);
        if (!account || account.status !== "active") return Promise.resolve("account_inactive");
        const taken = [...oauthGrants.values()].some(
          (g) => g.accountId === grant.accountId && g.clientId === grant.clientId,
        );
        if (taken) return Promise.resolve("account_client_taken");
        if (liveOtherGrants(grant.accountId, grant.clientId, limit.at) >= limit.maxOtherGrants) {
          return Promise.resolve("limit_reached");
        }
        if (!oauthClients.has(grant.clientId)) {
          return Promise.reject(new Error("oauth grant references a missing client"));
        }
        oauthGrants.set(grant.id, copy(grant));
        return Promise.resolve("inserted");
      },
      findGrantByRefreshRef(refDigest) {
        return Promise.resolve(findGrantBy((g) => g.refreshRefDigest === refDigest));
      },
      findGrant(id) {
        return Promise.resolve(findGrantBy((g) => g.id === id));
      },
      rotateGrant(id, expectedGeneration, update, accessToken, pruneBefore) {
        const found = oauthGrants.get(id);
        if (!found || found.generation !== expectedGeneration) return Promise.resolve(false);
        if (oauthAccessTokens.has(accessToken.digest)) {
          return Promise.reject(new Error("duplicate oauth access token"));
        }
        Object.assign(found, copy(update));
        oauthAccessTokens.set(accessToken.digest, copy(accessToken));
        for (const [digest, token] of oauthAccessTokens) {
          if (token.grantId === id && token.expiresAt.getTime() <= pruneBefore.getTime()) {
            oauthAccessTokens.delete(digest);
          }
        }
        return Promise.resolve(true);
      },
      findAccessToken(digest) {
        const token = oauthAccessTokens.get(digest);
        const grant = token ? oauthGrants.get(token.grantId) : undefined;
        const account = grant ? accounts.get(grant.accountId) : undefined;
        if (!token || !grant || !account) return Promise.resolve(null);
        return Promise.resolve({
          token: copy(token),
          grant: copy(grant),
          accountStatus: account.status,
        });
      },
      deleteGrant(id, match) {
        const found = oauthGrants.get(id);
        if (!found) return Promise.resolve(null);
        const owned =
          "clientId" in match
            ? found.clientId === match.clientId
            : found.accountId === match.accountId;
        return Promise.resolve(owned ? dropGrant(id) : null);
      },
      deleteGrantsForAccount(accountId) {
        const ended: OAuthGrantRecord[] = [];
        for (const grant of oauthGrants.values()) {
          if (grant.accountId !== accountId) continue;
          const dropped = dropGrant(grant.id);
          if (dropped) ended.push(dropped);
        }
        for (const [digest, code] of oauthCodes) {
          if (code.accountId === accountId) oauthCodes.delete(digest);
        }
        return Promise.resolve(ended);
      },
      listGrants(accountId, at) {
        return Promise.resolve(
          [...oauthGrants.values()]
            .filter((g) => g.accountId === accountId && g.expiresAt.getTime() > at.getTime())
            .toSorted(
              (a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : 1),
            )
            .map(copy),
        );
      },
      purge({ at, unusedBefore, idleBefore, windowBefore }) {
        const now = at.getTime();
        const grants: OAuthGrantRecord[] = [];
        for (const grant of oauthGrants.values()) {
          if (grant.expiresAt.getTime() > now) continue;
          const dropped = dropGrant(grant.id);
          if (dropped) grants.push(dropped);
        }
        let codes = 0;
        for (const [digest, code] of oauthCodes) {
          if (code.expiresAt.getTime() <= now) {
            oauthCodes.delete(digest);
            codes += 1;
          }
        }
        let accessTokens = 0;
        for (const [digest, token] of oauthAccessTokens) {
          if (token.expiresAt.getTime() <= now) {
            oauthAccessTokens.delete(digest);
            accessTokens += 1;
          }
        }
        const busy = new Set([
          ...[...oauthGrants.values()].map((g) => g.clientId),
          ...[...oauthCodes.values()].map((c) => c.clientId),
        ]);
        const clients: OAuthPurgeStoreResult["clients"] = [];
        for (const client of oauthClients.values()) {
          if (busy.has(client.id)) continue;
          const reason =
            client.lastUsedAt === null
              ? client.createdAt.getTime() < unusedBefore.getTime()
                ? "unused"
                : null
              : client.lastUsedAt.getTime() < idleBefore.getTime()
                ? "idle"
                : null;
          if (reason === null) continue;
          oauthClients.delete(client.id);
          clients.push({ id: client.id, reason });
        }
        let registrationWindows = 0;
        for (const slot of registrationCounts.keys()) {
          const start = Number(slot.slice(0, slot.indexOf("\u0000")));
          if (start < windowBefore.getTime()) {
            registrationCounts.delete(slot);
            registrationWindows += 1;
          }
        }
        return Promise.resolve({ clients, grants, codes, accessTokens, registrationWindows });
      },
    },
  };
}
