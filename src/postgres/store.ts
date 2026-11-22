import { sql, type Kysely, type Selectable } from "kysely";
import { addSeconds } from "../clock.js";
import { applyThrottle } from "../storage/throttle-logic.js";
import type {
  AccountRecord,
  ChallengeRecord,
  CredentialRecord,
  IdentkitStore,
  OtpFlowRecord,
  SessionRecord,
  TotpFactorRecord,
  VerificationRecord,
} from "../storage/types.js";
import type { IdentkitDatabase } from "./schema.js";

type Row<T extends keyof IdentkitDatabase> = Selectable<IdentkitDatabase[T]>;

const UNIQUE_VIOLATION = "23505";

function isUniqueViolation(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    Reflect.get(error, "code") === UNIQUE_VIOLATION
  );
}

/** Checks a value read from the database against the allowed set. */
function oneOf<const T extends string>(value: string, allowed: readonly T[]): T {
  const found = allowed.find((candidate) => candidate === value);
  if (found === undefined) throw new Error(`unexpected value in database: ${value}`);
  return found;
}

function oneOfOrNull<const T extends string>(
  value: string | null,
  allowed: readonly T[],
): T | null {
  return value === null ? null : oneOf(value, allowed);
}

const LEVELS = ["low", "substantial", "high"] as const;
const AUTH_METHODS = ["email_otp", "passkey", "totp"] as const;
const STEP_UP_METHODS = ["email_otp", "passkey", "totp"] as const;

const toAccount = (r: Row<"identkit_accounts">): AccountRecord => ({
  id: r.id,
  email: r.email,
  webauthnUserId: r.webauthn_user_id,
  status: oneOf(r.status, ["active", "disabled"]),
  createdAt: r.created_at,
  personKeyDigest: r.person_key_digest,
  assuranceLevel: oneOfOrNull(r.assurance_level, LEVELS),
  identityVerifiedAt: r.identity_verified_at,
});

const toFlow = (r: Row<"identkit_otp_flows">): OtpFlowRecord => ({
  id: r.id,
  purpose: oneOf(r.purpose, ["sign_in", "step_up"]),
  email: r.email,
  addressDigest: r.address_digest,
  sessionId: r.session_id,
  codeDigest: r.code_digest,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  attempts: r.attempts,
  maxAttempts: r.max_attempts,
  consumedAt: r.consumed_at,
  supersededAt: r.superseded_at,
});

const toSession = (r: Row<"identkit_sessions">): SessionRecord => ({
  id: r.id,
  accountId: r.account_id,
  tokenDigest: r.token_digest,
  state: oneOf(r.state, ["pending_second_factor", "complete"]),
  authMethods: r.auth_methods.map((m) => oneOf(m, AUTH_METHODS)),
  createdAt: r.created_at,
  lastSeenAt: r.last_seen_at,
  absoluteExpiresAt: r.absolute_expires_at,
  stepUp:
    r.step_up_method && r.step_up_at
      ? { method: oneOf(r.step_up_method, STEP_UP_METHODS), at: r.step_up_at }
      : null,
  revokedAt: r.revoked_at,
  revokeReason: r.revoke_reason,
});

const toCredential = (r: Row<"identkit_credentials">): CredentialRecord => ({
  id: r.id,
  accountId: r.account_id,
  publicKey: new Uint8Array(r.public_key),
  counter: Number(r.counter),
  transports: r.transports,
  deviceType: oneOf(r.device_type, ["singleDevice", "multiDevice"]),
  backedUp: r.backed_up,
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
  activatedAt: r.activated_at,
});

const toChallenge = (r: Row<"identkit_challenges">): ChallengeRecord => ({
  id: r.id,
  challengeDigest: r.challenge_digest,
  purpose: oneOf(r.purpose, [
    "registration",
    "sign_in",
    "second_factor",
    "step_up",
    "approval",
    "approval_code",
  ]),
  accountId: r.account_id,
  sessionId: r.session_id,
  enrollmentTokenDigest: r.enrollment_token_digest,
  payloadHash: r.payload_hash,
  nonce: r.nonce,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
});

function toDigits(value: number): 6 | 8 {
  if (value === 6 || value === 8) return value;
  throw new Error(`unexpected value in database: ${value}`);
}

const toTotpFactor = (r: Row<"identkit_totp_factors">): TotpFactorRecord => ({
  id: r.id,
  accountId: r.account_id,
  sealedSecret: r.sealed_secret,
  algorithm: oneOf(r.algorithm, ["SHA1", "SHA256", "SHA512"]),
  digits: toDigits(r.digits),
  createdAt: r.created_at,
  enrolmentSessionId: r.enrolment_session_id,
  activatedAt: r.activated_at,
  lastUsedStep: r.last_used_step === null ? null : Number(r.last_used_step),
  lastUsedAt: r.last_used_at,
});

const toVerification = (r: Row<"identkit_verifications">): VerificationRecord => ({
  id: r.id,
  accountId: r.account_id,
  vendorReference: r.vendor_reference,
  status: oneOf(r.status, ["pending", "processing", "verified", "failed", "expired", "conflict"]),
  assuranceLevel: oneOfOrNull(r.assurance_level, LEVELS),
  evidenceReference: r.evidence_reference,
  failureReason: r.failure_reason,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  completedAt: r.completed_at,
});

/**
 * PostgreSQL store. Pass a Kysely instance with a PostgreSQL dialect; apply the migrations
 * first (`migrateIdentkit` or the files in `migrations/`). Each guarded method is one
 * conditional statement or one transaction with a row lock.
 */
export function createPostgresStore(db: Kysely<IdentkitDatabase>): IdentkitStore {
  return {
    accounts: {
      async insert(a) {
        const row = await db
          .insertInto("identkit_accounts")
          .values({
            id: a.id,
            email: a.email,
            webauthn_user_id: a.webauthnUserId,
            status: a.status,
            created_at: a.createdAt,
            person_key_digest: a.personKeyDigest,
            assurance_level: a.assuranceLevel,
            identity_verified_at: a.identityVerifiedAt,
          })
          .onConflict((oc) => oc.column("email").doNothing())
          .returning("id")
          .executeTakeFirst();
        return row ? "inserted" : "email_taken";
      },
      async findById(id) {
        const r = await db
          .selectFrom("identkit_accounts")
          .selectAll()
          .where("id", "=", id)
          .executeTakeFirst();
        return r ? toAccount(r) : null;
      },
      async findByEmail(email) {
        const r = await db
          .selectFrom("identkit_accounts")
          .selectAll()
          .where("email", "=", email)
          .executeTakeFirst();
        return r ? toAccount(r) : null;
      },
      async setStatus(id, status) {
        await db.updateTable("identkit_accounts").set({ status }).where("id", "=", id).execute();
      },
      async linkPerson(id, digest, level, at) {
        try {
          const updated = await db
            .updateTable("identkit_accounts")
            .set({ person_key_digest: digest, assurance_level: level, identity_verified_at: at })
            .where("id", "=", id)
            .where("person_key_digest", "is", null)
            .returning("id")
            .executeTakeFirst();
          if (updated) return "linked";
        } catch (error) {
          if (isUniqueViolation(error)) return "person_linked_elsewhere";
          throw error;
        }
        const account = await db
          .selectFrom("identkit_accounts")
          .select("person_key_digest")
          .where("id", "=", id)
          .executeTakeFirst();
        if (!account) throw new Error("account not found");
        return account.person_key_digest === digest ? "already_linked" : "account_has_other_person";
      },
    },

    otp: {
      async claimSendSlot(gateKey, at, cooldownSeconds) {
        const claimed = await sql<{ last_sent_at: Date }>`
          INSERT INTO identkit_otp_send_gates (gate_key, last_sent_at)
          VALUES (${gateKey}, ${at})
          ON CONFLICT (gate_key) DO UPDATE SET last_sent_at = EXCLUDED.last_sent_at
          WHERE identkit_otp_send_gates.last_sent_at <= ${addSeconds(at, -cooldownSeconds)}
          RETURNING last_sent_at`.execute(db);
        if (claimed.rows.length > 0) {
          return { claimed: true, nextAllowedAt: addSeconds(at, cooldownSeconds) };
        }
        const row = await db
          .selectFrom("identkit_otp_send_gates")
          .select("last_sent_at")
          .where("gate_key", "=", gateKey)
          .executeTakeFirstOrThrow();
        return { claimed: false, nextAllowedAt: addSeconds(row.last_sent_at, cooldownSeconds) };
      },
      async supersedeOpen(addressDigest, purpose, at) {
        await db
          .updateTable("identkit_otp_flows")
          .set({ superseded_at: at })
          .where("address_digest", "=", addressDigest)
          .where("purpose", "=", purpose)
          .where("consumed_at", "is", null)
          .where("superseded_at", "is", null)
          .execute();
      },
      async insert(f) {
        await db
          .insertInto("identkit_otp_flows")
          .values({
            id: f.id,
            purpose: f.purpose,
            email: f.email,
            address_digest: f.addressDigest,
            session_id: f.sessionId,
            code_digest: f.codeDigest,
            created_at: f.createdAt,
            expires_at: f.expiresAt,
            attempts: f.attempts,
            max_attempts: f.maxAttempts,
            consumed_at: f.consumedAt,
            superseded_at: f.supersededAt,
          })
          .execute();
      },
      async findById(id) {
        const r = await db
          .selectFrom("identkit_otp_flows")
          .selectAll()
          .where("id", "=", id)
          .executeTakeFirst();
        return r ? toFlow(r) : null;
      },
      async reserveAttempt(id, at) {
        const reserved = await db
          .updateTable("identkit_otp_flows")
          .set((eb) => ({ attempts: eb("attempts", "+", 1) }))
          .where("id", "=", id)
          .where("consumed_at", "is", null)
          .where("superseded_at", "is", null)
          .where("expires_at", ">", at)
          .where((eb) => eb("attempts", "<", eb.ref("max_attempts")))
          .returning("attempts")
          .executeTakeFirst();
        if (reserved) return { status: "reserved", attempts: reserved.attempts };
        const flow = await db
          .selectFrom("identkit_otp_flows")
          .selectAll()
          .where("id", "=", id)
          .executeTakeFirst();
        if (
          flow &&
          flow.consumed_at === null &&
          flow.superseded_at === null &&
          flow.expires_at.getTime() > at.getTime() &&
          flow.attempts >= flow.max_attempts
        ) {
          return { status: "exhausted" };
        }
        return { status: "unavailable" };
      },
      async consume(id, at) {
        const row = await db
          .updateTable("identkit_otp_flows")
          .set({ consumed_at: at })
          .where("id", "=", id)
          .where("consumed_at", "is", null)
          .where("superseded_at", "is", null)
          .where("expires_at", ">", at)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
    },

    throttle: {
      async reserve(key, at, rule) {
        return db.transaction().execute(async (trx) => {
          // The no-op update makes the upsert return the row and hold its lock until commit,
          // also when a concurrent reset deleted it in between.
          const row = await trx
            .insertInto("identkit_throttles")
            .values({ key, window_start: at, attempts: 0, locked_until: null, lock_count: 0 })
            .onConflict((oc) =>
              oc.column("key").doUpdateSet((eb) => ({ key: eb.ref("excluded.key") })),
            )
            .returningAll()
            .executeTakeFirstOrThrow();
          const { next, result } = applyThrottle(
            {
              windowStart: row.window_start,
              attempts: row.attempts,
              lockedUntil: row.locked_until,
              lockCount: row.lock_count,
            },
            at,
            rule,
          );
          await trx
            .updateTable("identkit_throttles")
            .set({
              window_start: next.windowStart,
              attempts: next.attempts,
              locked_until: next.lockedUntil,
              lock_count: next.lockCount,
            })
            .where("key", "=", key)
            .execute();
          return result;
        });
      },
      async peek(key, at) {
        const row = await db
          .selectFrom("identkit_throttles")
          .select("locked_until")
          .where("key", "=", key)
          .executeTakeFirst();
        return row?.locked_until && at.getTime() < row.locked_until.getTime()
          ? row.locked_until
          : null;
      },
      async reset(key) {
        await db.deleteFrom("identkit_throttles").where("key", "=", key).execute();
      },
    },

    sessions: {
      async insert(s) {
        await db
          .insertInto("identkit_sessions")
          .values({
            id: s.id,
            account_id: s.accountId,
            token_digest: s.tokenDigest,
            state: s.state,
            auth_methods: s.authMethods,
            created_at: s.createdAt,
            last_seen_at: s.lastSeenAt,
            absolute_expires_at: s.absoluteExpiresAt,
            step_up_method: s.stepUp?.method ?? null,
            step_up_at: s.stepUp?.at ?? null,
            revoked_at: s.revokedAt,
            revoke_reason: s.revokeReason,
          })
          .execute();
      },
      async findByTokenDigest(digest) {
        const r = await db
          .selectFrom("identkit_sessions")
          .selectAll()
          .where("token_digest", "=", digest)
          .executeTakeFirst();
        return r ? toSession(r) : null;
      },
      async findById(id) {
        const r = await db
          .selectFrom("identkit_sessions")
          .selectAll()
          .where("id", "=", id)
          .executeTakeFirst();
        return r ? toSession(r) : null;
      },
      async touch(id, at) {
        await db
          .updateTable("identkit_sessions")
          .set({ last_seen_at: at })
          .where("id", "=", id)
          .where("revoked_at", "is", null)
          .where("last_seen_at", "<", at)
          .execute();
      },
      async rotate(id, oldDigest, newDigest, u) {
        const row = await db
          .updateTable("identkit_sessions")
          .set({
            token_digest: newDigest,
            state: u.state,
            auth_methods: u.authMethods,
            step_up_method: u.stepUp?.method ?? null,
            step_up_at: u.stepUp?.at ?? null,
            last_seen_at: u.lastSeenAt,
            absolute_expires_at: u.absoluteExpiresAt,
          })
          .where("id", "=", id)
          .where("token_digest", "=", oldDigest)
          .where("revoked_at", "is", null)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async revoke(id, at, reason) {
        const row = await db
          .updateTable("identkit_sessions")
          .set({ revoked_at: at, revoke_reason: reason })
          .where("id", "=", id)
          .where("revoked_at", "is", null)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async revokeAllForAccount(accountId, at, reason, exceptId) {
        let query = db
          .updateTable("identkit_sessions")
          .set({ revoked_at: at, revoke_reason: reason })
          .where("account_id", "=", accountId)
          .where("revoked_at", "is", null);
        if (exceptId !== undefined) query = query.where("id", "!=", exceptId);
        const rows = await query.returning("id").execute();
        return rows.map((r) => r.id);
      },
    },

    credentials: {
      async insert(c) {
        const row = await db
          .insertInto("identkit_credentials")
          .values({
            id: c.id,
            account_id: c.accountId,
            public_key: Buffer.from(c.publicKey),
            counter: c.counter,
            transports: c.transports,
            device_type: c.deviceType,
            backed_up: c.backedUp,
            created_at: c.createdAt,
            last_used_at: c.lastUsedAt,
            activated_at: c.activatedAt,
          })
          .onConflict((oc) => oc.column("id").doNothing())
          .returning("id")
          .executeTakeFirst();
        return row ? "inserted" : "duplicate";
      },
      async activate(id, accountId, publicKey, at) {
        const row = await db
          .updateTable("identkit_credentials")
          .set((eb) => ({ activated_at: eb.fn.coalesce("activated_at", eb.val(at)) }))
          .where("id", "=", id)
          .where("account_id", "=", accountId)
          .where("public_key", "=", Buffer.from(publicKey))
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async findById(id) {
        const r = await db
          .selectFrom("identkit_credentials")
          .selectAll()
          .where("id", "=", id)
          .where("activated_at", "is not", null)
          .executeTakeFirst();
        return r ? toCredential(r) : null;
      },
      async listByAccount(accountId) {
        const rows = await db
          .selectFrom("identkit_credentials")
          .selectAll()
          .where("account_id", "=", accountId)
          .where("activated_at", "is not", null)
          .orderBy("created_at")
          .execute();
        return rows.map(toCredential);
      },
      async updateCounter(id, expected, next, usedAt) {
        const row = await db
          .updateTable("identkit_credentials")
          .set({ counter: next, last_used_at: usedAt })
          .where("id", "=", id)
          .where("counter", "=", expected)
          .where("activated_at", "is not", null)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async delete(id, accountId, publicKey) {
        let query = db
          .deleteFrom("identkit_credentials")
          .where("id", "=", id)
          .where("account_id", "=", accountId);
        if (publicKey) query = query.where("public_key", "=", Buffer.from(publicKey));
        const row = await query.returning("id").executeTakeFirst();
        return row !== undefined;
      },
    },

    challenges: {
      async insert(c) {
        await db
          .insertInto("identkit_challenges")
          .values({
            id: c.id,
            challenge_digest: c.challengeDigest,
            purpose: c.purpose,
            account_id: c.accountId,
            session_id: c.sessionId,
            enrollment_token_digest: c.enrollmentTokenDigest,
            payload_hash: c.payloadHash,
            nonce: c.nonce,
            created_at: c.createdAt,
            expires_at: c.expiresAt,
          })
          .execute();
      },
      async consumeByDigest(digest, purpose) {
        const r = await db
          .deleteFrom("identkit_challenges")
          .where("challenge_digest", "=", digest)
          .where("purpose", "=", purpose)
          .returningAll()
          .executeTakeFirst();
        return r ? toChallenge(r) : null;
      },
    },

    totp: {
      async insert(f) {
        await db
          .insertInto("identkit_totp_factors")
          .values({
            id: f.id,
            account_id: f.accountId,
            sealed_secret: f.sealedSecret,
            algorithm: f.algorithm,
            digits: f.digits,
            created_at: f.createdAt,
            enrolment_session_id: f.enrolmentSessionId,
            activated_at: f.activatedAt,
            last_used_step: f.lastUsedStep,
            last_used_at: f.lastUsedAt,
          })
          .execute();
      },
      async findPending(id) {
        const r = await db
          .selectFrom("identkit_totp_factors")
          .selectAll()
          .where("id", "=", id)
          .where("activated_at", "is", null)
          .executeTakeFirst();
        return r ? toTotpFactor(r) : null;
      },
      async findActive(accountId) {
        const r = await db
          .selectFrom("identkit_totp_factors")
          .selectAll()
          .where("account_id", "=", accountId)
          .where("activated_at", "is not", null)
          .executeTakeFirst();
        return r ? toTotpFactor(r) : null;
      },
      async activate(id, accountId, step, at) {
        try {
          // The unique partial index on active factors refuses a second active factor.
          const row = await db
            .updateTable("identkit_totp_factors")
            .set({ activated_at: at, last_used_step: step, last_used_at: at })
            .where("id", "=", id)
            .where("account_id", "=", accountId)
            .where("activated_at", "is", null)
            .returning("id")
            .executeTakeFirst();
          return row !== undefined;
        } catch (error) {
          if (isUniqueViolation(error)) return false;
          throw error;
        }
      },
      async recordStep(id, accountId, step, at) {
        const row = await db
          .updateTable("identkit_totp_factors")
          .set({ last_used_step: step, last_used_at: at })
          .where("id", "=", id)
          .where("account_id", "=", accountId)
          .where("activated_at", "is not", null)
          .where((eb) => eb.or([eb("last_used_step", "is", null), eb("last_used_step", "<", step)]))
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async delete(id, accountId) {
        const row = await db
          .deleteFrom("identkit_totp_factors")
          .where("id", "=", id)
          .where("account_id", "=", accountId)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async deleteAllForAccount(accountId) {
        const rows = await db
          .deleteFrom("identkit_totp_factors")
          .where("account_id", "=", accountId)
          .returning("id")
          .execute();
        return rows.length;
      },
      async replaceSealedSecret(id, expected, next) {
        const row = await db
          .updateTable("identkit_totp_factors")
          .set({ sealed_secret: next })
          .where("id", "=", id)
          .where("sealed_secret", "=", expected)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
    },

    enrollment: {
      async insert(t) {
        await db
          .insertInto("identkit_enrollment_tokens")
          .values({
            token_digest: t.tokenDigest,
            account_id: t.accountId,
            created_at: t.createdAt,
            expires_at: t.expiresAt,
            consumed_at: t.consumedAt,
          })
          .execute();
      },
      async findByDigest(digest) {
        const r = await db
          .selectFrom("identkit_enrollment_tokens")
          .selectAll()
          .where("token_digest", "=", digest)
          .executeTakeFirst();
        return r
          ? {
              tokenDigest: r.token_digest,
              accountId: r.account_id,
              createdAt: r.created_at,
              expiresAt: r.expires_at,
              consumedAt: r.consumed_at,
            }
          : null;
      },
      async consume(digest, at) {
        const r = await db
          .updateTable("identkit_enrollment_tokens")
          .set({ consumed_at: at })
          .where("token_digest", "=", digest)
          .where("consumed_at", "is", null)
          .where("expires_at", ">", at)
          .returningAll()
          .executeTakeFirst();
        return r
          ? {
              tokenDigest: r.token_digest,
              accountId: r.account_id,
              createdAt: r.created_at,
              expiresAt: r.expires_at,
              consumedAt: r.consumed_at,
            }
          : null;
      },
    },

    verifications: {
      async insert(v) {
        await db
          .insertInto("identkit_verifications")
          .values({
            id: v.id,
            account_id: v.accountId,
            vendor_reference: v.vendorReference,
            status: v.status,
            assurance_level: v.assuranceLevel,
            evidence_reference: v.evidenceReference,
            failure_reason: v.failureReason,
            created_at: v.createdAt,
            expires_at: v.expiresAt,
            completed_at: v.completedAt,
          })
          .execute();
      },
      async findById(id) {
        const r = await db
          .selectFrom("identkit_verifications")
          .selectAll()
          .where("id", "=", id)
          .executeTakeFirst();
        return r ? toVerification(r) : null;
      },
      async findByVendorReference(reference) {
        const r = await db
          .selectFrom("identkit_verifications")
          .selectAll()
          .where("vendor_reference", "=", reference)
          .executeTakeFirst();
        return r ? toVerification(r) : null;
      },
      async setVendorReference(id, reference) {
        await db
          .updateTable("identkit_verifications")
          .set({ vendor_reference: reference })
          .where("id", "=", id)
          .execute();
      },
      async claim(id) {
        const row = await db
          .updateTable("identkit_verifications")
          .set({ status: "processing" })
          .where("id", "=", id)
          .where("status", "=", "pending")
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async finalize(id, u) {
        const row = await db
          .updateTable("identkit_verifications")
          .set({
            status: u.status,
            assurance_level: u.assuranceLevel,
            evidence_reference: u.evidenceReference,
            failure_reason: u.failureReason,
            completed_at: u.completedAt,
          })
          .where("id", "=", id)
          .where("status", "=", "processing")
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async complete(id, u) {
        const row = await db
          .updateTable("identkit_verifications")
          .set({
            status: u.status,
            assurance_level: u.assuranceLevel,
            evidence_reference: u.evidenceReference,
            failure_reason: u.failureReason,
            completed_at: u.completedAt,
          })
          .where("id", "=", id)
          .where("status", "=", "pending")
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
    },
  };
}
