import {
  sql,
  type ExpressionBuilder,
  type Kysely,
  type Selectable,
  type Transaction,
} from "kysely";
import { addSeconds } from "../clock.js";
import { knownAuthMethods } from "../storage/auth-methods.js";
import { applyThrottle } from "../storage/throttle-logic.js";
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
  OAuthImportTombstoneKind,
  OidcLinkRecord,
  OtpFlowRecord,
  SessionRecord,
  TotpFactorRecord,
  VerificationRecord,
} from "../storage/types.js";
import type { IdentkitDatabase } from "./schema.js";

type Row<T extends keyof IdentkitDatabase> = Selectable<IdentkitDatabase[T]>;

const UNIQUE_VIOLATION = "23505";
/** Ids per statement in `oauth.purge` and in a tombstone insert. */
const PURGE_CHUNK = 1000;
/** serialization_failure and deadlock_detected. */
const LOST_RACE = new Set(["40001", "40P01"]);

function sqlState(error: unknown): unknown {
  return typeof error === "object" && error !== null && "code" in error
    ? Reflect.get(error, "code")
    : undefined;
}

function isUniqueViolation(error: unknown): boolean {
  return sqlState(error) === UNIQUE_VIOLATION;
}

function isLostRace(error: unknown): boolean {
  const code = sqlState(error);
  return typeof code === "string" && LOST_RACE.has(code);
}

/**
 * Locks the client row FOR KEY SHARE inside a grant insert or import, right after the account
 * lock and before any grant row is touched. The foreign key check of the grant insert takes the
 * same lock, but only at the insert: by then a replacing insert holds the row lock of the grant it
 * deleted, and `deleteClient` (client FOR UPDATE, then the client's grants) could wait on it in
 * a cycle. Throws, as the foreign key would, if the client does not exist.
 */
async function lockClientForGrant(
  trx: Transaction<IdentkitDatabase>,
  clientId: string,
): Promise<void> {
  const client = await trx
    .selectFrom("identkit_oauth_clients")
    .select("id")
    .where("id", "=", clientId)
    .forKeyShare()
    .executeTakeFirst();
  if (!client) throw new Error("oauth grant references a missing client");
}

/** An expression builder over `identkit_oauth_clients as c`. */
type ClientsAsC = ExpressionBuilder<
  IdentkitDatabase & { c: IdentkitDatabase["identkit_oauth_clients"] },
  "c"
>;

/**
 * The purge rule for a client: past its date rule (never used and created before
 * `unusedBefore`, or last used before `idleBefore`), and holding no live grant and no live code.
 */
function purgeable(eb: ClientsAsC, b: { at: Date; unusedBefore: Date; idleBefore: Date }) {
  return eb.and([
    eb.or([
      eb.and([eb("c.last_used_at", "is", null), eb("c.created_at", "<", b.unusedBefore)]),
      eb.and([eb("c.last_used_at", "is not", null), eb("c.last_used_at", "<", b.idleBefore)]),
    ]),
    eb.not(
      eb.exists(
        eb
          .selectFrom("identkit_oauth_grants as g")
          .select("g.id")
          .whereRef("g.client_id", "=", "c.id")
          .where("g.expires_at", ">", b.at),
      ),
    ),
    eb.not(
      eb.exists(
        eb
          .selectFrom("identkit_oauth_codes as o")
          .select("o.digest")
          .whereRef("o.client_id", "=", "c.id")
          .where("o.expires_at", ">", b.at),
      ),
    ),
  ]);
}

/** Thrown inside a transaction to roll back an insert that a tombstone refuses. */
class RefusedByTombstone extends Error {}

/**
 * Writes the import tombstones of the deleted rows whose source is `import`, in the transaction
 * of their delete.
 */
async function writeTombstones(
  trx: Transaction<IdentkitDatabase>,
  kind: OAuthImportTombstoneKind,
  deleted: readonly { id: string; source: string }[],
  at: Date,
): Promise<void> {
  const ids = deleted.filter((row) => row.source === "import").map((row) => row.id);
  for (let i = 0; i < ids.length; i += PURGE_CHUNK) {
    await trx
      .insertInto("identkit_oauth_import_tombstones")
      .values(ids.slice(i, i + PURGE_CHUNK).map((id) => ({ kind, id, ended_at: at })))
      .onConflict((oc) => oc.columns(["kind", "id"]).doNothing())
      .execute();
  }
}

/**
 * True if a tombstone names the id. Called after the insert of the id, in its READ COMMITTED
 * transaction: a new statement, so it sees a tombstone that a concurrent delete of the same id
 * committed while the insert waited on that row.
 */
async function hasTombstone(
  trx: Transaction<IdentkitDatabase>,
  kind: OAuthImportTombstoneKind,
  id: string,
): Promise<boolean> {
  const row = await trx
    .selectFrom("identkit_oauth_import_tombstones")
    .select("id")
    .where("kind", "=", kind)
    .where("id", "=", id)
    .executeTakeFirst();
  return row !== undefined;
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
const OIDC_PROVIDERS = ["microsoft", "google", "oidc"] as const;
const OIDC_LINK_SOURCES = ["sign_in", "import"] as const;
const STEP_UP_METHODS = ["email_otp", "passkey", "totp"] as const;
const API_TOKEN_ALGORITHMS = ["hmac-sha256", "sha256"] as const;
const API_TOKEN_SOURCES = ["created", "import"] as const;
const OAUTH_ALGORITHMS = ["hmac-sha256", "sha256"] as const;
const OAUTH_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"] as const;
const OAUTH_CLIENT_SOURCES = ["dynamic", "import"] as const;
const OAUTH_GRANT_SOURCES = ["created", "import"] as const;
const ACCOUNT_STATUSES = ["active", "disabled"] as const;

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
  // Unknown methods, written by a later release, are dropped: fewer methods, never more rights.
  authMethods: knownAuthMethods(r.auth_methods),
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

const toEnrollmentToken = (r: Row<"identkit_enrollment_tokens">): EnrollmentTokenRecord => ({
  tokenDigest: r.token_digest,
  accountId: r.account_id,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  consumedAt: r.consumed_at,
  revokedAt: r.revoked_at,
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

const toOidcLink = (r: Row<"identkit_oidc_links">): OidcLinkRecord => ({
  id: r.id,
  accountId: r.account_id,
  linkKey: r.link_key,
  provider: oneOf(r.provider, OIDC_PROVIDERS),
  issuer: r.issuer,
  subject: r.subject,
  tenantId: r.tenant_id,
  source: oneOf(r.source, OIDC_LINK_SOURCES),
  createdAt: r.created_at,
});

const toApiToken = (r: Row<"identkit_api_tokens">): ApiTokenRecord => ({
  id: r.id,
  accountId: r.account_id,
  name: r.name,
  scopes: [...r.scopes],
  digest: r.digest,
  digestAlgorithm: oneOf(r.digest_algorithm, API_TOKEN_ALGORITHMS),
  source: oneOf(r.source, API_TOKEN_SOURCES),
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  lastUsedAt: r.last_used_at,
  revokedAt: r.revoked_at,
  revokeReason: r.revoke_reason,
});

const toOAuthClient = (r: Row<"identkit_oauth_clients">): OAuthClientRecord => ({
  id: r.id,
  secretDigest: r.secret_digest,
  secretDigestAlgorithm: oneOfOrNull(r.secret_digest_algorithm, OAUTH_ALGORITHMS),
  authMethod: oneOf(r.auth_method, OAUTH_AUTH_METHODS),
  grantTypes: [...r.grant_types],
  redirectUris: [...r.redirect_uris],
  name: r.name,
  source: oneOf(r.source, OAUTH_CLIENT_SOURCES),
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
});

const toOAuthGrant = (r: Row<"identkit_oauth_grants">): OAuthGrantRecord => ({
  id: r.id,
  accountId: r.account_id,
  clientId: r.client_id,
  scopes: [...r.scopes],
  resource: r.resource,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  generation: r.generation,
  refreshRefDigest: r.refresh_ref_digest,
  refreshDigest: r.refresh_digest,
  refreshDigestAlgorithm: oneOfOrNull(r.refresh_digest_algorithm, OAUTH_ALGORITHMS),
  previousRefreshDigest: r.previous_refresh_digest,
  refreshedAt: r.refreshed_at,
  refreshExpiresAt: r.refresh_expires_at,
  codeDigest: r.code_digest,
  source: oneOf(r.source, OAUTH_GRANT_SOURCES),
});

const toOAuthCode = (r: Row<"identkit_oauth_codes">): OAuthCodeRecord => ({
  digest: r.digest,
  clientId: r.client_id,
  accountId: r.account_id,
  redirectUri: r.redirect_uri,
  redirectUriExplicit: r.redirect_uri_explicit,
  codeChallenge: r.code_challenge,
  resource: r.resource,
  scopes: [...r.scopes],
  createdAt: r.created_at,
  expiresAt: r.expires_at,
});

const oauthGrantRow = (g: OAuthGrantRecord) => ({
  id: g.id,
  account_id: g.accountId,
  client_id: g.clientId,
  scopes: g.scopes,
  resource: g.resource,
  created_at: g.createdAt,
  expires_at: g.expiresAt,
  generation: g.generation,
  refresh_ref_digest: g.refreshRefDigest,
  refresh_digest: g.refreshDigest,
  refresh_digest_algorithm: g.refreshDigestAlgorithm,
  previous_refresh_digest: g.previousRefreshDigest,
  refreshed_at: g.refreshedAt,
  refresh_expires_at: g.refreshExpiresAt,
  code_digest: g.codeDigest,
  source: g.source,
});

const oauthAccessTokenRow = (t: OAuthAccessTokenRecord) => ({
  digest: t.digest,
  grant_id: t.grantId,
  generation: t.generation,
  scopes: t.scopes,
  created_at: t.createdAt,
  expires_at: t.expiresAt,
});

/**
 * PostgreSQL store. Pass a Kysely instance with a PostgreSQL dialect; apply the migrations
 * first (`migrateIdentkit` or the files in `migrations/`). Each guarded method is one
 * conditional statement or one transaction with a row lock.
 */
/**
 * Deletes the client with its grants and codes, and returns the grants, or null. Imported grants
 * get their tombstones. The client gets one too, unless this rolls back its import (`rollBack`):
 * then it matches only an imported client and writes no tombstone for it.
 */
async function endClient(
  db: Kysely<IdentkitDatabase>,
  id: string,
  at: Date,
  rollBack: boolean,
): Promise<OAuthGrantRecord[] | null> {
  return db
    .transaction()
    .setIsolationLevel("read committed")
    .execute(async (trx) => {
      // The row lock first: a concurrent grant insert or import takes a key share lock on the
      // client before it touches any grant row, so it waits here, then fails on the deleted
      // client. Without this lock, the client delete could cascade a grant committed after the
      // grant delete below. Both sides lock the client before any grant row, so they never wait
      // on each other in a cycle (a replacing insert holds the row lock of the grant it deletes).
      let lock = trx
        .selectFrom("identkit_oauth_clients")
        .select(["id", "source"])
        .where("id", "=", id);
      if (rollBack) lock = lock.where("source", "=", "import");
      const client = await lock.forUpdate().executeTakeFirst();
      if (!client) return null;
      const grants = await trx
        .deleteFrom("identkit_oauth_grants")
        .where("client_id", "=", id)
        .returningAll()
        .execute();
      // The foreign keys remove the grants' access tokens and the client's codes.
      await trx.deleteFrom("identkit_oauth_clients").where("id", "=", id).execute();
      await writeTombstones(trx, "grant", grants, at);
      if (!rollBack) await writeTombstones(trx, "client", [client], at);
      return grants.map(toOAuthGrant);
    });
}

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
          // also when a concurrent reset deleted it in between. The read, the decision and the
          // write below all run under that lock, so parallel attempts count one after another.
          const row = await trx
            .insertInto("identkit_throttles")
            .values({
              key,
              window_start: at,
              attempts: 0,
              locked_until: null,
              lock_count: 0,
              consecutive_failures: 0,
            })
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
              consecutiveFailures: row.consecutive_failures,
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
              consecutive_failures: next.consecutiveFailures,
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
      async issue(t) {
        await db.transaction().execute(async (trx) => {
          // The account row lock serializes concurrent issues, so at most one token stays.
          await trx
            .selectFrom("identkit_accounts")
            .select("id")
            .where("id", "=", t.accountId)
            .forUpdate()
            .executeTakeFirst();
          await trx
            .updateTable("identkit_enrollment_tokens")
            .set({ revoked_at: t.createdAt })
            .where("account_id", "=", t.accountId)
            .where("revoked_at", "is", null)
            .execute();
          await trx
            .insertInto("identkit_enrollment_tokens")
            .values({
              token_digest: t.tokenDigest,
              account_id: t.accountId,
              created_at: t.createdAt,
              expires_at: t.expiresAt,
              consumed_at: t.consumedAt,
              revoked_at: t.revokedAt,
            })
            .execute();
        });
      },
      async findByDigest(digest) {
        const r = await db
          .selectFrom("identkit_enrollment_tokens")
          .selectAll()
          .where("token_digest", "=", digest)
          .executeTakeFirst();
        return r ? toEnrollmentToken(r) : null;
      },
      async consume(digest, at) {
        const r = await db
          .updateTable("identkit_enrollment_tokens")
          .set({ consumed_at: at })
          .where("token_digest", "=", digest)
          .where("consumed_at", "is", null)
          .where("revoked_at", "is", null)
          .where("expires_at", ">", at)
          .returningAll()
          .executeTakeFirst();
        return r ? toEnrollmentToken(r) : null;
      },
      async revokeAllForAccount(accountId, at) {
        return db.transaction().execute(async (trx) => {
          // The same lock as `issue`: a revocation and an issue run one after the other.
          await trx
            .selectFrom("identkit_accounts")
            .select("id")
            .where("id", "=", accountId)
            .forUpdate()
            .executeTakeFirst();
          const rows = await trx
            .updateTable("identkit_enrollment_tokens")
            .set({ revoked_at: at })
            .where("account_id", "=", accountId)
            .where("revoked_at", "is", null)
            .returning("token_digest")
            .execute();
          return rows.length;
        });
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
    oidcLinks: {
      async insert(link, options) {
        // READ COMMITTED whatever the database default: each statement after the account row
        // lock then sees a link that the transaction holding the lock before committed. Under
        // REPEATABLE READ the snapshot would date from before that commit, and two exclusive
        // inserts for one account could both pass the check below.
        return db
          .transaction()
          .setIsolationLevel("read committed")
          .execute(async (trx) => {
            // The account row lock serializes exclusive inserts for one account, so at most one
            // link stays. The unique link key refuses a subject that is linked already.
            await trx
              .selectFrom("identkit_accounts")
              .select("id")
              .where("id", "=", link.accountId)
              .forUpdate()
              .executeTakeFirst();
            const taken = await trx
              .selectFrom("identkit_oidc_links")
              .select("id")
              .where("link_key", "=", link.linkKey)
              .executeTakeFirst();
            if (taken) return "link_taken";
            if (options.exclusive) {
              const existing = await trx
                .selectFrom("identkit_oidc_links")
                .select("id")
                .where("account_id", "=", link.accountId)
                .executeTakeFirst();
              if (existing) return "account_has_link";
            }
            const row = await trx
              .insertInto("identkit_oidc_links")
              .values({
                id: link.id,
                account_id: link.accountId,
                link_key: link.linkKey,
                provider: link.provider,
                issuer: link.issuer,
                subject: link.subject,
                tenant_id: link.tenantId,
                source: link.source,
                created_at: link.createdAt,
              })
              .onConflict((oc) => oc.column("link_key").doNothing())
              .returning("id")
              .executeTakeFirst();
            return row ? "inserted" : "link_taken";
          });
      },
      async findByKey(linkKey) {
        const r = await db
          .selectFrom("identkit_oidc_links")
          .selectAll()
          .where("link_key", "=", linkKey)
          .executeTakeFirst();
        return r ? toOidcLink(r) : null;
      },
      async listByAccount(accountId) {
        const rows = await db
          .selectFrom("identkit_oidc_links")
          .selectAll()
          .where("account_id", "=", accountId)
          .orderBy("created_at")
          .orderBy("id")
          .execute();
        return rows.map(toOidcLink);
      },
      async delete(id, accountId) {
        const row = await db
          .deleteFrom("identkit_oidc_links")
          .where("id", "=", id)
          .where("account_id", "=", accountId)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
    },
    apiTokens: {
      async insert(t, limit) {
        // READ COMMITTED whatever the database default, for the reason given at `oidcLinks`:
        // the count after the account row lock must see the tokens that the transaction holding
        // the lock before committed.
        return db
          .transaction()
          .setIsolationLevel("read committed")
          .execute(async (trx) => {
            // The account row lock serializes inserts for one account, so the count and the
            // insert below cannot interleave with another insert's. FOR NO KEY UPDATE conflicts
            // with itself, so it serializes token inserts as FOR UPDATE would, but not with the
            // FOR KEY SHARE locks of foreign key checks, so inserts of sessions for the same
            // account do not wait for it.
            await trx
              .selectFrom("identkit_accounts")
              .select("id")
              .where("id", "=", t.accountId)
              .forNoKeyUpdate()
              .executeTakeFirst();
            const taken = await trx
              .selectFrom("identkit_api_tokens")
              .select("id")
              .where("digest", "=", t.digest)
              .executeTakeFirst();
            if (taken) return "digest_taken";
            const { active } = await trx
              .selectFrom("identkit_api_tokens")
              .select((eb) => eb.fn.countAll<string>().as("active"))
              .where("account_id", "=", t.accountId)
              .where("revoked_at", "is", null)
              .where("expires_at", ">", limit.at)
              .executeTakeFirstOrThrow();
            if (Number(active) >= limit.maxActive) return "limit_reached";
            const row = await trx
              .insertInto("identkit_api_tokens")
              .values({
                id: t.id,
                account_id: t.accountId,
                name: t.name,
                scopes: t.scopes,
                digest: t.digest,
                digest_algorithm: t.digestAlgorithm,
                source: t.source,
                created_at: t.createdAt,
                expires_at: t.expiresAt,
                last_used_at: t.lastUsedAt,
                revoked_at: t.revokedAt,
                revoke_reason: t.revokeReason,
              })
              .onConflict((oc) => oc.column("digest").doNothing())
              .returning("id")
              .executeTakeFirst();
            return row ? "inserted" : "digest_taken";
          });
      },
      async findByDigests(digests) {
        if (digests.length === 0) return [];
        // One query: the token and the status of its account.
        const rows = await db
          .selectFrom("identkit_api_tokens as t")
          .innerJoin("identkit_accounts as a", "a.id", "t.account_id")
          .selectAll("t")
          .select("a.status as account_status")
          .where("t.digest", "in", [...digests])
          .execute();
        return rows.map((r) => ({
          record: toApiToken(r),
          accountStatus: oneOf(r.account_status, ["active", "disabled"]),
        }));
      },
      async listByAccount(accountId) {
        const rows = await db
          .selectFrom("identkit_api_tokens")
          .selectAll()
          .where("account_id", "=", accountId)
          .where("revoked_at", "is", null)
          .orderBy("created_at")
          .orderBy("id")
          .execute();
        return rows.map(toApiToken);
      },
      async markUsed(id, at, notAfter) {
        try {
          const row = await db
            .updateTable("identkit_api_tokens")
            .set({ last_used_at: at })
            .where("id", "=", id)
            .where("revoked_at", "is", null)
            .where((eb) =>
              eb.or([eb("last_used_at", "is", null), eb("last_used_at", "<=", notAfter)]),
            )
            .returning("id")
            .executeTakeFirst();
          return row !== undefined;
        } catch (error) {
          // Under REPEATABLE READ or SERIALIZABLE, a concurrent verify that wrote first makes
          // this UPDATE fail instead of match no row. Losing that race is the intended outcome:
          // no write and no event, and the request still succeeds.
          if (isLostRace(error)) return false;
          throw error;
        }
      },
      async revoke(id, accountId, at, reason) {
        const row = await db
          .updateTable("identkit_api_tokens")
          .set({ revoked_at: at, revoke_reason: reason })
          .where("id", "=", id)
          .where("account_id", "=", accountId)
          .where("revoked_at", "is", null)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async revokeAllForAccount(accountId, at, reason) {
        const rows = await db
          .updateTable("identkit_api_tokens")
          .set({ revoked_at: at, revoke_reason: reason })
          .where("account_id", "=", accountId)
          .where("revoked_at", "is", null)
          .returning("id")
          .execute();
        return rows.map((r) => r.id);
      },
      async delete(id, accountId) {
        const row = await db
          .deleteFrom("identkit_api_tokens")
          .where("id", "=", id)
          .where("account_id", "=", accountId)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
    },
    oauth: {
      async insertClient(c) {
        try {
          // The primary key makes a second insert of an id a no-op. Then the tombstone, in the
          // same transaction (see `hasTombstone`): a refused insert is rolled back.
          return await db
            .transaction()
            .setIsolationLevel("read committed")
            .execute(async (trx) => {
              const row = await trx
                .insertInto("identkit_oauth_clients")
                .values({
                  id: c.id,
                  secret_digest: c.secretDigest,
                  secret_digest_algorithm: c.secretDigestAlgorithm,
                  auth_method: c.authMethod,
                  grant_types: c.grantTypes,
                  redirect_uris: c.redirectUris,
                  name: c.name,
                  source: c.source,
                  created_at: c.createdAt,
                  last_used_at: c.lastUsedAt,
                })
                .onConflict((oc) => oc.column("id").doNothing())
                .returning("id")
                .executeTakeFirst();
              if (!row) return "id_taken" as const;
              if (await hasTombstone(trx, "client", c.id)) throw new RefusedByTombstone();
              return "inserted" as const;
            });
        } catch (error) {
          if (error instanceof RefusedByTombstone) return "revoked";
          throw error;
        }
      },
      async findClient(id) {
        const r = await db
          .selectFrom("identkit_oauth_clients")
          .selectAll()
          .where("id", "=", id)
          .executeTakeFirst();
        return r ? toOAuthClient(r) : null;
      },
      async markClientUsed(id, at, notAfter) {
        try {
          // Atomic: one UPDATE that matches only while the last use is old enough.
          const row = await db
            .updateTable("identkit_oauth_clients")
            .set({ last_used_at: at })
            .where("id", "=", id)
            .where((eb) =>
              eb.or([eb("last_used_at", "is", null), eb("last_used_at", "<=", notAfter)]),
            )
            .returning("id")
            .executeTakeFirst();
          return row !== undefined;
        } catch (error) {
          // A concurrent write under REPEATABLE READ: that call wrote, so this one need not.
          if (isLostRace(error)) return false;
          throw error;
        }
      },
      async upgradeClientSecret(id, oldDigest, newDigest) {
        // Atomic: compare-and-set in one UPDATE on the expected digest.
        const row = await db
          .updateTable("identkit_oauth_clients")
          .set({ secret_digest: newDigest, secret_digest_algorithm: "hmac-sha256" })
          .where("id", "=", id)
          .where("secret_digest", "=", oldDigest)
          .returning("id")
          .executeTakeFirst();
        return row !== undefined;
      },
      async deleteClient(id, at) {
        return endClient(db, id, at, false);
      },
      async reserveRegistration({ keys, windowStart }) {
        // One upsert per key, in order. Each is atomic: the row lock of ON CONFLICT DO UPDATE
        // makes the WHERE see the count of the call before, so the count never passes max.
        for (const { key, max } of keys) {
          const { rows } = await sql<{ count: number }>`
            INSERT INTO identkit_oauth_registration_counts AS c (key, window_start, count)
            VALUES (${key}, ${windowStart}, 1)
            ON CONFLICT (key, window_start)
            DO UPDATE SET count = c.count + 1 WHERE c.count < ${max}
            RETURNING c.count`.execute(db);
          if (rows.length === 0) return { limitReached: key };
        }
        return "reserved";
      },
      async insertCode(code) {
        await db
          .insertInto("identkit_oauth_codes")
          .values({
            digest: code.digest,
            client_id: code.clientId,
            account_id: code.accountId,
            redirect_uri: code.redirectUri,
            redirect_uri_explicit: code.redirectUriExplicit,
            code_challenge: code.codeChallenge,
            resource: code.resource,
            scopes: code.scopes,
            created_at: code.createdAt,
            expires_at: code.expiresAt,
          })
          .execute();
      },
      async consumeCode(digest) {
        // Atomic: one DELETE ... RETURNING. Only the call that deletes the row gets it.
        const r = await db
          .deleteFrom("identkit_oauth_codes")
          .where("digest", "=", digest)
          .returningAll()
          .executeTakeFirst();
        return r ? toOAuthCode(r) : null;
      },
      async endGrantByCode(codeDigest, at) {
        // Atomic: one DELETE ... RETURNING, and the tombstone in the same transaction.
        return db
          .transaction()
          .setIsolationLevel("read committed")
          .execute(async (trx) => {
            const r = await trx
              .deleteFrom("identkit_oauth_grants")
              .where("code_digest", "=", codeDigest)
              .returningAll()
              .executeTakeFirst();
            if (!r) return null;
            await writeTombstones(trx, "grant", [r], at);
            return toOAuthGrant(r);
          });
      },
      async insertGrant(grant, firstAccessToken, limit) {
        // READ COMMITTED whatever the database default, for the reason given at `oidcLinks`.
        return db
          .transaction()
          .setIsolationLevel("read committed")
          .execute(async (trx) => {
            // The account row lock serializes grant inserts and imports for one account, so
            // the count and the insert cannot interleave with another one's. FOR NO KEY UPDATE,
            // as at `apiTokens.insert`, so foreign key checks of other rows do not wait. Then
            // the client row, before any grant row (see `lockClientForGrant`).
            const account = await trx
              .selectFrom("identkit_accounts")
              .select("status")
              .where("id", "=", grant.accountId)
              .forNoKeyUpdate()
              .executeTakeFirst();
            if (!account || account.status !== "active") {
              return { status: "account_inactive" } as const;
            }
            await lockClientForGrant(trx, grant.clientId);
            const { live } = await trx
              .selectFrom("identkit_oauth_grants")
              .select((eb) => eb.fn.countAll<string>().as("live"))
              .where("account_id", "=", grant.accountId)
              .where("client_id", "<>", grant.clientId)
              .where("expires_at", ">", limit.at)
              .executeTakeFirstOrThrow();
            if (Number(live) >= limit.maxOtherGrants) return { status: "limit_reached" } as const;
            const replaced = await trx
              .deleteFrom("identkit_oauth_grants")
              .where("account_id", "=", grant.accountId)
              .where("client_id", "=", grant.clientId)
              .returningAll()
              .executeTakeFirst();
            if (replaced) await writeTombstones(trx, "grant", [replaced], limit.at);
            await trx.insertInto("identkit_oauth_grants").values(oauthGrantRow(grant)).execute();
            await trx
              .insertInto("identkit_oauth_access_tokens")
              .values(oauthAccessTokenRow(firstAccessToken))
              .execute();
            return {
              status: "inserted",
              replaced: replaced ? toOAuthGrant(replaced) : null,
            } as const;
          });
      },
      async importGrant(grant, limit) {
        try {
          return await db
            .transaction()
            .setIsolationLevel("read committed")
            .execute(async (trx) => {
              // The same account and client row locks as `insertGrant`.
              const account = await trx
                .selectFrom("identkit_accounts")
                .select("status")
                .where("id", "=", grant.accountId)
                .forNoKeyUpdate()
                .executeTakeFirst();
              if (account) await lockClientForGrant(trx, grant.clientId);
              const sameId = await trx
                .selectFrom("identkit_oauth_grants")
                .select("id")
                .where("id", "=", grant.id)
                .executeTakeFirst();
              if (sameId) return "id_taken";
              if (!account || account.status !== "active") return "account_inactive";
              const taken = await trx
                .selectFrom("identkit_oauth_grants")
                .select("id")
                .where("account_id", "=", grant.accountId)
                .where("client_id", "=", grant.clientId)
                .executeTakeFirst();
              if (taken) return "account_client_taken";
              const { live } = await trx
                .selectFrom("identkit_oauth_grants")
                .select((eb) => eb.fn.countAll<string>().as("live"))
                .where("account_id", "=", grant.accountId)
                .where("client_id", "<>", grant.clientId)
                .where("expires_at", ">", limit.at)
                .executeTakeFirstOrThrow();
              if (Number(live) >= limit.maxOtherGrants) return "limit_reached";
              const row = await trx
                .insertInto("identkit_oauth_grants")
                .values(oauthGrantRow(grant))
                .onConflict((oc) => oc.column("id").doNothing())
                .returning("id")
                .executeTakeFirst();
              if (!row) return "id_taken";
              // After the insert, in the same transaction (see `hasTombstone`).
              if (await hasTombstone(trx, "grant", grant.id)) throw new RefusedByTombstone();
              return "inserted";
            });
        } catch (error) {
          if (error instanceof RefusedByTombstone) return "revoked";
          throw error;
        }
      },
      async findGrantByRefreshRef(refDigest) {
        // One query: the grant and the status of its account.
        const r = await db
          .selectFrom("identkit_oauth_grants as g")
          .innerJoin("identkit_accounts as a", "a.id", "g.account_id")
          .selectAll("g")
          .select("a.status as account_status")
          .where("g.refresh_ref_digest", "=", refDigest)
          .executeTakeFirst();
        return r
          ? { grant: toOAuthGrant(r), accountStatus: oneOf(r.account_status, ACCOUNT_STATUSES) }
          : null;
      },
      async findGrant(id) {
        const r = await db
          .selectFrom("identkit_oauth_grants as g")
          .innerJoin("identkit_accounts as a", "a.id", "g.account_id")
          .selectAll("g")
          .select("a.status as account_status")
          .where("g.id", "=", id)
          .executeTakeFirst();
        return r
          ? { grant: toOAuthGrant(r), accountStatus: oneOf(r.account_status, ACCOUNT_STATUSES) }
          : null;
      },
      async rotateGrant(id, expectedGeneration, u, accessToken, pruneBefore) {
        try {
          return await db
            .transaction()
            .setIsolationLevel("read committed")
            .execute(async (trx) => {
              // Compare-and-set on the generation. Under READ COMMITTED a concurrent rotation
              // that committed first makes this UPDATE match no row after its wait.
              const row = await trx
                .updateTable("identkit_oauth_grants")
                .set({
                  generation: u.generation,
                  refresh_ref_digest: u.refreshRefDigest,
                  refresh_digest: u.refreshDigest,
                  refresh_digest_algorithm: u.refreshDigestAlgorithm,
                  previous_refresh_digest: u.previousRefreshDigest,
                  refreshed_at: u.refreshedAt,
                  refresh_expires_at: u.refreshExpiresAt,
                })
                .where("id", "=", id)
                .where("generation", "=", expectedGeneration)
                .returning("id")
                .executeTakeFirst();
              if (!row) return false;
              await trx
                .insertInto("identkit_oauth_access_tokens")
                .values(oauthAccessTokenRow(accessToken))
                .execute();
              await trx
                .deleteFrom("identkit_oauth_access_tokens")
                .where("grant_id", "=", id)
                .where("expires_at", "<=", pruneBefore)
                .execute();
              return true;
            });
        } catch (error) {
          // A serialization failure means a concurrent rotation won.
          if (isLostRace(error)) return false;
          throw error;
        }
      },
      async findAccessToken(digest) {
        // One query: the token, its grant and the status of the grant's account.
        const r = await db
          .selectFrom("identkit_oauth_access_tokens as t")
          .innerJoin("identkit_oauth_grants as g", "g.id", "t.grant_id")
          .innerJoin("identkit_accounts as a", "a.id", "g.account_id")
          .selectAll("g")
          .select([
            "t.digest as token_digest",
            "t.generation as token_generation",
            "t.scopes as token_scopes",
            "t.created_at as token_created_at",
            "t.expires_at as token_expires_at",
            "a.status as account_status",
          ])
          .where("t.digest", "=", digest)
          .executeTakeFirst();
        if (!r) return null;
        return {
          token: {
            digest: r.token_digest,
            grantId: r.id,
            generation: r.token_generation,
            scopes: [...r.token_scopes],
            createdAt: r.token_created_at,
            expiresAt: r.token_expires_at,
          },
          grant: toOAuthGrant(r),
          accountStatus: oneOf(r.account_status, ACCOUNT_STATUSES),
        };
      },
      async deleteGrant(id, match, at) {
        // Atomic: one DELETE ... RETURNING, scoped to the client or the account, and the
        // tombstone in the same transaction.
        return db
          .transaction()
          .setIsolationLevel("read committed")
          .execute(async (trx) => {
            let query = trx.deleteFrom("identkit_oauth_grants").where("id", "=", id);
            query =
              "clientId" in match
                ? query.where("client_id", "=", match.clientId)
                : query.where("account_id", "=", match.accountId);
            const r = await query.returningAll().executeTakeFirst();
            if (!r) return null;
            await writeTombstones(trx, "grant", [r], at);
            return toOAuthGrant(r);
          });
      },
      async deleteGrantsForAccount(accountId, at) {
        // One transaction: if the code delete failed after a committed grant delete, the ended
        // grants would never be returned, and a retry would find none to record.
        return db
          .transaction()
          .setIsolationLevel("read committed")
          .execute(async (trx) => {
            const rows = await trx
              .deleteFrom("identkit_oauth_grants")
              .where("account_id", "=", accountId)
              .returningAll()
              .execute();
            await trx
              .deleteFrom("identkit_oauth_codes")
              .where("account_id", "=", accountId)
              .execute();
            await writeTombstones(trx, "grant", rows, at);
            return rows.map(toOAuthGrant);
          });
      },
      async listGrants(accountId, at) {
        const rows = await db
          .selectFrom("identkit_oauth_grants")
          .selectAll()
          .where("account_id", "=", accountId)
          .where("expires_at", ">", at)
          .orderBy("created_at")
          .orderBy("id")
          .execute();
        return rows.map(toOAuthGrant);
      },
      async purge({ at, unusedBefore, idleBefore, windowBefore }) {
        // The expired grants with their tombstones in one transaction. The other expired rows
        // each on their own: they need no shared invariant, and each statement is idempotent.
        const grants = await db
          .transaction()
          .setIsolationLevel("read committed")
          .execute(async (trx) => {
            const rows = await trx
              .deleteFrom("identkit_oauth_grants")
              .where("expires_at", "<=", at)
              .returningAll()
              .execute();
            await writeTombstones(trx, "grant", rows, at);
            return rows;
          });
        const codes = await db
          .deleteFrom("identkit_oauth_codes")
          .where("expires_at", "<=", at)
          .executeTakeFirst();
        const tokens = await db
          .deleteFrom("identkit_oauth_access_tokens")
          .where("expires_at", "<=", at)
          .executeTakeFirst();
        // The clients in one READ COMMITTED transaction. First the candidates FOR UPDATE: only
        // clients past their date rule (never used and old, or used long ago) that hold no live
        // grant and no live code, in id order. So a busy client is never locked, and two
        // overlapping purges lock in the same order and never wait on each other in a cycle.
        // A grant insert or import holds a key share lock on its client until it commits, so
        // this waits for it, and one that starts later waits here and then fails on the deleted
        // client. The delete is a second statement, so its snapshot sees every grant committed
        // during the wait, and its NOT EXISTS keeps that client. A single DELETE would not: after
        // its wait it re-checks only the client row, which the grant insert did not change. A
        // grant that the client delete cascades is past its expiry (no live grant is left), so
        // it gets no tombstone; its import answers `expired` anyway.
        const deleted = await db
          .transaction()
          .setIsolationLevel("read committed")
          .execute(async (trx) => {
            const candidates = await trx
              .selectFrom("identkit_oauth_clients as c")
              .select("c.id")
              .where((eb) => purgeable(eb, { at, unusedBefore, idleBefore }))
              .forUpdate()
              .execute();
            const removed: { id: string; reason: "unused" | "idle" }[] = [];
            // In chunks, to stay far below the parameter limit of one statement.
            for (let i = 0; i < candidates.length; i += PURGE_CHUNK) {
              const rows = await trx
                .deleteFrom("identkit_oauth_clients as c")
                .where(
                  "c.id",
                  "in",
                  candidates.slice(i, i + PURGE_CHUNK).map((r) => r.id),
                )
                .where((eb) => purgeable(eb, { at, unusedBefore, idleBefore }))
                .returning(["c.id", "c.source", "c.last_used_at"])
                .execute();
              await writeTombstones(trx, "client", rows, at);
              for (const row of rows) {
                removed.push({ id: row.id, reason: row.last_used_at === null ? "unused" : "idle" });
              }
            }
            return removed;
          });
        const windows = await db
          .deleteFrom("identkit_oauth_registration_counts")
          .where("window_start", "<", windowBefore)
          .executeTakeFirst();
        return {
          clients: deleted,
          grants: grants.map(toOAuthGrant),
          codes: Number(codes.numDeletedRows),
          accessTokens: Number(tokens.numDeletedRows),
          registrationWindows: Number(windows.numDeletedRows),
        };
      },
      async findImportTombstone(kind, id) {
        const row = await db
          .selectFrom("identkit_oauth_import_tombstones")
          .select("ended_at")
          .where("kind", "=", kind)
          .where("id", "=", id)
          .executeTakeFirst();
        return row ? row.ended_at : null;
      },
      async rollBackImport(kind, id, at) {
        // A client goes as in `deleteClient`, with the same lock order, and only its grants
        // get tombstones. A grant goes in one DELETE, without a tombstone.
        if (kind === "client") return endClient(db, id, at, true);
        const row = await db
          .deleteFrom("identkit_oauth_grants")
          .where("id", "=", id)
          .where("source", "=", "import")
          .returning("id")
          .executeTakeFirst();
        return row === undefined ? null : [];
      },
    },
  };
}
