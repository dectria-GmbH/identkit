import { addSeconds } from "../clock.js";
import { knownAuthMethods } from "../storage/auth-methods.js";
import { applyThrottle, type ThrottleState } from "../storage/throttle-logic.js";
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
  OidcLinkRecord,
  OtpFlowRecord,
  SessionRecord,
  TotpFactorRecord,
  VerificationRecord,
} from "../storage/types.js";
import type { D1DatabaseLike } from "./types.js";

export interface D1StoreOptions {
  /**
   * How often `throttle.reserve` reads the state again after a concurrent call changed it
   * first. Each round, one of the competing calls wins, so this bounds the wait under load.
   * When the rounds run out, `reserve` throws and the attempt does not pass. Each round is at
   * most two D1 queries, so one `reserve` makes at most `2 * throttleRetries` queries. The
   * default keeps that within the D1 limit of 50 queries per Worker invocation on the Workers
   * Free plan, with room for the other queries of the call. Default 16.
   */
  throttleRetries?: number;
  /**
   * Set this only if `db` is a D1 session that you started with
   * `env.DB.withSession("first-primary")` in the same request. Without it, `createD1Store`
   * refuses a D1 session (an object with `getBookmark`). Only the first query of such a session
   * goes to the primary; later queries can go to a read replica that is as recent as that first
   * query. So start a new session and a new store in each request (each Worker invocation), and
   * never keep either at module scope or reuse it in a later request: a reused session can read
   * a replica that has not seen a revoked session, a disabled account or a new lock. A session
   * with another constraint can read such a replica at once. The plain binding (`env.DB`) reads
   * only from the primary and needs no option.
   */
  sessionConstraint?: "first-primary";
}

/** The default of `D1StoreOptions.throttleRetries`. */
export const D1_DEFAULT_THROTTLE_RETRIES = 16;

/** `throttle.reserve` lost the race for a key more often than `throttleRetries` allows. */
export class D1ThrottleContentionError extends Error {
  constructor(rounds: number) {
    super(`throttle state changed concurrently in each of ${rounds} rounds`);
    this.name = "D1ThrottleContentionError";
  }
}

type Row = Record<string, unknown>;

function isUniqueViolation(error: unknown): boolean {
  for (let e: unknown = error; e instanceof Error; e = e.cause) {
    if (e.message.includes("UNIQUE constraint failed")) return true;
  }
  return false;
}

function oneOf<const T extends string>(value: unknown, allowed: readonly T[]): T {
  const found = allowed.find((candidate) => candidate === value);
  if (found === undefined) throw new Error(`unexpected value in database: ${String(value)}`);
  return found;
}

function oneOfOrNull<const T extends string>(value: unknown, allowed: readonly T[]): T | null {
  return value === null ? null : oneOf(value, allowed);
}

function text(value: unknown): string {
  if (typeof value !== "string") throw new Error("unexpected value in database: not text");
  return value;
}

function textOrNull(value: unknown): string | null {
  return value === null ? null : text(value);
}

function integer(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error("unexpected value in database: not an integer");
  }
  return value;
}

function integerOrNull(value: unknown): number | null {
  return value === null ? null : integer(value);
}

/** Times are stored as integer milliseconds since the epoch, so SQLite compares numbers. */
// An invalid Date has no time. D1 would bind it as NULL, so for example `revoked_at` would stay
// NULL and the session stay live. PostgreSQL refuses an invalid Date, and so does this store.
function ms(date: Date): number {
  const time = date.getTime();
  if (!Number.isFinite(time)) throw new RangeError("invalid date: the time is not finite");
  return time;
}
const msOrNull = (date: Date | null): number | null => (date === null ? null : ms(date));
const date = (value: unknown): Date => new Date(integer(value));
const dateOrNull = (value: unknown): Date | null => (value === null ? null : date(value));

function stringList(value: unknown): string[] {
  const parsed: unknown = JSON.parse(text(value));
  if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string")) {
    throw new Error("unexpected value in database: not a list of strings");
  }
  return parsed;
}

/** D1 binds an ArrayBuffer as a BLOB. A copy holds exactly the bytes of the view. */
const blob = (bytes: Uint8Array): ArrayBuffer => new Uint8Array(bytes).buffer;

/** D1 returns a BLOB as an array of numbers; other drivers may return a buffer. */
function bytesFrom(value: unknown): Uint8Array {
  if (Array.isArray(value)) return Uint8Array.from(value.map(integer));
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(
      value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
    );
  }
  throw new Error("unexpected value in database: not a blob");
}

const LEVELS = ["low", "substantial", "high"] as const;
const OIDC_PROVIDERS = ["microsoft", "google", "oidc"] as const;
const OIDC_LINK_SOURCES = ["sign_in", "import"] as const;
const STEP_UP_METHODS = ["email_otp", "passkey", "totp"] as const;
const API_TOKEN_ALGORITHMS = ["hmac-sha256", "sha256"] as const;
const API_TOKEN_SOURCES = ["created", "import"] as const;
const CHALLENGE_PURPOSES = [
  "registration",
  "sign_in",
  "second_factor",
  "step_up",
  "approval",
  "approval_code",
] as const;
const VERIFICATION_STATUSES = [
  "pending",
  "processing",
  "verified",
  "failed",
  "expired",
  "conflict",
] as const;

const toOidcLink = (r: Row): OidcLinkRecord => ({
  id: text(r["id"]),
  accountId: text(r["account_id"]),
  linkKey: text(r["link_key"]),
  provider: oneOf(r["provider"], OIDC_PROVIDERS),
  issuer: text(r["issuer"]),
  subject: text(r["subject"]),
  tenantId: textOrNull(r["tenant_id"]),
  source: oneOf(r["source"], OIDC_LINK_SOURCES),
  createdAt: date(r["created_at"]),
});

const toApiToken = (r: Row): ApiTokenRecord => ({
  id: text(r["id"]),
  accountId: text(r["account_id"]),
  name: text(r["name"]),
  scopes: stringList(r["scopes"]),
  digest: text(r["digest"]),
  digestAlgorithm: oneOf(r["digest_algorithm"], API_TOKEN_ALGORITHMS),
  source: oneOf(r["source"], API_TOKEN_SOURCES),
  createdAt: date(r["created_at"]),
  expiresAt: date(r["expires_at"]),
  lastUsedAt: dateOrNull(r["last_used_at"]),
  revokedAt: dateOrNull(r["revoked_at"]),
  revokeReason: textOrNull(r["revoke_reason"]),
});

const API_TOKEN_COLUMNS =
  "id, account_id, name, scopes, digest, digest_algorithm, source, created_at, expires_at, " +
  "last_used_at, revoked_at, revoke_reason";

const OAUTH_ALGORITHMS = ["hmac-sha256", "sha256"] as const;
const OAUTH_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"] as const;
const OAUTH_CLIENT_SOURCES = ["dynamic", "import"] as const;
const OAUTH_GRANT_SOURCES = ["created", "import"] as const;
const ACCOUNT_STATUSES = ["active", "disabled"] as const;

const OAUTH_CLIENT_COLUMNS =
  "id, secret_digest, secret_digest_algorithm, auth_method, grant_types, redirect_uris, name, " +
  "source, created_at, last_used_at";
const OAUTH_GRANT_COLUMNS =
  "id, account_id, client_id, scopes, resource, created_at, expires_at, generation, " +
  "refresh_ref_digest, refresh_digest, refresh_digest_algorithm, previous_refresh_digest, " +
  "refreshed_at, refresh_expires_at, code_digest, source";
/**
 * The tombstone insert for the imported grants that `where` selects, before their delete in the
 * same batch. `?at` is the parameter that holds the time.
 */
const tombstoneGrants = (where: string, at: string) =>
  `INSERT INTO identkit_oauth_import_tombstones (kind, id, ended_at)
   SELECT 'grant', id, ${at} FROM identkit_oauth_grants
   WHERE source = 'import' AND ${where}
   ON CONFLICT DO NOTHING`;
/** As `tombstoneGrants`, for the clients that `where` selects (table alias `c`). */
const tombstoneClients = (where: string, at: string) =>
  `INSERT INTO identkit_oauth_import_tombstones (kind, id, ended_at)
   SELECT 'client', c.id, ${at} FROM identkit_oauth_clients AS c
   WHERE c.source = 'import' AND ${where}
   ON CONFLICT DO NOTHING`;
const OAUTH_CODE_COLUMNS =
  "digest, client_id, account_id, redirect_uri, redirect_uri_explicit, code_challenge, resource, " +
  "scopes, created_at, expires_at";
const OAUTH_ACCESS_TOKEN_COLUMNS = "digest, grant_id, generation, scopes, created_at, expires_at";
/** The grant columns with the alias `g.`, for joins. */
const OAUTH_GRANT_COLUMNS_G = OAUTH_GRANT_COLUMNS.split(", ")
  .map((c) => `g.${c}`)
  .join(", ");

const toOAuthClient = (r: Row): OAuthClientRecord => ({
  id: text(r["id"]),
  secretDigest: textOrNull(r["secret_digest"]),
  secretDigestAlgorithm: oneOfOrNull(r["secret_digest_algorithm"], OAUTH_ALGORITHMS),
  authMethod: oneOf(r["auth_method"], OAUTH_AUTH_METHODS),
  grantTypes: stringList(r["grant_types"]),
  redirectUris: stringList(r["redirect_uris"]),
  name: textOrNull(r["name"]),
  source: oneOf(r["source"], OAUTH_CLIENT_SOURCES),
  createdAt: date(r["created_at"]),
  lastUsedAt: dateOrNull(r["last_used_at"]),
});

const toOAuthGrant = (r: Row): OAuthGrantRecord => ({
  id: text(r["id"]),
  accountId: text(r["account_id"]),
  clientId: text(r["client_id"]),
  scopes: stringList(r["scopes"]),
  resource: text(r["resource"]),
  createdAt: date(r["created_at"]),
  expiresAt: date(r["expires_at"]),
  generation: integer(r["generation"]),
  refreshRefDigest: textOrNull(r["refresh_ref_digest"]),
  refreshDigest: textOrNull(r["refresh_digest"]),
  refreshDigestAlgorithm: oneOfOrNull(r["refresh_digest_algorithm"], OAUTH_ALGORITHMS),
  previousRefreshDigest: textOrNull(r["previous_refresh_digest"]),
  refreshedAt: dateOrNull(r["refreshed_at"]),
  refreshExpiresAt: dateOrNull(r["refresh_expires_at"]),
  codeDigest: textOrNull(r["code_digest"]),
  source: oneOf(r["source"], OAUTH_GRANT_SOURCES),
});

const toOAuthCode = (r: Row): OAuthCodeRecord => ({
  digest: text(r["digest"]),
  clientId: text(r["client_id"]),
  accountId: text(r["account_id"]),
  redirectUri: text(r["redirect_uri"]),
  redirectUriExplicit: integer(r["redirect_uri_explicit"]) === 1,
  codeChallenge: text(r["code_challenge"]),
  resource: text(r["resource"]),
  scopes: stringList(r["scopes"]),
  createdAt: date(r["created_at"]),
  expiresAt: date(r["expires_at"]),
});

const oauthGrantValues = (g: OAuthGrantRecord): unknown[] => [
  g.id,
  g.accountId,
  g.clientId,
  JSON.stringify(g.scopes),
  g.resource,
  ms(g.createdAt),
  ms(g.expiresAt),
  g.generation,
  g.refreshRefDigest,
  g.refreshDigest,
  g.refreshDigestAlgorithm,
  g.previousRefreshDigest,
  msOrNull(g.refreshedAt),
  msOrNull(g.refreshExpiresAt),
  g.codeDigest,
  g.source,
];

const oauthAccessTokenValues = (t: OAuthAccessTokenRecord): unknown[] => [
  t.digest,
  t.grantId,
  t.generation,
  JSON.stringify(t.scopes),
  ms(t.createdAt),
  ms(t.expiresAt),
];

const isRow = (value: unknown): value is Row => typeof value === "object" && value !== null;

/** The rows that one statement of a `batch()` returned. */
function batchRows(result: unknown): Row[] {
  const rows: unknown = isRow(result) ? result["results"] : undefined;
  if (!Array.isArray(rows) || !rows.every(isRow)) {
    throw new Error("unexpected D1 batch result: no rows");
  }
  return rows;
}

const OIDC_LINK_COLUMNS =
  "id, account_id, link_key, provider, issuer, subject, tenant_id, source, created_at";

const toAccount = (r: Row): AccountRecord => ({
  id: text(r["id"]),
  email: text(r["email"]),
  webauthnUserId: text(r["webauthn_user_id"]),
  status: oneOf(r["status"], ["active", "disabled"]),
  createdAt: date(r["created_at"]),
  personKeyDigest: textOrNull(r["person_key_digest"]),
  assuranceLevel: oneOfOrNull(r["assurance_level"], LEVELS),
  identityVerifiedAt: dateOrNull(r["identity_verified_at"]),
});

const toFlow = (r: Row): OtpFlowRecord => ({
  id: text(r["id"]),
  purpose: oneOf(r["purpose"], ["sign_in", "step_up"]),
  email: text(r["email"]),
  addressDigest: text(r["address_digest"]),
  sessionId: textOrNull(r["session_id"]),
  codeDigest: text(r["code_digest"]),
  createdAt: date(r["created_at"]),
  expiresAt: date(r["expires_at"]),
  attempts: integer(r["attempts"]),
  maxAttempts: integer(r["max_attempts"]),
  consumedAt: dateOrNull(r["consumed_at"]),
  supersededAt: dateOrNull(r["superseded_at"]),
});

function toSession(r: Row): SessionRecord {
  const stepUpMethod = oneOfOrNull(r["step_up_method"], STEP_UP_METHODS);
  const stepUpAt = dateOrNull(r["step_up_at"]);
  return {
    id: text(r["id"]),
    accountId: text(r["account_id"]),
    tokenDigest: text(r["token_digest"]),
    state: oneOf(r["state"], ["pending_second_factor", "complete"]),
    // Unknown methods, written by a later release, are dropped: fewer methods, never more rights.
    authMethods: knownAuthMethods(stringList(r["auth_methods"])),
    createdAt: date(r["created_at"]),
    lastSeenAt: date(r["last_seen_at"]),
    absoluteExpiresAt: date(r["absolute_expires_at"]),
    stepUp: stepUpMethod && stepUpAt ? { method: stepUpMethod, at: stepUpAt } : null,
    revokedAt: dateOrNull(r["revoked_at"]),
    revokeReason: textOrNull(r["revoke_reason"]),
  };
}

const toCredential = (r: Row): CredentialRecord => ({
  id: text(r["id"]),
  accountId: text(r["account_id"]),
  publicKey: bytesFrom(r["public_key"]),
  counter: integer(r["counter"]),
  transports: stringList(r["transports"]),
  deviceType: oneOf(r["device_type"], ["singleDevice", "multiDevice"]),
  backedUp: integer(r["backed_up"]) === 1,
  createdAt: date(r["created_at"]),
  lastUsedAt: dateOrNull(r["last_used_at"]),
  activatedAt: dateOrNull(r["activated_at"]),
});

const toChallenge = (r: Row): ChallengeRecord => ({
  id: text(r["id"]),
  challengeDigest: text(r["challenge_digest"]),
  purpose: oneOf(r["purpose"], CHALLENGE_PURPOSES),
  accountId: textOrNull(r["account_id"]),
  sessionId: textOrNull(r["session_id"]),
  enrollmentTokenDigest: textOrNull(r["enrollment_token_digest"]),
  payloadHash: textOrNull(r["payload_hash"]),
  nonce: textOrNull(r["nonce"]),
  createdAt: date(r["created_at"]),
  expiresAt: date(r["expires_at"]),
});

function toDigits(value: unknown): 6 | 8 {
  if (value === 6 || value === 8) return value;
  throw new Error(`unexpected value in database: ${String(value)}`);
}

const toTotpFactor = (r: Row): TotpFactorRecord => ({
  id: text(r["id"]),
  accountId: text(r["account_id"]),
  sealedSecret: text(r["sealed_secret"]),
  algorithm: oneOf(r["algorithm"], ["SHA1", "SHA256", "SHA512"]),
  digits: toDigits(r["digits"]),
  createdAt: date(r["created_at"]),
  enrolmentSessionId: textOrNull(r["enrolment_session_id"]),
  activatedAt: dateOrNull(r["activated_at"]),
  lastUsedStep: integerOrNull(r["last_used_step"]),
  lastUsedAt: dateOrNull(r["last_used_at"]),
});

const toEnrollmentToken = (r: Row): EnrollmentTokenRecord => ({
  tokenDigest: text(r["token_digest"]),
  accountId: text(r["account_id"]),
  createdAt: date(r["created_at"]),
  expiresAt: date(r["expires_at"]),
  consumedAt: dateOrNull(r["consumed_at"]),
  revokedAt: dateOrNull(r["revoked_at"]),
});

const toVerification = (r: Row): VerificationRecord => ({
  id: text(r["id"]),
  accountId: text(r["account_id"]),
  vendorReference: textOrNull(r["vendor_reference"]),
  status: oneOf(r["status"], VERIFICATION_STATUSES),
  assuranceLevel: oneOfOrNull(r["assurance_level"], LEVELS),
  evidenceReference: textOrNull(r["evidence_reference"]),
  failureReason: textOrNull(r["failure_reason"]),
  createdAt: date(r["created_at"]),
  expiresAt: date(r["expires_at"]),
  completedAt: dateOrNull(r["completed_at"]),
});

const toThrottleState = (r: Row): ThrottleState => ({
  windowStart: date(r["window_start"]),
  attempts: integer(r["attempts"]),
  lockedUntil: dateOrNull(r["locked_until"]),
  lockCount: integer(r["lock_count"]),
  consecutiveFailures: integer(r["consecutive_failures"]),
});

const sameThrottleState = (a: ThrottleState, b: ThrottleState): boolean =>
  ms(a.windowStart) === ms(b.windowStart) &&
  a.attempts === b.attempts &&
  msOrNull(a.lockedUntil) === msOrNull(b.lockedUntil) &&
  a.lockCount === b.lockCount &&
  a.consecutiveFailures === b.consecutiveFailures;

/** A D1 session from `withSession()` has `getBookmark`; the plain binding has not. */
const isD1Session = (db: D1DatabaseLike): boolean =>
  typeof Reflect.get(db, "getBookmark") === "function";

const SESSION_COLUMNS =
  "id, account_id, token_digest, state, auth_methods, created_at, last_seen_at, " +
  "absolute_expires_at, step_up_method, step_up_at, revoked_at, revoke_reason";
const CREDENTIAL_COLUMNS =
  "id, account_id, public_key, counter, transports, device_type, backed_up, created_at, " +
  "last_used_at, activated_at";
const TOTP_COLUMNS =
  "id, account_id, sealed_secret, algorithm, digits, created_at, enrolment_session_id, " +
  "activated_at, last_used_step, last_used_at";

/**
 * Cloudflare D1 (SQLite) store. Apply the D1 migrations first (`migrateIdentkitD1` or the
 * files in `migrations-d1/`). D1 has no interactive transactions. D1 runs the statements of a
 * database one after another, and each statement and each `batch()` is atomic. So every
 * guarded method is one conditional statement that checks the expected state in its `WHERE`
 * and reports through `RETURNING` whether it matched, or one `batch()`. The comment at each
 * guarded method names how its atomicity holds.
 */
export function createD1Store(db: D1DatabaseLike, options: D1StoreOptions = {}): IdentkitStore {
  const throttleRetries = options.throttleRetries ?? D1_DEFAULT_THROTTLE_RETRIES;
  if (!Number.isSafeInteger(throttleRetries) || throttleRetries < 1) {
    throw new RangeError("throttleRetries must be a positive integer");
  }
  if (isD1Session(db) && options.sessionConstraint !== "first-primary") {
    throw new TypeError(
      "createD1Store got a D1 session. A session can read from a lagging read replica, so a " +
        "revoked session or a disabled account can still read as active. Pass the plain " +
        'binding (env.DB), or a session from env.DB.withSession("first-primary") together ' +
        'with the option sessionConstraint: "first-primary".',
    );
  }
  const one = (query: string, ...values: unknown[]) =>
    db
      .prepare(query)
      .bind(...values)
      .first();
  const all = async (query: string, ...values: unknown[]) =>
    (
      await db
        .prepare(query)
        .bind(...values)
        .all()
    ).results;
  const run = async (query: string, ...values: unknown[]): Promise<void> => {
    await db
      .prepare(query)
      .bind(...values)
      .run();
  };

  return {
    accounts: {
      async insert(a) {
        // Atomic: one INSERT. The unique e-mail makes a second insert of the address a no-op.
        const row = await one(
          `INSERT INTO identkit_accounts (id, email, webauthn_user_id, status, created_at,
             person_key_digest, assurance_level, identity_verified_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
           ON CONFLICT (email) DO NOTHING
           RETURNING id`,
          a.id,
          a.email,
          a.webauthnUserId,
          a.status,
          ms(a.createdAt),
          a.personKeyDigest,
          a.assuranceLevel,
          msOrNull(a.identityVerifiedAt),
        );
        return row ? "inserted" : "email_taken";
      },
      async findById(id) {
        const r = await one("SELECT * FROM identkit_accounts WHERE id = ?1", id);
        return r ? toAccount(r) : null;
      },
      async findByEmail(email) {
        const r = await one("SELECT * FROM identkit_accounts WHERE email = ?1", email);
        return r ? toAccount(r) : null;
      },
      async setStatus(id, status) {
        await run("UPDATE identkit_accounts SET status = ?2 WHERE id = ?1", id, status);
      },
      async linkPerson(id, digest, level, at) {
        // Atomic: one UPDATE that sets the person only while the account has none. The unique
        // person digest refuses a person that another account holds. The read after a miss
        // sees a value that never changes back.
        try {
          const updated = await one(
            `UPDATE identkit_accounts
             SET person_key_digest = ?2, assurance_level = ?3, identity_verified_at = ?4
             WHERE id = ?1 AND person_key_digest IS NULL
             RETURNING id`,
            id,
            digest,
            level,
            ms(at),
          );
          if (updated) return "linked";
        } catch (error) {
          if (isUniqueViolation(error)) return "person_linked_elsewhere";
          throw error;
        }
        const account = await one(
          "SELECT person_key_digest FROM identkit_accounts WHERE id = ?1",
          id,
        );
        if (!account) throw new Error("account not found");
        return account["person_key_digest"] === digest
          ? "already_linked"
          : "account_has_other_person";
      },
    },

    otp: {
      async claimSendSlot(gateKey, at, cooldownSeconds) {
        // Atomic: one upsert. Its update runs only if the cooldown elapsed, and RETURNING
        // reports whether it ran.
        const claimed = await one(
          `INSERT INTO identkit_otp_send_gates (gate_key, last_sent_at) VALUES (?1, ?2)
           ON CONFLICT (gate_key) DO UPDATE SET last_sent_at = excluded.last_sent_at
           WHERE identkit_otp_send_gates.last_sent_at <= ?3
           RETURNING last_sent_at`,
          gateKey,
          ms(at),
          ms(addSeconds(at, -cooldownSeconds)),
        );
        if (claimed) return { claimed: true, nextAllowedAt: addSeconds(at, cooldownSeconds) };
        const row = await one(
          "SELECT last_sent_at FROM identkit_otp_send_gates WHERE gate_key = ?1",
          gateKey,
        );
        if (!row) throw new Error("send gate not found");
        return {
          claimed: false,
          nextAllowedAt: addSeconds(date(row["last_sent_at"]), cooldownSeconds),
        };
      },
      async supersedeOpen(addressDigest, purpose, at) {
        await run(
          `UPDATE identkit_otp_flows SET superseded_at = ?3
           WHERE address_digest = ?1 AND purpose = ?2
             AND consumed_at IS NULL AND superseded_at IS NULL`,
          addressDigest,
          purpose,
          ms(at),
        );
      },
      async insert(f) {
        await run(
          `INSERT INTO identkit_otp_flows (id, purpose, email, address_digest, session_id,
             code_digest, created_at, expires_at, attempts, max_attempts, consumed_at,
             superseded_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
          f.id,
          f.purpose,
          f.email,
          f.addressDigest,
          f.sessionId,
          f.codeDigest,
          ms(f.createdAt),
          ms(f.expiresAt),
          f.attempts,
          f.maxAttempts,
          msOrNull(f.consumedAt),
          msOrNull(f.supersededAt),
        );
      },
      async findById(id) {
        const r = await one("SELECT * FROM identkit_otp_flows WHERE id = ?1", id);
        return r ? toFlow(r) : null;
      },
      async reserveAttempt(id, at) {
        // Atomic: one UPDATE that counts the attempt only below the limit of an open flow.
        // The read after a miss only picks the reason.
        const reserved = await one(
          `UPDATE identkit_otp_flows SET attempts = attempts + 1
           WHERE id = ?1 AND consumed_at IS NULL AND superseded_at IS NULL
             AND expires_at > ?2 AND attempts < max_attempts
           RETURNING attempts`,
          id,
          ms(at),
        );
        if (reserved) return { status: "reserved", attempts: integer(reserved["attempts"]) };
        const r = await one("SELECT * FROM identkit_otp_flows WHERE id = ?1", id);
        const flow = r ? toFlow(r) : null;
        if (
          flow &&
          flow.consumedAt === null &&
          flow.supersededAt === null &&
          flow.expiresAt.getTime() > at.getTime() &&
          flow.attempts >= flow.maxAttempts
        ) {
          return { status: "exhausted" };
        }
        return { status: "unavailable" };
      },
      async consume(id, at) {
        // Atomic: one UPDATE that matches only an open flow.
        const row = await one(
          `UPDATE identkit_otp_flows SET consumed_at = ?2
           WHERE id = ?1 AND consumed_at IS NULL AND superseded_at IS NULL AND expires_at > ?2
           RETURNING id`,
          id,
          ms(at),
        );
        return row !== null;
      },
    },

    throttle: {
      async reserve(key, at, rule) {
        // Atomic by compare-and-set: read the state, apply `applyThrottle`, then write the
        // next state with one statement that matches only if every stored field still has
        // the value that was read (a new key: an INSERT that matches only if no row exists).
        // If a concurrent call changed the state first, the write matches nothing and the
        // round starts again on the new state. So each attempt counts on the state that the
        // previous attempt left, as under the row lock of the PostgreSQL store.
        for (let round = 0; round < throttleRetries; round += 1) {
          const row = await one(
            `SELECT window_start, attempts, locked_until, lock_count, consecutive_failures
             FROM identkit_throttles WHERE key = ?1`,
            key,
          );
          const state = row ? toThrottleState(row) : null;
          const { next, result } = applyThrottle(state, at, rule);
          // A running lock changes nothing. The read is the point the decision holds for.
          if (state && sameThrottleState(state, next)) return result;
          const written = state
            ? await one(
                `UPDATE identkit_throttles
                 SET window_start = ?2, attempts = ?3, locked_until = ?4, lock_count = ?5,
                   consecutive_failures = ?6
                 WHERE key = ?1 AND window_start = ?7 AND attempts = ?8 AND locked_until IS ?9
                   AND lock_count = ?10 AND consecutive_failures = ?11
                 RETURNING key`,
                key,
                ms(next.windowStart),
                next.attempts,
                msOrNull(next.lockedUntil),
                next.lockCount,
                next.consecutiveFailures,
                ms(state.windowStart),
                state.attempts,
                msOrNull(state.lockedUntil),
                state.lockCount,
                state.consecutiveFailures,
              )
            : await one(
                `INSERT INTO identkit_throttles (key, window_start, attempts, locked_until,
                   lock_count, consecutive_failures)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (key) DO NOTHING
                 RETURNING key`,
                key,
                ms(next.windowStart),
                next.attempts,
                msOrNull(next.lockedUntil),
                next.lockCount,
                next.consecutiveFailures,
              );
          if (written) return result;
        }
        throw new D1ThrottleContentionError(throttleRetries);
      },
      async peek(key, at) {
        const row = await one("SELECT locked_until FROM identkit_throttles WHERE key = ?1", key);
        const lockedUntil = row ? dateOrNull(row["locked_until"]) : null;
        return lockedUntil && at.getTime() < lockedUntil.getTime() ? lockedUntil : null;
      },
      async reset(key) {
        await run("DELETE FROM identkit_throttles WHERE key = ?1", key);
      },
    },

    sessions: {
      async insert(s) {
        await run(
          `INSERT INTO identkit_sessions (${SESSION_COLUMNS})
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
          s.id,
          s.accountId,
          s.tokenDigest,
          s.state,
          JSON.stringify(s.authMethods),
          ms(s.createdAt),
          ms(s.lastSeenAt),
          ms(s.absoluteExpiresAt),
          s.stepUp?.method ?? null,
          s.stepUp ? ms(s.stepUp.at) : null,
          msOrNull(s.revokedAt),
          s.revokeReason,
        );
      },
      async findByTokenDigest(digest) {
        const r = await one(
          `SELECT ${SESSION_COLUMNS} FROM identkit_sessions WHERE token_digest = ?1`,
          digest,
        );
        return r ? toSession(r) : null;
      },
      async findById(id) {
        const r = await one(`SELECT ${SESSION_COLUMNS} FROM identkit_sessions WHERE id = ?1`, id);
        return r ? toSession(r) : null;
      },
      async touch(id, at) {
        await run(
          `UPDATE identkit_sessions SET last_seen_at = ?2
           WHERE id = ?1 AND revoked_at IS NULL AND last_seen_at < ?2`,
          id,
          ms(at),
        );
      },
      async rotate(id, oldDigest, newDigest, u) {
        // Atomic: one UPDATE that matches only a live session that still has the old token.
        const row = await one(
          `UPDATE identkit_sessions
           SET token_digest = ?3, state = ?4, auth_methods = ?5, step_up_method = ?6,
             step_up_at = ?7, last_seen_at = ?8, absolute_expires_at = ?9
           WHERE id = ?1 AND token_digest = ?2 AND revoked_at IS NULL
           RETURNING id`,
          id,
          oldDigest,
          newDigest,
          u.state,
          JSON.stringify(u.authMethods),
          u.stepUp?.method ?? null,
          u.stepUp ? ms(u.stepUp.at) : null,
          ms(u.lastSeenAt),
          ms(u.absoluteExpiresAt),
        );
        return row !== null;
      },
      async revoke(id, at, reason) {
        // Atomic: one UPDATE that matches only a live session.
        const row = await one(
          `UPDATE identkit_sessions SET revoked_at = ?2, revoke_reason = ?3
           WHERE id = ?1 AND revoked_at IS NULL
           RETURNING id`,
          id,
          ms(at),
          reason,
        );
        return row !== null;
      },
      async revokeAllForAccount(accountId, at, reason, exceptId) {
        // Atomic: one UPDATE over the live sessions of the account.
        const rows = await all(
          `UPDATE identkit_sessions SET revoked_at = ?2, revoke_reason = ?3
           WHERE account_id = ?1 AND revoked_at IS NULL AND (?4 IS NULL OR id != ?4)
           RETURNING id`,
          accountId,
          ms(at),
          reason,
          exceptId ?? null,
        );
        return rows.map((r) => text(r["id"]));
      },
    },

    credentials: {
      async insert(c) {
        // Atomic: one INSERT. An id that exists makes it a no-op.
        const row = await one(
          `INSERT INTO identkit_credentials (${CREDENTIAL_COLUMNS})
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
           ON CONFLICT (id) DO NOTHING
           RETURNING id`,
          c.id,
          c.accountId,
          blob(c.publicKey),
          c.counter,
          JSON.stringify(c.transports),
          c.deviceType,
          c.backedUp ? 1 : 0,
          ms(c.createdAt),
          msOrNull(c.lastUsedAt),
          msOrNull(c.activatedAt),
        );
        return row ? "inserted" : "duplicate";
      },
      async activate(id, accountId, publicKey, at) {
        // Atomic: one UPDATE that matches only the row of this account and public key.
        const row = await one(
          `UPDATE identkit_credentials SET activated_at = COALESCE(activated_at, ?4)
           WHERE id = ?1 AND account_id = ?2 AND public_key = ?3
           RETURNING id`,
          id,
          accountId,
          blob(publicKey),
          ms(at),
        );
        return row !== null;
      },
      async findById(id) {
        const r = await one(
          `SELECT ${CREDENTIAL_COLUMNS} FROM identkit_credentials
           WHERE id = ?1 AND activated_at IS NOT NULL`,
          id,
        );
        return r ? toCredential(r) : null;
      },
      async listByAccount(accountId) {
        const rows = await all(
          `SELECT ${CREDENTIAL_COLUMNS} FROM identkit_credentials
           WHERE account_id = ?1 AND activated_at IS NOT NULL
           ORDER BY created_at`,
          accountId,
        );
        return rows.map(toCredential);
      },
      async updateCounter(id, expected, next, usedAt) {
        // Atomic: compare-and-set in one UPDATE on the expected counter.
        const row = await one(
          `UPDATE identkit_credentials SET counter = ?3, last_used_at = ?4
           WHERE id = ?1 AND counter = ?2 AND activated_at IS NOT NULL
           RETURNING id`,
          id,
          expected,
          next,
          ms(usedAt),
        );
        return row !== null;
      },
      async delete(id, accountId, publicKey) {
        const row = publicKey
          ? await one(
              `DELETE FROM identkit_credentials
               WHERE id = ?1 AND account_id = ?2 AND public_key = ?3
               RETURNING id`,
              id,
              accountId,
              blob(publicKey),
            )
          : await one(
              "DELETE FROM identkit_credentials WHERE id = ?1 AND account_id = ?2 RETURNING id",
              id,
              accountId,
            );
        return row !== null;
      },
    },

    challenges: {
      async insert(c) {
        await run(
          `INSERT INTO identkit_challenges (id, challenge_digest, purpose, account_id,
             session_id, enrollment_token_digest, payload_hash, nonce, created_at, expires_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
          c.id,
          c.challengeDigest,
          c.purpose,
          c.accountId,
          c.sessionId,
          c.enrollmentTokenDigest,
          c.payloadHash,
          c.nonce,
          ms(c.createdAt),
          ms(c.expiresAt),
        );
      },
      async consumeByDigest(digest, purpose) {
        // Atomic: one DELETE ... RETURNING. Only the call that deletes the row gets it.
        const r = await one(
          `DELETE FROM identkit_challenges WHERE challenge_digest = ?1 AND purpose = ?2
           RETURNING *`,
          digest,
          purpose,
        );
        return r ? toChallenge(r) : null;
      },
    },

    totp: {
      async insert(f) {
        await run(
          `INSERT INTO identkit_totp_factors (${TOTP_COLUMNS})
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
          f.id,
          f.accountId,
          f.sealedSecret,
          f.algorithm,
          f.digits,
          ms(f.createdAt),
          f.enrolmentSessionId,
          msOrNull(f.activatedAt),
          f.lastUsedStep,
          msOrNull(f.lastUsedAt),
        );
      },
      async findPending(id) {
        const r = await one(
          `SELECT ${TOTP_COLUMNS} FROM identkit_totp_factors
           WHERE id = ?1 AND activated_at IS NULL`,
          id,
        );
        return r ? toTotpFactor(r) : null;
      },
      async findActive(accountId) {
        const r = await one(
          `SELECT ${TOTP_COLUMNS} FROM identkit_totp_factors
           WHERE account_id = ?1 AND activated_at IS NOT NULL`,
          accountId,
        );
        return r ? toTotpFactor(r) : null;
      },
      async activate(id, accountId, step, at) {
        // Atomic: one UPDATE that matches only a pending factor. The unique partial index on
        // active factors refuses a second active factor of the account.
        try {
          const row = await one(
            `UPDATE identkit_totp_factors
             SET activated_at = ?4, last_used_step = ?3, last_used_at = ?4
             WHERE id = ?1 AND account_id = ?2 AND activated_at IS NULL
             RETURNING id`,
            id,
            accountId,
            step,
            ms(at),
          );
          return row !== null;
        } catch (error) {
          if (isUniqueViolation(error)) return false;
          throw error;
        }
      },
      async recordStep(id, accountId, step, at) {
        // Atomic: one UPDATE that matches only if the step is above the stored one.
        const row = await one(
          `UPDATE identkit_totp_factors SET last_used_step = ?3, last_used_at = ?4
           WHERE id = ?1 AND account_id = ?2 AND activated_at IS NOT NULL
             AND (last_used_step IS NULL OR last_used_step < ?3)
           RETURNING id`,
          id,
          accountId,
          step,
          ms(at),
        );
        return row !== null;
      },
      async delete(id, accountId) {
        const row = await one(
          "DELETE FROM identkit_totp_factors WHERE id = ?1 AND account_id = ?2 RETURNING id",
          id,
          accountId,
        );
        return row !== null;
      },
      async deleteAllForAccount(accountId) {
        const rows = await all(
          "DELETE FROM identkit_totp_factors WHERE account_id = ?1 RETURNING id",
          accountId,
        );
        return rows.length;
      },
      async replaceSealedSecret(id, expected, next) {
        // Atomic: compare-and-set in one UPDATE on the expected sealed secret.
        const row = await one(
          `UPDATE identkit_totp_factors SET sealed_secret = ?3
           WHERE id = ?1 AND sealed_secret = ?2
           RETURNING id`,
          id,
          expected,
          next,
        );
        return row !== null;
      },
    },

    enrollment: {
      async issue(t) {
        // Atomic: one batch, which D1 runs as one transaction with no other statement in
        // between. It revokes the earlier tokens and inserts this one, so of two concurrent
        // issues the later one revokes the earlier token. `revokeAllForAccount` is one
        // statement, so it runs wholly before or wholly after this batch.
        await db.batch([
          db
            .prepare(
              `UPDATE identkit_enrollment_tokens SET revoked_at = ?2
               WHERE account_id = ?1 AND revoked_at IS NULL`,
            )
            .bind(t.accountId, ms(t.createdAt)),
          db
            .prepare(
              `INSERT INTO identkit_enrollment_tokens (token_digest, account_id, created_at,
                 expires_at, consumed_at, revoked_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
            )
            .bind(
              t.tokenDigest,
              t.accountId,
              ms(t.createdAt),
              ms(t.expiresAt),
              msOrNull(t.consumedAt),
              msOrNull(t.revokedAt),
            ),
        ]);
      },
      async findByDigest(digest) {
        const r = await one(
          "SELECT * FROM identkit_enrollment_tokens WHERE token_digest = ?1",
          digest,
        );
        return r ? toEnrollmentToken(r) : null;
      },
      async consume(digest, at) {
        // Atomic: one UPDATE that matches only an unexpired, unconsumed, unrevoked token.
        const r = await one(
          `UPDATE identkit_enrollment_tokens SET consumed_at = ?2
           WHERE token_digest = ?1 AND consumed_at IS NULL AND revoked_at IS NULL
             AND expires_at > ?2
           RETURNING *`,
          digest,
          ms(at),
        );
        return r ? toEnrollmentToken(r) : null;
      },
      async revokeAllForAccount(accountId, at) {
        // Atomic: one UPDATE. It runs wholly before or wholly after an `issue` batch, so it
        // never misses a token that a concurrent issue inserts before it.
        const rows = await all(
          `UPDATE identkit_enrollment_tokens SET revoked_at = ?2
           WHERE account_id = ?1 AND revoked_at IS NULL
           RETURNING token_digest`,
          accountId,
          ms(at),
        );
        return rows.length;
      },
    },

    verifications: {
      async insert(v) {
        await run(
          `INSERT INTO identkit_verifications (id, account_id, vendor_reference, status,
             assurance_level, evidence_reference, failure_reason, created_at, expires_at,
             completed_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
          v.id,
          v.accountId,
          v.vendorReference,
          v.status,
          v.assuranceLevel,
          v.evidenceReference,
          v.failureReason,
          ms(v.createdAt),
          ms(v.expiresAt),
          msOrNull(v.completedAt),
        );
      },
      async findById(id) {
        const r = await one("SELECT * FROM identkit_verifications WHERE id = ?1", id);
        return r ? toVerification(r) : null;
      },
      async findByVendorReference(reference) {
        const r = await one(
          "SELECT * FROM identkit_verifications WHERE vendor_reference = ?1",
          reference,
        );
        return r ? toVerification(r) : null;
      },
      async setVendorReference(id, reference) {
        await run(
          "UPDATE identkit_verifications SET vendor_reference = ?2 WHERE id = ?1",
          id,
          reference,
        );
      },
      async claim(id) {
        // Atomic: one UPDATE that matches only a pending verification.
        const row = await one(
          `UPDATE identkit_verifications SET status = 'processing'
           WHERE id = ?1 AND status = 'pending'
           RETURNING id`,
          id,
        );
        return row !== null;
      },
      async finalize(id, u) {
        return finish(id, "processing", u);
      },
      async complete(id, u) {
        return finish(id, "pending", u);
      },
    },

    oidcLinks: {
      async insert(link, insertOptions) {
        // Atomic: one INSERT ... SELECT. Its WHERE checks that the account has no link (if
        // exclusive) in the same statement, and the unique link key makes a second insert of a
        // subject a no-op. The read after a miss only names the reason.
        const row = await one(
          `INSERT INTO identkit_oidc_links (${OIDC_LINK_COLUMNS})
           SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9
           WHERE ?10 = 0 OR NOT EXISTS (
             SELECT 1 FROM identkit_oidc_links WHERE account_id = ?2
           )
           ON CONFLICT (link_key) DO NOTHING
           RETURNING id`,
          link.id,
          link.accountId,
          link.linkKey,
          link.provider,
          link.issuer,
          link.subject,
          link.tenantId,
          link.source,
          ms(link.createdAt),
          insertOptions.exclusive ? 1 : 0,
        );
        if (row) return "inserted";
        const taken = await one(
          "SELECT id FROM identkit_oidc_links WHERE link_key = ?1",
          link.linkKey,
        );
        return taken ? "link_taken" : "account_has_link";
      },
      async findByKey(linkKey) {
        const r = await one(
          `SELECT ${OIDC_LINK_COLUMNS} FROM identkit_oidc_links WHERE link_key = ?1`,
          linkKey,
        );
        return r ? toOidcLink(r) : null;
      },
      async listByAccount(accountId) {
        const rows = await all(
          `SELECT ${OIDC_LINK_COLUMNS} FROM identkit_oidc_links
           WHERE account_id = ?1 ORDER BY created_at, id`,
          accountId,
        );
        return rows.map(toOidcLink);
      },
      async delete(id, accountId) {
        const row = await one(
          "DELETE FROM identkit_oidc_links WHERE id = ?1 AND account_id = ?2 RETURNING id",
          id,
          accountId,
        );
        return row !== null;
      },
    },

    apiTokens: {
      async insert(t, limit) {
        // Atomic: one INSERT ... SELECT. Its WHERE counts the active tokens of the account in
        // the same statement, so concurrent inserts never exceed the limit, and the unique
        // digest makes a second insert of a digest a no-op. The read after a miss only names
        // the reason.
        const row = await one(
          `INSERT INTO identkit_api_tokens (${API_TOKEN_COLUMNS})
           SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
           WHERE (
             SELECT count(*) FROM identkit_api_tokens
             WHERE account_id = ?2 AND revoked_at IS NULL AND expires_at > ?13
           ) < ?14
           ON CONFLICT (digest) DO NOTHING
           RETURNING id`,
          t.id,
          t.accountId,
          t.name,
          JSON.stringify(t.scopes),
          t.digest,
          t.digestAlgorithm,
          t.source,
          ms(t.createdAt),
          ms(t.expiresAt),
          msOrNull(t.lastUsedAt),
          msOrNull(t.revokedAt),
          t.revokeReason,
          ms(limit.at),
          limit.maxActive,
        );
        if (row) return "inserted";
        const taken = await one("SELECT id FROM identkit_api_tokens WHERE digest = ?1", t.digest);
        return taken ? "digest_taken" : "limit_reached";
      },
      async findByDigests(digests) {
        if (digests.length === 0) return [];
        // One query: the token and the status of its account.
        const placeholders = digests.map((_, i) => `?${i + 1}`).join(", ");
        const columns = API_TOKEN_COLUMNS.split(", ")
          .map((c) => `t.${c}`)
          .join(", ");
        const rows = await all(
          `SELECT ${columns}, a.status AS account_status
           FROM identkit_api_tokens t JOIN identkit_accounts a ON a.id = t.account_id
           WHERE t.digest IN (${placeholders})`,
          ...digests,
        );
        return rows.map((r) => ({
          record: toApiToken(r),
          accountStatus: oneOf(r["account_status"], ["active", "disabled"]),
        }));
      },
      async listByAccount(accountId) {
        const rows = await all(
          `SELECT ${API_TOKEN_COLUMNS} FROM identkit_api_tokens
           WHERE account_id = ?1 AND revoked_at IS NULL ORDER BY created_at, id`,
          accountId,
        );
        return rows.map(toApiToken);
      },
      async markUsed(id, at, notAfter) {
        // Atomic: one UPDATE that matches only while the last use is old enough.
        const row = await one(
          `UPDATE identkit_api_tokens SET last_used_at = ?2
           WHERE id = ?1 AND revoked_at IS NULL AND (last_used_at IS NULL OR last_used_at <= ?3)
           RETURNING id`,
          id,
          ms(at),
          ms(notAfter),
        );
        return row !== null;
      },
      async revoke(id, accountId, at, reason) {
        // Atomic: one UPDATE that matches only a token that is not revoked yet.
        const row = await one(
          `UPDATE identkit_api_tokens SET revoked_at = ?3, revoke_reason = ?4
           WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL
           RETURNING id`,
          id,
          accountId,
          ms(at),
          reason,
        );
        return row !== null;
      },
      async revokeAllForAccount(accountId, at, reason) {
        // Atomic: one UPDATE. It runs wholly before or wholly after a concurrent insert.
        const rows = await all(
          `UPDATE identkit_api_tokens SET revoked_at = ?2, revoke_reason = ?3
           WHERE account_id = ?1 AND revoked_at IS NULL
           RETURNING id`,
          accountId,
          ms(at),
          reason,
        );
        return rows.map((r) => text(r["id"]));
      },
      async delete(id, accountId) {
        const row = await one(
          "DELETE FROM identkit_api_tokens WHERE id = ?1 AND account_id = ?2 RETURNING id",
          id,
          accountId,
        );
        return row !== null;
      },
    },

    oauth: {
      async insertClient(c) {
        // Atomic: one INSERT that a tombstone of the id refuses; the primary key makes a second
        // insert of an id a no-op. The read after a miss only names the reason.
        const row = await one(
          `INSERT INTO identkit_oauth_clients (${OAUTH_CLIENT_COLUMNS})
           SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
           WHERE NOT EXISTS (SELECT 1 FROM identkit_oauth_import_tombstones
                             WHERE kind = 'client' AND id = ?1)
           ON CONFLICT (id) DO NOTHING
           RETURNING id`,
          c.id,
          c.secretDigest,
          c.secretDigestAlgorithm,
          c.authMethod,
          JSON.stringify(c.grantTypes),
          JSON.stringify(c.redirectUris),
          c.name,
          c.source,
          ms(c.createdAt),
          msOrNull(c.lastUsedAt),
        );
        if (row) return "inserted";
        if (await one("SELECT id FROM identkit_oauth_clients WHERE id = ?1", c.id)) {
          return "id_taken";
        }
        const tombstone = await one(
          "SELECT id FROM identkit_oauth_import_tombstones WHERE kind = 'client' AND id = ?1",
          c.id,
        );
        return tombstone ? "revoked" : "id_taken";
      },
      async findClient(id) {
        const r = await one(
          `SELECT ${OAUTH_CLIENT_COLUMNS} FROM identkit_oauth_clients WHERE id = ?1`,
          id,
        );
        return r ? toOAuthClient(r) : null;
      },
      async markClientUsed(id, at, notAfter) {
        // Atomic: one UPDATE that matches only while the last use is old enough.
        const row = await one(
          `UPDATE identkit_oauth_clients SET last_used_at = ?2
           WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at <= ?3)
           RETURNING id`,
          id,
          ms(at),
          ms(notAfter),
        );
        return row !== null;
      },
      async upgradeClientSecret(id, oldDigest, newDigest) {
        // Atomic: compare-and-set in one UPDATE on the expected digest.
        const row = await one(
          `UPDATE identkit_oauth_clients
           SET secret_digest = ?3, secret_digest_algorithm = 'hmac-sha256'
           WHERE id = ?1 AND secret_digest = ?2
           RETURNING id`,
          id,
          oldDigest,
          newDigest,
        );
        return row !== null;
      },
      async deleteClient(id, at) {
        // One batch, so no grant can come between the two deletes, and the tombstones go with
        // them. The foreign keys remove the grants' access tokens and the client's codes.
        const [, , grants, client] = await db.batch([
          db.prepare(tombstoneGrants("client_id = ?1", "?2")).bind(id, ms(at)),
          db.prepare(tombstoneClients("c.id = ?1", "?2")).bind(id, ms(at)),
          db
            .prepare(
              `DELETE FROM identkit_oauth_grants WHERE client_id = ?1
               RETURNING ${OAUTH_GRANT_COLUMNS}`,
            )
            .bind(id),
          db.prepare("DELETE FROM identkit_oauth_clients WHERE id = ?1 RETURNING id").bind(id),
        ]);
        return batchRows(client).length === 1 ? batchRows(grants).map(toOAuthGrant) : null;
      },
      async reserveRegistration({ keys, windowStart }) {
        // One upsert per key, in order, and no further key after a refusal. Each upsert is one
        // atomic statement whose WHERE sees the count of the call before, so no count passes
        // its max. Not one batch: a batch would count the later keys also after a refusal.
        for (const { key, max } of keys) {
          const row = await one(
            `INSERT INTO identkit_oauth_registration_counts (key, window_start, count)
             VALUES (?1, ?2, 1)
             ON CONFLICT (key, window_start)
             DO UPDATE SET count = count + 1 WHERE count < ?3
             RETURNING count`,
            key,
            ms(windowStart),
            max,
          );
          if (row === null) return { limitReached: key };
        }
        return "reserved";
      },
      async insertCode(code) {
        await run(
          `INSERT INTO identkit_oauth_codes (${OAUTH_CODE_COLUMNS})
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
          code.digest,
          code.clientId,
          code.accountId,
          code.redirectUri,
          code.redirectUriExplicit ? 1 : 0,
          code.codeChallenge,
          code.resource,
          JSON.stringify(code.scopes),
          ms(code.createdAt),
          ms(code.expiresAt),
        );
      },
      async consumeCode(digest) {
        // Atomic: one DELETE ... RETURNING. Only the call that deletes the row gets it.
        const r = await one(
          `DELETE FROM identkit_oauth_codes WHERE digest = ?1 RETURNING ${OAUTH_CODE_COLUMNS}`,
          digest,
        );
        return r ? toOAuthCode(r) : null;
      },
      async endGrantByCode(codeDigest, at) {
        // Atomic: one batch, the tombstone and the DELETE ... RETURNING.
        const [, deleted] = await db.batch([
          db.prepare(tombstoneGrants("code_digest = ?1", "?2")).bind(codeDigest, ms(at)),
          db
            .prepare(
              `DELETE FROM identkit_oauth_grants WHERE code_digest = ?1
               RETURNING ${OAUTH_GRANT_COLUMNS}`,
            )
            .bind(codeDigest),
        ]);
        const [r] = batchRows(deleted);
        return r ? toOAuthGrant(r) : null;
      },
      async insertGrant(grant, firstAccessToken, limit) {
        // Atomic: one batch, which D1 runs as one transaction. Both writes carry the same
        // guard: the account is active and holds fewer than max live grants of other clients.
        // The delete changes no grant of another client, so the insert reads the same guard
        // state. The access token insert follows only a grant that exists. The read after a
        // miss only names the reason.
        const guard = `(SELECT status FROM identkit_accounts WHERE id = ?1) = 'active'
          AND (SELECT count(*) FROM identkit_oauth_grants
               WHERE account_id = ?1 AND client_id <> ?2 AND expires_at > ?3) < ?4`;
        const guardValues = [grant.accountId, grant.clientId, ms(limit.at), limit.maxOtherGrants];
        const [, deleted, inserted] = await db.batch([
          db
            .prepare(tombstoneGrants(`account_id = ?1 AND client_id = ?2 AND ${guard}`, "?3"))
            .bind(...guardValues),
          db
            .prepare(
              `DELETE FROM identkit_oauth_grants
               WHERE account_id = ?1 AND client_id = ?2 AND ${guard}
               RETURNING ${OAUTH_GRANT_COLUMNS}`,
            )
            .bind(...guardValues),
          db
            .prepare(
              `INSERT INTO identkit_oauth_grants (${OAUTH_GRANT_COLUMNS})
               SELECT ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
               WHERE ${guard}
               RETURNING id`,
            )
            .bind(...guardValues, ...oauthGrantValues(grant)),
          db
            .prepare(
              `INSERT INTO identkit_oauth_access_tokens (${OAUTH_ACCESS_TOKEN_COLUMNS})
               SELECT ?1, ?2, ?3, ?4, ?5, ?6
               WHERE EXISTS (SELECT 1 FROM identkit_oauth_grants WHERE id = ?2)`,
            )
            .bind(...oauthAccessTokenValues(firstAccessToken)),
        ]);
        if (batchRows(inserted).length === 1) {
          const [replaced] = batchRows(deleted);
          return { status: "inserted", replaced: replaced ? toOAuthGrant(replaced) : null };
        }
        const account = await one(
          "SELECT status FROM identkit_accounts WHERE id = ?1",
          grant.accountId,
        );
        return account?.["status"] === "active"
          ? { status: "limit_reached" }
          : { status: "account_inactive" };
      },
      async importGrant(grant, limit) {
        // Atomic: one INSERT ... SELECT with the guard of `insertGrant`, which also requires
        // that the account holds no grant of this client and that no tombstone names the id; a
        // unique key makes it a no-op. The reads after a miss only name the reason.
        const row = await one(
          `INSERT INTO identkit_oauth_grants (${OAUTH_GRANT_COLUMNS})
           SELECT ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
           WHERE (SELECT status FROM identkit_accounts WHERE id = ?1) = 'active'
             AND NOT EXISTS (SELECT 1 FROM identkit_oauth_grants
                             WHERE account_id = ?1 AND client_id = ?2)
             AND (SELECT count(*) FROM identkit_oauth_grants
                  WHERE account_id = ?1 AND client_id <> ?2 AND expires_at > ?3) < ?4
             AND NOT EXISTS (SELECT 1 FROM identkit_oauth_import_tombstones
                             WHERE kind = 'grant' AND id = ?5)
           ON CONFLICT DO NOTHING
           RETURNING id`,
          grant.accountId,
          grant.clientId,
          ms(limit.at),
          limit.maxOtherGrants,
          ...oauthGrantValues(grant),
        );
        if (row) return "inserted";
        if (await one("SELECT id FROM identkit_oauth_grants WHERE id = ?1", grant.id)) {
          return "id_taken";
        }
        const tombstone = await one(
          "SELECT id FROM identkit_oauth_import_tombstones WHERE kind = 'grant' AND id = ?1",
          grant.id,
        );
        if (tombstone) return "revoked";
        const account = await one(
          "SELECT status FROM identkit_accounts WHERE id = ?1",
          grant.accountId,
        );
        if (account?.["status"] !== "active") return "account_inactive";
        const taken = await one(
          "SELECT id FROM identkit_oauth_grants WHERE account_id = ?1 AND client_id = ?2",
          grant.accountId,
          grant.clientId,
        );
        return taken ? "account_client_taken" : "limit_reached";
      },
      async findGrantByRefreshRef(refDigest) {
        // One query: the grant and the status of its account.
        const r = await one(
          `SELECT ${OAUTH_GRANT_COLUMNS_G}, a.status AS account_status
           FROM identkit_oauth_grants g JOIN identkit_accounts a ON a.id = g.account_id
           WHERE g.refresh_ref_digest = ?1`,
          refDigest,
        );
        return r
          ? {
              grant: toOAuthGrant(r),
              accountStatus: oneOf(r["account_status"], ACCOUNT_STATUSES),
            }
          : null;
      },
      async findGrant(id) {
        const r = await one(
          `SELECT ${OAUTH_GRANT_COLUMNS_G}, a.status AS account_status
           FROM identkit_oauth_grants g JOIN identkit_accounts a ON a.id = g.account_id
           WHERE g.id = ?1`,
          id,
        );
        return r
          ? {
              grant: toOAuthGrant(r),
              accountStatus: oneOf(r["account_status"], ACCOUNT_STATUSES),
            }
          : null;
      },
      async rotateGrant(id, expectedGeneration, u, accessToken, pruneBefore) {
        // Atomic: one batch. (1) is the compare-and-set on the generation. (2) inserts the
        // access token only if (1) matched: the new refresh digest is random, so only this
        // rotation can have written it. The rotation won if (2) returned a row. (3) prunes.
        const [, insertedToken] = await db.batch([
          db
            .prepare(
              `UPDATE identkit_oauth_grants
               SET generation = ?3, refresh_ref_digest = ?4, refresh_digest = ?5,
                 refresh_digest_algorithm = ?6, previous_refresh_digest = ?7, refreshed_at = ?8,
                 refresh_expires_at = ?9
               WHERE id = ?1 AND generation = ?2`,
            )
            .bind(
              id,
              expectedGeneration,
              u.generation,
              u.refreshRefDigest,
              u.refreshDigest,
              u.refreshDigestAlgorithm,
              u.previousRefreshDigest,
              ms(u.refreshedAt),
              ms(u.refreshExpiresAt),
            ),
          db
            .prepare(
              `INSERT INTO identkit_oauth_access_tokens (${OAUTH_ACCESS_TOKEN_COLUMNS})
               SELECT ?1, ?2, ?3, ?4, ?5, ?6
               WHERE EXISTS (SELECT 1 FROM identkit_oauth_grants
                             WHERE id = ?2 AND generation = ?7 AND refresh_digest = ?8)
               RETURNING digest`,
            )
            .bind(...oauthAccessTokenValues(accessToken), u.generation, u.refreshDigest),
          db
            .prepare(
              `DELETE FROM identkit_oauth_access_tokens WHERE grant_id = ?1 AND expires_at <= ?2`,
            )
            .bind(id, ms(pruneBefore)),
        ]);
        return batchRows(insertedToken).length === 1;
      },
      async findAccessToken(digest) {
        // One query: the token, its grant and the status of the grant's account.
        const r = await one(
          `SELECT ${OAUTH_GRANT_COLUMNS_G}, t.digest AS token_digest,
             t.generation AS token_generation, t.scopes AS token_scopes,
             t.created_at AS token_created_at, t.expires_at AS token_expires_at,
             a.status AS account_status
           FROM identkit_oauth_access_tokens t
           JOIN identkit_oauth_grants g ON g.id = t.grant_id
           JOIN identkit_accounts a ON a.id = g.account_id
           WHERE t.digest = ?1`,
          digest,
        );
        if (!r) return null;
        const grant = toOAuthGrant(r);
        return {
          token: {
            digest: text(r["token_digest"]),
            grantId: grant.id,
            generation: integer(r["token_generation"]),
            scopes: stringList(r["token_scopes"]),
            createdAt: date(r["token_created_at"]),
            expiresAt: date(r["token_expires_at"]),
          },
          grant,
          accountStatus: oneOf(r["account_status"], ACCOUNT_STATUSES),
        };
      },
      async deleteGrant(id, match, at) {
        // Atomic: one batch, the tombstone and the DELETE ... RETURNING, scoped to the client or
        // the account.
        const column = "clientId" in match ? "client_id" : "account_id";
        const owner = "clientId" in match ? match.clientId : match.accountId;
        const [, deleted] = await db.batch([
          db.prepare(tombstoneGrants(`id = ?1 AND ${column} = ?2`, "?3")).bind(id, owner, ms(at)),
          db
            .prepare(
              `DELETE FROM identkit_oauth_grants WHERE id = ?1 AND ${column} = ?2
               RETURNING ${OAUTH_GRANT_COLUMNS}`,
            )
            .bind(id, owner),
        ]);
        const [r] = batchRows(deleted);
        return r ? toOAuthGrant(r) : null;
      },
      async deleteGrantsForAccount(accountId, at) {
        // One batch: the tombstones, the grants (their access tokens go by foreign key) and the
        // codes.
        const [, grants] = await db.batch([
          db.prepare(tombstoneGrants("account_id = ?1", "?2")).bind(accountId, ms(at)),
          db
            .prepare(
              `DELETE FROM identkit_oauth_grants WHERE account_id = ?1
               RETURNING ${OAUTH_GRANT_COLUMNS}`,
            )
            .bind(accountId),
          db.prepare("DELETE FROM identkit_oauth_codes WHERE account_id = ?1").bind(accountId),
        ]);
        return batchRows(grants).map(toOAuthGrant);
      },
      async listGrants(accountId, at) {
        const rows = await all(
          `SELECT ${OAUTH_GRANT_COLUMNS} FROM identkit_oauth_grants
           WHERE account_id = ?1 AND expires_at > ?2 ORDER BY created_at, id`,
          accountId,
          ms(at),
        );
        return rows.map(toOAuthGrant);
      },
      async purge({ at, unusedBefore, idleBefore, windowBefore }) {
        // One batch, which D1 runs as one transaction. A client delete checks in its own WHERE
        // that the client holds no live grant and no live code, so a grant created before the
        // batch keeps its client, and a grant insert after it fails on the missing client. Each
        // delete of grants or clients follows the tombstone insert with the same WHERE.
        const free = `NOT EXISTS (SELECT 1 FROM identkit_oauth_grants g
                                  WHERE g.client_id = c.id AND g.expires_at > ?1)
          AND NOT EXISTS (SELECT 1 FROM identkit_oauth_codes o
                          WHERE o.client_id = c.id AND o.expires_at > ?1)`;
        const unusedRule = `c.last_used_at IS NULL AND c.created_at < ?2 AND ${free}`;
        const idleRule = `c.last_used_at IS NOT NULL AND c.last_used_at < ?2 AND ${free}`;
        const [, grants, codes, tokens, , unused, , idle, windows] = await db.batch([
          db.prepare(tombstoneGrants("expires_at <= ?1", "?1")).bind(ms(at)),
          db
            .prepare(
              `DELETE FROM identkit_oauth_grants WHERE expires_at <= ?1
               RETURNING ${OAUTH_GRANT_COLUMNS}`,
            )
            .bind(ms(at)),
          db
            .prepare("DELETE FROM identkit_oauth_codes WHERE expires_at <= ?1 RETURNING digest")
            .bind(ms(at)),
          db
            .prepare(
              "DELETE FROM identkit_oauth_access_tokens WHERE expires_at <= ?1 RETURNING digest",
            )
            .bind(ms(at)),
          db.prepare(tombstoneClients(unusedRule, "?1")).bind(ms(at), ms(unusedBefore)),
          db
            .prepare(`DELETE FROM identkit_oauth_clients AS c WHERE ${unusedRule} RETURNING id`)
            .bind(ms(at), ms(unusedBefore)),
          db.prepare(tombstoneClients(idleRule, "?1")).bind(ms(at), ms(idleBefore)),
          db
            .prepare(`DELETE FROM identkit_oauth_clients AS c WHERE ${idleRule} RETURNING id`)
            .bind(ms(at), ms(idleBefore)),
          db
            .prepare(
              `DELETE FROM identkit_oauth_registration_counts WHERE window_start < ?1
               RETURNING key`,
            )
            .bind(ms(windowBefore)),
        ]);
        return {
          clients: [
            ...batchRows(unused).map((r) => ({ id: text(r["id"]), reason: "unused" as const })),
            ...batchRows(idle).map((r) => ({ id: text(r["id"]), reason: "idle" as const })),
          ],
          grants: batchRows(grants).map(toOAuthGrant),
          codes: batchRows(codes).length,
          accessTokens: batchRows(tokens).length,
          registrationWindows: batchRows(windows).length,
        };
      },
      async findImportTombstone(kind, id) {
        const r = await one(
          "SELECT ended_at FROM identkit_oauth_import_tombstones WHERE kind = ?1 AND id = ?2",
          kind,
          id,
        );
        return r ? date(r["ended_at"]) : null;
      },
      async rollBackImport(kind, id, at) {
        if (kind === "grant") {
          // One DELETE, no tombstone. The foreign key removes the grant's access tokens.
          const r = await one(
            "DELETE FROM identkit_oauth_grants WHERE id = ?1 AND source = 'import' RETURNING id",
            id,
          );
          return r === null ? null : [];
        }
        // One batch, as in `deleteClient`: the client gets no tombstone, its grants do. Every
        // statement matches only while the client is an imported one. The foreign keys remove
        // the grants' access tokens and the client's codes.
        const imported =
          "EXISTS (SELECT 1 FROM identkit_oauth_clients WHERE id = ?1 AND source = 'import')";
        const [, grants, client] = await db.batch([
          db.prepare(tombstoneGrants(`client_id = ?1 AND ${imported}`, "?2")).bind(id, ms(at)),
          db
            .prepare(
              `DELETE FROM identkit_oauth_grants WHERE client_id = ?1 AND ${imported}
               RETURNING ${OAUTH_GRANT_COLUMNS}`,
            )
            .bind(id),
          db
            .prepare(
              "DELETE FROM identkit_oauth_clients WHERE id = ?1 AND source = 'import' RETURNING id",
            )
            .bind(id),
        ]);
        return batchRows(client).length === 1 ? batchRows(grants).map(toOAuthGrant) : null;
      },
    },
  };

  // Atomic: one UPDATE that matches only a verification in the expected state.
  async function finish(
    id: string,
    from: "pending" | "processing",
    u: Pick<
      VerificationRecord,
      "status" | "assuranceLevel" | "evidenceReference" | "failureReason" | "completedAt"
    >,
  ): Promise<boolean> {
    const row = await one(
      `UPDATE identkit_verifications
       SET status = ?3, assurance_level = ?4, evidence_reference = ?5, failure_reason = ?6,
         completed_at = ?7
       WHERE id = ?1 AND status = ?2
       RETURNING id`,
      id,
      from,
      u.status,
      u.assuranceLevel,
      u.evidenceReference,
      u.failureReason,
      msOrNull(u.completedAt),
    );
    return row !== null;
  }
}
