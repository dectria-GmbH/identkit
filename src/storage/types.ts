import type { AuthMethod, StepUpMethod } from "../config.js";
import type { TotpAlgorithm, TotpDigits } from "../totp-core.js";

export type AccountStatus = "active" | "disabled";
export type AssuranceLevel = "low" | "substantial" | "high";

export interface AccountRecord {
  id: string;
  /** Normalized e-mail address. Unique: one address belongs to at most one account. */
  email: string;
  /** Random WebAuthn user handle (base64url). Not derived from the id or the address. */
  webauthnUserId: string;
  status: AccountStatus;
  createdAt: Date;
  /** Keyed hash of the verified person key. Unique: one person has at most one account. */
  personKeyDigest: string | null;
  assuranceLevel: AssuranceLevel | null;
  identityVerifiedAt: Date | null;
}

export type OtpPurpose = "sign_in" | "step_up";

export interface OtpFlowRecord {
  id: string;
  purpose: OtpPurpose;
  email: string;
  addressDigest: string;
  /** Session the code belongs to. Set for `step_up`, null for `sign_in`. */
  sessionId: string | null;
  codeDigest: string;
  createdAt: Date;
  expiresAt: Date;
  attempts: number;
  maxAttempts: number;
  consumedAt: Date | null;
  supersededAt: Date | null;
}

export type ReserveAttemptResult =
  { status: "reserved"; attempts: number } | { status: "exhausted" } | { status: "unavailable" };

export interface ThrottleResult {
  allowed: boolean;
  lockedUntil: Date | null;
  /** True if this call caused the lock. */
  lockedNow: boolean;
}

export interface ThrottleRule {
  /** Attempts per window. */
  maxFailures: number;
  windowSeconds: number;
  /** Attempts since the last reset, across windows. */
  maxConsecutiveFailures: number;
  lockSeconds: number;
  maxLockSeconds: number;
}

export type SessionState = "pending_second_factor" | "complete";

export interface StepUpRecord {
  method: StepUpMethod;
  at: Date;
}

export interface SessionRecord {
  id: string;
  accountId: string;
  tokenDigest: string;
  state: SessionState;
  authMethods: AuthMethod[];
  createdAt: Date;
  lastSeenAt: Date;
  absoluteExpiresAt: Date;
  stepUp: StepUpRecord | null;
  revokedAt: Date | null;
  revokeReason: string | null;
}

export interface SessionUpdate {
  state: SessionState;
  authMethods: AuthMethod[];
  stepUp: StepUpRecord | null;
  lastSeenAt: Date;
  absoluteExpiresAt: Date;
}

export interface CredentialRecord {
  /** Credential id (base64url). */
  id: string;
  accountId: string;
  /** COSE public key. */
  publicKey: Uint8Array;
  counter: number;
  transports: string[];
  deviceType: "singleDevice" | "multiDevice";
  backedUp: boolean;
  createdAt: Date;
  lastUsedAt: Date | null;
  /**
   * When the registration that created it completed. A credential with null here is still
   * being registered: the store hides it from every read, so it cannot be used yet.
   */
  activatedAt: Date | null;
}

/** `approval_code`: a pending approval that waits for a TOTP code, not a WebAuthn challenge. */
export type ChallengePurpose =
  "registration" | "sign_in" | "second_factor" | "step_up" | "approval" | "approval_code";

export interface ChallengeRecord {
  id: string;
  /** Keyed hash of the challenge string (base64url) that the client signs. */
  challengeDigest: string;
  purpose: ChallengePurpose;
  accountId: string | null;
  sessionId: string | null;
  enrollmentTokenDigest: string | null;
  /** For approvals: SHA-256 hex of the payload that the challenge commits to. */
  payloadHash: string | null;
  /** For approvals: random nonce (base64url) mixed into the challenge. */
  nonce: string | null;
  createdAt: Date;
  expiresAt: Date;
}

export interface TotpFactorRecord {
  id: string;
  accountId: string;
  /** The secret, sealed by the `SecretSealer` for this factor id and account. Never plain. */
  sealedSecret: string;
  algorithm: TotpAlgorithm;
  digits: TotpDigits;
  createdAt: Date;
  /** Session that started the enrolment. Only that session can confirm it. */
  enrolmentSessionId: string | null;
  /** Null until a first valid code confirmed the enrolment. The store hides pending factors. */
  activatedAt: Date | null;
  /** Latest accepted time step. A step at or below it is never accepted again. */
  lastUsedStep: number | null;
  lastUsedAt: Date | null;
}

export interface EnrollmentTokenRecord {
  tokenDigest: string;
  accountId: string;
  createdAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
  /** Set when a newer token or an administrative revocation replaced it. Never cleared. */
  revokedAt: Date | null;
}

/** `processing`: the vendor reported success and identkit is linking the person. */
export type VerificationStatus =
  "pending" | "processing" | "verified" | "failed" | "expired" | "conflict";

export interface VerificationRecord {
  id: string;
  accountId: string;
  vendorReference: string | null;
  status: VerificationStatus;
  assuranceLevel: AssuranceLevel | null;
  evidenceReference: string | null;
  failureReason: string | null;
  createdAt: Date;
  expiresAt: Date;
  completedAt: Date | null;
}

/** Kind of an external identity provider. It decides the shape of the link key. */
export type OidcProviderKind = "microsoft" | "google" | "oidc";

/** `sign_in`: bound at a first sign-in. `import`: recorded by `oidc.importLink`. */
export type OidcLinkSource = "sign_in" | "import";

/**
 * Link between an account and a subject at an external OpenID Connect provider. The link key
 * identifies the subject, never the e-mail address: Microsoft (tenant id, object id), Google
 * (subject), any other provider (issuer, subject).
 */
export interface OidcLinkRecord {
  id: string;
  accountId: string;
  /** Canonical, unique: a JSON array such as `["microsoft","<tid>","<oid>"]`. */
  linkKey: string;
  provider: OidcProviderKind;
  /** The issuer of the subject's ID tokens. For Microsoft the tenant's v2.0 issuer. */
  issuer: string;
  /** Microsoft: the object id (`oid`). Google and others: `sub`. */
  subject: string;
  /** Microsoft tenant id (`tid`); null for other providers. */
  tenantId: string | null;
  source: OidcLinkSource;
  createdAt: Date;
}

/**
 * `link_taken`: a link with this key exists (for this or another account). `account_has_link`:
 * the insert was exclusive and the account already has a link.
 */
export type InsertOidcLinkResult = "inserted" | "link_taken" | "account_has_link";

/**
 * How the stored digest of a personal API token was made. `hmac-sha256`: the keyed HMAC of the
 * `SecretHasher` (purpose `api-token`), for every token that identkit creates. `sha256`: an
 * unkeyed SHA-256 hex digest of the whole token, only for tokens imported from an earlier
 * system. It is weaker: whoever reads the table can test guesses offline without a key.
 */
export type ApiTokenDigestAlgorithm = "hmac-sha256" | "sha256";

/** `created`: by `apiTokens.create`. `import`: by `apiTokens.import`. */
export type ApiTokenSource = "created" | "import";

/** A personal API token. The store holds only its digest, never the token. */
export interface ApiTokenRecord {
  id: string;
  accountId: string;
  /** A label the owner chose, at most 64 characters. */
  name: string;
  /** Opaque scope strings, stored and returned as given. */
  scopes: string[];
  /** Lowercase hex digest of the whole token. Unique. */
  digest: string;
  digestAlgorithm: ApiTokenDigestAlgorithm;
  source: ApiTokenSource;
  createdAt: Date;
  expiresAt: Date;
  /** Updated at most once per `lastUsedIntervalSeconds`. */
  lastUsedAt: Date | null;
  revokedAt: Date | null;
  revokeReason: string | null;
}

/** A token found by digest, with the status of its account from the same read. */
export interface ApiTokenLookup {
  record: ApiTokenRecord;
  accountStatus: AccountStatus;
}

/**
 * `limit_reached`: the account has `maxActive` active tokens (not revoked, not expired) already.
 * `digest_taken`: a token with this digest exists, revoked or not, for any account.
 */
export type InsertApiTokenResult = "inserted" | "limit_reached" | "digest_taken";

export type LinkPersonResult =
  "linked" | "already_linked" | "person_linked_elsewhere" | "account_has_other_person";

/**
 * Storage port. Every method that guards a security rule is atomic on its own, so two
 * concurrent calls cannot both pass a single-use or limit check.
 */
export interface IdentkitStore {
  accounts: {
    insert(account: AccountRecord): Promise<"inserted" | "email_taken">;
    findById(id: string): Promise<AccountRecord | null>;
    findByEmail(email: string): Promise<AccountRecord | null>;
    setStatus(id: string, status: AccountStatus): Promise<void>;
    /** Links a person to an account. Fails if the person is linked to another account. */
    linkPerson(
      id: string,
      personKeyDigest: string,
      assuranceLevel: AssuranceLevel,
      at: Date,
    ): Promise<LinkPersonResult>;
  };
  otp: {
    /**
     * Atomically checks the send cooldown for `gateKey` and, if it elapsed, records `at`
     * as the last send. `claimed` is false while the cooldown runs.
     */
    claimSendSlot(
      gateKey: string,
      at: Date,
      cooldownSeconds: number,
    ): Promise<{ claimed: boolean; nextAllowedAt: Date }>;
    /** Marks all open flows of the address and purpose as superseded. */
    supersedeOpen(addressDigest: string, purpose: OtpPurpose, at: Date): Promise<void>;
    insert(flow: OtpFlowRecord): Promise<void>;
    findById(id: string): Promise<OtpFlowRecord | null>;
    /**
     * Atomically counts one attempt if the flow is open (not consumed, not superseded,
     * not expired at `at`) and below its attempt limit.
     */
    reserveAttempt(id: string, at: Date): Promise<ReserveAttemptResult>;
    /** Atomically marks an open flow consumed. Returns false if it was not open. */
    consume(id: string, at: Date): Promise<boolean>;
  };
  throttle: {
    /**
     * Atomically counts one attempt for `key` under `rule`: both limits, the timed release and
     * the doubling lock. A custom store must call `applyThrottle` (exported by identkit) on the
     * stored state inside its own atomic section and save every field of the result; a store
     * that skips a field skips a limit. For a key without stored state, pass `null`. Returns
     * the `result` of `applyThrottle`.
     */
    reserve(key: string, at: Date, rule: ThrottleRule): Promise<ThrottleResult>;
    /** The stored `lockedUntil` while `at` is before it, else null. Writes nothing. */
    peek(key: string, at: Date): Promise<Date | null>;
    /**
     * Removes every field of the key: attempts, window, lock, lock count and consecutive count.
     * A reset that keeps the consecutive count or the lock count leaves a success or an unlock
     * incomplete.
     */
    reset(key: string): Promise<void>;
  };
  sessions: {
    insert(session: SessionRecord): Promise<void>;
    findByTokenDigest(digest: string): Promise<SessionRecord | null>;
    findById(id: string): Promise<SessionRecord | null>;
    touch(id: string, at: Date): Promise<void>;
    /**
     * Atomically replaces the token of a live session. Returns false if the session is
     * revoked or its token is no longer `oldDigest`.
     */
    rotate(
      id: string,
      oldDigest: string,
      newDigest: string,
      update: SessionUpdate,
    ): Promise<boolean>;
    /** Returns true if this call revoked the session. */
    revoke(id: string, at: Date, reason: string): Promise<boolean>;
    /** Revokes all live sessions of the account except `exceptId`. Returns their ids. */
    revokeAllForAccount(
      accountId: string,
      at: Date,
      reason: string,
      exceptId?: string,
    ): Promise<string[]>;
  };
  credentials: {
    /** Inserts as given. An id that exists, active or not, is a duplicate. */
    insert(credential: CredentialRecord): Promise<"inserted" | "duplicate">;
    /**
     * Marks the pending credential with this id, account and public key active. Returns false
     * if it is gone or another registration's row now holds the id.
     */
    activate(id: string, accountId: string, publicKey: Uint8Array, at: Date): Promise<boolean>;
    /** Active credentials only. */
    findById(id: string): Promise<CredentialRecord | null>;
    /** Active credentials only. */
    listByAccount(accountId: string): Promise<CredentialRecord[]>;
    /** Compare-and-set of the signature counter of an active credential. */
    updateCounter(id: string, expected: number, next: number, usedAt: Date): Promise<boolean>;
    /** Deletes the credential of the account, pending or active; with `publicKey` only that row. */
    delete(id: string, accountId: string, publicKey?: Uint8Array): Promise<boolean>;
  };
  challenges: {
    insert(challenge: ChallengeRecord): Promise<void>;
    /**
     * Atomically removes and returns the challenge with this digest and purpose. A challenge
     * of another purpose stays, so one ceremony cannot destroy another one's challenge.
     */
    consumeByDigest(digest: string, purpose: ChallengePurpose): Promise<ChallengeRecord | null>;
  };
  totp: {
    insert(factor: TotpFactorRecord): Promise<void>;
    /** A pending (not yet confirmed) factor by id. */
    findPending(id: string): Promise<TotpFactorRecord | null>;
    /** The active factor of the account. An account has at most one. */
    findActive(accountId: string): Promise<TotpFactorRecord | null>;
    /**
     * Atomically activates the pending factor and records `step` as its latest used step.
     * Returns false if it is gone, already active, or the account has another active factor.
     */
    activate(id: string, accountId: string, step: number, at: Date): Promise<boolean>;
    /**
     * Atomically records `step` as the latest used step of the active factor, only if it is
     * above the stored one. Returns false otherwise, so a time step is accepted once.
     */
    recordStep(id: string, accountId: string, step: number, at: Date): Promise<boolean>;
    /** Deletes the factor of the account, pending or active. */
    delete(id: string, accountId: string): Promise<boolean>;
    /**
     * Deletes every factor of the account, pending and active, and returns how many went.
     * A pending factor deleted here can no longer be activated.
     */
    deleteAllForAccount(accountId: string): Promise<number>;
    /** Compare-and-set of the sealed secret, for key rotation. */
    replaceSealedSecret(id: string, expected: string, next: string): Promise<boolean>;
  };
  enrollment: {
    /**
     * Atomically revokes every earlier token of the account, also consumed ones, and inserts
     * this one. Two concurrent calls leave at most one token that is not revoked.
     */
    issue(token: EnrollmentTokenRecord): Promise<void>;
    findByDigest(digest: string): Promise<EnrollmentTokenRecord | null>;
    /** Atomically consumes an unexpired, unconsumed token that is not revoked. */
    consume(digest: string, at: Date): Promise<EnrollmentTokenRecord | null>;
    /**
     * Revokes every token of the account that is not revoked yet, also consumed ones, and
     * returns how many it revoked. Serialize it with `issue` for the same account (the
     * PostgreSQL store locks the account row); otherwise a token issued at the same moment
     * can stay usable.
     */
    revokeAllForAccount(accountId: string, at: Date): Promise<number>;
  };
  verifications: {
    insert(record: VerificationRecord): Promise<void>;
    findById(id: string): Promise<VerificationRecord | null>;
    findByVendorReference(reference: string): Promise<VerificationRecord | null>;
    setVendorReference(id: string, reference: string): Promise<void>;
    /** Moves a pending verification to `processing`. Returns false if it was not pending. */
    claim(id: string): Promise<boolean>;
    /** Moves a processing verification to a final state. Returns false if it was not processing. */
    finalize(
      id: string,
      update: Pick<
        VerificationRecord,
        "status" | "assuranceLevel" | "evidenceReference" | "failureReason" | "completedAt"
      >,
    ): Promise<boolean>;
    /** Moves a pending verification to a final state. Returns false if it was not pending. */
    complete(
      id: string,
      update: Pick<
        VerificationRecord,
        "status" | "assuranceLevel" | "evidenceReference" | "failureReason" | "completedAt"
      >,
    ): Promise<boolean>;
  };
  /**
   * Links to external OpenID Connect subjects. Optional, so a store written for an earlier
   * release still fits the type; `createIdentkit` throws `NotConfiguredError` if the `oidc`
   * option is set and the store has no `oidcLinks`. The built-in stores implement it.
   */
  oidcLinks?: {
    /**
     * Atomically inserts the link unless a link with its key exists (`link_taken`). With
     * `exclusive`, also unless the account has any link (`account_has_link`); two concurrent
     * exclusive inserts for one account leave at most one link.
     */
    insert(link: OidcLinkRecord, options: { exclusive: boolean }): Promise<InsertOidcLinkResult>;
    findByKey(linkKey: string): Promise<OidcLinkRecord | null>;
    /** The links of the account, oldest first. */
    listByAccount(accountId: string): Promise<OidcLinkRecord[]>;
    /** Deletes the link of the account. Returns false if there is none with this id. */
    delete(id: string, accountId: string): Promise<boolean>;
  };
  /**
   * Personal API tokens. Optional, so a store written for an earlier release still fits the
   * type; `createIdentkit` throws `NotConfiguredError` if the `apiTokens` option is set and the
   * store has no `apiTokens`. The built-in stores implement it.
   */
  apiTokens?: {
    /**
     * Atomically inserts the token unless a token with its digest exists (`digest_taken`) or
     * the account has `limit.maxActive` or more active tokens at `limit.at` (`limit_reached`).
     * Active means not revoked and `expiresAt` after `limit.at`. Concurrent inserts for one
     * account never leave more than `limit.maxActive` active tokens.
     */
    insert(
      token: ApiTokenRecord,
      limit: { maxActive: number; at: Date },
    ): Promise<InsertApiTokenResult>;
    /**
     * The tokens whose digest is one of `digests`, revoked and expired ones included, each with
     * the status of its account, read in one query. identkit passes at most two digests.
     */
    findByDigests(digests: readonly string[]): Promise<ApiTokenLookup[]>;
    /** The tokens of the account that are not revoked, expired ones included, oldest first. */
    listByAccount(accountId: string): Promise<ApiTokenRecord[]>;
    /**
     * Atomically sets `lastUsedAt` to `at` if the token is not revoked and its `lastUsedAt` is
     * null or at most `notAfter`. Returns false otherwise, so of concurrent calls one writes.
     */
    markUsed(id: string, at: Date, notAfter: Date): Promise<boolean>;
    /** Revokes the token of the account. Returns true if this call revoked it. */
    revoke(id: string, accountId: string, at: Date, reason: string): Promise<boolean>;
    /** Revokes every token of the account that is not revoked yet. Returns their ids. */
    revokeAllForAccount(accountId: string, at: Date, reason: string): Promise<string[]>;
    /** Deletes the token of the account, for a rollback. Returns false if it is gone. */
    delete(id: string, accountId: string): Promise<boolean>;
  };
}
