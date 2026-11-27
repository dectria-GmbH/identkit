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

/** How an OAuth client authenticates at the token and revocation endpoints (RFC 7591). */
export type OAuthClientAuthMethod = "none" | "client_secret_basic" | "client_secret_post";

/**
 * How a stored OAuth secret digest was made. `hmac-sha256`: the keyed HMAC of the
 * `SecretHasher`, for every secret that identkit issues. `sha256`: an unkeyed SHA-256 hex digest,
 * only for client secrets and refresh tokens imported from an earlier system.
 */
export type OAuthDigestAlgorithm = "hmac-sha256" | "sha256";

/** `dynamic`: by dynamic client registration (RFC 7591). `import`: by `oauth.importClient`. */
export type OAuthClientSource = "dynamic" | "import";

/** `created`: by a code exchange. `import`: by `oauth.importGrant`. */
export type OAuthGrantSource = "created" | "import";

/**
 * What an import tombstone names. Every built-in store keeps one for each imported grant and
 * each imported client that ended, so that a later import of the same id answers `revoked`.
 */
export type OAuthImportTombstoneKind = "grant" | "client";

/** A registered OAuth client. The store holds only the digest of its secret. */
export interface OAuthClientRecord {
  /** The public `client_id`. */
  id: string;
  /** Lowercase hex digest of the client secret; null for a public client. */
  secretDigest: string | null;
  secretDigestAlgorithm: OAuthDigestAlgorithm | null;
  authMethod: OAuthClientAuthMethod;
  /** As registered, for example `["authorization_code", "refresh_token"]`. */
  grantTypes: string[];
  /** Exact strings, as registered. */
  redirectUris: string[];
  /** The registered `client_name` after identkit removed unsafe characters, or null. */
  name: string | null;
  source: OAuthClientSource;
  createdAt: Date;
  /** Written at an approval (at most twice a day) and a refresh (at most once a day). */
  lastUsedAt: Date | null;
}

/**
 * The consent of one account for one client. At most one per (account, client). Ending it is a
 * delete: its access tokens go with it, and every token of it stops at once.
 */
export interface OAuthGrantRecord {
  id: string;
  accountId: string;
  clientId: string;
  /** Opaque scope strings, stored as granted. */
  scopes: string[];
  /** The resource (RFC 8707) that every token of the grant is for. */
  resource: string;
  createdAt: Date;
  /** Absolute end of the grant. */
  expiresAt: Date;
  /** Counts the refresh rotations; the first tokens have generation 1. */
  generation: number;
  /** Digest of the fixed part of the refresh token. Unique; null until the grant has one. */
  refreshRefDigest: string | null;
  /** Digest of the current refresh token; null if the client gets none. */
  refreshDigest: string | null;
  refreshDigestAlgorithm: OAuthDigestAlgorithm | null;
  /** Digest of the refresh token before the current one, for the race grace. */
  previousRefreshDigest: string | null;
  /** Time of the last rotation, or null. */
  refreshedAt: Date | null;
  refreshExpiresAt: Date | null;
  /** Digest of the authorization code that created the grant. Unique. */
  codeDigest: string | null;
  source: OAuthGrantSource;
}

/** One issued access token. The store holds only its digest. */
export interface OAuthAccessTokenRecord {
  /** Lowercase hex digest of the whole token. Unique. */
  digest: string;
  grantId: string;
  /** The grant generation that issued it. */
  generation: number;
  /** The token's own scopes: the grant's, or fewer. */
  scopes: string[];
  createdAt: Date;
  expiresAt: Date;
}

/** An authorization code in flight. Single use; the store holds only its digest. */
export interface OAuthCodeRecord {
  digest: string;
  clientId: string;
  accountId: string;
  /** The redirect URI of the authorization request, exactly. */
  redirectUri: string;
  /**
   * True if the authorization request named `redirect_uri`. Only then must the token request
   * name it too (RFC 6749 section 4.1.3); a token request that names it must match either way.
   */
  redirectUriExplicit: boolean;
  /** The S256 code challenge (RFC 7636). */
  codeChallenge: string;
  resource: string;
  scopes: string[];
  createdAt: Date;
  expiresAt: Date;
}

/** A grant with the status of its account, read in one query. */
export interface OAuthGrantLookup {
  grant: OAuthGrantRecord;
  accountStatus: AccountStatus;
}

/** An access token with its grant and the status of the grant's account, read in one query. */
export interface OAuthAccessTokenLookup {
  token: OAuthAccessTokenRecord;
  grant: OAuthGrantRecord;
  accountStatus: AccountStatus;
}

/** The fields that a refresh rotation writes. */
export interface OAuthGrantRotation {
  /** The new generation: the expected one plus one. */
  generation: number;
  refreshRefDigest: string;
  refreshDigest: string;
  refreshDigestAlgorithm: OAuthDigestAlgorithm;
  previousRefreshDigest: string | null;
  refreshedAt: Date;
  refreshExpiresAt: Date;
}

/**
 * `limit_reached`: the account holds `maxOtherGrants` or more live grants of other clients.
 * `account_inactive`: the account is missing or not active.
 */
export type InsertOAuthGrantResult =
  | { status: "inserted"; replaced: OAuthGrantRecord | null }
  | { status: "limit_reached" }
  | { status: "account_inactive" };

/**
 * `id_taken`: a grant with this id exists. `account_client_taken`: the account holds a grant of
 * this client. `revoked`: a tombstone names the id. Others as for `InsertOAuthGrantResult`.
 */
export type ImportOAuthGrantStoreResult =
  | "inserted"
  | "id_taken"
  | "account_client_taken"
  | "limit_reached"
  | "account_inactive"
  | "revoked";

/** What `oauth.purge` removed in the store. */
export interface OAuthPurgeStoreResult {
  clients: { id: string; reason: "unused" | "idle" }[];
  /** Grants past their `expiresAt`. */
  grants: OAuthGrantRecord[];
  codes: number;
  accessTokens: number;
  registrationWindows: number;
}

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
  /**
   * The OAuth authorization server. Optional, so a store written for an earlier release still
   * fits the type; `createIdentkit` throws `NotConfiguredError` if the `oauth` option is set and
   * the store has no `oauth`. The built-in stores implement it. A grant delete removes its
   * access tokens; a client delete removes its grants and codes; an account delete removes its
   * grants and codes.
   *
   * Import tombstones: every call that deletes a grant or a client whose `source` is `import`
   * writes a tombstone of its kind and id, atomically with the delete, with the time `at` of the
   * call. Only `rollBackImport` deletes the rolled-back row itself without one. Inserts and
   * imports refuse an id that a tombstone names, so an ended imported grant or client never
   * comes back by a new import.
   */
  oauth?: {
    /**
     * Inserts the client unless a client with its id exists (`id_taken`) or a client tombstone
     * names the id (`revoked`). Against a concurrent delete that writes the tombstone, the insert
     * is either refused or deleted by it.
     */
    insertClient(client: OAuthClientRecord): Promise<"inserted" | "id_taken" | "revoked">;
    findClient(id: string): Promise<OAuthClientRecord | null>;
    /**
     * Atomically sets `lastUsedAt` to `at` if it is null or at most `notAfter`. Returns false
     * otherwise, so of concurrent calls one writes.
     */
    markClientUsed(id: string, at: Date, notAfter: Date): Promise<boolean>;
    /**
     * Compare-and-set of the client secret digest: replaces `oldDigest` with the keyed
     * `newDigest` (algorithm `hmac-sha256`). Returns false if the stored digest is not `oldDigest`.
     */
    upgradeClientSecret(id: string, oldDigest: string, newDigest: string): Promise<boolean>;
    /**
     * Atomically deletes the client, its grants and its codes. Returns the deleted grants, or
     * null if the client does not exist. A grant inserted concurrently is either returned or
     * refused (its client is gone); it is never deleted unreturned.
     */
    deleteClient(id: string, at: Date): Promise<OAuthGrantRecord[] | null>;
    /**
     * Counts one registration for each key in order, in the window that starts at
     * `windowStart`. Stops at the first key whose count is at `max` already and returns it;
     * the keys before it keep their count. No key ever exceeds its `max`, also under
     * concurrent calls.
     */
    reserveRegistration(input: {
      keys: readonly { key: string; max: number }[];
      windowStart: Date;
    }): Promise<"reserved" | { limitReached: string }>;
    insertCode(code: OAuthCodeRecord): Promise<void>;
    /** Atomically removes and returns the code. Of concurrent calls exactly one gets it. */
    consumeCode(digest: string): Promise<OAuthCodeRecord | null>;
    /** Atomically deletes and returns the grant that the code created, or null. */
    endGrantByCode(codeDigest: string, at: Date): Promise<OAuthGrantRecord | null>;
    /**
     * Atomically: if the account is active and holds fewer than `limit.maxOtherGrants` live
     * grants (`expiresAt` after `limit.at`) of other clients, deletes the account's grant of
     * this client (returned as `replaced`), inserts the grant and its first access token.
     * Concurrent inserts for one account never exceed the limit. Throws if the client does not
     * exist. Against a concurrent `deleteClient`, one of the two waits for the other: the grant
     * is either returned by that delete or refused for its missing client.
     */
    insertGrant(
      grant: OAuthGrantRecord,
      firstAccessToken: OAuthAccessTokenRecord,
      limit: { maxOtherGrants: number; at: Date },
    ): Promise<InsertOAuthGrantResult>;
    /**
     * As `insertGrant`, without an access token, and it never replaces a grant. Refuses an id
     * that a grant tombstone names (`revoked`), also one written by a concurrent delete.
     */
    importGrant(
      grant: OAuthGrantRecord,
      limit: { maxOtherGrants: number; at: Date },
    ): Promise<ImportOAuthGrantStoreResult>;
    findGrantByRefreshRef(refDigest: string): Promise<OAuthGrantLookup | null>;
    findGrant(id: string): Promise<OAuthGrantLookup | null>;
    /**
     * Compare-and-set on the generation: if the grant still has `expectedGeneration`, writes
     * `update`, inserts `accessToken` and deletes the grant's access tokens that expire at or
     * before `pruneBefore`. Of concurrent rotations with one expected generation exactly one
     * returns true, and only its access token exists. `update.refreshDigest` is new for each
     * call (a fresh random token); the D1 store uses it to tell which rotation won.
     */
    rotateGrant(
      id: string,
      expectedGeneration: number,
      update: OAuthGrantRotation,
      accessToken: OAuthAccessTokenRecord,
      pruneBefore: Date,
    ): Promise<boolean>;
    findAccessToken(digest: string): Promise<OAuthAccessTokenLookup | null>;
    /**
     * Atomically deletes the grant if it belongs to the client or the account, and returns it.
     * A client can end only its own grants, an account only its own.
     */
    deleteGrant(
      id: string,
      match: { clientId: string } | { accountId: string },
      at: Date,
    ): Promise<OAuthGrantRecord | null>;
    /**
     * Deletes every grant and code of the account and returns the grants, atomically: a failure
     * deletes nothing, so a retry still returns every grant. Idempotent.
     */
    deleteGrantsForAccount(accountId: string, at: Date): Promise<OAuthGrantRecord[]>;
    /** The grants of the account with `expiresAt` after `at`, oldest first. */
    listGrants(accountId: string, at: Date): Promise<OAuthGrantRecord[]>;
    /**
     * Deletes grants, codes and access tokens that expire at or before `at`; clients never used
     * (`lastUsedAt` null) and created before `unusedBefore`; clients last used before
     * `idleBefore`; and registration windows that start before `windowBefore`. Never deletes a
     * client that holds a live grant or a live code, also not one whose grant a concurrent
     * insert or import commits: that grant either keeps the client or is refused.
     */
    purge(input: {
      at: Date;
      unusedBefore: Date;
      idleBefore: Date;
      windowBefore: Date;
    }): Promise<OAuthPurgeStoreResult>;
    /** The time of the tombstone of this kind and id, or null if there is none. */
    findImportTombstone(kind: OAuthImportTombstoneKind, id: string): Promise<Date | null>;
    /**
     * Deletes an imported grant or client whose import the audit sink refused, without a
     * tombstone for it: for the audit trail the import did not happen, so a retry may import it
     * again. Matches only a row whose `source` is `import`. A client delete takes its grants and
     * codes, and returns the grants; these did happen, so each imported one gets its tombstone
     * with the time `at`, atomically with the delete. Returns null if no such row exists, and
     * an empty list for a grant.
     */
    rollBackImport(
      kind: OAuthImportTombstoneKind,
      id: string,
      at: Date,
    ): Promise<OAuthGrantRecord[] | null>;
  };
}
