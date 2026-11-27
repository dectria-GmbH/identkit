import { createHash } from "node:crypto";
import { randomBytes, toBase64Url } from "./bytes.js";
import { addSeconds } from "./clock.js";
import type { ApprovalEvidenceLevel } from "./config.js";
import type { Context } from "./context.js";
import { digestsEqual, isTokenShaped, randomToken, type SecretHasher } from "./crypto.js";
import { InvalidArgumentError, MethodNotAllowedError } from "./errors.js";
import type { PasskeyCore } from "./passkey-core.js";
import type { SessionInternals } from "./sessions.js";
import type { TotpEngine } from "./totp.js";
import {
  authenticationOptions,
  readClientChallenge,
  readClientField,
  verifyAssertion,
  type AuthenticationResponseJSON,
  type PasskeyRequestOptions,
  type RelyingParty,
} from "./webauthn.js";

const PAYLOAD_HASH_PATTERN = /^[0-9a-f]{64}$/;
const APPROVAL_DOMAIN = "identkit/approval/v1";
const LEVELS: readonly ApprovalEvidenceLevel[] = ["signature", "code-confirmation"];

/**
 * Level `signature`: a proof that one person approved one payload with one passkey. A
 * verifier with the credential's public key can check it again later with
 * `checkApprovalEvidence`.
 */
export interface ApprovalProof {
  version: 1;
  level: "signature";
  accountId: string;
  credentialId: string;
  /** SHA-256 of the approved payload, lowercase hex. */
  payloadHash: string;
  /** Random value that, with the payload hash, determines the signed challenge. */
  nonce: string;
  challenge: string;
  rpId: string;
  origin: string;
  counter: number;
  verifiedAt: string;
  assertion: AuthenticationResponseJSON["response"];
}

/**
 * Level `code-confirmation`: a server-side record that the session's account entered a
 * valid TOTP code for one pending approval of this payload hash.
 *
 * What this level does NOT give:
 * - The code is not bound to the payload. It shows only that someone with the account's
 *   TOTP secret entered a current code while this approval was pending; the person may not
 *   have seen the payload.
 * - The TOTP secret is held by the server too, so the server (or anyone who reads its
 *   sealed store and key) could produce the same record.
 * - A third party cannot check it. `mac` is an HMAC with the deployment's `SecretHasher`
 *   key: it shows only that this deployment wrote the record and nobody changed it since.
 *   `checkApprovalEvidence` needs that key, rejects a record whose HMAC does not match, and
 *   reports a matching one as `recorded_not_independently_verifiable`, never as `verified`.
 *   It is evidence, not a proof.
 *
 * The record holds no code and no secret.
 */
export interface CodeConfirmationEvidence {
  version: 1;
  level: "code-confirmation";
  accountId: string;
  /** SHA-256 of the approved payload, lowercase hex. */
  payloadHash: string;
  /** When the server accepted the code (ISO 8601). */
  recordedAt: string;
  /** The TOTP time step that was accepted and consumed. */
  timeStep: number;
  /** HMAC (via `SecretHasher`, purpose `approval-evidence`) over the fields above. */
  mac: string;
}

/** Every approval evidence carries its `level`, so a consumer can show and report it. */
export type ApprovalEvidence = ApprovalProof | CodeConfirmationEvidence;

export type StartApprovalResult =
  | { status: "ok"; level: "signature"; options: PasskeyRequestOptions }
  | { status: "ok"; level: "code-confirmation"; approvalId: string; expiresAt: Date }
  | { status: "denied"; reason: "no_session" | "no_passkey" | "no_totp" | "no_factor" };

/**
 * `evidence.level` comes from the pending approval that `start` stored on the server, never
 * from the verify input. Check it (or pass `levels`) before you use level-specific fields or
 * show the evidence as a signature.
 */
export type VerifyApprovalResult =
  | { status: "approved"; evidence: ApprovalProof }
  | { status: "approved"; evidence: CodeConfirmationEvidence }
  | { status: "failed"; reason: "no_session" | "invalid" | "locked" };

export interface ApprovalStartInput {
  sessionToken: string;
  payloadHash: string;
  /**
   * Narrows the policy's `approvalEvidenceLevels` for this call; it can never widen them. Set
   * it from your own server code, for example `["signature"]` for a high-value action, never
   * from client input.
   */
  levels?: ApprovalEvidenceLevel[];
}

interface ApprovalVerifyBase {
  sessionToken: string;
  payloadHash: string;
  /** Narrows the accepted levels for this call, like `start`. Set it from server code. */
  levels?: ApprovalEvidenceLevel[];
}

/** Completes a pending approval: with a passkey `response`, or with `approvalId` and `code`. */
export type ApprovalVerifyInput =
  | (ApprovalVerifyBase & { response: AuthenticationResponseJSON })
  | (ApprovalVerifyBase & {
      /** The `approvalId` that `start` returned. */
      approvalId: string;
      /** A current TOTP code of the session's account. */
      code: string;
    });

export interface Approvals {
  /**
   * Starts one approval of `payloadHash` for the session's account. identkit picks the level:
   * the strongest one that the policy and `levels` both allow and the account can use. That
   * is `signature` (a passkey challenge that commits to the payload hash) if the account has a
   * passkey, else `code-confirmation` (a pending approval for a TOTP code). Throws
   * `MethodNotAllowedError` if the policy and `levels` leave no level.
   */
  start(input: ApprovalStartInput): Promise<StartApprovalResult>;
  /**
   * Completes the pending approval. The level of the evidence is the level of the pending
   * approval stored by `start`, and it must still be allowed by the policy and `levels`.
   * - With `response`: verifies the signed challenge. Succeeds only for the same payload
   *   hash, the same session, a passkey of the session's account, and a challenge not used
   *   before.
   * - With `approvalId` and `code`: consumes the pending approval (one attempt) and the code's
   *   time step, and returns a recorded evidence. Succeeds only for the same payload hash,
   *   session and account.
   * Input with both or neither form throws `InvalidArgumentError`.
   */
  verify(input: ApprovalVerifyInput): Promise<VerifyApprovalResult>;
}

/**
 * The challenge for an approval: SHA-256 over a domain label, the nonce, the payload hash
 * and the account id. The signature therefore covers who approves what.
 */
export function approvalChallenge(nonce: string, payloadHash: string, accountId: string): string {
  return createHash("sha256")
    .update(`${APPROVAL_DOMAIN}\u0000${nonce}\u0000${payloadHash}\u0000${accountId}`, "utf8")
    .digest("base64url");
}

/** SHA-256 hex of a payload, for use as `payloadHash`. */
export function hashPayload(payload: Uint8Array | string): string {
  return createHash("sha256").update(payload).digest("hex");
}

/** The fields the evidence HMAC covers, in a fixed, unambiguous encoding. */
function evidenceMacInput(evidence: Omit<CodeConfirmationEvidence, "mac">): string {
  return JSON.stringify([
    "identkit/approval-code/v1",
    evidence.version,
    evidence.level,
    evidence.accountId,
    evidence.payloadHash,
    evidence.recordedAt,
    evidence.timeStep,
  ]);
}

/**
 * The levels this call accepts: the policy's `approvalEvidenceLevels`, narrowed by `levels`.
 * Throws `InvalidArgumentError` for a malformed filter and `MethodNotAllowedError` if nothing
 * is left.
 */
async function allowedLevels(ctx: Context, levels: unknown): Promise<ApprovalEvidenceLevel[]> {
  const policy = await ctx.getPolicy();
  if (levels !== undefined) {
    if (
      !Array.isArray(levels) ||
      levels.length === 0 ||
      !levels.every((l) => LEVELS.some((known) => known === l))
    ) {
      throw new InvalidArgumentError("levels must be a non-empty list of approval levels");
    }
  }
  const filter: unknown[] = levels === undefined ? [...LEVELS] : levels;
  const allowed = policy.approvalEvidenceLevels.filter((l) => filter.includes(l));
  if (allowed.length === 0) throw new MethodNotAllowedError("approval level");
  return allowed;
}

export function createApprovals(
  ctx: Context,
  core: PasskeyCore,
  totp: TotpEngine,
  internals: SessionInternals,
): Approvals {
  const { config, clock, hasher, store } = ctx;

  const failed = async (
    reason: string,
    payloadHash: string | null,
    accountId: string | undefined,
    level: ApprovalEvidenceLevel,
  ): Promise<{ status: "failed"; reason: "no_session" | "invalid" }> => {
    await ctx.emit({
      type: "approval.failed",
      reason,
      level,
      ...(accountId ? { accountId } : {}),
      ...(payloadHash && PAYLOAD_HASH_PATTERN.test(payloadHash) ? { payloadHash } : {}),
    });
    return { status: "failed", reason: reason === "no_session" ? "no_session" : "invalid" };
  };

  async function startCodeConfirmation(
    input: ApprovalStartInput,
    session: { id: string; accountId: string },
  ): Promise<StartApprovalResult> {
    totp.requireSealer();
    const approvalId = randomToken();
    const now = clock.now();
    const expiresAt = addSeconds(now, config.totp.approvalTtlSeconds);
    const challengeId = randomToken();
    await store.challenges.insert({
      id: challengeId,
      challengeDigest: await hasher.digest("approval-id", approvalId),
      purpose: "approval_code",
      accountId: session.accountId,
      sessionId: session.id,
      enrollmentTokenDigest: null,
      payloadHash: input.payloadHash,
      nonce: null,
      createdAt: now,
      expiresAt,
    });
    await ctx.emit({
      type: "approval.challenge_created",
      accountId: session.accountId,
      sessionId: session.id,
      challengeId,
      payloadHash: input.payloadHash,
      level: "code-confirmation",
    });
    return { status: "ok", level: "code-confirmation", approvalId, expiresAt };
  }

  async function verifyCodeConfirmation(
    input: ApprovalVerifyBase & { approvalId: string; code: string },
  ): Promise<VerifyApprovalResult> {
    const level = "code-confirmation" as const;
    if (typeof input.payloadHash !== "string" || !PAYLOAD_HASH_PATTERN.test(input.payloadHash)) {
      return failed("payload_malformed", null, undefined, level);
    }
    const loaded = await internals.load(input.sessionToken, "complete");
    if (!loaded) return failed("no_session", input.payloadHash, undefined, level);
    const { record: session } = loaded;
    // Consumed whether or not the code is right: one attempt per pending approval.
    const pending = isTokenShaped(input.approvalId)
      ? await store.challenges.consumeByDigest(
          await hasher.digest("approval-id", input.approvalId),
          "approval_code",
        )
      : null;
    if (
      !pending ||
      pending.purpose !== "approval_code" ||
      clock.now().getTime() >= pending.expiresAt.getTime() ||
      pending.sessionId !== session.id ||
      pending.accountId !== session.accountId
    ) {
      return failed("challenge", input.payloadHash, session.accountId, level);
    }
    if (pending.payloadHash !== input.payloadHash) {
      return failed("payload_mismatch", input.payloadHash, session.accountId, level);
    }
    const checked = await totp.check({
      accountId: session.accountId,
      code: input.code,
      purpose: "approval",
      sessionId: session.id,
    });
    if (checked.status !== "accepted") {
      const failure = await failed(
        `code_${checked.reason}`,
        input.payloadHash,
        session.accountId,
        level,
      );
      return checked.reason === "locked" ? { status: "failed", reason: "locked" } : failure;
    }
    // The record is valid as of `recordedAt`: a removal of the factor or a revocation of the
    // session that raced with the check yields no evidence.
    const recordedAt = clock.now();
    if (
      !(await totp.isStillCurrent(checked.factor)) ||
      !(await internals.loadById(session.id, "complete"))
    ) {
      return failed("factor_or_session_gone", input.payloadHash, session.accountId, level);
    }
    const unsigned = {
      version: 1 as const,
      level,
      accountId: session.accountId,
      payloadHash: input.payloadHash,
      recordedAt: recordedAt.toISOString(),
      timeStep: checked.step,
    };
    const evidence: CodeConfirmationEvidence = {
      ...unsigned,
      mac: await hasher.digest("approval-evidence", evidenceMacInput(unsigned)),
    };
    await ctx.emit({
      type: "approval.code_confirmation_recorded",
      accountId: session.accountId,
      sessionId: session.id,
      factorId: checked.factor.id,
      challengeId: pending.id,
      payloadHash: input.payloadHash,
      level,
    });
    return { status: "approved", evidence };
  }

  async function start(input: ApprovalStartInput): Promise<StartApprovalResult> {
    if (typeof input.payloadHash !== "string" || !PAYLOAD_HASH_PATTERN.test(input.payloadHash)) {
      throw new TypeError("payloadHash must be a lowercase hex SHA-256 digest");
    }
    const allowed = await allowedLevels(ctx, input.levels);
    const loaded = await internals.load(input.sessionToken, "complete");
    if (!loaded) return { status: "denied", reason: "no_session" };
    const session = loaded.record;
    // The strongest level that is allowed and usable; never a level the client asked for.
    if (allowed.includes("signature")) {
      const allow = await core.allowList(session.accountId);
      if (allow.length > 0) return startSignature(input, session, allow);
    }
    if (allowed.includes("code-confirmation") && (await store.totp.findActive(session.accountId))) {
      return startCodeConfirmation(input, session);
    }
    if (allowed.length === 2) return { status: "denied", reason: "no_factor" };
    return { status: "denied", reason: allowed[0] === "signature" ? "no_passkey" : "no_totp" };
  }

  async function verify(input: ApprovalVerifyInput): Promise<VerifyApprovalResult> {
    const hasResponse = "response" in input;
    const hasCode = "approvalId" in input || "code" in input;
    if (hasResponse === hasCode) {
      throw new InvalidArgumentError("pass either response, or approvalId and code");
    }
    const allowed = await allowedLevels(ctx, input.levels);
    // Each form consumes only a pending approval of its own level, which `start` stored.
    if (hasResponse) {
      if (!allowed.includes("signature")) throw new MethodNotAllowedError("signature");
      return verifySignature(input);
    }
    if (!allowed.includes("code-confirmation")) {
      throw new MethodNotAllowedError("code-confirmation");
    }
    return verifyCodeConfirmation(input);
  }

  async function startSignature(
    input: ApprovalStartInput,
    session: { id: string; accountId: string },
    allow: { id: string; transports: string[] }[],
  ): Promise<StartApprovalResult> {
    const nonce = toBase64Url(randomBytes(32));
    const challenge = approvalChallenge(nonce, input.payloadHash, session.accountId);
    const { record } = await core.issueChallenge(
      "approval",
      {
        accountId: session.accountId,
        sessionId: session.id,
        payloadHash: input.payloadHash,
        nonce,
      },
      challenge,
    );
    await ctx.emit({
      type: "approval.challenge_created",
      accountId: session.accountId,
      sessionId: session.id,
      challengeId: record.id,
      payloadHash: input.payloadHash,
      level: "signature",
    });
    const options = await authenticationOptions({
      rp: core.rp,
      challenge,
      timeoutSeconds: config.webauthn.challengeTtlSeconds,
      allow,
    });
    return { status: "ok", level: "signature", options };
  }

  async function verifySignature(
    input: ApprovalVerifyBase & { response: AuthenticationResponseJSON },
  ): Promise<VerifyApprovalResult> {
    const level = "signature" as const;
    if (typeof input.payloadHash !== "string" || !PAYLOAD_HASH_PATTERN.test(input.payloadHash)) {
      return failed("payload_malformed", null, undefined, level);
    }
    const loaded = await internals.load(input.sessionToken, "complete");
    if (!loaded) return failed("no_session", input.payloadHash, undefined, level);
    const { record: session } = loaded;
    const consumed = await core.consumeChallenge(
      input.response?.response?.clientDataJSON,
      "approval",
    );
    if (
      !consumed ||
      consumed.record.sessionId !== session.id ||
      consumed.record.accountId !== session.accountId ||
      consumed.record.nonce === null
    ) {
      return failed("challenge", input.payloadHash, session.accountId, level);
    }
    // The challenge the person signed must commit to the payload hash given now.
    const expectedChallenge = approvalChallenge(
      consumed.record.nonce,
      input.payloadHash,
      session.accountId,
    );
    if (expectedChallenge !== consumed.challenge) {
      return failed("payload_mismatch", input.payloadHash, session.accountId, level);
    }
    const verified = await core.verifyCredentialAssertion({
      response: input.response,
      expectedChallenge,
      expectedAccountId: session.accountId,
    });
    if (!verified) return failed("assertion", input.payloadHash, session.accountId, level);

    // The proof is valid as of `verifiedAt`: the passkey is checked again at that moment, so a
    // revocation that raced with the ceremony yields no proof.
    const verifiedAt = clock.now();
    if (!(await core.isStillCurrent(verified.credential))) {
      return failed("credential_revoked", input.payloadHash, session.accountId, level);
    }
    const origin = readClientField(input.response.response.clientDataJSON, "origin") ?? "";
    const evidence: ApprovalProof = {
      version: 1,
      level: "signature",
      accountId: session.accountId,
      credentialId: verified.credential.id,
      payloadHash: input.payloadHash,
      nonce: consumed.record.nonce,
      challenge: expectedChallenge,
      rpId: core.rp.rpId,
      origin,
      counter: verified.counter,
      verifiedAt: verifiedAt.toISOString(),
      assertion: { ...input.response.response },
    };
    await ctx.emit({
      type: "approval.verified",
      accountId: session.accountId,
      sessionId: session.id,
      credentialId: verified.credential.id,
      challengeId: consumed.record.id,
      payloadHash: input.payloadHash,
      level: "signature",
    });
    return { status: "approved", evidence };
  }

  return { start, verify };
}

/**
 * Result of `checkApprovalEvidence`. Switch on the exact `status`: accept only the status you
 * mean. The result is an object, so it is always truthy: never use it as a boolean, and never
 * accept on `status !== "invalid"`.
 * - `verified`: a signature evidence checked out with the given public key.
 * - `recorded_not_independently_verifiable`: a code-confirmation evidence whose HMAC matches
 *   the given `hasher`. It is a server record, not a proof anyone else can check, so it is
 *   never reported as `verified`.
 * - `invalid`: the evidence does not check out, its HMAC does not match, or its level is
 *   unknown.
 */
export type ApprovalEvidenceCheck =
  | { status: "verified"; level: "signature" }
  | { status: "recorded_not_independently_verifiable"; level: "code-confirmation" }
  | { status: "invalid" };

export interface ApprovalEvidenceVerifier {
  credentialPublicKey: Uint8Array;
  rpId: string;
  origins: string[];
}

export interface CheckApprovalEvidenceInput {
  evidence: ApprovalEvidence;
  /** Required for level `signature`: the public key from your own credential record. */
  verifier?: ApprovalEvidenceVerifier;
  /** Required for level `code-confirmation`: the same `SecretHasher` that recorded it. */
  hasher?: SecretHasher;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Checks an approval evidence again, without storage. Takes exactly one options object and
 * throws `InvalidArgumentError` (code `invalid_argument`) for any other shape: a second
 * argument, an evidence passed directly, or a missing `verifier` or `hasher` for the level.
 * So a call written for an earlier form fails loudly, also from untyped JavaScript.
 *
 * For level `signature` it checks that the signed challenge commits to the payload hash and
 * the account id, that the signature verifies with the given public key, and that RP ID,
 * origin and counter in the proof match what was signed. It cannot check `verifiedAt`, nor
 * that `credentialId` belonged to `accountId`: look up the public key through your own
 * record of that account's credentials. It does not check whether the credential is still
 * registered.
 *
 * For level `code-confirmation` it recomputes the HMAC with `hasher`. A record whose HMAC does
 * not match is `invalid`; a matching one is `recorded_not_independently_verifiable`, which
 * shows only that this deployment recorded it. See `CodeConfirmationEvidence`.
 */
export async function checkApprovalEvidence(
  input: CheckApprovalEvidenceInput,
  ...extra: unknown[]
): Promise<ApprovalEvidenceCheck> {
  const raw: unknown = input;
  if (extra.length > 0 || !isObject(raw) || !isObject(raw["evidence"])) {
    throw new InvalidArgumentError(
      "pass one object: { evidence, verifier } or { evidence, hasher }",
    );
  }
  if ("version" in raw || "level" in raw) {
    throw new InvalidArgumentError("pass the evidence as { evidence }, not directly");
  }
  const { evidence, verifier, hasher } = input;
  const invalid: ApprovalEvidenceCheck = { status: "invalid" };
  if (evidence.level === "code-confirmation") {
    const digest: unknown = isObject(hasher) ? hasher["digest"] : undefined;
    if (!hasher || typeof digest !== "function") {
      throw new InvalidArgumentError("a code-confirmation evidence needs the hasher");
    }
    return (await recordIsIntact(raw["evidence"], hasher))
      ? { status: "recorded_not_independently_verifiable", level: "code-confirmation" }
      : invalid;
  }
  if (evidence.level === "signature") {
    if (!isObject(verifier)) {
      throw new InvalidArgumentError("a signature evidence needs the verifier");
    }
    const payloadHash: unknown = evidence.payloadHash;
    if (
      evidence.version !== 1 ||
      typeof payloadHash !== "string" ||
      !PAYLOAD_HASH_PATTERN.test(payloadHash)
    ) {
      return invalid;
    }
    return (await verifySignatureEvidence(evidence, verifier))
      ? { status: "verified", level: "signature" }
      : invalid;
  }
  return invalid;
}

/** Recomputes the evidence HMAC. Any field of the wrong type makes the record invalid. */
async function recordIsIntact(
  evidence: Record<string, unknown>,
  hasher: SecretHasher,
): Promise<boolean> {
  const { version, level, accountId, payloadHash, recordedAt, timeStep, mac } = evidence;
  if (
    version !== 1 ||
    level !== "code-confirmation" ||
    typeof accountId !== "string" ||
    typeof payloadHash !== "string" ||
    !PAYLOAD_HASH_PATTERN.test(payloadHash) ||
    typeof recordedAt !== "string" ||
    typeof timeStep !== "number" ||
    !Number.isSafeInteger(timeStep) ||
    typeof mac !== "string"
  ) {
    return false;
  }
  const expected = await hasher.digest(
    "approval-evidence",
    evidenceMacInput({ version, level, accountId, payloadHash, recordedAt, timeStep }),
  );
  return digestsEqual(expected, mac);
}

async function verifySignatureEvidence(
  proof: ApprovalProof,
  verifier: ApprovalEvidenceVerifier,
): Promise<boolean> {
  if (proof.rpId !== verifier.rpId) return false;
  const expectedChallenge = approvalChallenge(proof.nonce, proof.payloadHash, proof.accountId);
  if (readClientChallenge(proof.assertion?.clientDataJSON) !== expectedChallenge) return false;
  const rp: RelyingParty = { rpId: verifier.rpId, rpName: "", origins: verifier.origins };
  try {
    const verified = await verifyAssertion({
      rp,
      response: {
        id: proof.credentialId,
        rawId: proof.credentialId,
        type: "public-key",
        response: proof.assertion,
        clientExtensionResults: {},
      },
      expectedChallenge,
      credential: {
        id: proof.credentialId,
        publicKey: verifier.credentialPublicKey,
        transports: [],
      },
    });
    return verified.origin === proof.origin && verified.newCounter === proof.counter;
  } catch {
    return false;
  }
}
