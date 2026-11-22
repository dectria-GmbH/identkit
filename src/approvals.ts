import { createHash, randomBytes } from "node:crypto";
import { addSeconds } from "./clock.js";
import type { ApprovalProofLevel } from "./config.js";
import type { Context } from "./context.js";
import { digestsEqual, isTokenShaped, randomToken } from "./crypto.js";
import { MethodNotAllowedError } from "./errors.js";
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

/**
 * Level `signature`: evidence that one person approved one payload with one passkey. A
 * verifier with the credential's public key can check it again later with
 * `verifyApprovalEvidence`.
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
 * - The code is not bound to the payload. It proves only that someone with the account's
 *   TOTP secret entered a current code while this approval was pending; the person may not
 *   have seen the payload.
 * - The TOTP secret is held by the server too, so the server (or anyone who reads its
 *   sealed store and key) could produce the same record.
 * - A third party cannot check it. `mac` is an HMAC with the deployment's `SecretHasher`
 *   key: it shows only that this deployment wrote the record and nobody changed it since.
 *   `verifyApprovalEvidence` reports it as `recorded_not_independently_verifiable`, never
 *   as `verified`.
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
  | { status: "denied"; reason: "no_session" | "no_passkey" };

export type StartCodeConfirmationResult =
  | { status: "ok"; level: "code-confirmation"; approvalId: string; expiresAt: Date }
  | { status: "denied"; reason: "no_session" | "no_totp" };

export type VerifyApprovalResult =
  | { status: "approved"; proof: ApprovalProof }
  | { status: "failed"; reason: "no_session" | "invalid" };

export type VerifyCodeConfirmationResult =
  | { status: "approved"; proof: CodeConfirmationEvidence }
  | { status: "failed"; reason: "no_session" | "invalid" | "locked" };

export interface SignatureApprovalStart {
  sessionToken: string;
  payloadHash: string;
  level?: "signature";
}

export interface CodeConfirmationStart {
  sessionToken: string;
  payloadHash: string;
  level: "code-confirmation";
}

export interface SignatureApprovalVerify {
  sessionToken: string;
  payloadHash: string;
  level?: "signature";
  response: AuthenticationResponseJSON;
}

export interface CodeConfirmationVerify {
  sessionToken: string;
  payloadHash: string;
  /** Required: the level is never inferred from the other fields. */
  level: "code-confirmation";
  /** The `approvalId` that `start` returned. */
  approvalId: string;
  /** A current TOTP code of the session's account. */
  code: string;
}

export type ApprovalStartResult = StartApprovalResult | StartCodeConfirmationResult;

/**
 * The result names the level of its proof (`proof.level`). The type does not depend on the
 * input, so a caller that passes untyped input must still check `proof.level` before it uses
 * level-specific fields or shows the proof as a signature.
 */
export type ApprovalVerifyResult = VerifyApprovalResult | VerifyCodeConfirmationResult;

export interface Approvals {
  /**
   * Level `signature` (no `level`, or `level: "signature"`): creates a passkey challenge that
   * commits to `payloadHash`. The person signs it with a passkey of the session's account.
   *
   * Level `code-confirmation`: creates one pending approval of `payloadHash` for the
   * session's account, to be confirmed with a TOTP code. Throws `MethodNotAllowedError`
   * unless the policy's `approvalProofLevel` is `code-confirmation`.
   */
  start(input: SignatureApprovalStart): Promise<StartApprovalResult>;
  start(input: CodeConfirmationStart): Promise<StartCodeConfirmationResult>;
  /**
   * Level `signature` (with `response`): verifies the signed challenge. Succeeds only for the
   * same payload hash, the same session, a passkey of the session's account, and a challenge
   * not used before.
   *
   * Level `code-confirmation` (`level: "code-confirmation"`, `approvalId` and `code`):
   * consumes the pending approval (one attempt per pending approval) and the code's time step,
   * and returns a recorded evidence. Succeeds only for the same payload hash, session and
   * account. An `approvalId` or `code` without that level throws `TypeError`.
   */
  verify(input: SignatureApprovalVerify | CodeConfirmationVerify): Promise<ApprovalVerifyResult>;
  /**
   * Checks the HMAC of a code-confirmation evidence with this deployment's key. `intact`
   * shows only that this deployment wrote the record and nobody changed it. It does not
   * show that the person saw or approved the payload, and it is not an independent proof.
   */
  checkRecordedEvidence(
    evidence: CodeConfirmationEvidence,
  ): Promise<{ status: "intact" } | { status: "invalid" }>;
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

/** Signature proofs are always accepted; code confirmations only if the policy allows them. */
async function assertLevelAllowed(ctx: Context, level: ApprovalProofLevel): Promise<void> {
  const policy = await ctx.getPolicy();
  if (level === "code-confirmation" && policy.approvalProofLevel !== "code-confirmation") {
    throw new MethodNotAllowedError("code-confirmation");
  }
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
    accountId?: string,
    level: ApprovalProofLevel = "signature",
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
    input: CodeConfirmationStart,
  ): Promise<StartCodeConfirmationResult> {
    await assertLevelAllowed(ctx, "code-confirmation");
    totp.requireSealer();
    const loaded = await internals.load(input.sessionToken, "complete");
    if (!loaded) return { status: "denied", reason: "no_session" };
    const { record: session } = loaded;
    if (!(await store.totp.findActive(session.accountId))) {
      return { status: "denied", reason: "no_totp" };
    }
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
    input: CodeConfirmationVerify,
  ): Promise<VerifyCodeConfirmationResult> {
    await assertLevelAllowed(ctx, "code-confirmation");
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
    const proof: CodeConfirmationEvidence = {
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
    return { status: "approved", proof };
  }

  function start(input: SignatureApprovalStart): Promise<StartApprovalResult>;
  function start(input: CodeConfirmationStart): Promise<StartCodeConfirmationResult>;
  async function start(
    input: SignatureApprovalStart | CodeConfirmationStart,
  ): Promise<ApprovalStartResult> {
    if (typeof input.payloadHash !== "string" || !PAYLOAD_HASH_PATTERN.test(input.payloadHash)) {
      throw new TypeError("payloadHash must be a lowercase hex SHA-256 digest");
    }
    if (input.level === "code-confirmation") return startCodeConfirmation(input);
    if (input.level !== undefined && input.level !== "signature") {
      throw new TypeError("level must be signature or code-confirmation");
    }
    return startSignature(input);
  }

  async function verify(
    input: SignatureApprovalVerify | CodeConfirmationVerify,
  ): Promise<ApprovalVerifyResult> {
    if (input.level === "code-confirmation") {
      if ("response" in input) throw new TypeError("a code confirmation takes no response");
      return verifyCodeConfirmation(input);
    }
    if (input.level !== undefined && input.level !== "signature") {
      throw new TypeError("level must be signature or code-confirmation");
    }
    if ("code" in input || "approvalId" in input) {
      throw new TypeError('a code confirmation needs level: "code-confirmation"');
    }
    return verifySignature(input);
  }

  async function startSignature(input: SignatureApprovalStart): Promise<StartApprovalResult> {
    const loaded = await internals.load(input.sessionToken, "complete");
    if (!loaded) return { status: "denied", reason: "no_session" };
    const allow = await core.allowList(loaded.record.accountId);
    if (allow.length === 0) return { status: "denied", reason: "no_passkey" };
    const nonce = randomBytes(32).toString("base64url");
    const challenge = approvalChallenge(nonce, input.payloadHash, loaded.record.accountId);
    const { record } = await core.issueChallenge(
      "approval",
      {
        accountId: loaded.record.accountId,
        sessionId: loaded.record.id,
        payloadHash: input.payloadHash,
        nonce,
      },
      challenge,
    );
    await ctx.emit({
      type: "approval.challenge_created",
      accountId: loaded.record.accountId,
      sessionId: loaded.record.id,
      challengeId: record.id,
      payloadHash: input.payloadHash,
    });
    const options = await authenticationOptions({
      rp: core.rp,
      challenge,
      timeoutSeconds: config.webauthn.challengeTtlSeconds,
      allow,
    });
    return { status: "ok", level: "signature", options };
  }

  async function verifySignature(input: SignatureApprovalVerify): Promise<VerifyApprovalResult> {
    if (typeof input.payloadHash !== "string" || !PAYLOAD_HASH_PATTERN.test(input.payloadHash)) {
      return failed("payload_malformed", null);
    }
    const loaded = await internals.load(input.sessionToken, "complete");
    if (!loaded) return failed("no_session", input.payloadHash);
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
      return failed("challenge", input.payloadHash, session.accountId);
    }
    // The challenge the person signed must commit to the payload hash given now.
    const expectedChallenge = approvalChallenge(
      consumed.record.nonce,
      input.payloadHash,
      session.accountId,
    );
    if (expectedChallenge !== consumed.challenge) {
      return failed("payload_mismatch", input.payloadHash, session.accountId);
    }
    const verified = await core.verifyCredentialAssertion({
      response: input.response,
      expectedChallenge,
      expectedAccountId: session.accountId,
    });
    if (!verified) return failed("assertion", input.payloadHash, session.accountId);

    // The proof is valid as of `verifiedAt`: the passkey is checked again at that moment, so a
    // revocation that raced with the ceremony yields no proof.
    const verifiedAt = clock.now();
    if (!(await core.isStillCurrent(verified.credential))) {
      return failed("credential_revoked", input.payloadHash, session.accountId);
    }
    const origin = readClientField(input.response.response.clientDataJSON, "origin") ?? "";
    const proof: ApprovalProof = {
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
    return { status: "approved", proof };
  }

  return {
    start,
    verify,
    async checkRecordedEvidence(evidence) {
      if (
        evidence?.version !== 1 ||
        evidence.level !== "code-confirmation" ||
        typeof evidence.mac !== "string"
      ) {
        return { status: "invalid" };
      }
      const expected = await hasher.digest("approval-evidence", evidenceMacInput(evidence));
      return digestsEqual(expected, evidence.mac) ? { status: "intact" } : { status: "invalid" };
    },
  };
}

/**
 * Result of `verifyApprovalEvidence`. Compare `status === "verified"`; the result is an
 * object, so it is always truthy and must never be used as a boolean.
 * - `verified`: a signature evidence checked out with the given public key.
 * - `recorded_not_independently_verifiable`: a code-confirmation evidence. It is a server
 *   record, not a proof anyone else can check, so it is never reported as `verified`.
 * - `invalid`: the evidence does not check out, or its level is unknown.
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

/**
 * Checks an approval evidence again, without storage.
 *
 * For level `signature` it checks that the signed challenge commits to the payload hash and
 * the account id, that the signature verifies with the given public key, and that RP ID,
 * origin and counter in the proof match what was signed. It cannot check `verifiedAt`, nor
 * that `credentialId` belonged to `accountId`: look up the public key through your own
 * record of that account's credentials. It does not check whether the credential is still
 * registered.
 *
 * For level `code-confirmation` it returns `recorded_not_independently_verifiable` for any
 * record of the right shape, forged or not: nothing in the record can be checked without the
 * server's keys. Before you accept such a record, check it with
 * `approvals.checkRecordedEvidence`; even then it shows only what the server recorded. See
 * `CodeConfirmationEvidence`.
 *
 * It takes one options object, so a call written for the earlier boolean form
 * (`verifyApprovalEvidence(proof, verifier)`) no longer compiles.
 */
export async function verifyApprovalEvidence(input: {
  evidence: ApprovalEvidence;
  verifier?: ApprovalEvidenceVerifier;
}): Promise<ApprovalEvidenceCheck> {
  const { evidence, verifier } = input;
  const invalid: ApprovalEvidenceCheck = { status: "invalid" };
  if (evidence?.version !== 1 || !PAYLOAD_HASH_PATTERN.test(evidence.payloadHash)) {
    return invalid;
  }
  if (evidence.level === "code-confirmation") {
    return { status: "recorded_not_independently_verifiable", level: "code-confirmation" };
  }
  if (evidence.level !== "signature" || !verifier) return invalid;
  return (await verifySignatureEvidence(evidence, verifier))
    ? { status: "verified", level: "signature" }
    : invalid;
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
