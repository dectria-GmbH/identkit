import { createHash, randomBytes } from "node:crypto";
import type { Context } from "./context.js";
import type { PasskeyCore } from "./passkey-core.js";
import type { SessionInternals } from "./sessions.js";
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
 * Evidence that one person approved one payload with one passkey. A verifier with the
 * credential's public key can check it again later with `verifyApprovalEvidence`.
 */
export interface ApprovalProof {
  version: 1;
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

export type StartApprovalResult =
  | { status: "ok"; options: PasskeyRequestOptions }
  | { status: "denied"; reason: "no_session" | "no_passkey" };

export type VerifyApprovalResult =
  | { status: "approved"; proof: ApprovalProof }
  | { status: "failed"; reason: "no_session" | "invalid" };

export interface Approvals {
  /**
   * Creates a passkey challenge that commits to `payloadHash`. The person signs it with a
   * passkey of the session's account.
   */
  start(input: { sessionToken: string; payloadHash: string }): Promise<StartApprovalResult>;
  /**
   * Verifies the signed challenge. Succeeds only for the same payload hash, the same
   * session, a passkey of the session's account, and a challenge not used before.
   */
  verify(input: {
    sessionToken: string;
    payloadHash: string;
    response: AuthenticationResponseJSON;
  }): Promise<VerifyApprovalResult>;
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

export function createApprovals(
  ctx: Context,
  core: PasskeyCore,
  internals: SessionInternals,
): Approvals {
  const { config, clock } = ctx;

  const failed = async (
    reason: string,
    payloadHash: string | null,
    accountId?: string,
  ): Promise<VerifyApprovalResult> => {
    await ctx.emit({
      type: "approval.failed",
      reason,
      ...(accountId ? { accountId } : {}),
      ...(payloadHash && PAYLOAD_HASH_PATTERN.test(payloadHash) ? { payloadHash } : {}),
    });
    return { status: "failed", reason: reason === "no_session" ? "no_session" : "invalid" };
  };

  return {
    async start(input) {
      if (typeof input.payloadHash !== "string" || !PAYLOAD_HASH_PATTERN.test(input.payloadHash)) {
        throw new TypeError("payloadHash must be a lowercase hex SHA-256 digest");
      }
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
      return { status: "ok", options };
    },

    async verify(input) {
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
      });
      return { status: "approved", proof };
    },
  };
}

/**
 * Checks an approval proof again, without storage. It checks that the signed challenge
 * commits to the payload hash and the account id, that the signature verifies with the given
 * public key, and that RP ID, origin and counter in the proof match what was signed.
 *
 * It cannot check `verifiedAt`, nor that `credentialId` belonged to `accountId`: look up the
 * public key through your own record of that account's credentials. It does not check
 * whether the credential is still registered.
 */
export async function verifyApprovalEvidence(
  proof: ApprovalProof,
  verifier: { credentialPublicKey: Uint8Array; rpId: string; origins: string[] },
): Promise<boolean> {
  if (proof.version !== 1 || !PAYLOAD_HASH_PATTERN.test(proof.payloadHash)) return false;
  if (proof.rpId !== verifier.rpId) return false;
  const expectedChallenge = approvalChallenge(proof.nonce, proof.payloadHash, proof.accountId);
  if (readClientChallenge(proof.assertion.clientDataJSON) !== expectedChallenge) return false;
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
