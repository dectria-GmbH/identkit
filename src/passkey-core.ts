import { timingSafeEqual } from "node:crypto";
import { addSeconds } from "./clock.js";
import type { Context } from "./context.js";
import { randomId, randomToken } from "./crypto.js";
import type {
  AccountRecord,
  ChallengePurpose,
  ChallengeRecord,
  CredentialRecord,
} from "./storage/types.js";
import {
  checkCounter,
  readClientChallenge,
  verifyAssertion,
  type AuthenticationResponseJSON,
  type RelyingParty,
} from "./webauthn.js";

function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.byteLength === b.byteLength && timingSafeEqual(a, b);
}

export interface ChallengeBinding {
  accountId: string | null;
  sessionId: string | null;
  enrollmentTokenDigest?: string | null;
  payloadHash?: string | null;
  nonce?: string | null;
}

export interface PasskeyCore {
  rp: RelyingParty;
  issueChallenge(
    purpose: ChallengePurpose,
    binding: ChallengeBinding,
    challenge?: string,
  ): Promise<{ challenge: string; record: ChallengeRecord }>;
  /**
   * Consumes the challenge named in the client data. The challenge is gone after this call,
   * whether or not the rest of the verification succeeds.
   */
  consumeChallenge(
    clientDataJSON: unknown,
    purpose: ChallengePurpose,
  ): Promise<{ challenge: string; record: ChallengeRecord } | null>;
  /**
   * Verifies an assertion against a stored credential and applies the counter rule.
   * Returns null on any failure.
   */
  verifyCredentialAssertion(input: {
    response: AuthenticationResponseJSON;
    expectedChallenge: string;
    expectedAccountId: string | null;
    allowedCredentialIds?: string[];
  }): Promise<{ credential: CredentialRecord; account: AccountRecord; counter: number } | null>;
  allowList(accountId: string): Promise<{ id: string; transports: string[] }[]>;
  /**
   * True if the same credential (id, account and public key) is still registered and its
   * account is active. Call it after writing the result of an assertion, so a revocation that
   * raced with the ceremony cannot be missed.
   */
  isStillCurrent(credential: CredentialRecord): Promise<boolean>;
}

export function createPasskeyCore(ctx: Context): PasskeyCore {
  const { config, store, hasher, clock } = ctx;
  const rp: RelyingParty = {
    rpId: config.webauthn.rpId,
    rpName: config.webauthn.rpName,
    origins: config.webauthn.origins,
  };

  return {
    rp,

    async issueChallenge(purpose, binding, challenge = randomToken()) {
      const now = clock.now();
      const record: ChallengeRecord = {
        id: randomId(),
        challengeDigest: await hasher.digest("webauthn-challenge", challenge),
        purpose,
        accountId: binding.accountId,
        sessionId: binding.sessionId,
        enrollmentTokenDigest: binding.enrollmentTokenDigest ?? null,
        payloadHash: binding.payloadHash ?? null,
        nonce: binding.nonce ?? null,
        createdAt: now,
        expiresAt: addSeconds(now, config.webauthn.challengeTtlSeconds),
      };
      await store.challenges.insert(record);
      return { challenge, record };
    },

    async consumeChallenge(clientDataJSON, purpose) {
      const challenge = readClientChallenge(clientDataJSON);
      if (!challenge) return null;
      const record = await store.challenges.consumeByDigest(
        await hasher.digest("webauthn-challenge", challenge),
        purpose,
      );
      // The store filters by purpose; checking again guards against a faulty store.
      if (!record || record.purpose !== purpose) return null;
      if (clock.now().getTime() >= record.expiresAt.getTime()) return null;
      return { challenge, record };
    },

    async verifyCredentialAssertion(input) {
      const { response } = input;
      if (
        !response ||
        typeof response.id !== "string" ||
        response.id !== response.rawId ||
        response.type !== "public-key"
      ) {
        return null;
      }
      if (input.allowedCredentialIds && !input.allowedCredentialIds.includes(response.id)) {
        return null;
      }
      const credential = await store.credentials.findById(response.id);
      if (!credential) return null;
      if (input.expectedAccountId !== null && credential.accountId !== input.expectedAccountId) {
        return null;
      }
      const account = await store.accounts.findById(credential.accountId);
      if (!account || account.status !== "active") return null;
      const userHandle = response.response?.userHandle;
      if (userHandle !== undefined && userHandle !== account.webauthnUserId) return null;

      let verified;
      try {
        verified = await verifyAssertion({
          rp,
          response,
          expectedChallenge: input.expectedChallenge,
          credential,
        });
      } catch {
        return null;
      }

      if (!checkCounter(credential.counter, verified.newCounter)) {
        await ctx.emit({
          type: "passkey.counter_regression",
          accountId: account.id,
          credentialId: credential.id,
          reason: `stored ${credential.counter}, received ${verified.newCounter}`,
        });
        return null;
      }
      const updated = await store.credentials.updateCounter(
        credential.id,
        credential.counter,
        verified.newCounter,
        clock.now(),
      );
      if (!updated) return null;
      return { credential, account, counter: verified.newCounter };
    },

    async isStillCurrent(credential) {
      const current = await store.credentials.findById(credential.id);
      if (
        !current ||
        current.accountId !== credential.accountId ||
        !timingSafeEqualBytes(current.publicKey, credential.publicKey)
      ) {
        return false;
      }
      const account = await store.accounts.findById(credential.accountId);
      return account?.status === "active";
    },

    async allowList(accountId) {
      const credentials = await store.credentials.listByAccount(accountId);
      return credentials.map((c) => ({ id: c.id, transports: c.transports }));
    },
  };
}
