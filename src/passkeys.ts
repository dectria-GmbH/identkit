import { addSeconds } from "./clock.js";
import type { Context } from "./context.js";
import { isTokenShaped, randomToken } from "./crypto.js";
import { assertMethodAllowed } from "./email-otp.js";
import type { PasskeyCore } from "./passkey-core.js";
import { toAccountView, type AccountView } from "./accounts.js";
import type { IssuedSession, SessionInternals, Sessions } from "./sessions.js";
import type { AccountRecord, CredentialRecord, SessionRecord } from "./storage/types.js";
import {
  authenticationOptions,
  registrationOptions,
  verifyRegistration,
  type AuthenticationResponseJSON,
  type PasskeyCreationOptions,
  type PasskeyRequestOptions,
  type RegistrationResponseJSON,
} from "./webauthn.js";

/**
 * What allows a passkey registration:
 * - `sessionToken`: a full session with a fresh step-up. If the account already has a
 *   passkey, the step-up must be a passkey step-up.
 * - `enrollmentToken`: a single-use token from `passkeys.issueEnrollmentToken`, for
 *   onboarding without another factor or for recovery after identity verification.
 */
export type RegistrationGrant = { sessionToken: string } | { enrollmentToken: string };

export type RegistrationDenied = {
  status: "denied";
  reason: "no_session" | "step_up_required" | "invalid_enrollment";
};

export type StartRegistrationResult =
  { status: "ok"; options: PasskeyCreationOptions } | RegistrationDenied;

export type FinishRegistrationResult =
  | { status: "registered"; credentialId: string; revokedSessions: number }
  | RegistrationDenied
  | { status: "failed"; reason: "invalid" | "duplicate" };

export type PasskeySignInResult =
  | ({ status: "signed_in"; account: AccountView } & IssuedSession)
  | { status: "failed"; reason: "invalid" };

export type SecondFactorStart =
  | { status: "ok"; options: PasskeyRequestOptions }
  | { status: "denied"; reason: "no_pending_session" };

export interface PasskeyInfo {
  id: string;
  transports: string[];
  deviceType: CredentialRecord["deviceType"];
  backedUp: boolean;
  createdAt: Date;
  lastUsedAt: Date | null;
}

export interface Passkeys {
  startRegistration(grant: RegistrationGrant): Promise<StartRegistrationResult>;
  finishRegistration(
    grant: RegistrationGrant,
    response: RegistrationResponseJSON,
  ): Promise<FinishRegistrationResult>;
  /** Starts a sign-in without a user name (discoverable credential). */
  startSignIn(): Promise<{ options: PasskeyRequestOptions }>;
  finishSignIn(response: AuthenticationResponseJSON): Promise<PasskeySignInResult>;
  /** Second factor after an e-mail code sign-in that returned `second_factor_required`. */
  startSecondFactor(pendingToken: string): Promise<SecondFactorStart>;
  finishSecondFactor(
    pendingToken: string,
    response: AuthenticationResponseJSON,
  ): Promise<PasskeySignInResult>;
  list(accountId: string): Promise<PasskeyInfo[]>;
  /**
   * Removes a passkey of the session's account. Needs a fresh passkey step-up. Revokes all
   * other sessions of the account.
   */
  remove(
    sessionToken: string,
    credentialId: string,
  ): Promise<
    | { status: "removed" }
    | { status: "denied"; reason: "no_session" | "step_up_required" | "not_found" }
  >;
  /** Administrative removal after loss or theft. Revokes all sessions of the account. */
  revoke(accountId: string, credentialId: string): Promise<boolean>;
  /**
   * Administrative: issues a single-use registration token for the account. Deliver it out
   * of band. identkit stores only its keyed hash.
   */
  issueEnrollmentToken(accountId: string): Promise<{ token: string; expiresAt: Date }>;
}

export function createPasskeys(
  ctx: Context,
  core: PasskeyCore,
  sessions: Sessions,
  internals: SessionInternals,
): Passkeys {
  const { config, store, hasher, clock } = ctx;

  function hasFreshStepUp(record: SessionRecord, requirePasskey: boolean): boolean {
    const stepUp = record.stepUp;
    if (!stepUp) return false;
    if (requirePasskey && stepUp.method !== "passkey") return false;
    return clock.now().getTime() < addSeconds(stepUp.at, config.stepUp.validitySeconds).getTime();
  }

  type ResolvedGrant =
    | {
        ok: true;
        account: AccountRecord;
        sessionId: string | null;
        enrollmentTokenDigest: string | null;
      }
    | RegistrationDenied;

  async function resolveGrant(grant: RegistrationGrant): Promise<ResolvedGrant> {
    if ("sessionToken" in grant) {
      const loaded = await internals.load(grant.sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const existing = await store.credentials.listByAccount(loaded.record.accountId);
      if (!hasFreshStepUp(loaded.record, existing.length > 0)) {
        return { status: "denied", reason: "step_up_required" };
      }
      const account = await store.accounts.findById(loaded.record.accountId);
      if (!account || account.status !== "active")
        return { status: "denied", reason: "no_session" };
      return { ok: true, account, sessionId: loaded.record.id, enrollmentTokenDigest: null };
    }
    if (!isTokenShaped(grant.enrollmentToken)) {
      return { status: "denied", reason: "invalid_enrollment" };
    }
    const digest = await hasher.digest("enrollment-token", grant.enrollmentToken);
    const token = await store.enrollment.findByDigest(digest);
    if (!token || token.consumedAt !== null || clock.now().getTime() >= token.expiresAt.getTime()) {
      return { status: "denied", reason: "invalid_enrollment" };
    }
    const account = await store.accounts.findById(token.accountId);
    if (!account || account.status !== "active") {
      return { status: "denied", reason: "invalid_enrollment" };
    }
    return { ok: true, account, sessionId: null, enrollmentTokenDigest: digest };
  }

  const failRegistration = async (
    accountId: string,
    reason: string,
  ): Promise<{ status: "failed"; reason: "invalid" }> => {
    await ctx.emit({ type: "passkey.registration_failed", accountId, reason });
    return { status: "failed", reason: "invalid" };
  };

  async function signInFailed(reason: string, accountId?: string): Promise<PasskeySignInResult> {
    await ctx.emit({
      type: "passkey.sign_in_failed",
      reason,
      ...(accountId ? { accountId } : {}),
    });
    return { status: "failed", reason: "invalid" };
  }

  return {
    async startRegistration(grant) {
      const resolved = await resolveGrant(grant);
      if (!("ok" in resolved)) return resolved;
      const { account } = resolved;
      const { challenge } = await core.issueChallenge("registration", {
        accountId: account.id,
        sessionId: resolved.sessionId,
        enrollmentTokenDigest: resolved.enrollmentTokenDigest,
      });
      const options = await registrationOptions({
        rp: core.rp,
        userId: account.webauthnUserId,
        userName: account.email,
        challenge,
        timeoutSeconds: config.webauthn.challengeTtlSeconds,
        exclude: await core.allowList(account.id),
      });
      return { status: "ok", options };
    },

    async finishRegistration(grant, response) {
      const resolved = await resolveGrant(grant);
      if (!("ok" in resolved)) return resolved;
      const { account } = resolved;
      const consumed = await core.consumeChallenge(
        response?.response?.clientDataJSON,
        "registration",
      );
      if (
        !consumed ||
        consumed.record.accountId !== account.id ||
        consumed.record.sessionId !== resolved.sessionId ||
        consumed.record.enrollmentTokenDigest !== resolved.enrollmentTokenDigest
      ) {
        return failRegistration(account.id, "challenge");
      }

      let verified;
      try {
        verified = await verifyRegistration({
          rp: core.rp,
          response,
          expectedChallenge: consumed.challenge,
        });
      } catch {
        return failRegistration(account.id, "verification");
      }

      if (resolved.enrollmentTokenDigest !== null) {
        const used = await store.enrollment.consume(resolved.enrollmentTokenDigest, clock.now());
        if (!used || used.accountId !== account.id) {
          return { status: "denied", reason: "invalid_enrollment" };
        }
        await ctx.emit({ type: "enrollment.used", accountId: account.id });
      }

      const inserted = await store.credentials.insert({
        id: verified.credentialId,
        accountId: account.id,
        publicKey: verified.publicKey,
        counter: verified.counter,
        transports: verified.transports,
        deviceType: verified.deviceType,
        backedUp: verified.backedUp,
        createdAt: clock.now(),
        lastUsedAt: null,
      });
      if (inserted === "duplicate") {
        await ctx.emit({
          type: "passkey.registration_failed",
          accountId: account.id,
          reason: "duplicate",
        });
        return { status: "failed", reason: "duplicate" };
      }
      await ctx.emit({
        type: "passkey.registered",
        accountId: account.id,
        credentialId: verified.credentialId,
        method: resolved.enrollmentTokenDigest ? "enrollment_token" : "session",
      });
      const revokedSessions = await sessions.revokeAll(
        account.id,
        resolved.sessionId ? { exceptSessionId: resolved.sessionId } : undefined,
      );
      return { status: "registered", credentialId: verified.credentialId, revokedSessions };
    },

    async startSignIn() {
      assertMethodAllowed((await ctx.getPolicy()).signInMethods, "passkey");
      const { challenge } = await core.issueChallenge("sign_in", {
        accountId: null,
        sessionId: null,
      });
      const options = await authenticationOptions({
        rp: core.rp,
        challenge,
        timeoutSeconds: config.webauthn.challengeTtlSeconds,
        allow: [],
      });
      return { options };
    },

    async finishSignIn(response) {
      assertMethodAllowed((await ctx.getPolicy()).signInMethods, "passkey");
      const consumed = await core.consumeChallenge(response?.response?.clientDataJSON, "sign_in");
      if (!consumed) return signInFailed("challenge");
      const verified = await core.verifyCredentialAssertion({
        response,
        expectedChallenge: consumed.challenge,
        expectedAccountId: null,
      });
      if (!verified) return signInFailed("assertion");
      const issued = await internals.create({
        accountId: verified.account.id,
        state: "complete",
        authMethods: ["passkey"],
        stepUp: { method: "passkey", at: clock.now() },
      });
      return { status: "signed_in", account: toAccountView(verified.account), ...issued };
    },

    async startSecondFactor(pendingToken) {
      const loaded = await internals.load(pendingToken, "pending_second_factor");
      if (!loaded) return { status: "denied", reason: "no_pending_session" };
      const { challenge } = await core.issueChallenge("second_factor", {
        accountId: loaded.record.accountId,
        sessionId: loaded.record.id,
      });
      const options = await authenticationOptions({
        rp: core.rp,
        challenge,
        timeoutSeconds: config.webauthn.challengeTtlSeconds,
        allow: await core.allowList(loaded.record.accountId),
      });
      return { status: "ok", options };
    },

    async finishSecondFactor(pendingToken, response) {
      const loaded = await internals.load(pendingToken, "pending_second_factor");
      if (!loaded) return signInFailed("no_pending_session");
      const { record } = loaded;
      const consumed = await core.consumeChallenge(
        response?.response?.clientDataJSON,
        "second_factor",
      );
      if (!consumed || consumed.record.sessionId !== record.id) {
        return signInFailed("challenge", record.accountId);
      }
      const verified = await core.verifyCredentialAssertion({
        response,
        expectedChallenge: consumed.challenge,
        expectedAccountId: record.accountId,
      });
      if (!verified) return signInFailed("assertion", record.accountId);
      const issued = await internals.elevate(
        loaded,
        { state: "complete", addMethod: "passkey", stepUp: { method: "passkey", at: clock.now() } },
        "second_factor",
      );
      if (!issued) return signInFailed("rotation", record.accountId);
      return { status: "signed_in", account: toAccountView(verified.account), ...issued };
    },

    async list(accountId) {
      const credentials = await store.credentials.listByAccount(accountId);
      return credentials.map((c) => ({
        id: c.id,
        transports: c.transports,
        deviceType: c.deviceType,
        backedUp: c.backedUp,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
      }));
    },

    async remove(sessionToken, credentialId) {
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      if (!hasFreshStepUp(loaded.record, true))
        return { status: "denied", reason: "step_up_required" };
      const removed = await store.credentials.delete(credentialId, loaded.record.accountId);
      if (!removed) return { status: "denied", reason: "not_found" };
      await ctx.emit({
        type: "passkey.removed",
        accountId: loaded.record.accountId,
        credentialId,
        sessionId: loaded.record.id,
      });
      await sessions.revokeAll(loaded.record.accountId, { exceptSessionId: loaded.record.id });
      return { status: "removed" };
    },

    async revoke(accountId, credentialId) {
      const removed = await store.credentials.delete(credentialId, accountId);
      if (!removed) return false;
      await ctx.emit({
        type: "passkey.removed",
        accountId,
        credentialId,
        reason: "administrative",
      });
      await sessions.revokeAll(accountId);
      return true;
    },

    async issueEnrollmentToken(accountId) {
      const account = await store.accounts.findById(accountId);
      if (!account) throw new Error("account not found");
      const token = randomToken();
      const now = clock.now();
      const expiresAt = addSeconds(now, config.enrollment.tokenTtlSeconds);
      await store.enrollment.insert({
        tokenDigest: await hasher.digest("enrollment-token", token),
        accountId,
        createdAt: now,
        expiresAt,
        consumedAt: null,
      });
      await ctx.emit({ type: "enrollment.issued", accountId });
      return { token, expiresAt };
    },
  };
}
