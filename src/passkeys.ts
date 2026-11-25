import { addSeconds } from "./clock.js";
import type { Context } from "./context.js";
import { enrolledSecondFactors, factorChangeStepUp, hasFreshStepUp } from "./second-factor.js";
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
 *   passkey, the step-up must be a passkey step-up; if it has only a TOTP factor, a TOTP
 *   step-up.
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
  /** Administrative: takes a bare id. Do not pass client input without your own check. */
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
  /**
   * Administrative removal after loss or theft. Revokes all sessions and all enrollment
   * tokens of the account, on every call: also when the passkey is already gone, so a retry
   * after an error completes the revocation. Returns false if no passkey was removed.
   */
  revoke(accountId: string, credentialId: string): Promise<boolean>;
  /**
   * Administrative: issues a single-use registration token for the account. Deliver it out
   * of band. identkit stores only its keyed hash. Every earlier token of the account stops
   * working; a registration that is using one fails at its next check after the insert.
   */
  issueEnrollmentToken(accountId: string): Promise<{ token: string; expiresAt: Date }>;
  /**
   * Administrative: revokes every enrollment token of the account and returns how many it
   * revoked. A registration that is using one of them fails at its next check after the
   * insert; one that passed its last check keeps its passkey.
   */
  revokeEnrollmentTokens(accountId: string): Promise<number>;
}

export function createPasskeys(
  ctx: Context,
  core: PasskeyCore,
  sessions: Sessions,
  internals: SessionInternals,
): Passkeys {
  const { config, store, hasher, clock } = ctx;

  /** The step-up a registration needs, counting the account's factors other than `newId`. */
  async function registrationStepUpHolds(record: SessionRecord, newId?: string) {
    const enrolled = await enrolledSecondFactors(
      ctx,
      record.accountId,
      newId === undefined ? {} : { passkeyId: newId },
    );
    return await hasFreshStepUp(ctx, record, factorChangeStepUp(enrolled));
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
      if (!(await registrationStepUpHolds(loaded.record))) {
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
    if (
      !token ||
      token.consumedAt !== null ||
      token.revokedAt !== null ||
      clock.now().getTime() >= token.expiresAt.getTime()
    ) {
      return { status: "denied", reason: "invalid_enrollment" };
    }
    const account = await store.accounts.findById(token.accountId);
    if (!account || account.status !== "active") {
      return { status: "denied", reason: "invalid_enrollment" };
    }
    return { ok: true, account, sessionId: null, enrollmentTokenDigest: digest };
  }

  /** Applies the registration grant again, counting only the passkeys other than `newId`. */
  async function grantStillHolds(
    grant: RegistrationGrant,
    resolved: { sessionId: string | null; enrollmentTokenDigest: string | null },
    accountId: string,
    newId: string,
  ): Promise<true | RegistrationDenied> {
    const { sessionId, enrollmentTokenDigest } = resolved;
    const account = await store.accounts.findById(accountId);
    if (!account || account.status !== "active") return { status: "denied", reason: "no_session" };
    if (!("sessionToken" in grant)) {
      // The token is consumed by now. A newer token or a revocation since then ends the grant.
      const token =
        enrollmentTokenDigest === null
          ? null
          : await store.enrollment.findByDigest(enrollmentTokenDigest);
      if (!token || token.accountId !== accountId || token.revokedAt !== null) {
        return { status: "denied", reason: "invalid_enrollment" };
      }
      return true;
    }
    // By id: a token rotation in another tab is not a lost grant.
    const live = sessionId === null ? null : await internals.loadById(sessionId, "complete");
    if (!live) return { status: "denied", reason: "no_session" };
    if (!(await registrationStepUpHolds(live, newId))) {
      return { status: "denied", reason: "step_up_required" };
    }
    return true;
  }

  const failRegistration = async (
    accountId: string,
    reason: string,
  ): Promise<{ status: "failed"; reason: "invalid" }> => {
    await ctx.emit({ type: "passkey.registration_failed", accountId, reason });
    return { status: "failed", reason: "invalid" };
  };

  /**
   * Runs a session revocation after a passkey delete. If it throws, records the removal (best
   * effort) before the error goes up: a retry finds no passkey and cannot record it any more.
   */
  async function revokeRecordingRemoval(
    revoke: () => Promise<unknown>,
    removedEvent: Parameters<Context["emit"]>[0] | null,
  ): Promise<void> {
    try {
      await revoke();
    } catch (error) {
      if (removedEvent) await ctx.emit(removedEvent).catch(() => undefined);
      throw error;
    }
  }

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
        // Pending: invisible and unusable until the grant was checked again below.
        activatedAt: null,
      });
      if (inserted === "duplicate") {
        await ctx.emit({
          type: "passkey.registration_failed",
          accountId: account.id,
          reason: "duplicate",
        });
        return { status: "failed", reason: "duplicate" };
      }
      // The grant was checked before the insert. A revocation, a removed step-up passkey or a
      // concurrent first registration in between must not leave this passkey behind. Until
      // the activation the passkey cannot sign in, step up or approve.
      const holds = await grantStillHolds(grant, resolved, account.id, verified.credentialId);
      if (holds !== true) {
        await store.credentials.delete(verified.credentialId, account.id, verified.publicKey);
        await ctx.emit({
          type: "passkey.registration_failed",
          accountId: account.id,
          reason: "grant_changed",
        });
        return holds;
      }
      // From the activation on, the passkey can be usable. A revocation between the check above
      // and the activation would be missed, so check once more. If the check fails after the
      // activation, or anything throws, the passkey goes and every session of the account ends;
      // a sign-in that raced with the delete is caught by its own re-check.
      // Async, so a store that throws synchronously still gets the retry below.
      const remove = async () =>
        store.credentials.delete(verified.credentialId, account.id, verified.publicKey);
      const disable = async () => store.accounts.setStatus(account.id, "disabled");
      const undo = async () => {
        try {
          // One retry: a passkey that survives here could sign in again later.
          await remove().catch(remove);
        } catch (error) {
          // The passkey may still be active without a valid grant: fail closed and disable the
          // account until an operator looks at it, as the TOTP enrolment does.
          const disabled = await disable()
            .catch(disable)
            .then(
              () => true,
              () => false,
            );
          await ctx
            .emit({
              type: "passkey.registration_failed",
              accountId: account.id,
              reason: disabled
                ? "cleanup_failed_account_disabled"
                : "cleanup_failed_disable_failed",
            })
            .catch(() => undefined);
          if (disabled) {
            await ctx
              .emit({ type: "account.disabled", accountId: account.id, reason: "passkey_cleanup" })
              .catch(() => undefined);
          }
          throw error;
        } finally {
          await sessions.revokeAll(account.id);
        }
      };
      let activated = false;
      let outcome: true | RegistrationDenied;
      try {
        activated = await store.credentials.activate(
          verified.credentialId,
          account.id,
          verified.publicKey,
          clock.now(),
        );
        outcome = activated
          ? await grantStillHolds(grant, resolved, account.id, verified.credentialId)
          : { status: "denied", reason: "no_session" };
      } catch (error) {
        // Keep the original error; `undo` records its own failure.
        await undo().catch(() => undefined);
        throw error;
      }
      if (outcome !== true) {
        // Not activated means this registration's row is gone: nothing was usable, nothing to end.
        if (activated) await undo();
        else await remove();
        await ctx.emit({
          type: "passkey.registration_failed",
          accountId: account.id,
          reason: "grant_changed",
        });
        return outcome;
      }
      // Revoke first: if the audit sink fails afterwards, no other session survives.
      const revokedSessions = await sessions.revokeAll(
        account.id,
        resolved.sessionId ? { exceptSessionId: resolved.sessionId } : undefined,
      );
      await ctx.emit({
        type: "passkey.registered",
        accountId: account.id,
        credentialId: verified.credentialId,
        method: resolved.enrollmentTokenDigest ? "enrollment_token" : "session",
      });
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
      // A revocation of the passkey between the check above and the insert would miss this
      // session. Checking again after the insert closes that window.
      if (!(await core.isStillCurrent(verified.credential))) {
        await sessions.revokeById(issued.session.id, "credential_revoked");
        return signInFailed("credential_revoked", verified.account.id);
      }
      return { status: "signed_in", account: toAccountView(verified.account), ...issued };
    },

    async startSecondFactor(pendingToken) {
      assertMethodAllowed((await ctx.getPolicy()).secondFactorMethods, "passkey");
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
      assertMethodAllowed((await ctx.getPolicy()).secondFactorMethods, "passkey");
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
      if (!(await core.isStillCurrent(verified.credential))) {
        await sessions.revokeById(record.id, "credential_revoked");
        return signInFailed("credential_revoked", record.accountId);
      }
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
      if (!(await hasFreshStepUp(ctx, loaded.record, ["passkey"])))
        return { status: "denied", reason: "step_up_required" };
      const removed = await store.credentials.delete(credentialId, loaded.record.accountId);
      const removedEvent = {
        type: "passkey.removed",
        accountId: loaded.record.accountId,
        credentialId,
        sessionId: loaded.record.id,
      } as const;
      // Always, also when the passkey is gone: a retry after a failed revocation must still
      // end the other sessions. Revoke before the audit event, so a failing sink skips nothing.
      await revokeRecordingRemoval(
        () => sessions.revokeAll(loaded.record.accountId, { exceptSessionId: loaded.record.id }),
        removed ? removedEvent : null,
      );
      if (!removed) return { status: "denied", reason: "not_found" };
      await ctx.emit(removedEvent);
      return { status: "removed" };
    },

    async revoke(accountId, credentialId) {
      // Tokens first: a registration that runs with one of them fails its check after the insert.
      const revokedTokens = await store.enrollment.revokeAllForAccount(accountId, clock.now());
      const removed = await store.credentials.delete(credentialId, accountId);
      const removedEvent = {
        type: "passkey.removed",
        accountId,
        credentialId,
        reason: "administrative",
      } as const;
      // Always, also when the passkey is gone: a retry after a failed revocation must still
      // end the sessions. Revoke before the audit events, so a failing sink skips nothing.
      await revokeRecordingRemoval(
        () => sessions.revokeAll(accountId),
        removed ? removedEvent : null,
      );
      // The removal first: a retry finds no passkey and cannot record it any more.
      if (removed) await ctx.emit(removedEvent);
      if (revokedTokens > 0) {
        await ctx.emit({ type: "enrollment.revoked", accountId, reason: "passkey_revoked" });
      }
      return removed;
    },

    async issueEnrollmentToken(accountId) {
      const account = await store.accounts.findById(accountId);
      if (!account) throw new Error("account not found");
      const token = randomToken();
      const now = clock.now();
      const expiresAt = addSeconds(now, config.enrollment.tokenTtlSeconds);
      await store.enrollment.issue({
        tokenDigest: await hasher.digest("enrollment-token", token),
        accountId,
        createdAt: now,
        expiresAt,
        consumedAt: null,
        revokedAt: null,
      });
      await ctx.emit({ type: "enrollment.issued", accountId });
      return { token, expiresAt };
    },

    async revokeEnrollmentTokens(accountId) {
      const revoked = await store.enrollment.revokeAllForAccount(accountId, clock.now());
      if (revoked > 0) {
        await ctx.emit({ type: "enrollment.revoked", accountId, reason: "administrative" });
      }
      return revoked;
    },
  };
}
