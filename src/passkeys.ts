import { addSeconds } from "./clock.js";
import type { Context } from "./context.js";
import { enrolledSecondFactors, factorChangeStepUp, hasFreshStepUp } from "./second-factor.js";
import { isTokenShaped, randomToken } from "./crypto.js";
import { assertMethodAllowed } from "./email-otp.js";
import { PasskeyCleanupError } from "./errors.js";
import type { PasskeyCore } from "./passkey-core.js";
import { toAccountView, type AccountView } from "./accounts.js";
import { emitApiTokensRevoked, revokeAllApiTokens } from "./api-tokens.js";
import { emitOAuthGrantsEnded, endAllOAuthGrants } from "./oauth/grant-end.js";
import {
  finishRollback,
  finishThenRunHook,
  noRevocation,
  type IssuedSession,
  type Revocation,
  type SessionInternals,
  type Sessions,
} from "./sessions.js";
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
  /**
   * Throws `OperationRolledBackError` if it removed the new passkey again after an error: the
   * registration did not take effect. Throws `PasskeyCleanupError` if the grant was lost after
   * the activation and the store failed to delete the new passkey and to disable the account:
   * the passkey may still sign in.
   */
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
   * after an error completes the revocation. Returns false if no passkey was removed. If it
   * throws after the token revocation, it records `enrollment.revoked` first (best effort),
   * because a retry finds no token to revoke.
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
   * Runs a session revocation after a passkey change that a retry cannot repeat (a delete). If
   * it throws, records the change (best effort) before the error goes up: a
   * retry finds nothing to change and cannot record it any more.
   */
  async function revokeRecordingChange<T>(
    revoke: () => Promise<T>,
    changeEvent: Parameters<Context["emit"]>[0] | null,
  ): Promise<T> {
    try {
      return await revoke();
    } catch (error) {
      if (changeEvent) await ctx.emit(changeEvent).catch(() => undefined);
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
      const grantChangedEvent = {
        type: "passkey.registration_failed",
        accountId: account.id,
        reason: "grant_changed",
      } as const;
      if (holds !== true) {
        // The pending passkey was never usable: nothing to revoke. An error still goes up as
        // `OperationRolledBackError`, so the caller cannot take it for a registered passkey.
        const rolledBack = await finishRollback(account.id, noRevocation, null, async () => {
          await store.credentials.delete(verified.credentialId, account.id, verified.publicKey);
          await ctx.emit(grantChangedEvent);
        });
        if (rolledBack) throw rolledBack;
        return holds;
      }
      // From the activation on, the passkey can be usable. A revocation between the check above
      // and the activation would be missed, so check once more. If the check fails after the
      // activation, or anything throws, the passkey goes and every session of the account ends;
      // a sign-in that raced with the delete is caught by its own re-check.
      // Async, so a store that throws synchronously still gets the retry below.
      const remove = async () =>
        store.credentials.delete(verified.credentialId, account.id, verified.publicKey);
      // As `accounts.disable`: the status, then the account's API tokens and its OAuth grants,
      // which it returns. A token or grant store error counts as a failed disable: an operator
      // who enables the account again must know that its tokens or grants may still be live.
      const disable = async () => {
        await store.accounts.setStatus(account.id, "disabled");
        const tokenIds = await revokeAllApiTokens(ctx, account.id, "account_disabled");
        const grants = await endAllOAuthGrants(ctx, account.id);
        return { tokenIds, grants };
      };
      // Removes the passkey and revokes every session of the account. Returns the revocation, or
      // null and the store's error if the revocation failed, for `finishRollback`. If the passkey
      // cannot be removed, the rollback is incomplete: `undo` disables the account, runs the hook
      // best effort and throws the delete's error, or `PasskeyCleanupError` if the disable
      // failed.
      const undo = async () => {
        let cleanupFailure: { error: unknown } | null = null;
        try {
          // One retry: a passkey that survives here could sign in again later.
          await remove().catch(remove);
        } catch (error) {
          // The passkey may still be active without a valid grant: fail closed and disable the
          // account until an operator looks at it, as the TOTP enrolment does.
          const ended = await disable()
            .catch(disable)
            .catch(() => null);
          const disabled = ended !== null;
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
            await emitApiTokensRevoked(ctx, account.id, ended.tokenIds, "account_disabled").catch(
              () => undefined,
            );
            await emitOAuthGrantsEnded(ctx, account.id, ended.grants, "account_disabled").catch(
              () => undefined,
            );
          }
          // The audit event above is best effort. If the account is still active, the caller
          // must learn that a passkey without a grant may sign in.
          cleanupFailure = {
            error: disabled
              ? error
              : new PasskeyCleanupError(account.id, verified.credentialId, { cause: error }),
          };
        }
        let revocation: Revocation | null = null;
        let failure: { error: unknown } | null = null;
        try {
          revocation = await internals.revokeAllDeferringHook(account.id);
        } catch (error) {
          // The store revocation failed, so other sessions may survive: record it.
          await ctx
            .emit({
              type: "passkey.registration_failed",
              accountId: account.id,
              reason: "cleanup_failed",
            })
            .catch(() => undefined);
          failure = { error };
        }
        if (cleanupFailure) {
          await revocation?.runHook().catch(() => undefined);
          throw cleanupFailure.error;
        }
        return { revocation, failure };
      };
      // For the error paths: returns the error to throw. `OperationRolledBackError` carries the
      // original error as `cause`. If the passkey could not be removed, the rollback is
      // incomplete: the original error goes up, or `PasskeyCleanupError`, which outweighs it.
      const rollBack = async (error: unknown): Promise<unknown> => {
        let undone: Awaited<ReturnType<typeof undo>>;
        try {
          undone = await undo();
        } catch (undoError) {
          return undoError instanceof PasskeyCleanupError ? undoError : error;
        }
        return (await finishRollback(account.id, undone.revocation, { error })) ?? error;
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
        throw await rollBack(error);
      }
      if (outcome !== true) {
        // Not activated means this registration's row is gone: nothing was usable, nothing to end.
        const undone = activated ? await undo() : { revocation: noRevocation, failure: null };
        // The audit event, then the hook; each runs also when the other fails. Any error goes up
        // as `OperationRolledBackError`, so the caller cannot take it for a registered passkey.
        const rolledBack = await finishRollback(
          account.id,
          undone.revocation,
          undone.failure,
          async () => {
            if (!activated) await remove();
            await ctx.emit(grantChangedEvent);
          },
        );
        if (rolledBack) throw rolledBack;
        return outcome;
      }
      // Revoke first: if the audit sink fails afterwards, no other session survives. If the
      // store revocation fails, the passkey goes and every session ends, as for the TOTP
      // enrolment. A sink error on the revoked sessions' events is not such a failure: the
      // sessions are revoked and the registration stands.
      let revoked: Revocation;
      try {
        revoked = await internals.revokeAllDeferringHook(
          account.id,
          resolved.sessionId ? { exceptSessionId: resolved.sessionId } : undefined,
        );
      } catch (error) {
        throw await rollBack(error);
      }
      // Hook last, also when the audit sink throws: the passkey is registered and a retried
      // registration cannot reach the hook. A throwing hook surfaces as
      // `AllSessionsRevokedHookError`, which names how to re-run it.
      await finishThenRunHook(revoked, () =>
        ctx.emit({
          type: "passkey.registered",
          accountId: account.id,
          credentialId: verified.credentialId,
          method: resolved.enrollmentTokenDigest ? "enrollment_token" : "session",
        }),
      );
      return {
        status: "registered",
        credentialId: verified.credentialId,
        revokedSessions: revoked.count,
      };
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
      const revoked = await revokeRecordingChange(
        () =>
          internals.revokeAllDeferringHook(loaded.record.accountId, {
            exceptSessionId: loaded.record.id,
          }),
        removed ? removedEvent : null,
      );
      // Hook last: a throwing hook must not skip the audit event, nor a throwing sink the hook.
      await finishThenRunHook(revoked, async () => {
        if (removed) await ctx.emit(removedEvent);
      });
      return removed ? { status: "removed" } : { status: "denied", reason: "not_found" };
    },

    async revoke(accountId, credentialId) {
      // Tokens first: a registration that runs with one of them fails its check after the insert.
      const revokedTokens = await store.enrollment.revokeAllForAccount(accountId, clock.now());
      const tokensEvent =
        revokedTokens > 0
          ? ({ type: "enrollment.revoked", accountId, reason: "passkey_revoked" } as const)
          : null;
      const removedEvent = {
        type: "passkey.removed",
        accountId,
        credentialId,
        reason: "administrative",
      } as const;
      // A retry finds no open token and cannot record the token revocation any more.
      const recordTokensBestEffort = async () => {
        if (tokensEvent) await ctx.emit(tokensEvent).catch(() => undefined);
      };
      let removed: boolean;
      let revoked: Revocation;
      try {
        removed = await store.credentials.delete(credentialId, accountId);
        // Always, also when the passkey is gone: a retry after a failed revocation must still
        // end the sessions. Revoke before the audit events, so a failing sink skips nothing.
        revoked = await revokeRecordingChange(
          () => internals.revokeAllDeferringHook(accountId),
          removed ? removedEvent : null,
        );
      } catch (error) {
        await recordTokensBestEffort();
        throw error;
      }
      // Hook last: a throwing hook must not skip the audit events, nor a throwing sink the hook.
      await finishThenRunHook(revoked, async () => {
        try {
          // The removal first: a retry finds no passkey and cannot record it any more.
          if (removed) await ctx.emit(removedEvent);
        } catch (error) {
          await recordTokensBestEffort();
          throw error;
        }
        if (tokensEvent) await ctx.emit(tokensEvent);
      });
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
