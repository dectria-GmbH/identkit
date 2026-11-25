import { toAccountView, type AccountView } from "./accounts.js";
import { addSeconds } from "./clock.js";
import type { Context } from "./context.js";
import { randomId } from "./crypto.js";
import { assertMethodAllowed } from "./email-otp.js";
import { MethodNotAllowedError, NotConfiguredError } from "./errors.js";
import type { SecretSealer } from "./sealer.js";
import { enrolledSecondFactors, factorChangeStepUp, hasFreshStepUp } from "./second-factor.js";
import type { IssuedSession, SessionInternals, Sessions } from "./sessions.js";
import type { SessionRecord, TotpFactorRecord } from "./storage/types.js";
import {
  base32Encode,
  generateTotpSecret,
  matchTimeStep,
  provisioningUri,
  TOTP_PERIOD_SECONDS,
  type TotpAlgorithm,
  type TotpDigits,
} from "./totp-core.js";

/** Why a TOTP code was not accepted. The caller sees only `invalid` or `locked`. */
export type TotpCheckFailure = { status: "failed"; reason: "invalid" | "locked" };

export type TotpPurpose = "second_factor" | "step_up" | "approval";

export type StartTotpEnrolmentResult =
  | {
      status: "ok";
      factorId: string;
      /**
       * The secret, base32. Shown once, to the person who enrols: identkit returns it only
       * here and never again. Do not store or log it.
       */
      secret: string;
      /** `otpauth://totp/...` for a QR code. It contains the secret, like `secret`. */
      provisioningUri: string;
      algorithm: TotpAlgorithm;
      digits: TotpDigits;
      periodSeconds: number;
      /** Confirm with a first code before this time. */
      expiresAt: Date;
    }
  | { status: "denied"; reason: "no_session" | "step_up_required" | "already_enrolled" };

export type ConfirmTotpEnrolmentResult =
  | { status: "enrolled"; factorId: string; revokedSessions: number }
  | { status: "denied"; reason: "no_session" | "step_up_required" }
  | { status: "failed"; reason: "invalid" | "expired" | "locked" };

export type TotpSignInResult =
  ({ status: "signed_in"; account: AccountView } & IssuedSession) | TotpCheckFailure;

export interface TotpFactorInfo {
  id: string;
  algorithm: TotpAlgorithm;
  digits: TotpDigits;
  createdAt: Date;
  activatedAt: Date;
  lastUsedAt: Date | null;
}

export interface Totp {
  /**
   * Starts a TOTP enrolment for the session's account. Needs a full session with a fresh
   * step-up; if the account has a passkey, a passkey step-up. The factor stays unusable until
   * `confirmEnrolment` accepted a first code.
   */
  startEnrolment(sessionToken: string): Promise<StartTotpEnrolmentResult>;
  /**
   * Confirms an enrolment with a first valid code from the app. Activates the factor and
   * revokes every other session of the account.
   */
  confirmEnrolment(
    sessionToken: string,
    input: { factorId: string; code: string },
  ): Promise<ConfirmTotpEnrolmentResult>;
  /** Second factor after an e-mail code sign-in that returned `second_factor_required`. */
  verifySecondFactor(pendingToken: string, input: { code: string }): Promise<TotpSignInResult>;
  /** Administrative: takes a bare id. Never returns the secret. */
  get(accountId: string): Promise<TotpFactorInfo | null>;
  /**
   * Removes the TOTP factor of the session's account. Needs a fresh step-up with the
   * strongest factor of the account (passkey, else TOTP). Revokes all other sessions.
   */
  remove(
    sessionToken: string,
  ): Promise<
    | { status: "removed" }
    | { status: "denied"; reason: "no_session" | "step_up_required" | "not_found" }
  >;
  /**
   * Administrative removal after loss or theft. Deletes every TOTP factor of the account,
   * pending enrolments included, and revokes all its sessions, also when it finds no factor,
   * so a retry after an error completes the revocation. Returns true if it removed a factor.
   */
  revoke(accountId: string): Promise<boolean>;
  /**
   * Administrative: seals the account's TOTP secret again with the sealer's active key, for
   * key rotation. Returns false if the account has no active factor.
   */
  reseal(accountId: string): Promise<boolean>;
}

/** Shared code check for second factor, step-up and approval. */
export interface TotpEngine {
  /**
   * Checks a code against the account's active factor and consumes its time step. Failed
   * codes count against the account's lockout before the comparison. A time step accepted
   * once, for any purpose, is never accepted again.
   */
  check(input: {
    accountId: string;
    code: string;
    purpose: TotpPurpose;
    sessionId: string;
  }): Promise<{ status: "accepted"; factor: TotpFactorRecord; step: number } | TotpCheckFailure>;
  /** True if the same factor is still the account's active factor and the account is active. */
  isStillCurrent(factor: TotpFactorRecord): Promise<boolean>;
  requireSealer(): SecretSealer;
}

/** Associated data for sealing: a sealed secret opens only for this factor and account. */
export const sealContext = (factorId: string, accountId: string) =>
  `identkit/totp-secret\u0000${factorId}\u0000${accountId}`;

export const throttleKey = (accountId: string) => `totp:${accountId}`;
export const enrolmentThrottleKey = (accountId: string) => `totp-enrolment:${accountId}`;
const FACTOR_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

function codeShapeMatches(code: unknown, digits: TotpDigits): code is string {
  return typeof code === "string" && code.length === digits && /^[0-9]+$/.test(code);
}

/** TOTP is usable only if some part of the policy names it. */
async function assertTotpInPolicy(ctx: Context): Promise<void> {
  const policy = await ctx.getPolicy();
  if (
    !policy.secondFactorMethods.includes("totp") &&
    !policy.stepUpMethods.includes("totp") &&
    !policy.approvalEvidenceLevels.includes("code-confirmation")
  ) {
    throw new MethodNotAllowedError("totp");
  }
}

export function createTotpEngine(ctx: Context): TotpEngine {
  const { config, store, clock } = ctx;

  function requireSealer(): SecretSealer {
    if (!ctx.sealer) throw new NotConfiguredError("sealer");
    return ctx.sealer;
  }

  /** Opens the secret, finds the matching step, and wipes the plaintext copy. */
  async function matchCode(factor: TotpFactorRecord, code: string): Promise<number | null> {
    const secret = await requireSealer().open(
      factor.sealedSecret,
      sealContext(factor.id, factor.accountId),
    );
    try {
      return matchTimeStep({
        secret,
        code,
        at: clock.now(),
        driftSteps: config.totp.driftSteps,
        algorithm: factor.algorithm,
        digits: factor.digits,
      });
    } finally {
      secret.fill(0);
    }
  }

  async function fail(
    reason: TotpCheckFailure["reason"],
    detail: string,
    input: { accountId: string; purpose: string; sessionId: string },
    factorId?: string,
  ): Promise<TotpCheckFailure> {
    await ctx.emit({
      type: "totp.verify_failed",
      accountId: input.accountId,
      sessionId: input.sessionId,
      purpose: input.purpose,
      reason: detail,
      ...(factorId ? { factorId } : {}),
    });
    return { status: "failed", reason };
  }

  return {
    requireSealer,

    async check(input) {
      requireSealer();
      const factor = await store.totp.findActive(input.accountId);
      if (!factor) return fail("invalid", "no_factor", input);
      if (!codeShapeMatches(input.code, factor.digits)) {
        return fail("invalid", "malformed", input, factor.id);
      }
      const now = clock.now();
      const key = throttleKey(input.accountId);
      if (await store.throttle.peek(key, now)) return fail("locked", "locked", input, factor.id);
      // Counted before the comparison, so concurrent guesses cannot exceed the limit.
      const throttle = await store.throttle.reserve(key, now, config.totp.lockout);
      if (!throttle.allowed) {
        if (throttle.lockedNow) {
          await ctx.emit({ type: "totp.locked", accountId: input.accountId, factorId: factor.id });
        }
        return fail("locked", "locked", input, factor.id);
      }
      const step = await matchCode(factor, input.code);
      if (step === null) return fail("invalid", "wrong_code", input, factor.id);
      // Compare-and-set in the store: of two requests with the same step, one wins.
      if (!(await store.totp.recordStep(factor.id, factor.accountId, step, now))) {
        return fail("invalid", "replayed", input, factor.id);
      }
      await store.throttle.reset(key);
      await ctx.emit({
        type: "totp.verified",
        accountId: input.accountId,
        sessionId: input.sessionId,
        factorId: factor.id,
        purpose: input.purpose,
      });
      return { status: "accepted", factor, step };
    },

    async isStillCurrent(factor) {
      // By id: a reseal changes the sealed form only, the factor stays the same.
      const current = await store.totp.findActive(factor.accountId);
      if (!current || current.id !== factor.id) return false;
      const account = await store.accounts.findById(factor.accountId);
      return account?.status === "active";
    },
  };
}

export function createTotp(
  ctx: Context,
  engine: TotpEngine,
  sessions: Sessions,
  internals: SessionInternals,
): Totp {
  const { config, store, clock } = ctx;

  /**
   * The enrolment grant: a live session, an active account and the factor-change step-up.
   * `newFactorId` is the factor being enrolled, left out when the check runs again after
   * its activation.
   */
  async function grantHolds(
    record: SessionRecord,
    newFactorId?: string,
  ): Promise<true | { status: "denied"; reason: "no_session" | "step_up_required" }> {
    const account = await store.accounts.findById(record.accountId);
    if (!account || account.status !== "active") return { status: "denied", reason: "no_session" };
    const enrolled = await enrolledSecondFactors(
      ctx,
      record.accountId,
      newFactorId === undefined ? {} : { totpId: newFactorId },
    );
    if (!(await hasFreshStepUp(ctx, record, factorChangeStepUp(enrolled)))) {
      return { status: "denied", reason: "step_up_required" };
    }
    return true;
  }

  const enrolmentFailed = async (
    accountId: string,
    reason: string,
    factorId?: string,
  ): Promise<void> => {
    await ctx.emit({
      type: "totp.enrolment_failed",
      accountId,
      reason,
      ...(factorId ? { factorId } : {}),
    });
  };

  async function signInFailed(
    reason: TotpCheckFailure["reason"],
    detail: string,
    accountId?: string,
  ): Promise<TotpCheckFailure> {
    await ctx.emit({
      type: "totp.verify_failed",
      purpose: "second_factor",
      reason: detail,
      ...(accountId ? { accountId } : {}),
    });
    return { status: "failed", reason };
  }

  return {
    async startEnrolment(sessionToken) {
      await assertTotpInPolicy(ctx);
      const sealer = engine.requireSealer();
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const { record } = loaded;
      if (await store.totp.findActive(record.accountId)) {
        return { status: "denied", reason: "already_enrolled" };
      }
      const holds = await grantHolds(record);
      if (holds !== true) return holds;
      const account = await store.accounts.findById(record.accountId);
      if (!account) return { status: "denied", reason: "no_session" };

      const now = clock.now();
      const factorId = randomId();
      const { algorithm, digits } = config.totp;
      const secret = generateTotpSecret(algorithm);
      try {
        await store.totp.insert({
          id: factorId,
          accountId: account.id,
          sealedSecret: await sealer.seal(secret, sealContext(factorId, account.id)),
          algorithm,
          digits,
          createdAt: now,
          enrolmentSessionId: record.id,
          activatedAt: null,
          lastUsedStep: null,
          lastUsedAt: null,
        });
        await ctx.emit({
          type: "totp.enrolment_started",
          accountId: account.id,
          sessionId: record.id,
          factorId,
        });
        return {
          status: "ok",
          factorId,
          secret: base32Encode(secret),
          provisioningUri: provisioningUri({
            secret,
            issuer: config.totp.issuer,
            accountName: account.email,
            algorithm,
            digits,
          }),
          algorithm,
          digits,
          periodSeconds: TOTP_PERIOD_SECONDS,
          expiresAt: addSeconds(now, config.totp.enrolmentTtlSeconds),
        };
      } finally {
        secret.fill(0);
      }
    },

    async confirmEnrolment(sessionToken, input) {
      await assertTotpInPolicy(ctx);
      const sealer = engine.requireSealer();
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const { record } = loaded;
      const holds = await grantHolds(record);
      if (holds !== true) return holds;

      const factor =
        typeof input.factorId === "string" && FACTOR_ID_PATTERN.test(input.factorId)
          ? await store.totp.findPending(input.factorId)
          : null;
      if (
        !factor ||
        factor.accountId !== record.accountId ||
        factor.enrolmentSessionId !== record.id
      ) {
        await enrolmentFailed(record.accountId, "unknown_enrolment");
        return { status: "failed", reason: "invalid" };
      }
      const now = clock.now();
      if (
        now.getTime() >= addSeconds(factor.createdAt, config.totp.enrolmentTtlSeconds).getTime()
      ) {
        await enrolmentFailed(record.accountId, "expired", factor.id);
        return { status: "failed", reason: "expired" };
      }
      if (!codeShapeMatches(input.code, factor.digits)) {
        await enrolmentFailed(record.accountId, "malformed", factor.id);
        return { status: "failed", reason: "invalid" };
      }
      const key = enrolmentThrottleKey(record.accountId);
      if (await store.throttle.peek(key, now)) {
        await enrolmentFailed(record.accountId, "locked", factor.id);
        return { status: "failed", reason: "locked" };
      }
      const throttle = await store.throttle.reserve(key, now, config.totp.lockout);
      if (!throttle.allowed) {
        await enrolmentFailed(record.accountId, "locked", factor.id);
        return { status: "failed", reason: "locked" };
      }
      const secret = await sealer.open(
        factor.sealedSecret,
        sealContext(factor.id, factor.accountId),
      );
      let step: number | null;
      try {
        step = matchTimeStep({
          secret,
          code: input.code,
          at: now,
          driftSteps: config.totp.driftSteps,
          algorithm: factor.algorithm,
          digits: factor.digits,
        });
      } finally {
        secret.fill(0);
      }
      if (step === null) {
        await enrolmentFailed(record.accountId, "wrong_code", factor.id);
        return { status: "failed", reason: "invalid" };
      }
      // From the activation on, the factor can be usable. A revocation or a lost step-up
      // between the check above and the activation would be missed, so check once more. If
      // that check fails, or anything throws from the activation on (also an activation that
      // committed and then lost its reply), the factor goes and every session of the account
      // ends.
      const remove = async () => store.totp.delete(factor.id, factor.accountId);
      const removeAll = async () => store.totp.deleteAllForAccount(factor.accountId);
      const disable = async () => store.accounts.setStatus(factor.accountId, "disabled");
      const undo = async () => {
        try {
          await remove().catch(remove).catch(removeAll);
        } catch (error) {
          // The factor may still be active with a secret that someone without the grant
          // knows: fail closed and disable the account until an operator looks at it.
          const disabled = await disable()
            .catch(disable)
            .then(
              () => true,
              () => false,
            );
          await ctx
            .emit({
              type: "totp.enrolment_failed",
              accountId: factor.accountId,
              factorId: factor.id,
              reason: disabled
                ? "cleanup_failed_account_disabled"
                : "cleanup_failed_disable_failed",
            })
            .catch(() => undefined);
          if (disabled) {
            await ctx
              .emit({
                type: "account.disabled",
                accountId: factor.accountId,
                reason: "totp_cleanup",
              })
              .catch(() => undefined);
          }
          throw error;
        } finally {
          await sessions.revokeAll(factor.accountId);
        }
      };
      // The confirming code's step is recorded, so it cannot sign in or step up afterwards.
      let activated: boolean;
      try {
        activated = await store.totp.activate(factor.id, factor.accountId, step, now);
      } catch (error) {
        await undo().catch(() => undefined);
        throw error;
      }
      if (!activated) {
        await enrolmentFailed(record.accountId, "not_activated", factor.id);
        return { status: "failed", reason: "invalid" };
      }

      let outcome: true | { status: "denied"; reason: "no_session" | "step_up_required" };
      try {
        const live = await internals.loadById(record.id, "complete");
        outcome = live
          ? await grantHolds(live, factor.id)
          : { status: "denied", reason: "no_session" };
      } catch (error) {
        await undo().catch(() => undefined);
        throw error;
      }
      if (outcome !== true) {
        await undo();
        await enrolmentFailed(record.accountId, "grant_changed", factor.id);
        return outcome;
      }
      // Revoke first: if the audit sink fails afterwards, no other session survives. If the
      // revocation fails, the factor goes and every session ends, as for any other error.
      let revokedSessions: number;
      try {
        revokedSessions = await sessions.revokeAll(factor.accountId, {
          exceptSessionId: record.id,
        });
      } catch (error) {
        await undo().catch(() => undefined);
        throw error;
      }
      // Only now: a store error here must not skip the check and the revocation above.
      await store.throttle.reset(key);
      await ctx.emit({
        type: "totp.enrolled",
        accountId: factor.accountId,
        sessionId: record.id,
        factorId: factor.id,
      });
      return { status: "enrolled", factorId: factor.id, revokedSessions };
    },

    async verifySecondFactor(pendingToken, input) {
      assertMethodAllowed((await ctx.getPolicy()).secondFactorMethods, "totp");
      const loaded = await internals.load(pendingToken, "pending_second_factor");
      if (!loaded) return signInFailed("invalid", "no_pending_session");
      const { record } = loaded;
      const checked = await engine.check({
        accountId: record.accountId,
        code: input.code,
        purpose: "second_factor",
        sessionId: record.id,
      });
      if (checked.status !== "accepted") return checked;
      const issued = await internals.elevate(
        loaded,
        { state: "complete", addMethod: "totp", stepUp: { method: "totp", at: clock.now() } },
        "second_factor",
      );
      if (!issued) return signInFailed("invalid", "rotation", record.accountId);
      // A removal that raced with this check must not leave a session behind.
      if (!(await engine.isStillCurrent(checked.factor))) {
        await sessions.revokeById(record.id, "factor_removed");
        return signInFailed("invalid", "factor_removed", record.accountId);
      }
      const account = await store.accounts.findById(record.accountId);
      if (!account) {
        await sessions.revokeById(record.id, "account_disabled");
        return signInFailed("invalid", "no_account", record.accountId);
      }
      return { status: "signed_in", account: toAccountView(account), ...issued };
    },

    async get(accountId) {
      const factor = await store.totp.findActive(accountId);
      if (!factor || factor.activatedAt === null) return null;
      return {
        id: factor.id,
        algorithm: factor.algorithm,
        digits: factor.digits,
        createdAt: factor.createdAt,
        activatedAt: factor.activatedAt,
        lastUsedAt: factor.lastUsedAt,
      };
    },

    async remove(sessionToken) {
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const { record } = loaded;
      const factor = await store.totp.findActive(record.accountId);
      if (!factor) return { status: "denied", reason: "not_found" };
      const enrolled = await enrolledSecondFactors(ctx, record.accountId);
      if (!(await hasFreshStepUp(ctx, record, factorChangeStepUp(enrolled)))) {
        return { status: "denied", reason: "step_up_required" };
      }
      if (!(await store.totp.delete(factor.id, record.accountId))) {
        return { status: "denied", reason: "not_found" };
      }
      // Revoke first: if the audit sink fails afterwards, no other session survives. One
      // retry: a retried `remove` would answer `not_found` and not reach the revocation.
      const revokeOthers = async () =>
        sessions.revokeAll(record.accountId, { exceptSessionId: record.id });
      await revokeOthers().catch(revokeOthers);
      await ctx.emit({
        type: "totp.removed",
        accountId: record.accountId,
        sessionId: record.id,
        factorId: factor.id,
      });
      return { status: "removed" };
    },

    async revoke(accountId) {
      const factor = await store.totp.findActive(accountId);
      // Pending factors too: an enrolment confirmed at this moment must not survive.
      const deleted = await store.totp.deleteAllForAccount(accountId);
      // Always, also without a factor: a retry after a failed revocation must still end them.
      await sessions.revokeAll(accountId);
      if (deleted === 0) return false;
      await ctx.emit({
        type: "totp.removed",
        accountId,
        ...(factor ? { factorId: factor.id } : {}),
        reason: "administrative",
      });
      return true;
    },

    async reseal(accountId) {
      const sealer = engine.requireSealer();
      const factor = await store.totp.findActive(accountId);
      if (!factor) return false;
      const context = sealContext(factor.id, factor.accountId);
      const secret = await sealer.open(factor.sealedSecret, context);
      let resealed: string;
      try {
        resealed = await sealer.seal(secret, context);
      } finally {
        secret.fill(0);
      }
      if (!(await store.totp.replaceSealedSecret(factor.id, factor.sealedSecret, resealed))) {
        return false;
      }
      await ctx.emit({ type: "totp.resealed", accountId, factorId: factor.id });
      return true;
    },
  };
}
