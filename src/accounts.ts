import { emitApiTokensRevoked, revokeAllApiTokens } from "./api-tokens.js";
import type { Context } from "./context.js";
import { randomBytes, toBase64Url } from "./bytes.js";
import { randomId } from "./crypto.js";
import { normalizeEmail } from "./email.js";
import { AllSessionsRevokedHookError } from "./errors.js";
import { throttleKey as otpThrottleKey } from "./email-otp.js";
import { totpEnrolmentThrottleKey, totpThrottleKey } from "./throttle-keys.js";
import { emitOAuthGrantsEnded, endAllOAuthGrants } from "./oauth/grant-end.js";
import { finishThenRunHook, type Revocation } from "./sessions.js";
import type { AccountRecord, OAuthGrantRecord } from "./storage/types.js";

export interface AccountView {
  id: string;
  email: string;
  status: AccountRecord["status"];
  createdAt: Date;
  identityVerified: boolean;
  assuranceLevel: AccountRecord["assuranceLevel"];
}

export type CreateAccountResult =
  { status: "created"; account: AccountView } | { status: "email_taken" };

/**
 * Administrative account operations. These calls trust their caller: expose them only to
 * privileged code paths, never to an unauthenticated client.
 */
export interface Accounts {
  /**
   * Creates an account for an address. An address belongs to at most one account, and a
   * verified person to at most one account, so this never yields a second account for the
   * same address.
   */
  create(input: { email: string }): Promise<CreateAccountResult>;
  get(accountId: string): Promise<AccountView | null>;
  findByEmail(email: string): Promise<AccountView | null>;
  /**
   * Disables the account, revokes all its sessions and personal API tokens, and ends all its
   * OAuth grants and codes. Records `account.disabled` only if the account was not disabled
   * yet, so a retry after an error does not record it twice.
   */
  disable(accountId: string): Promise<void>;
  /**
   * Lifts the failure locks of the account: e-mail codes of its address (sign-in and step-up)
   * and TOTP (checks and enrolment confirmation). Clears the lock, the lock length and both
   * failure counts, as a success would. Returns false if the account does not exist.
   * Operator only: a caller who can unlock can guess without limit. The audit event
   * `lockout.released` is written before the resets: if a reset throws, call again.
   */
  unlock(accountId: string): Promise<boolean>;
  /**
   * Lifts the e-mail code locks of an address (sign-in and step-up), also for an address
   * without an account. Operator only, like `unlock`.
   */
  unlockAddress(email: string): Promise<void>;
}

export function toAccountView(record: AccountRecord): AccountView {
  return {
    id: record.id,
    email: record.email,
    status: record.status,
    createdAt: record.createdAt,
    identityVerified: record.personKeyDigest !== null,
    assuranceLevel: record.assuranceLevel,
  };
}

export function newAccountRecord(email: string, createdAt: Date): AccountRecord {
  return {
    id: randomId(),
    email,
    webauthnUserId: toBase64Url(randomBytes(32)),
    status: "active",
    createdAt,
    personKeyDigest: null,
    assuranceLevel: null,
    identityVerifiedAt: null,
  };
}

export function createAccounts(
  ctx: Context,
  revokeAll: (accountId: string) => Promise<Revocation>,
): Accounts {
  const { store, clock, hasher } = ctx;

  /** Resets the e-mail code throttles of an address digest. */
  async function releaseAddress(addressDigest: string): Promise<void> {
    await store.throttle.reset(otpThrottleKey("sign_in", addressDigest));
    await store.throttle.reset(otpThrottleKey("step_up", addressDigest));
  }

  return {
    async create(input) {
      const email = normalizeEmail(input.email);
      const record = newAccountRecord(email, clock.now());
      const result = await store.accounts.insert(record);
      if (result === "email_taken") return { status: "email_taken" };
      await ctx.emit({ type: "account.created", accountId: record.id, reason: "administrative" });
      return { status: "created", account: toAccountView(record) };
    },
    async get(accountId) {
      const record = await store.accounts.findById(accountId);
      return record ? toAccountView(record) : null;
    },
    async findByEmail(email) {
      const record = await store.accounts.findByEmail(normalizeEmail(email));
      return record ? toAccountView(record) : null;
    },
    async unlock(accountId) {
      const record = await store.accounts.findById(accountId);
      if (!record) return false;
      // Normalized like a code request, also for a row written outside identkit. A malformed
      // address never got a code lock (every code path normalizes first), so keep it as is.
      let email = record.email;
      try {
        email = normalizeEmail(record.email);
      } catch {
        // Keep the stored value: its TOTP locks must still be lifted.
      }
      const addressDigest = await hasher.digest("address", email);
      // The event first: a reset that fails after an earlier one lifted a lock must not leave
      // a released lock without its audit record. A retry writes the event again.
      await ctx.emit({
        type: "lockout.released",
        accountId,
        addressDigest,
        reason: "administrative",
      });
      await releaseAddress(addressDigest);
      await store.throttle.reset(totpThrottleKey(accountId));
      await store.throttle.reset(totpEnrolmentThrottleKey(accountId));
      return true;
    },
    async unlockAddress(email) {
      const addressDigest = await hasher.digest("address", normalizeEmail(email));
      // The event first, as in `unlock`.
      await ctx.emit({ type: "lockout.released", addressDigest, reason: "administrative" });
      await releaseAddress(addressDigest);
    },
    async disable(accountId) {
      const record = await store.accounts.findById(accountId);
      if (!record) return;
      // Only the call that changes the status records it, so a retry after an error does not
      // record the disable twice.
      const changed = record.status !== "disabled";
      const event = { type: "account.disabled", accountId } as const;
      await store.accounts.setStatus(accountId, "disabled");
      // API tokens first, but sessions and the hook do not depend on them: a store error there
      // (for example a schema without the token table) must not leave the account's sessions
      // live. That error goes up at the end; `verify` refuses tokens of a disabled account anyway.
      let tokenIds: string[] = [];
      let tokenFailure: { error: unknown } | null = null;
      try {
        tokenIds = await revokeAllApiTokens(ctx, accountId, "account_disabled");
      } catch (error) {
        tokenFailure = { error };
      }
      // OAuth grants next, with the same rule: a store error goes up at the end, and
      // `validateAccessToken` and a refresh refuse a disabled account anyway.
      let grants: OAuthGrantRecord[] = [];
      let grantFailure: { error: unknown } | null = null;
      try {
        grants = await endAllOAuthGrants(ctx, accountId);
      } catch (error) {
        grantFailure = { error };
      }
      let revoked: Revocation;
      try {
        revoked = await revokeAll(accountId);
      } catch (error) {
        // A retry finds the account disabled and these tokens and grants gone, and records
        // none of them: record them now.
        if (changed) await ctx.emit(event).catch(() => undefined);
        await emitApiTokensRevoked(ctx, accountId, tokenIds, "account_disabled").catch(
          () => undefined,
        );
        await emitOAuthGrantsEnded(ctx, accountId, grants, "account_disabled").catch(
          () => undefined,
        );
        throw error;
      }
      // Hook last: a throwing hook must not skip the audit events, nor a throwing sink the hook.
      // Which error goes up: the hook's, then the sink's, then the token store's, then the grant
      // store's. Only a failed hook leaves something live, and a refused event is lost for good:
      // a retry of `disable` repeats the token revocation and the end of the grants, their
      // events and the hook, but records neither `account.disabled` (the account is disabled
      // already) nor `session.revoked` (the sessions are revoked already). The tokens and grants
      // stay unusable while the account is disabled, but a retry is the only call that removes
      // them. The hook's error carries the store errors as `tokenRevocationError` and
      // `grantRevocationError`; the sink's error is not changed, so after it the store errors
      // show only on the retry. With both store errors and no other, the token store's goes up.
      const finished = finishThenRunHook(revoked, async () => {
        let failure: { error: unknown } | null = null;
        try {
          if (changed) await ctx.emit(event);
        } catch (error) {
          failure = { error };
        }
        try {
          await emitApiTokensRevoked(ctx, accountId, tokenIds, "account_disabled");
        } catch (error) {
          failure ??= { error };
        }
        try {
          await emitOAuthGrantsEnded(ctx, accountId, grants, "account_disabled");
        } catch (error) {
          failure ??= { error };
        }
        if (failure) throw failure.error;
      });
      const storeFailure = tokenFailure ?? grantFailure;
      if (!storeFailure) return finished;
      try {
        await finished;
      } catch (error) {
        if (!(error instanceof AllSessionsRevokedHookError)) throw error;
        throw new AllSessionsRevokedHookError(error.accountId, error.exceptSessionId, {
          cause: error.cause,
          auditError: error.auditError,
          ...(tokenFailure ? { tokenRevocationError: tokenFailure.error } : {}),
          ...(grantFailure ? { grantRevocationError: grantFailure.error } : {}),
        });
      }
      throw storeFailure.error;
    },
  };
}
