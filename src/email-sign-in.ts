import { newAccountRecord, toAccountView, type AccountView } from "./accounts.js";
import type { SecondFactorMethod } from "./config.js";
import type { Context } from "./context.js";
import {
  assertMethodAllowed,
  type CodeFailure,
  type OtpEngine,
  type RequestCodeResult,
} from "./email-otp.js";
import { enrolledSecondFactors } from "./second-factor.js";
import type { IssuedSession, SessionInternals } from "./sessions.js";
import type { AccountRecord } from "./storage/types.js";

export type EmailSignInResult =
  | ({ status: "signed_in"; account: AccountView; accountCreated: boolean } & IssuedSession)
  | {
      status: "second_factor_required";
      pendingToken: string;
      expiresAt: Date;
      /** Methods that can complete this sign-in: enrolled and allowed by the policy. */
      methods: SecondFactorMethod[];
    }
  /**
   * A second factor is due but none can be used: the account is privileged and has none
   * (`enrolment_required`), or it has one that the policy does not allow (`method_not_allowed`).
   * Only the holder of a valid code sees this answer.
   */
  | { status: "second_factor_unavailable"; reason: "enrolment_required" | "method_not_allowed" }
  | CodeFailure;

export interface EmailSignIn {
  /**
   * Sends a sign-in code to the address. The result is the same for a known and an unknown
   * address. Throws `MethodNotAllowedError` if the policy does not allow e-mail codes.
   */
  requestCode(input: { email: string }): Promise<RequestCodeResult>;
  /** Verifies the code of a flow. A code works once, only for the flow that requested it. */
  verifyCode(input: { flowId: string; code: string }): Promise<EmailSignInResult>;
}

export function createEmailSignIn(
  ctx: Context,
  otp: OtpEngine,
  internals: SessionInternals,
): EmailSignIn {
  const { store, clock } = ctx;

  async function accountFor(
    email: string,
    allowCreate: boolean,
  ): Promise<{ account: AccountRecord; created: boolean } | null> {
    const existing = await store.accounts.findByEmail(email);
    if (existing) return { account: existing, created: false };
    if (!allowCreate) return null;
    const record = newAccountRecord(email, clock.now());
    if ((await store.accounts.insert(record)) === "inserted") {
      await ctx.emit({ type: "account.created", accountId: record.id, reason: "first_sign_in" });
      return { account: record, created: true };
    }
    // Another request created the account for this address in the meantime.
    const raced = await store.accounts.findByEmail(email);
    return raced ? { account: raced, created: false } : null;
  }

  return {
    async requestCode(input) {
      assertMethodAllowed((await ctx.getPolicy()).signInMethods, "email_otp");
      return otp.issue({ email: input.email, purpose: "sign_in", sessionId: null });
    },

    async verifyCode(input) {
      const policy = await ctx.getPolicy();
      assertMethodAllowed(policy.signInMethods, "email_otp");
      const checked = await otp.check({ ...input, purpose: "sign_in", sessionId: null });
      if (checked.status !== "verified") return checked;

      const found = await accountFor(checked.flow.email, policy.createAccountOnFirstSignIn);
      if (!found || found.account.status !== "active") {
        // Only the holder of a valid code reaches this point; the answer stays generic.
        await ctx.emit({
          type: "otp.verify_failed",
          flowId: checked.flow.id,
          addressDigest: checked.flow.addressDigest,
          purpose: "sign_in",
          reason: found ? "account_disabled" : "no_account",
        });
        return { status: "failed", reason: "invalid" };
      }
      const { account, created } = found;

      // The consumer decides who is privileged; a privileged account always needs a second
      // factor, whatever the policy says.
      const privileged = await ctx.isPrivilegedAccount(toAccountView(account));

      /** Null if no second factor is due; else the methods that can complete the sign-in. */
      const secondFactorDue = async (): Promise<SecondFactorMethod[] | null> => {
        const enrolled = await enrolledSecondFactors(ctx, account.id);
        const required =
          privileged || (policy.secondFactor === "if_enrolled" && enrolled.length > 0);
        if (!required) return null;
        return enrolled.filter((m) => policy.secondFactorMethods.includes(m));
      };

      async function pendingSession(methods: SecondFactorMethod[]): Promise<EmailSignInResult> {
        if (methods.length === 0) {
          const reason =
            (await enrolledSecondFactors(ctx, account.id)).length === 0
              ? "enrolment_required"
              : "method_not_allowed";
          await ctx.emit({
            type: "second_factor.unavailable",
            accountId: account.id,
            reason,
          });
          return { status: "second_factor_unavailable", reason };
        }
        const pending = await internals.create({
          accountId: account.id,
          state: "pending_second_factor",
          authMethods: ["email_otp"],
          stepUp: null,
        });
        await ctx.emit({
          type: "second_factor.required",
          accountId: account.id,
          sessionId: pending.session.id,
        });
        return {
          status: "second_factor_required",
          pendingToken: pending.token,
          expiresAt: pending.session.expiresAt,
          methods,
        };
      }

      const due = await secondFactorDue();
      if (due !== null) return pendingSession(due);

      const issued = await internals.create({
        accountId: account.id,
        state: "complete",
        authMethods: ["email_otp"],
        stepUp: { method: "email_otp", at: clock.now() },
      });
      // A first second factor enrolled while this sign-in ran makes the second factor due:
      // check again after the insert, so the race cannot yield a full session.
      const dueNow = await secondFactorDue();
      if (dueNow !== null) {
        if (await store.sessions.revoke(issued.session.id, clock.now(), "second_factor_due")) {
          await ctx.emit({
            type: "session.revoked",
            accountId: account.id,
            sessionId: issued.session.id,
            reason: "second_factor_due",
          });
        }
        return pendingSession(dueNow);
      }
      return {
        status: "signed_in",
        account: toAccountView(account),
        accountCreated: created,
        ...issued,
      };
    },
  };
}
