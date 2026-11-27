import { toAccountView, type AccountView } from "./accounts.js";
import type { SecondFactorMethod, SignInPolicy } from "./config.js";
import type { Context } from "./context.js";
import { enrolledSecondFactors } from "./second-factor.js";
import type { IssuedSession, SessionInternals } from "./sessions.js";
import type { AccountRecord, StepUpRecord } from "./storage/types.js";

/** The outcome of a first factor that proved control of an active account. */
export type FirstFactorResult =
  | ({ status: "signed_in"; account: AccountView } & IssuedSession)
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
   */
  | { status: "second_factor_unavailable"; reason: "enrolment_required" | "method_not_allowed" };

/**
 * Completes a sign-in after a first factor (an e-mail code or an external provider): a full
 * session, or a pending one if a second factor is due by the policy or because the account is
 * privileged.
 */
export async function completeFirstFactor(
  ctx: Context,
  internals: SessionInternals,
  input: {
    account: AccountRecord;
    policy: SignInPolicy;
    method: "email_otp" | "oidc";
    /** What the full session records as its step-up; null if the method is no step-up. */
    stepUp: StepUpRecord | null;
  },
): Promise<FirstFactorResult> {
  const { store, clock } = ctx;
  const { account, policy, method } = input;

  // The consumer decides who is privileged; a privileged account always needs a second
  // factor, whatever the policy says.
  const privileged = await ctx.isPrivilegedAccount(toAccountView(account));

  /** Null if no second factor is due; else the methods that can complete the sign-in. */
  const secondFactorDue = async (): Promise<SecondFactorMethod[] | null> => {
    const enrolled = await enrolledSecondFactors(ctx, account.id);
    const required = privileged || (policy.secondFactor === "if_enrolled" && enrolled.length > 0);
    if (!required) return null;
    return enrolled.filter((m) => policy.secondFactorMethods.includes(m));
  };

  async function pendingSession(methods: SecondFactorMethod[]): Promise<FirstFactorResult> {
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
      authMethods: [method],
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
    authMethods: [method],
    stepUp: input.stepUp,
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
  return { status: "signed_in", account: toAccountView(account), ...issued };
}
