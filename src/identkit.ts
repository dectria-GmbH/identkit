import { createAccounts, type Accounts } from "./accounts.js";
import { createApprovals, type Approvals } from "./approvals.js";
import type { AuditSink } from "./audit.js";
import { systemClock, type Clock } from "./clock.js";
import { parseConfig, signInPolicySchema, type SignInPolicy } from "./config.js";
import { createEmitter, type Context, type MailSender } from "./context.js";
import type { SecretHasher } from "./crypto.js";
import { createEmailSignIn, type EmailSignIn } from "./email-sign-in.js";
import { createOtpEngine } from "./email-otp.js";
import {
  createIdentityVerification,
  type IdentityVerification,
  type IdentityVerificationAdapter,
} from "./identity-verification.js";
import { createPasskeyCore } from "./passkey-core.js";
import { createPasskeys, type Passkeys } from "./passkeys.js";
import { createSessions, type Sessions } from "./sessions.js";
import { createStepUp, type StepUp } from "./step-up.js";
import type { IdentkitStore } from "./storage/types.js";

export interface IdentkitOptions {
  /** Validated with `identkitConfigSchema`. Every time and limit value is required. */
  config: unknown;
  store: IdentkitStore;
  hasher: SecretHasher;
  mail: MailSender;
  audit: AuditSink;
  /**
   * The operator policy, or a function that returns the current one. A function is called
   * on every policy-dependent call, so a policy change applies at once.
   */
  policy: SignInPolicy | (() => SignInPolicy | Promise<SignInPolicy>);
  clock?: Clock;
  identityVerification?: IdentityVerificationAdapter;
}

export interface Identkit {
  emailSignIn: EmailSignIn;
  passkeys: Passkeys;
  stepUp: StepUp;
  sessions: Sessions;
  approvals: Approvals;
  accounts: Accounts;
  identityVerification: IdentityVerification;
}

export function createIdentkit(options: IdentkitOptions): Identkit {
  const config = parseConfig(options.config);
  const clock = options.clock ?? systemClock;
  const policySource = options.policy;
  if (typeof policySource !== "function") signInPolicySchema.parse(policySource);

  const ctx: Context = {
    config,
    store: options.store,
    hasher: options.hasher,
    clock,
    mail: options.mail,
    identityVerification: options.identityVerification ?? null,
    getPolicy: async () =>
      signInPolicySchema.parse(
        typeof policySource === "function" ? await policySource() : policySource,
      ),
    emit: createEmitter(options.audit, clock),
  };

  const otp = createOtpEngine(ctx);
  const { sessions, internals } = createSessions(ctx);
  const core = createPasskeyCore(ctx);

  return {
    emailSignIn: createEmailSignIn(ctx, otp, internals),
    passkeys: createPasskeys(ctx, core, sessions, internals),
    stepUp: createStepUp(ctx, otp, core, internals),
    sessions,
    approvals: createApprovals(ctx, core, internals),
    accounts: createAccounts(ctx, (accountId) => sessions.revokeAll(accountId)),
    identityVerification: createIdentityVerification(ctx),
  };
}
