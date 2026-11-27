import { createAccounts, type Accounts, type AccountView } from "./accounts.js";
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
import { NotConfiguredError } from "./errors.js";
import { createOidc, unconfiguredOidc, type Oidc, type OidcOptions } from "./oidc.js";
import type { SecretSealer } from "./sealer.js";
import { createSessions, type AllSessionsRevokedHook, type Sessions } from "./sessions.js";
import { createStepUp, type StepUp } from "./step-up.js";
import type { IdentkitStore } from "./storage/types.js";
import { createTotp, createTotpEngine, type Totp } from "./totp.js";

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
  /**
   * Required. Decides whether an account is privileged. A privileged account always needs a
   * second factor after an e-mail code, whatever the policy's `secondFactor` says, and is
   * refused a session if it has none. Pass `() => false` if no account is privileged.
   * Called on every e-mail code sign-in; if it throws, the sign-in fails.
   */
  isPrivilegedAccount: (account: AccountView) => boolean | Promise<boolean>;
  /**
   * Encrypts TOTP secrets at rest. Required for every TOTP call; without it they throw
   * `NotConfiguredError`.
   */
  sealer?: SecretSealer;
  clock?: Clock;
  identityVerification?: IdentityVerificationAdapter;
  /**
   * Called after every `sessions.revokeAll`, also when accounts, passkeys or TOTP call it (for
   * example on a disable, a new passkey or a TOTP removal), and also when no session was live.
   * Use it to end sessions that your application keeps itself. It runs last: after the
   * revocation, the calling operation's own writes and its audit events. It runs also when the
   * audit sink throws on those events; the sink's first error then goes up after it. If it
   * throws, the calling operation throws `AllSessionsRevokedHookError` (with the sink's error as
   * `auditError`, if any); everything identkit does is done by then and the operation's writes
   * stand. An operation that identkit rolled back throws `OperationRolledBackError` instead,
   * with `hookFailed` true. Re-run the hook with
   * `sessions.revokeAll(error.accountId, error.revokeAllOptions)`. Make it idempotent.
   */
  onAllSessionsRevoked?: AllSessionsRevokedHook;
  /**
   * Sign-in through external OpenID Connect providers. Needs the config section `oidc`, a
   * `sealer` and a store with `oidcLinks`; `createIdentkit` throws `NotConfiguredError` if one
   * is missing. Without this option, every `identkit.oidc` call throws `NotConfiguredError`.
   *
   * Deploy this release to every instance before you set it, and finish a gradual deployment
   * first: an identkit release without OIDC sign-in (any release before this one) cannot read
   * the sessions of an OIDC sign-in and fails them. A rollback to such a release after the
   * first OIDC sign-in fails those sessions too.
   */
  oidc?: OidcOptions;
}

export interface Identkit {
  emailSignIn: EmailSignIn;
  passkeys: Passkeys;
  stepUp: StepUp;
  sessions: Sessions;
  approvals: Approvals;
  totp: Totp;
  accounts: Accounts;
  identityVerification: IdentityVerification;
  oidc: Oidc;
}

export function createIdentkit(options: IdentkitOptions): Identkit {
  const config = parseConfig(options.config);
  const clock = options.clock ?? systemClock;
  const policySource = options.policy;
  if (typeof policySource !== "function") {
    const policy = signInPolicySchema.parse(policySource);
    const usesTotp =
      policy.secondFactorMethods.includes("totp") ||
      policy.stepUpMethods.includes("totp") ||
      policy.approvalEvidenceLevels.includes("code-confirmation");
    if (usesTotp && !options.sealer) throw new NotConfiguredError("sealer");
  }
  const isPrivileged = options.isPrivilegedAccount;
  if (typeof isPrivileged !== "function") {
    throw new TypeError("isPrivilegedAccount is required: pass () => false if no account is");
  }

  const ctx: Context = {
    config,
    store: options.store,
    hasher: options.hasher,
    clock,
    mail: options.mail,
    identityVerification: options.identityVerification ?? null,
    sealer: options.sealer ?? null,
    // Strict: a hook that returns no boolean (for example a missing `return`) is a bug that
    // would make every account non-privileged, so it fails the sign-in instead.
    isPrivilegedAccount: async (account) => {
      const result: unknown = await isPrivileged(account);
      if (typeof result !== "boolean") {
        throw new TypeError("isPrivilegedAccount must return a boolean");
      }
      return result;
    },
    getPolicy: async () =>
      signInPolicySchema.parse(
        typeof policySource === "function" ? await policySource() : policySource,
      ),
    emit: createEmitter(options.audit, clock),
  };

  const otp = createOtpEngine(ctx);
  const onAllSessionsRevoked = options.onAllSessionsRevoked ?? null;
  if (onAllSessionsRevoked !== null && typeof onAllSessionsRevoked !== "function") {
    throw new TypeError("onAllSessionsRevoked must be a function");
  }
  const { sessions, internals } = createSessions(ctx, onAllSessionsRevoked);
  const core = createPasskeyCore(ctx);
  const totpEngine = createTotpEngine(ctx);

  return {
    emailSignIn: createEmailSignIn(ctx, otp, internals),
    passkeys: createPasskeys(ctx, core, sessions, internals),
    stepUp: createStepUp(ctx, otp, core, totpEngine, internals),
    sessions,
    approvals: createApprovals(ctx, core, totpEngine, internals),
    totp: createTotp(ctx, totpEngine, sessions, internals),
    accounts: createAccounts(ctx, (accountId) => internals.revokeAllDeferringHook(accountId)),
    identityVerification: createIdentityVerification(ctx),
    oidc: options.oidc ? createOidc(ctx, internals, options.oidc) : unconfiguredOidc(),
  };
}
