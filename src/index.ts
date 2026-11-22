export { createIdentkit, type Identkit, type IdentkitOptions } from "./identkit.js";
export {
  identkitConfigSchema,
  signInPolicySchema,
  parseConfig,
  MAX_CODE_TTL_SECONDS,
  MAX_ADDRESS_FAILURES,
  type IdentkitConfig,
  type SignInPolicy,
  type SignInMethod,
  type StepUpMethod,
} from "./config.js";
export { systemClock, type Clock } from "./clock.js";
export {
  createHmacHasher,
  MIN_HASH_KEY_BYTES,
  OTP_DIGITS,
  TOKEN_BYTES,
  type HashPurpose,
  type SecretHasher,
} from "./crypto.js";
export type { AuditEvent, AuditEventType, AuditSink } from "./audit.js";
export type { MailSender, OtpMailPurpose } from "./context.js";
export { IdentkitError, MethodNotAllowedError, NotConfiguredError } from "./errors.js";
export { normalizeEmail, InvalidEmailError } from "./email.js";
export type { RequestCodeResult, CodeFailure } from "./email-otp.js";
export type { EmailSignIn, EmailSignInResult } from "./email-sign-in.js";
export type {
  Passkeys,
  PasskeyInfo,
  PasskeySignInResult,
  RegistrationGrant,
  StartRegistrationResult,
  FinishRegistrationResult,
  SecondFactorStart,
} from "./passkeys.js";
export type { StepUp, StepUpResult } from "./step-up.js";
export type { Sessions, SessionView, IssuedSession, StepUpCheck } from "./sessions.js";
export {
  approvalChallenge,
  hashPayload,
  verifyApprovalEvidence,
  type Approvals,
  type ApprovalProof,
  type StartApprovalResult,
  type VerifyApprovalResult,
} from "./approvals.js";
export type { Accounts, AccountView, CreateAccountResult } from "./accounts.js";
export type {
  IdentityVerification,
  IdentityVerificationAdapter,
  VendorResult,
  VerificationView,
} from "./identity-verification.js";
export type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  PasskeyCreationOptions,
  PasskeyRequestOptions,
} from "./webauthn.js";
export { createMemoryStore } from "./storage/memory.js";
export type * from "./storage/types.js";
