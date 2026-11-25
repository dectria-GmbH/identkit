export { createIdentkit, type Identkit, type IdentkitOptions } from "./identkit.js";
export {
  identkitConfigSchema,
  signInPolicySchema,
  parseConfig,
  MAX_CODE_TTL_SECONDS,
  MAX_ADDRESS_FAILURES,
  MAX_TOTP_DRIFT_STEPS,
  type IdentkitConfig,
  type SignInPolicy,
  type SignInMethod,
  type SecondFactorMethod,
  type AuthMethod,
  type StepUpMethod,
  type ApprovalEvidenceLevel,
} from "./config.js";
export {
  createAesGcmSealer,
  SealedSecretError,
  SEALER_KEY_BYTES,
  type AesGcmSealerOptions,
  type SecretSealer,
} from "./sealer.js";
export {
  TOTP_INTEROPERABLE_PARAMETERS,
  TOTP_PERIOD_SECONDS,
  TOTP_SECRET_BYTES,
  type TotpAlgorithm,
  type TotpDigits,
} from "./totp-core.js";
export type {
  Totp,
  TotpFactorInfo,
  TotpSignInResult,
  TotpCheckFailure,
  StartTotpEnrolmentResult,
  ConfirmTotpEnrolmentResult,
} from "./totp.js";
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
export {
  IdentkitError,
  InvalidArgumentError,
  MethodNotAllowedError,
  NotConfiguredError,
} from "./errors.js";
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
  checkApprovalEvidence,
  type Approvals,
  type ApprovalProof,
  type ApprovalEvidence,
  type ApprovalEvidenceCheck,
  type ApprovalEvidenceVerifier,
  type CheckApprovalEvidenceInput,
  type CodeConfirmationEvidence,
  type ApprovalStartInput,
  type ApprovalVerifyInput,
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
export { applyThrottle, lockDuration, type ThrottleState } from "./storage/throttle-logic.js";
export type * from "./storage/types.js";
