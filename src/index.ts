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
  AllSessionsRevokedHookError,
  IdentkitError,
  InvalidArgumentError,
  MethodNotAllowedError,
  NotConfiguredError,
  OAuthClientRolledBackError,
  OperationRolledBackError,
  PasskeyCleanupError,
  SessionsNotRevokedError,
} from "./errors.js";
export { NodeCryptoUnavailableError } from "./node-crypto.js";
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
export type {
  Sessions,
  SessionView,
  IssuedSession,
  StepUpCheck,
  AllSessionsRevokedEvent,
  AllSessionsRevokedHook,
} from "./sessions.js";
export {
  approvalChallenge,
  approvalChallengeAsync,
  hashPayload,
  hashPayloadAsync,
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
export {
  apiTokenOptionsSchema,
  parseBearerToken,
  type ApiTokens,
  type ApiTokenAuditErrorHandler,
  type ApiTokenOptions,
  type ApiTokenView,
  type ApiTokenRefusal,
  type CreateApiTokenResult,
  type VerifyApiTokenResult,
  type ImportApiTokenInput,
  type ImportApiTokenResult,
} from "./api-tokens.js";
export {
  oauthOptionsSchema,
  type AuthorizeBeginResult,
  type AuthorizeDecisionResult,
  type AuthorizeError,
  type AuthorizeRefusal,
  type ImportOAuthClientInput,
  type ImportOAuthClientResult,
  type ImportOAuthGrantInput,
  type ImportOAuthGrantResult,
  type OAuth,
  type OAuthAuthorize,
  type OAuthAccessTokenRefusal,
  type OAuthGrantEndReason,
  type OAuthGrantView,
  type OAuthTokenFailure,
  type ValidateAccessTokenResult,
  type OAuthAdmitHook,
  type OAuthAdmitRequest,
  type OAuthAuditErrorHandler,
  type OAuthClientView,
  type OAuthEndpointResult,
  type OAuthLegacyAccessTokenVerifier,
  type OAuthLegacyRefreshTokenVerifier,
  type OAuthMetadata,
  type OAuthOptions,
  type OAuthParams,
  type OAuthStoreErrorHandler,
  type WwwAuthenticateInput,
} from "./oauth/index.js";
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
export type {
  Oidc,
  OidcOptions,
  OidcBindRequest,
  OidcBeginResult,
  OidcSignInResult,
  OidcFailure,
  OidcRefusal,
  OidcLinkView,
  OidcImportInput,
  OidcImportResult,
} from "./oidc.js";
export {
  microsoftProvider,
  googleProvider,
  oidcProvider,
  MICROSOFT_CONSUMER_TENANT_ID,
  type OidcProvider,
  type MicrosoftProviderOptions,
  type GoogleProviderOptions,
  type GenericOidcProviderOptions,
} from "./oidc-providers.js";
export { createJwksCache, type JwksCache, type OidcFetch } from "./oidc-jwks.js";
export type { IdTokenAlgorithm } from "./oidc-jwt.js";
export { createMemoryStore } from "./storage/memory.js";
export { applyThrottle, lockDuration, type ThrottleState } from "./storage/throttle-logic.js";
export type * from "./storage/types.js";
