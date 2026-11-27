/**
 * Security-relevant events. Events never carry a code, token, token digest, challenge, key, TOTP
 * secret, sealed secret, provisioning URI, e-mail address, ID token or provider subject. `addressDigest` is a keyed hash of the normalized address, so a consumer can
 * correlate events for one address without identkit writing the address itself.
 */
export type AuditEventType =
  | "otp.sent"
  | "otp.send_refused"
  | "otp.verified"
  | "otp.verify_failed"
  | "otp.locked"
  | "address.locked"
  | "lockout.released"
  | "account.created"
  | "account.disabled"
  | "session.created"
  | "session.rotated"
  | "session.revoked"
  | "session.expired"
  | "second_factor.required"
  | "second_factor.unavailable"
  | "step_up.granted"
  | "step_up.failed"
  | "passkey.registered"
  | "passkey.registration_failed"
  | "passkey.removed"
  | "passkey.sign_in_failed"
  | "passkey.counter_regression"
  | "approval.challenge_created"
  | "approval.verified"
  | "approval.code_confirmation_recorded"
  | "approval.failed"
  | "totp.enrolment_started"
  | "totp.enrolled"
  | "totp.enrolment_failed"
  | "totp.verified"
  | "totp.verify_failed"
  | "totp.locked"
  | "totp.removed"
  | "totp.resealed"
  | "enrollment.issued"
  | "enrollment.used"
  | "enrollment.revoked"
  | "identity_verification.started"
  | "identity_verification.completed"
  | "identity_verification.failed"
  | "identity_verification.expired"
  | "identity_verification.person_conflict"
  | "oidc.signed_in"
  | "oidc.sign_in_failed"
  | "oidc.binding_refused"
  | "oidc.link_created"
  | "oidc.link_imported"
  | "oidc.link_removed"
  | "api_token.created"
  | "api_token.imported"
  | "api_token.revoked"
  | "api_token.used";

export interface AuditEvent {
  type: AuditEventType;
  at: Date;
  accountId?: string;
  sessionId?: string;
  flowId?: string;
  credentialId?: string;
  /** Id of a TOTP factor. */
  factorId?: string;
  verificationId?: string;
  challengeId?: string;
  addressDigest?: string;
  purpose?: string;
  method?: string;
  reason?: string;
  /** SHA-256 hex of the approved payload, for approval events. */
  payloadHash?: string;
  /** Approval proof level, for approval events: `signature` or `code-confirmation`. */
  level?: string;
  /** OIDC events: the configured provider id, or the provider kind for imports and removals. */
  provider?: string;
  /** OIDC events: id of the link between an account and a provider subject. */
  linkId?: string;
  /** API token events: the token's id, never the token or its digest. */
  tokenId?: string;
  /** `api_token.created` and `api_token.imported`: the scopes the token was given. */
  scopes?: string[];
}

/**
 * Receives audit events. identkit awaits `emit`; if it throws, the calling operation
 * fails, so an operation never succeeds without its audit record. One exception:
 * `api_token.used` is best effort, and `apiTokens.verify` still succeeds (see the option
 * `apiTokens.onAuditError`).
 */
export interface AuditSink {
  emit(event: AuditEvent): void | Promise<void>;
}
