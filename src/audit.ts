/**
 * Security-relevant events. Events never carry a code, token, challenge, key, TOTP secret,
 * sealed secret, provisioning URI or e-mail address. `addressDigest` is a keyed hash of the normalized address, so a consumer can
 * correlate events for one address without identkit writing the address itself.
 */
export type AuditEventType =
  | "otp.sent"
  | "otp.send_refused"
  | "otp.verified"
  | "otp.verify_failed"
  | "otp.locked"
  | "address.locked"
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
  | "identity_verification.started"
  | "identity_verification.completed"
  | "identity_verification.failed"
  | "identity_verification.expired"
  | "identity_verification.person_conflict";

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
}

/**
 * Receives audit events. identkit awaits `emit`; if it throws, the calling operation
 * fails, so an operation never succeeds without its audit record.
 */
export interface AuditSink {
  emit(event: AuditEvent): void | Promise<void>;
}
