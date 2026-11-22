import type { AuditEvent, AuditSink } from "./audit.js";
import type { Clock } from "./clock.js";
import type { IdentkitConfig, SignInPolicy } from "./config.js";
import type { SecretHasher } from "./crypto.js";
import type { IdentityVerificationAdapter } from "./identity-verification.js";
import type { IdentkitStore } from "./storage/types.js";

export type OtpMailPurpose = "sign_in" | "step_up";

/**
 * Delivers a one-time code by e-mail. identkit passes only the recipient, the code, the
 * purpose and the lifetime. The message must not carry other personal data.
 */
export interface MailSender {
  sendCode(message: {
    to: string;
    code: string;
    purpose: OtpMailPurpose;
    expiresInMinutes: number;
  }): Promise<void>;
}

export interface Context {
  config: IdentkitConfig;
  store: IdentkitStore;
  hasher: SecretHasher;
  clock: Clock;
  mail: MailSender;
  getPolicy: () => Promise<SignInPolicy>;
  identityVerification: IdentityVerificationAdapter | null;
  emit(event: Omit<AuditEvent, "at"> & { at?: Date }): Promise<void>;
}

export function createEmitter(sink: AuditSink, clock: Clock): Context["emit"] {
  return async (event) => {
    await sink.emit({ ...event, at: event.at ?? clock.now() });
  };
}
