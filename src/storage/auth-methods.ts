import type { AuthMethod } from "../config.js";

/** The session methods this release knows. */
export const AUTH_METHODS = ["email_otp", "passkey", "totp", "oidc"] as const;

// Fails to compile if `AuthMethod` gains a member that the list above lacks.
const complete: [Exclude<AuthMethod, (typeof AUTH_METHODS)[number]>] extends [never]
  ? true
  : never = true;
void complete;

/**
 * Keeps the session methods this release knows and drops the others. A later release may write
 * a method that this one does not know, for example during a gradual deployment or after a
 * rollback. Dropping it fails closed: a session reports fewer methods, and no rule of identkit
 * grants more to a session with fewer methods (step-up has its own field).
 */
export function knownAuthMethods(values: readonly string[]): AuthMethod[] {
  return values.filter((value): value is AuthMethod =>
    (AUTH_METHODS as readonly string[]).includes(value),
  );
}
