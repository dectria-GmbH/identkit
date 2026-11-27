/** Base class of errors that identkit throws on purpose. */
export class IdentkitError extends Error {
  constructor(
    readonly code: string,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * The operator policy does not allow this method for this call. The decision depends only
 * on the policy, never on the account or the address.
 */
export class MethodNotAllowedError extends IdentkitError {
  constructor(method: string) {
    super("method_not_allowed", `method not allowed by policy: ${method}`);
  }
}

/** A required collaborator (for example the identity verification adapter) is missing. */
export class NotConfiguredError extends IdentkitError {
  constructor(what: string) {
    super("not_configured", `not configured: ${what}`);
  }
}

/**
 * A call got arguments of the wrong shape, for example from untyped code written for an
 * earlier form of the API. identkit throws instead of guessing.
 */
export class InvalidArgumentError extends IdentkitError {
  constructor(message: string) {
    super("invalid_argument", message);
  }
}

/**
 * A passkey registration lost its grant after the passkey was activated, and identkit could
 * neither delete the passkey nor disable the account. The passkey may still sign in. Remove it
 * with `passkeys.revoke(accountId, credentialId)`. `cause` holds the store error.
 */
export class PasskeyCleanupError extends IdentkitError {
  constructor(
    readonly accountId: string,
    readonly credentialId: string,
    options?: ErrorOptions,
  ) {
    super(
      "passkey_cleanup_failed",
      "a passkey without a valid grant may still be active; revoke it with passkeys.revoke",
      options,
    );
  }
}

/**
 * The option `onAllSessionsRevoked` threw. identkit finished its own work before it called the
 * hook: the identkit sessions are revoked, and the calling operation's writes and audit events
 * are complete. To re-run the hook, call
 * `sessions.revokeAll(error.accountId, error.revokeAllOptions)`; that call is idempotent.
 * `cause` holds the hook's error.
 */
export class AllSessionsRevokedHookError extends IdentkitError {
  /** The options for `sessions.revokeAll` that re-run the hook for the same sessions. */
  readonly revokeAllOptions: { exceptSessionId?: string };

  constructor(
    readonly accountId: string,
    /** The session that stayed live, or null. */
    readonly exceptSessionId: string | null,
    options?: ErrorOptions,
  ) {
    super(
      "all_sessions_revoked_hook_failed",
      "onAllSessionsRevoked failed after the revocation; call sessions.revokeAll again",
      options,
    );
    this.revokeAllOptions = exceptSessionId === null ? {} : { exceptSessionId };
  }
}
