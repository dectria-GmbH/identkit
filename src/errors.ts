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
 * hook: the identkit sessions are revoked, and the calling operation's writes are complete. Its
 * audit events are complete too, unless `auditError` is set. To re-run the hook, call
 * `sessions.revokeAll(error.accountId, error.revokeAllOptions)`; that call is idempotent.
 * `cause` holds the hook's error.
 *
 * This error does not mean that the operation succeeded. If `rolledBack` is true, the operation
 * did not take effect. If an operation fails for another reason and rolls back, that error goes
 * up and the hook runs best effort, so a rollback never throws this error for a hook failure.
 */
export class AllSessionsRevokedHookError extends IdentkitError {
  /** The options for `sessions.revokeAll` that re-run the hook for the same sessions. */
  readonly revokeAllOptions: { exceptSessionId?: string };
  /**
   * The first error of the same operation's audit events (the revoked sessions, then the
   * operation's own events), else undefined. identkit runs the hook also after a failing sink,
   * and this error then wins, because only the hook needs a re-run. The event the sink refused
   * is missing; identkit still offered every other event of the operation to the sink, and
   * those may be missing too if the sink stayed down. In `totp.confirmEnrolment` it can also be
   * the throttle store's error from the reset after a successful enrolment.
   */
  readonly auditError: unknown;
  /**
   * True if the operation did not take effect: a TOTP enrolment or a passkey registration whose
   * grant changed before it completed. identkit removed the new factor or passkey and revoked
   * every session of the account; without the hook failure the call would have returned
   * `denied`. `revokeAllOptions` is then `{}`. False for every other operation.
   */
  readonly rolledBack: boolean;

  constructor(
    readonly accountId: string,
    /** The session that stayed live, or null. */
    readonly exceptSessionId: string | null,
    options?: ErrorOptions & { auditError?: unknown; rolledBack?: boolean },
  ) {
    super(
      "all_sessions_revoked_hook_failed",
      "onAllSessionsRevoked failed after the revocation; call sessions.revokeAll again",
      options,
    );
    this.revokeAllOptions = exceptSessionId === null ? {} : { exceptSessionId };
    this.auditError = options?.auditError;
    this.rolledBack = options?.rolledBack === true;
  }
}
