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

/** The message of an error for another error's message; never throws. */
function messageOf(error: unknown): string {
  try {
    return error instanceof Error ? error.message : String(error);
  } catch {
    return "unknown error";
  }
}

/** The message of `AllSessionsRevokedHookError`: names each store error of `accounts.disable`. */
function hookErrorMessage(options?: {
  tokenRevocationError?: unknown;
  grantRevocationError?: unknown;
}): string {
  const failed: string[] = [];
  if (options?.tokenRevocationError !== undefined) {
    failed.push(
      `the revocation of the API tokens failed (${messageOf(options.tokenRevocationError)})`,
    );
  }
  if (options?.grantRevocationError !== undefined) {
    failed.push(`the end of the OAuth grants failed (${messageOf(options.grantRevocationError)})`);
  }
  if (failed.length === 0) {
    return "onAllSessionsRevoked failed after the revocation; call sessions.revokeAll again";
  }
  return (
    `onAllSessionsRevoked failed after the revocation, and ${failed.join(" and ")}; ` +
    "call accounts.disable again"
  );
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
 * hook: the identkit sessions are revoked, and the calling operation's writes stand. Its audit
 * events are complete too, unless `auditError` is set. To re-run the hook, call
 * `sessions.revokeAll(error.accountId, error.revokeAllOptions)`; that call is idempotent.
 * `cause` holds the hook's error.
 *
 * An operation that identkit rolled back never throws this error; it throws
 * `OperationRolledBackError`, which says whether the hook failed.
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
   * Set only by `accounts.disable`: the store's error on the revocation of the account's API
   * tokens, else undefined. The hook error wins over it, because only the hook leaves something
   * live now (`verify` refuses tokens of a disabled account). But the tokens are not revoked:
   * call `accounts.disable` again, which also re-runs the hook. Until that call succeeds,
   * enabling the account again in the store brings the tokens back. The message then names
   * this call and includes the store error's message, because an `Error` in this field
   * serializes to `{}` in JSON.
   */
  readonly tokenRevocationError: unknown;
  /**
   * Set only by `accounts.disable`: the store's error on the end of the account's OAuth grants
   * and codes, else undefined. Same rule as `tokenRevocationError`: the hook error wins, a
   * disabled account's grants are refused (`validateAccessToken` and refresh check the account
   * status), and `accounts.disable` again ends them. The message names this error too.
   */
  readonly grantRevocationError: unknown;

  constructor(
    readonly accountId: string,
    /** The session that stayed live, or null. */
    readonly exceptSessionId: string | null,
    options?: ErrorOptions & {
      auditError?: unknown;
      tokenRevocationError?: unknown;
      grantRevocationError?: unknown;
    },
  ) {
    super("all_sessions_revoked_hook_failed", hookErrorMessage(options), options);
    this.revokeAllOptions = exceptSessionId === null ? {} : { exceptSessionId };
    this.auditError = options?.auditError;
    this.tokenRevocationError = options?.tokenRevocationError;
    this.grantRevocationError = options?.grantRevocationError;
  }
}

/**
 * identkit rolled the operation back: it did not take effect. `totp.confirmEnrolment` and
 * `passkeys.finishRegistration` throw it when they rolled back and an error came up: the store
 * failed after the new factor or passkey was stored, or the grant changed before the operation
 * completed and the store, the audit sink or the hook then failed (without such an error, the
 * call returns `denied`). identkit removed the new factor or passkey and revoked every session
 * of the account. If it cannot remove them, it disables the account and throws the store's
 * error or `PasskeyCleanupError` instead: the factor or passkey may then still be active.
 *
 * `apiTokens.create` and `apiTokens.import` throw it when the audit sink refused the event of the
 * new token: identkit deleted the token again, and `cause` holds the sink's error. They revoke
 * no session, so `hookFailed` is false. `oauth.importGrant` does the same for
 * `oauth.grant_imported` and the imported grant. If the delete fails, the store's error goes up instead
 * and the token stands (a created token is unusable then: its plaintext was never returned).
 *
 * `oauth.token` throws it for a code exchange when the audit sink refused `oauth.grant_created`,
 * or `oauth.grant_ended` of the grant that the exchange replaced: identkit deleted the new grant
 * again, and `cause` holds the sink's error. One exception to the rule below: an exchange
 * replaces the account's earlier grant of the same client, and that grant stays ended. It is not
 * restored, so its client must connect again. Its `oauth.grant_ended` event (reason `replaced`)
 * goes to the sink before `oauth.grant_created`; if the sink refused that event, the grant ended
 * without its record. If the delete fails, the store's error goes up instead and the new grant
 * stands, unusable (its tokens were never returned).
 *
 * If you catch this error, the operation did not take effect. Any other error means that
 * identkit did not roll back: what it wrote before the error stands. After any other error from
 * `totp.confirmEnrolment` or `passkeys.finishRegistration`, check `totp.get` or `passkeys.list`.
 *
 * `cause` holds the first error: the store's, the audit sink's, or the hook's. If `hookFailed`
 * is true, the hook `onAllSessionsRevoked` threw, or the store failed before identkit could
 * call it: call `sessions.revokeAll(error.accountId, error.revokeAllOptions)` to finish the
 * revocation and run the hook. `revokeAllOptions` is always `{}`, so that call also ends the
 * session that started the operation.
 */
export class OperationRolledBackError extends IdentkitError {
  /** The options for `sessions.revokeAll` that finish the rollback's revocation. Always `{}`. */
  readonly revokeAllOptions: { exceptSessionId?: string } = {};
  /** True if the rollback's revocation or its hook did not complete. */
  readonly hookFailed: boolean;

  constructor(
    readonly accountId: string,
    options: { cause: unknown; hookFailed: boolean },
  ) {
    super("operation_rolled_back", "the operation was rolled back and did not take effect", {
      cause: options.cause,
    });
    this.hookFailed = options.hookFailed;
  }
}

/**
 * identkit rolled a client operation back: it did not take effect. `oauth.register` throws it
 * when the audit sink refused `oauth.client_registered`, and `oauth.importClient` when it
 * refused `oauth.client_imported`: identkit deleted the new client again,
 * and `cause` holds the sink's error. `clientId` names the deleted client; it was never
 * returned to the caller. A client belongs to no account, so this is not an
 * `OperationRolledBackError`, and no session was revoked. If the delete fails, the store's error
 * goes up instead and the client stands without its record; nobody holds its id or secret.
 */
export class OAuthClientRolledBackError extends IdentkitError {
  constructor(
    readonly clientId: string,
    options: { cause: unknown },
  ) {
    super(
      "oauth_client_rolled_back",
      "the client operation was rolled back and did not take effect",
      options,
    );
  }
}

/**
 * The operation's writes stand, but the store failed to revoke the account's other sessions,
 * and a retry of the operation cannot reach that revocation (for example `totp.remove`, whose
 * factor is gone). Finish it with `sessions.revokeAll(error.accountId, error.revokeAllOptions)`;
 * that call also runs the hook `onAllSessionsRevoked`. `cause` holds the store's error.
 */
export class SessionsNotRevokedError extends IdentkitError {
  /** The options for `sessions.revokeAll` that finish the revocation. */
  readonly revokeAllOptions: { exceptSessionId?: string };

  constructor(
    readonly accountId: string,
    /** The session that should stay live, or null. */
    readonly exceptSessionId: string | null,
    options: { cause: unknown },
  ) {
    super(
      "sessions_not_revoked",
      "the other sessions of the account were not revoked; call sessions.revokeAll",
      options,
    );
    this.revokeAllOptions = exceptSessionId === null ? {} : { exceptSessionId };
  }
}
