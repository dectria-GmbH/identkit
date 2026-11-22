/** Base class of errors that identkit throws on purpose. */
export class IdentkitError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
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
