import {
  bytesEqual,
  hmac,
  importHmacKey,
  lazyKey,
  randomBytes,
  randomInt,
  toBase64Url,
  toHex,
  utf8,
} from "./bytes.js";

/**
 * Domain separation labels for keyed hashes. A hash made for one purpose never matches
 * a hash made for another purpose, even for the same input.
 */
export type HashPurpose =
  | "otp-code"
  | "address"
  | "session-token"
  | "webauthn-challenge"
  | "enrollment-token"
  | "person-key"
  | "approval-id"
  | "approval-evidence"
  | "api-token"
  | "oauth-client-secret"
  | "oauth-code"
  | "oauth-access-token"
  | "oauth-refresh-ref"
  | "oauth-refresh-token"
  | "oauth-registration-address";

/**
 * Computes keyed one-way hashes of secrets and identifiers. identkit stores only these
 * hashes, never the secret itself. Implement this interface to keep the key in an
 * external key service; `createHmacHasher` is the in-process implementation.
 */
export interface SecretHasher {
  /** Returns a lowercase hex digest. Equal inputs and purposes give equal digests. */
  digest(purpose: HashPurpose, value: string): Promise<string>;
}

export const MIN_HASH_KEY_BYTES = 32;

/** HMAC-SHA-256 with a secret key held in process memory. */
export function createHmacHasher(key: Uint8Array): SecretHasher {
  if (key.byteLength < MIN_HASH_KEY_BYTES) {
    throw new RangeError(`hash key must have at least ${MIN_HASH_KEY_BYTES} bytes`);
  }
  // Copy now, so a later change to `key` has no effect. The key is imported on the first
  // digest, not here: some runtimes allow no crypto work while a module is loading. The copy
  // is wiped once the import succeeds.
  const hmacKey = lazyKey(new Uint8Array(key), (bytes) => importHmacKey(bytes, "SHA-256"));
  return {
    digest: async (purpose, value) =>
      toHex(await hmac(await hmacKey(), utf8(`${purpose}\u0000${value}`))),
  };
}

/** Number of random bytes in every bearer token and challenge (256 bits). */
export const TOKEN_BYTES = 32;

export function randomToken(): string {
  return toBase64Url(randomBytes(TOKEN_BYTES));
}

export function randomId(): string {
  return toBase64Url(randomBytes(16));
}

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** True if the value has the shape of a token from `randomToken`. */
export function isTokenShaped(value: unknown): value is string {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

export const OTP_DIGITS = 6;

/** A uniformly random numeric one-time code with `OTP_DIGITS` digits. */
export function randomNumericCode(): string {
  return randomInt(0, 10 ** OTP_DIGITS)
    .toString()
    .padStart(OTP_DIGITS, "0");
}

/** Constant-time comparison of two hex digests. Different lengths compare unequal. */
export function digestsEqual(a: string, b: string): boolean {
  return bytesEqual(utf8(a), utf8(b));
}
