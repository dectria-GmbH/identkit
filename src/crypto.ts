import { createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";

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
  | "approval-evidence";

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
  const keyCopy = Buffer.from(key);
  return {
    digest: (purpose, value) => {
      const mac = createHmac("sha256", keyCopy);
      mac.update(purpose, "utf8");
      mac.update("\u0000", "utf8");
      mac.update(value, "utf8");
      return Promise.resolve(mac.digest("hex"));
    },
  };
}

/** Number of random bytes in every bearer token and challenge (256 bits). */
export const TOKEN_BYTES = 32;

export function randomToken(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

export function randomId(): string {
  return randomBytes(16).toString("base64url");
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
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.byteLength !== right.byteLength) {
    // Compare against itself so both branches do comparable work.
    timingSafeEqual(left, left);
    return false;
  }
  return timingSafeEqual(left, right);
}
