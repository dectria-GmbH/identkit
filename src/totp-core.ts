/**
 * TOTP primitives (RFC 6238 over HOTP, RFC 4226) with the Web Crypto API only. No storage,
 * no policy: the TOTP service in `totp.ts` applies those.
 */
import { hmac, importHmacKey, randomBytes, type HashName, type WebCryptoKey } from "./bytes.js";
import { digestsEqual } from "./crypto.js";

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";
export type TotpDigits = 6 | 8;

/** Time step length in seconds. Fixed: authenticator apps support 30 seconds. */
export const TOTP_PERIOD_SECONDS = 30;

/**
 * The parameters that common authenticator apps support. Several apps ignore the
 * `algorithm` and `digits` parameters of a provisioning URI and always use these values, so
 * any other choice can enrol a factor that the app then computes wrongly.
 */
export const TOTP_INTEROPERABLE_PARAMETERS = { algorithm: "SHA1", digits: 6 } as const;

const HASH: Record<TotpAlgorithm, HashName> = {
  SHA1: "SHA-1",
  SHA256: "SHA-256",
  SHA512: "SHA-512",
};

/**
 * Secret length in bytes per algorithm: the output length of the hash. RFC 4226 asks for at
 * least 128 bits and recommends 160; RFC 2104 recommends a key no shorter than the output.
 */
export const TOTP_SECRET_BYTES: Record<TotpAlgorithm, number> = {
  SHA1: 20,
  SHA256: 32,
  SHA512: 64,
};

export function generateTotpSecret(algorithm: TotpAlgorithm): Uint8Array {
  return randomBytes(TOTP_SECRET_BYTES[algorithm]);
}

/** The time step that contains `at`. */
export function timeStepAt(at: Date): number {
  return Math.floor(at.getTime() / 1000 / TOTP_PERIOD_SECONDS);
}

/** The 8-byte big-endian counter message of HOTP. */
function counterMessage(counter: number): Uint8Array {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError("invalid counter");
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));
  return message;
}

/** Dynamic truncation, RFC 4226 section 5.3, of an HMAC value to `digits` digits. */
export function truncateHotp(mac: Uint8Array, digits: TotpDigits): string {
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const binary =
    (((mac[offset] ?? 0) & 0x7f) << 24) |
    ((mac[offset + 1] ?? 0) << 16) |
    ((mac[offset + 2] ?? 0) << 8) |
    (mac[offset + 3] ?? 0);
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

async function hotpWithKey(
  key: WebCryptoKey,
  counter: number,
  digits: TotpDigits,
): Promise<string> {
  return truncateHotp(await hmac(key, counterMessage(counter)), digits);
}

/** HOTP value (RFC 4226) for one counter value. */
export async function hotp(
  secret: Uint8Array,
  counter: number,
  algorithm: TotpAlgorithm,
  digits: TotpDigits,
): Promise<string> {
  return hotpWithKey(await importHmacKey(secret, HASH[algorithm]), counter, digits);
}

/** TOTP value (RFC 6238) for the time step that contains `at`. */
export function totpAt(
  secret: Uint8Array,
  at: Date,
  algorithm: TotpAlgorithm,
  digits: TotpDigits,
): Promise<string> {
  return hotp(secret, timeStepAt(at), algorithm, digits);
}

/**
 * Finds the time step whose code equals `code`, within `driftSteps` steps on either side of
 * the step that contains `at`. Every candidate is computed and compared in constant time, so
 * the work does not depend on where (or whether) the code matches. If several steps match,
 * the latest one is returned, so accepting it consumes the most.
 */
export async function matchTimeStep(input: {
  secret: Uint8Array;
  code: string;
  at: Date;
  driftSteps: number;
  algorithm: TotpAlgorithm;
  digits: TotpDigits;
}): Promise<number | null> {
  const current = timeStepAt(input.at);
  const steps: number[] = [];
  for (let step = current - input.driftSteps; step <= current + input.driftSteps; step += 1) {
    counterMessage(step);
    steps.push(step);
  }
  const key = await importHmacKey(input.secret, HASH[input.algorithm]);
  const candidates = await Promise.all(steps.map((step) => hotpWithKey(key, step, input.digits)));
  let matched: number | null = null;
  candidates.forEach((candidate, index) => {
    if (digestsEqual(candidate, input.code)) matched = steps[index] ?? null;
  });
  return matched;
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32 without padding, as provisioning URIs use it. */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** Decodes RFC 4648 base32 (case-insensitive, padding optional). Throws on other input. */
export function base32Decode(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(/=+$/, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new TypeError("invalid base32 input");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(output);
}

/**
 * The `otpauth://totp/` URI that authenticator apps read from a QR code. identkit returns it
 * as a string; render the QR code in your own UI. It contains the secret: show it once, to
 * the person who enrols, and never store or log it.
 */
export function provisioningUri(input: {
  secret: Uint8Array;
  issuer: string;
  accountName: string;
  algorithm: TotpAlgorithm;
  digits: TotpDigits;
}): string {
  const label = `${encodeURIComponent(input.issuer)}:${encodeURIComponent(input.accountName)}`;
  const params = new URLSearchParams({
    secret: base32Encode(input.secret),
    issuer: input.issuer,
    algorithm: input.algorithm,
    digits: String(input.digits),
    period: String(TOTP_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
