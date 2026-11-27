/**
 * Byte helpers over the Web Crypto API (`globalThis.crypto`) and standard globals only, so
 * the core runs in Node 24 and in runtimes without Node modules, such as Cloudflare Workers.
 */

const encoder = new TextEncoder();

/** UTF-8 bytes of a string. A lone surrogate becomes U+FFFD, as in `Buffer.from(text)`. */
export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text);
}

/** Cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  // getRandomValues fills at most 65536 bytes per call.
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65536, length)));
  }
  return bytes;
}

const UINT32_RANGE = 2 ** 32;

/**
 * A uniformly random integer in `[min, max)`. Rejection sampling over 32-bit values: draws
 * above the largest multiple of the range are discarded, so no value is more likely.
 */
export function randomInt(min: number, max: number): number {
  const range = max - min;
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || range <= 0) {
    throw new RangeError("randomInt needs safe integers with min < max");
  }
  if (range > UINT32_RANGE) throw new RangeError("randomInt range must not exceed 2^32");
  const limit = UINT32_RANGE - (UINT32_RANGE % range);
  const draw = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(draw);
    const value = draw[0] ?? 0;
    if (value < limit) return min + (value % range);
  }
}

/**
 * Constant-time comparison of two byte arrays. The time depends only on the length of `a`.
 * Different lengths compare unequal.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  let difference = a.byteLength ^ b.byteLength;
  for (let i = 0; i < a.byteLength; i += 1) {
    // A missing byte of a shorter `b` reads as 0; the length difference above already counts.
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return difference === 0;
}

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE64URL_INDEX = new Map(
  Array.from({ length: BASE64URL_ALPHABET.length }, (_, index) => [
    BASE64URL_ALPHABET.charAt(index),
    index,
  ]),
);

/** RFC 4648 base64url without padding, as `Buffer#toString("base64url")` writes it. */
export function toBase64Url(bytes: Uint8Array): string {
  let output = "";
  let i = 0;
  for (; i + 2 < bytes.byteLength; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    output +=
      (BASE64URL_ALPHABET[(n >>> 18) & 63] ?? "") +
      (BASE64URL_ALPHABET[(n >>> 12) & 63] ?? "") +
      (BASE64URL_ALPHABET[(n >>> 6) & 63] ?? "") +
      (BASE64URL_ALPHABET[n & 63] ?? "");
  }
  const rest = bytes.byteLength - i;
  if (rest > 0) {
    const n = ((bytes[i] ?? 0) << 16) | (rest === 2 ? (bytes[i + 1] ?? 0) << 8 : 0);
    output +=
      (BASE64URL_ALPHABET[(n >>> 18) & 63] ?? "") + (BASE64URL_ALPHABET[(n >>> 12) & 63] ?? "");
    if (rest === 2) output += BASE64URL_ALPHABET[(n >>> 6) & 63] ?? "";
  }
  return output;
}

/**
 * Decodes base64url without padding. Returns null for a character outside the alphabet or
 * an impossible length. Unused trailing bits are ignored, as in `Buffer.from(text, "base64url")`.
 */
export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  if (text.length % 4 === 1) return null;
  const output = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const char of text) {
    const digit = BASE64URL_INDEX.get(char);
    if (digit === undefined) return null;
    value = ((value << 6) | digit) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output[index] = (value >>> bits) & 0xff;
      index += 1;
    }
  }
  return output;
}

/** Lowercase hex, as `Buffer#toString("hex")` writes it. */
export function toHex(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) output += byte.toString(16).padStart(2, "0");
  return output;
}

/** Concatenates byte arrays into a new array. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

export type HashName = "SHA-1" | "SHA-256" | "SHA-512";

/** A Web Crypto key, named without the DOM library or `node:crypto` types. */
export type WebCryptoKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;

/**
 * Imports raw bytes as a non-extractable HMAC signing key. Web Crypto copies the bytes, so
 * this makes no copy of its own; the caller wipes `key` when it no longer needs it.
 */
export function importHmacKey(key: Uint8Array, hash: HashName): Promise<WebCryptoKey> {
  return crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, false, ["sign"]);
}

/**
 * Returns a function that imports `bytes` as a key on its first call and returns that key
 * after. When the import succeeds, `bytes` is wiped, so the raw key does not stay in memory
 * next to the key object. When it fails, the next call tries again.
 */
export function lazyKey(
  bytes: Uint8Array,
  importKey: (bytes: Uint8Array) => Promise<WebCryptoKey>,
): () => Promise<WebCryptoKey> {
  let pending: Promise<WebCryptoKey> | undefined;
  return () => {
    pending ??= importKey(bytes).then(
      (key) => {
        bytes.fill(0);
        return key;
      },
      (error: unknown) => {
        pending = undefined;
        throw error;
      },
    );
    return pending;
  };
}

/** HMAC of `data` with an imported key. */
export async function hmac(key: WebCryptoKey, data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

/** SHA-256 of `data`. */
export async function sha256(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}
