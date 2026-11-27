import {
  concatBytes,
  fromBase64Url,
  lazyKey,
  randomBytes,
  toBase64Url,
  utf8,
  type WebCryptoKey,
} from "./bytes.js";
import { IdentkitError } from "./errors.js";

/**
 * Encrypts secrets that identkit must read back, such as TOTP secrets, which cannot be
 * hashed because verification needs the plaintext. `seal` and `open` use authenticated
 * encryption bound to `context`: a sealed value opens only with the same context, so a
 * value copied to another row or account does not open. Implement this interface to keep
 * the key in an external key service; `createAesGcmSealer` is the in-process implementation.
 */
export interface SecretSealer {
  /** Returns an opaque string that holds the ciphertext and what `open` needs. */
  seal(plaintext: Uint8Array, context: string): Promise<string>;
  /**
   * Returns the plaintext. Rejects with `SealedSecretError` if the value was changed, was
   * sealed for another context, or no configured key opens it.
   */
  open(sealed: string, context: string): Promise<Uint8Array>;
}

/** A sealed value did not open. The message never contains key, plaintext or ciphertext. */
export class SealedSecretError extends IdentkitError {
  constructor() {
    super("sealed_secret_unreadable", "sealed secret could not be opened");
  }
}

export const SEALER_KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const FORMAT = "v1";
const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const PART_PATTERN = /^[A-Za-z0-9_-]+$/;

/** The key id and the context are authenticated, so neither can be swapped. */
const additionalData = (keyId: string, context: string) =>
  utf8(`identkit/sealed/${FORMAT}\u0000${keyId}\u0000${context}`);

const gcm = (
  iv: Uint8Array<ArrayBuffer>,
  keyId: string,
  context: string,
): Parameters<typeof crypto.subtle.encrypt>[0] => ({
  name: "AES-GCM",
  iv,
  additionalData: additionalData(keyId, context),
  tagLength: TAG_BYTES * 8,
});

export interface AesGcmSealerOptions {
  /**
   * Keys by id. Each key has exactly 32 random bytes. Keep old keys here until every value
   * sealed with them was sealed again with the active key.
   */
  keys: Record<string, Uint8Array>;
  /** Id of the key that new values are sealed with. */
  activeKeyId: string;
}

/**
 * AES-256-GCM with a random 96-bit IV per value. The sealed form is
 * `v1.<keyId>.<iv>.<ciphertext>.<tag>` (base64url parts). The key id and the context are
 * authenticated as additional data, so neither can be swapped.
 */
export function createAesGcmSealer(options: AesGcmSealerOptions): SecretSealer {
  const keyBytes = new Map<string, Uint8Array<ArrayBuffer>>();
  for (const [id, key] of Object.entries(options.keys)) {
    if (!KEY_ID_PATTERN.test(id))
      throw new RangeError("sealer key id must match [A-Za-z0-9_-]{1,32}");
    if (key.byteLength !== SEALER_KEY_BYTES) {
      throw new RangeError(`sealer key must have exactly ${SEALER_KEY_BYTES} bytes`);
    }
    keyBytes.set(id, new Uint8Array(key));
  }
  if (!keyBytes.has(options.activeKeyId)) {
    throw new RangeError("activeKeyId must name one of the keys");
  }
  const activeKeyId = options.activeKeyId;

  // Keys are imported on first use, not here: some runtimes allow no crypto work while a
  // module is loading. Imported keys are not extractable; the raw copies are wiped after import.
  const cryptoKeys = new Map<string, () => Promise<WebCryptoKey>>();
  for (const [id, bytes] of keyBytes) {
    cryptoKeys.set(
      id,
      lazyKey(bytes, (raw) =>
        crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]),
      ),
    );
  }
  const cryptoKey = (id: string) => cryptoKeys.get(id)?.();

  return {
    async seal(plaintext, context) {
      const key = cryptoKey(activeKeyId);
      if (!key) throw new RangeError("activeKeyId must name one of the keys");
      const iv = randomBytes(IV_BYTES);
      const input = new Uint8Array(plaintext);
      let sealed: Uint8Array;
      try {
        // Web Crypto returns the ciphertext with the tag appended.
        sealed = new Uint8Array(
          await crypto.subtle.encrypt(gcm(iv, activeKeyId, context), await key, input),
        );
      } finally {
        input.fill(0);
      }
      const ciphertext = sealed.subarray(0, sealed.byteLength - TAG_BYTES);
      const tag = sealed.subarray(sealed.byteLength - TAG_BYTES);
      return [FORMAT, activeKeyId, toBase64Url(iv), toBase64Url(ciphertext), toBase64Url(tag)].join(
        ".",
      );
    },

    async open(sealed, context) {
      try {
        const parts = typeof sealed === "string" ? sealed.split(".") : [];
        const [format, keyId, ivText, ciphertextText, tagText] = parts;
        if (
          parts.length !== 5 ||
          format !== FORMAT ||
          keyId === undefined ||
          ivText === undefined ||
          ciphertextText === undefined ||
          tagText === undefined ||
          ![ivText, ciphertextText, tagText].every((p) => PART_PATTERN.test(p))
        ) {
          throw new SealedSecretError();
        }
        const key = cryptoKey(keyId);
        const iv = fromBase64Url(ivText);
        const tag = fromBase64Url(tagText);
        const ciphertext = fromBase64Url(ciphertextText);
        if (
          !key ||
          !iv ||
          !tag ||
          !ciphertext ||
          iv.byteLength !== IV_BYTES ||
          tag.byteLength !== TAG_BYTES
        ) {
          throw new SealedSecretError();
        }
        // Web Crypto checks the tag before it returns any plaintext.
        return new Uint8Array(
          await crypto.subtle.decrypt(
            gcm(iv, keyId, context),
            await key,
            concatBytes(ciphertext, tag),
          ),
        );
      } catch {
        // The library error says nothing secret, but a fixed error keeps it that way.
        throw new SealedSecretError();
      }
    },
  };
}
