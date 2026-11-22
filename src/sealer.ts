import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
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
  Buffer.from(`identkit/sealed/${FORMAT}\u0000${keyId}\u0000${context}`, "utf8");

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
  const keys = new Map<string, Buffer>();
  for (const [id, key] of Object.entries(options.keys)) {
    if (!KEY_ID_PATTERN.test(id))
      throw new RangeError("sealer key id must match [A-Za-z0-9_-]{1,32}");
    if (key.byteLength !== SEALER_KEY_BYTES) {
      throw new RangeError(`sealer key must have exactly ${SEALER_KEY_BYTES} bytes`);
    }
    keys.set(id, Buffer.from(key));
  }
  const activeKey = keys.get(options.activeKeyId);
  if (!activeKey) throw new RangeError("activeKeyId must name one of the keys");
  const activeKeyId = options.activeKeyId;

  return {
    seal(plaintext, context) {
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv("aes-256-gcm", activeKey, iv, { authTagLength: TAG_BYTES });
      cipher.setAAD(additionalData(activeKeyId, context));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();
      return Promise.resolve(
        [
          FORMAT,
          activeKeyId,
          iv.toString("base64url"),
          ciphertext.toString("base64url"),
          tag.toString("base64url"),
        ].join("."),
      );
    },

    open(sealed, context) {
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
        const key = keys.get(keyId);
        const iv = Buffer.from(ivText, "base64url");
        const tag = Buffer.from(tagText, "base64url");
        if (!key || iv.byteLength !== IV_BYTES || tag.byteLength !== TAG_BYTES) {
          throw new SealedSecretError();
        }
        const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
        decipher.setAAD(additionalData(keyId, context));
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([
          decipher.update(Buffer.from(ciphertextText, "base64url")),
          decipher.final(),
        ]);
        return Promise.resolve(new Uint8Array(plaintext));
      } catch {
        // The library error says nothing secret, but a fixed error keeps it that way.
        return Promise.reject(new SealedSecretError());
      }
    },
  };
}
