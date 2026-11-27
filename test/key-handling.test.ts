import { afterEach, describe, expect, it, vi } from "vitest";
import type { WebCryptoKey } from "../src/bytes.js";
import { createAesGcmSealer, createHmacHasher, InvalidArgumentError } from "../src/index.js";
import {
  createFakeIdentityVerificationAdapter,
  generateTotpCode,
  generateTotpCodeAsync,
} from "../src/testing/index.js";
import { hotp, matchTimeStep } from "../src/totp-core.js";
import { DIGESTS, HASH_KEY_HEX, SEAL_KEY_K1_HEX, SEALED } from "./compat-vectors.js";

const hex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));

afterEach(() => {
  vi.restoreAllMocks();
});

/** Records the raw key bytes that each importKey call receives. */
function recordImports() {
  const seen: Uint8Array[] = [];
  const original = crypto.subtle.importKey.bind(crypto.subtle);
  const spy = vi.spyOn(crypto.subtle, "importKey");
  spy.mockImplementation(((format: "raw", keyData: Uint8Array, ...rest: never[]) => {
    seen.push(keyData);
    return Reflect.apply(original, undefined, [format, keyData, ...rest]) as Promise<WebCryptoKey>;
  }) as typeof crypto.subtle.importKey);
  return { seen, spy };
}

describe("key material handling", () => {
  it("rule: TOTP key import makes no copy of the secret", async () => {
    const { seen } = recordImports();
    const secret = new TextEncoder().encode("12345678901234567890");
    expect(await hotp(secret, 0, "SHA1", 6)).toBe("755224");
    const step = await matchTimeStep({
      secret,
      code: "287082",
      at: new Date(30_000),
      driftSteps: 1,
      algorithm: "SHA1",
      digits: 6,
    });
    expect(step).toBe(1);
    expect(seen).toHaveLength(2);
    // The secret object itself goes to Web Crypto, so wiping it leaves no copy behind.
    for (const keyData of seen) expect(keyData).toBe(secret);
  });

  it("rule: hasher - a failed key import is retried, the raw copy is wiped after import", async () => {
    const { seen, spy } = recordImports();
    const hasher = createHmacHasher(hex(HASH_KEY_HEX));
    const [purpose, value, digest] = DIGESTS[1] ?? ["", "", ""];
    spy.mockRejectedValueOnce(new Error("transient import failure"));
    await expect(hasher.digest(purpose as "otp-code", value)).rejects.toThrow("transient");
    expect(await hasher.digest(purpose as "otp-code", value)).toBe(digest);
    expect(await hasher.digest(purpose as "otp-code", value)).toBe(digest);
    expect(spy).toHaveBeenCalledTimes(2);
    const imported = seen.at(-1);
    expect(imported?.byteLength).toBe(32);
    expect(imported?.every((byte) => byte === 0)).toBe(true);
  });

  it("rule: sealer - a failed key import is retried, the raw copy is wiped after import", async () => {
    const { seen, spy } = recordImports();
    const sealer = createAesGcmSealer({ keys: { k1: hex(SEAL_KEY_K1_HEX) }, activeKeyId: "k1" });
    const [plaintext, context, sealed] = SEALED[0] ?? ["", "", ""];
    spy.mockRejectedValueOnce(new Error("transient import failure"));
    await expect(sealer.seal(hex(plaintext), context)).rejects.toThrow("transient");
    const again = await sealer.seal(hex(plaintext), context);
    expect(Buffer.from(await sealer.open(again, context)).toString("hex")).toBe(plaintext);
    expect(Buffer.from(await sealer.open(sealed, context)).toString("hex")).toBe(plaintext);
    expect(spy).toHaveBeenCalledTimes(2);
    const imported = seen.at(-1);
    expect(imported?.byteLength).toBe(32);
    expect(imported?.every((byte) => byte === 0)).toBe(true);
  });

  it("rule: empty secrets are refused the same way in the sync and async helpers", async () => {
    expect(() =>
      createFakeIdentityVerificationAdapter({ outcome: "fail", callbackSecret: "" }),
    ).toThrow(InvalidArgumentError);
    const input = { secret: "", at: new Date(0) };
    expect(() => generateTotpCode(input)).toThrow(InvalidArgumentError);
    await expect(generateTotpCodeAsync(input)).rejects.toBeInstanceOf(InvalidArgumentError);
  });
});
