import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createAesGcmSealer, SealedSecretError } from "../src/index.js";

const secret = new Uint8Array(randomBytes(20));
const context = "identkit/totp-secret\u0000factor-1\u0000account-1";

function flipChar(text: string, index: number): string {
  const char = text[index] === "A" ? "B" : "A";
  return text.slice(0, index) + char + text.slice(index + 1);
}

describe("AES-256-GCM sealer", () => {
  it("seals and opens; the sealed form holds no plaintext", async () => {
    const sealer = createAesGcmSealer({ keys: { k1: randomBytes(32) }, activeKeyId: "k1" });
    const sealed = await sealer.seal(secret, context);
    expect(sealed.startsWith("v1.k1.")).toBe(true);
    expect(sealed).not.toContain(Buffer.from(secret).toString("base64url"));
    expect(sealed).not.toContain(Buffer.from(secret).toString("hex"));
    expect(Buffer.from(await sealer.open(sealed, context)).equals(Buffer.from(secret))).toBe(true);
    // A fresh IV per value: the same secret seals differently each time.
    expect(await sealer.seal(secret, context)).not.toBe(sealed);
  });

  it("rule: sealed secret unreadable with a wrong key", async () => {
    const right = createAesGcmSealer({ keys: { k1: randomBytes(32) }, activeKeyId: "k1" });
    const wrong = createAesGcmSealer({ keys: { k1: randomBytes(32) }, activeKeyId: "k1" });
    const sealed = await right.seal(secret, context);
    await expect(wrong.open(sealed, context)).rejects.toBeInstanceOf(SealedSecretError);
    const unknownId = createAesGcmSealer({ keys: { k2: randomBytes(32) }, activeKeyId: "k2" });
    await expect(unknownId.open(sealed, context)).rejects.toBeInstanceOf(SealedSecretError);
  });

  it("rule: sealed secret tamper detected - ciphertext, tag, IV, key id and context", async () => {
    const k1 = randomBytes(32);
    const sealer = createAesGcmSealer({ keys: { k1, k2: k1 }, activeKeyId: "k1" });
    const sealed = await sealer.seal(secret, context);
    const [format, keyId, iv, ciphertext, tag] = sealed.split(".") as [
      string,
      string,
      string,
      string,
      string,
    ];
    const variants = [
      [format, keyId, iv, flipChar(ciphertext, 3), tag],
      [format, keyId, iv, ciphertext, flipChar(tag, 3)],
      [format, keyId, flipChar(iv, 3), ciphertext, tag],
      // Same key bytes under another id: the id is authenticated, so this fails too.
      [format, "k2", iv, ciphertext, tag],
      ["v2", keyId, iv, ciphertext, tag],
      [format, keyId, iv, ciphertext],
    ].map((parts) => parts.join("."));
    for (const variant of variants) {
      await expect(sealer.open(variant, context), variant).rejects.toBeInstanceOf(
        SealedSecretError,
      );
    }
    await expect(sealer.open(sealed, `${context}x`)).rejects.toBeInstanceOf(SealedSecretError);
    await expect(sealer.open("", context)).rejects.toBeInstanceOf(SealedSecretError);
  });

  it("the error says nothing about key, plaintext or ciphertext", async () => {
    const sealer = createAesGcmSealer({ keys: { k1: randomBytes(32) }, activeKeyId: "k1" });
    const sealed = await sealer.seal(secret, context);
    const error = await sealer.open(sealed, "other").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SealedSecretError);
    const text = `${String(error)} ${JSON.stringify(error)}`;
    expect(text).not.toContain(sealed.split(".")[3]);
    expect(text).not.toContain(Buffer.from(secret).toString("hex"));
  });

  it("rotation: an old key still opens, new values use the active key", async () => {
    const old = randomBytes(32);
    const before = createAesGcmSealer({ keys: { old }, activeKeyId: "old" });
    const sealed = await before.seal(secret, context);
    const after = createAesGcmSealer({ keys: { old, next: randomBytes(32) }, activeKeyId: "next" });
    expect(Buffer.from(await after.open(sealed, context)).equals(Buffer.from(secret))).toBe(true);
    const resealed = await after.seal(await after.open(sealed, context), context);
    expect(resealed.startsWith("v1.next.")).toBe(true);
  });

  it("refuses keys of the wrong length, bad ids and an unknown active key", () => {
    expect(() => createAesGcmSealer({ keys: { k: randomBytes(31) }, activeKeyId: "k" })).toThrow(
      RangeError,
    );
    expect(() =>
      createAesGcmSealer({ keys: { "bad.id": randomBytes(32) }, activeKeyId: "bad.id" }),
    ).toThrow(RangeError);
    expect(() => createAesGcmSealer({ keys: { k: randomBytes(32) }, activeKeyId: "x" })).toThrow(
      RangeError,
    );
  });
});
