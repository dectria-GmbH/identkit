import { createDecipheriv } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  approvalChallenge,
  approvalChallengeAsync,
  createAesGcmSealer,
  createHmacHasher,
  hashPayload,
  hashPayloadAsync,
  type HashPurpose,
} from "../src/index.js";
import {
  APPROVAL_CHALLENGES,
  DIGESTS,
  HASH_KEY_HEX,
  PAYLOAD_HASHES,
  SEAL_KEY_K1_HEX,
  SEAL_KEY_OLD_HEX,
  SEALED,
} from "./compat-vectors.js";

const hex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));

const sealer = () =>
  createAesGcmSealer({
    keys: { k1: hex(SEAL_KEY_K1_HEX), old: hex(SEAL_KEY_OLD_HEX) },
    activeKeyId: "k1",
  });

describe("compatibility with values stored by identkit 0.1.1", () => {
  it("rule: digests match the 0.1.1 digests for every purpose", async () => {
    const hasher = createHmacHasher(hex(HASH_KEY_HEX));
    for (const [purpose, value, digest] of DIGESTS) {
      expect(await hasher.digest(purpose as HashPurpose, value), `${purpose} ${value}`).toBe(
        digest,
      );
    }
  });

  it("rule: values sealed by 0.1.1 still open, also with a rotated-out key", async () => {
    const opener = sealer();
    for (const [plaintext, context, sealed] of SEALED) {
      expect(Buffer.from(await opener.open(sealed, context)).toString("hex")).toBe(plaintext);
    }
  });

  it("rule: new sealed values keep the 0.1.1 format and open with plain AES-256-GCM", async () => {
    const plaintext = hex("000102030405060708090a0b0c0d0e0f10111213");
    const context = "identkit/totp-secret\u0000factor-1\u0000account-1";
    const sealed = await sealer().seal(plaintext, context);
    const [format, keyId, iv, ciphertext, tag, ...rest] = sealed.split(".");
    expect([format, keyId, rest.length]).toEqual(["v1", "k1", 0]);
    const decipher = createDecipheriv(
      "aes-256-gcm",
      hex(SEAL_KEY_K1_HEX),
      Buffer.from(iv ?? "", "base64url"),
      { authTagLength: 16 },
    );
    decipher.setAAD(Buffer.from(`identkit/sealed/v1\u0000k1\u0000${context}`, "utf8"));
    decipher.setAuthTag(Buffer.from(tag ?? "", "base64url"));
    const opened = Buffer.concat([
      decipher.update(Buffer.from(ciphertext ?? "", "base64url")),
      decipher.final(),
    ]);
    expect(opened.toString("hex")).toBe(Buffer.from(plaintext).toString("hex"));
    expect(Buffer.from(iv ?? "", "base64url").byteLength).toBe(12);
  });

  it("rule: payload hashes match 0.1.1, sync and async", async () => {
    for (const [payload, digest] of PAYLOAD_HASHES) {
      const input = payload.startsWith("bytes:") ? hex(payload.slice(6)) : payload;
      expect(hashPayload(input), `sync ${payload}`).toBe(digest);
      expect(await hashPayloadAsync(input), `async ${payload}`).toBe(digest);
    }
  });

  it("rule: approval challenges match 0.1.1, sync and async", async () => {
    for (const [nonce, payloadHash, accountId, challenge] of APPROVAL_CHALLENGES) {
      expect(approvalChallenge(nonce, payloadHash, accountId), `sync ${nonce}`).toBe(challenge);
      expect(await approvalChallengeAsync(nonce, payloadHash, accountId), `async ${nonce}`).toBe(
        challenge,
      );
    }
  });
});
