import { describe, expect, it } from "vitest";
import {
  base32Decode,
  base32Encode,
  hotp,
  matchTimeStep,
  provisioningUri,
  timeStepAt,
  totpAt,
  type TotpAlgorithm,
} from "../src/totp-core.js";

/** RFC 6238 appendix B: seeds per hash function, and the 8-digit codes per time. */
const SEEDS: Record<TotpAlgorithm, Buffer> = {
  SHA1: Buffer.from("12345678901234567890", "ascii"),
  SHA256: Buffer.from("12345678901234567890123456789012", "ascii"),
  SHA512: Buffer.from("1234567890123456789012345678901234567890123456789012345678901234", "ascii"),
};

const VECTORS: [number, string, string, string][] = [
  [59, "94287082", "46119246", "90693936"],
  [1111111109, "07081804", "68084774", "25091201"],
  [1111111111, "14050471", "67062674", "99943326"],
  [1234567890, "89005924", "91819424", "93441116"],
  [2000000000, "69279037", "90698825", "38618901"],
  [20000000000, "65353130", "77737706", "47863826"],
];

describe("TOTP primitives", () => {
  it("rule: RFC 6238 test vectors - SHA-1, SHA-256 and SHA-512, 8 digits", async () => {
    for (const [seconds, sha1, sha256, sha512] of VECTORS) {
      const at = new Date(seconds * 1000);
      expect(await totpAt(SEEDS.SHA1, at, "SHA1", 8), `SHA1 ${seconds}`).toBe(sha1);
      expect(await totpAt(SEEDS.SHA256, at, "SHA256", 8), `SHA256 ${seconds}`).toBe(sha256);
      expect(await totpAt(SEEDS.SHA512, at, "SHA512", 8), `SHA512 ${seconds}`).toBe(sha512);
    }
  });

  it("rule: RFC 6238 test vectors - 6 digits are the last 6 of the 8-digit value", async () => {
    for (const [seconds, sha1] of VECTORS) {
      expect(await totpAt(SEEDS.SHA1, new Date(seconds * 1000), "SHA1", 6)).toBe(sha1.slice(2));
    }
  });

  it("RFC 4226 appendix D: HOTP values for counters 0 to 9", async () => {
    const expected = [
      "755224",
      "287082",
      "359152",
      "969429",
      "338314",
      "254676",
      "287922",
      "162583",
      "399871",
      "520489",
    ];
    const actual = await Promise.all(
      expected.map((_, counter) => hotp(SEEDS.SHA1, counter, "SHA1", 6)),
    );
    expect(actual).toEqual(expected);
  });

  it("rule: drift window - matches only within driftSteps of the current step", async () => {
    const at = new Date(1_893_456_000_000);
    const step = timeStepAt(at);
    const codeAt = (offset: number) => hotp(SEEDS.SHA1, step + offset, "SHA1", 6);
    const match = async (offset: number, driftSteps: number) =>
      matchTimeStep({
        secret: SEEDS.SHA1,
        code: await codeAt(offset),
        at,
        driftSteps,
        algorithm: "SHA1",
        digits: 6,
      });
    expect(await match(0, 0)).toBe(step);
    expect(await match(1, 0)).toBeNull();
    expect(await match(-1, 0)).toBeNull();
    expect(await match(1, 1)).toBe(step + 1);
    expect(await match(-1, 1)).toBe(step - 1);
    expect(await match(2, 1)).toBeNull();
    expect(await match(-2, 1)).toBeNull();
  });

  it("base32 round-trips and matches RFC 4648 examples", () => {
    expect(base32Encode(Buffer.from("foobar"))).toBe("MZXW6YTBOI");
    expect(base32Encode(Buffer.from("f"))).toBe("MY");
    expect(Buffer.from(base32Decode("MZXW6YTBOI")).toString()).toBe("foobar");
    expect(Buffer.from(base32Decode("mzxw6ytboi======")).toString()).toBe("foobar");
    expect(() => base32Decode("MZ1")).toThrow(TypeError);
    for (const bytes of [SEEDS.SHA1, SEEDS.SHA256, SEEDS.SHA512]) {
      expect(Buffer.from(base32Decode(base32Encode(bytes))).equals(bytes)).toBe(true);
    }
  });

  it("builds a provisioning URI with all parameters", () => {
    const uri = new URL(
      provisioningUri({
        secret: SEEDS.SHA1,
        issuer: "Example portal",
        accountName: "person@example.org",
        algorithm: "SHA1",
        digits: 6,
      }),
    );
    expect(uri.protocol).toBe("otpauth:");
    expect(uri.host).toBe("totp");
    expect(decodeURIComponent(uri.pathname)).toBe("/Example portal:person@example.org");
    expect(Object.fromEntries(uri.searchParams)).toEqual({
      secret: base32Encode(SEEDS.SHA1),
      issuer: "Example portal",
      algorithm: "SHA1",
      digits: "6",
      period: "30",
    });
  });
});
