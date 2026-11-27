import { randomBytes as nodeRandomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  bytesEqual,
  concatBytes,
  fromBase64Url,
  randomBytes,
  randomInt,
  toBase64Url,
  toHex,
  utf8,
} from "../src/bytes.js";
import { digestsEqual, randomNumericCode } from "../src/crypto.js";

afterEach(() => {
  vi.restoreAllMocks();
});

/** Makes getRandomValues return the given 32-bit values, one per call. */
function feedUint32(values: number[]) {
  const queue = [...values];
  return vi
    .spyOn(crypto, "getRandomValues")
    .mockImplementation(<T extends ArrayBufferView>(array: T): T => {
      const next = queue.shift();
      if (next === undefined) throw new Error("no more values");
      new DataView(array.buffer, array.byteOffset, array.byteLength).setUint32(0, next, true);
      return array;
    });
}

describe("byte helpers", () => {
  it("rule: constant-time compare - equal, different and different-length inputs", () => {
    expect(bytesEqual(utf8("abc"), utf8("abc"))).toBe(true);
    expect(bytesEqual(utf8("abc"), utf8("abd"))).toBe(false);
    expect(bytesEqual(utf8("abc"), utf8("ab"))).toBe(false);
    expect(bytesEqual(utf8("ab"), utf8("abc"))).toBe(false);
    // A longer input whose extra bytes are zero must not compare equal.
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1, 2, 0]), new Uint8Array([1, 2]))).toBe(false);
    expect(bytesEqual(new Uint8Array(), new Uint8Array())).toBe(true);
    expect(digestsEqual("00ff", "00ff")).toBe(true);
    expect(digestsEqual("00ff", "00fe")).toBe(false);
    expect(digestsEqual("00ff", "00ff0")).toBe(false);
  });

  it("rule: randomInt rejects draws above the largest multiple of the range", () => {
    // Range 10**6: 2**32 % 10**6 = 967296, so draws from 4294000000 up are biased.
    const limit = 2 ** 32 - (2 ** 32 % 10 ** 6);
    const spy = feedUint32([limit, 2 ** 32 - 1, 123]);
    expect(randomInt(0, 10 ** 6)).toBe(123);
    expect(spy).toHaveBeenCalledTimes(3);
    spy.mockRestore();
    feedUint32([limit - 1]);
    expect(randomInt(0, 10 ** 6)).toBe((limit - 1) % 10 ** 6);
  });

  it("randomInt stays in range and rejects bad bounds", () => {
    for (let i = 0; i < 200; i += 1) {
      const value = randomInt(5, 8);
      expect(value).toBeGreaterThanOrEqual(5);
      expect(value).toBeLessThan(8);
    }
    expect(() => randomInt(3, 3)).toThrow(RangeError);
    expect(() => randomInt(0, 2 ** 32 + 1)).toThrow(RangeError);
    expect(randomNumericCode()).toMatch(/^\d{6}$/);
  });

  it("randomBytes fills more than one getRandomValues block", () => {
    const bytes = randomBytes(70_000);
    expect(bytes.byteLength).toBe(70_000);
    expect(bytes.subarray(65_536).some((b) => b !== 0)).toBe(true);
  });

  it("base64url and hex match Buffer for every length up to 64", () => {
    for (let length = 0; length <= 64; length += 1) {
      const bytes = new Uint8Array(nodeRandomBytes(length));
      const text = Buffer.from(bytes).toString("base64url");
      expect(toBase64Url(bytes)).toBe(text);
      expect(toHex(bytes)).toBe(Buffer.from(bytes).toString("hex"));
      expect(Buffer.from(fromBase64Url(text) ?? []).equals(Buffer.from(bytes))).toBe(true);
    }
    expect(fromBase64Url("abcde")).toBeNull();
    expect(fromBase64Url("ab+c")).toBeNull();
    expect(fromBase64Url("ab=c")).toBeNull();
    expect(toHex(concatBytes(new Uint8Array([1]), new Uint8Array([2, 255])))).toBe("0102ff");
  });

  it("utf8 matches Buffer, including a lone surrogate", () => {
    for (const text of ["", "abc", "Grüße \u{1F511}", "lone \uD800 end"]) {
      expect(Buffer.from(utf8(text)).equals(Buffer.from(text, "utf8"))).toBe(true);
    }
  });
});
