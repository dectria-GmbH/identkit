import { describe, expect, it } from "vitest";
import { createHmacHasher, parseConfig, signInPolicySchema } from "../src/index.js";
import { testConfig } from "./helpers.js";

describe("configuration", () => {
  it("accepts the example configuration", () => {
    expect(() => parseConfig(testConfig)).not.toThrow();
  });

  it("has no hidden defaults: every time and limit value is required", () => {
    const paths: [string, string][] = [
      ["emailOtp", "codeTtlSeconds"],
      ["emailOtp", "maxAttemptsPerCode"],
      ["emailOtp", "resendCooldownSeconds"],
      ["emailOtp", "addressLockout"],
      ["sessions", "idleTimeoutSeconds"],
      ["sessions", "absoluteTimeoutSeconds"],
      ["sessions", "pendingTimeoutSeconds"],
      ["stepUp", "validitySeconds"],
      ["webauthn", "challengeTtlSeconds"],
      ["identityVerification", "timeoutSeconds"],
      ["enrollment", "tokenTtlSeconds"],
    ];
    for (const [section, key] of paths) {
      const copy = structuredClone(testConfig) as Record<string, Record<string, unknown>>;
      delete copy[section]?.[key];
      expect(() => parseConfig(copy), `${section}.${key}`).toThrow();
    }
  });

  it("refuses a code lifetime above 10 minutes", () => {
    const config = structuredClone(testConfig);
    config.emailOtp.codeTtlSeconds = 601;
    expect(() => parseConfig(config)).toThrow();
  });

  it("refuses an absolute timeout below the idle timeout", () => {
    const config = structuredClone(testConfig);
    config.sessions.absoluteTimeoutSeconds = 60;
    expect(() => parseConfig(config)).toThrow();
  });

  it("refuses origins with a path, plain http outside localhost, and unknown keys", () => {
    for (const origins of [
      ["https://portal.example/app"],
      ["http://portal.example"],
      ["https://portal.example/"],
    ]) {
      const config = structuredClone(testConfig);
      config.webauthn.origins = origins;
      expect(() => parseConfig(config), origins[0]).toThrow();
    }
    expect(() => parseConfig({ ...testConfig, extra: 1 })).toThrow();
  });

  it("refuses a hash key shorter than 32 bytes", () => {
    expect(() => createHmacHasher(new Uint8Array(31))).toThrow(RangeError);
  });

  it("refuses an empty method list in the policy", () => {
    expect(() =>
      signInPolicySchema.parse({
        signInMethods: [],
        secondFactor: "none",
        stepUpMethods: ["passkey"],
        createAccountOnFirstSignIn: true,
      }),
    ).toThrow();
  });
});
