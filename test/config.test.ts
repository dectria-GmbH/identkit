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
      ["totp", "issuer"],
      ["totp", "algorithm"],
      ["totp", "digits"],
      ["totp", "driftSteps"],
      ["totp", "enrolmentTtlSeconds"],
      ["totp", "approvalTtlSeconds"],
      ["totp", "lockout"],
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

  it("bounds the TOTP settings: drift window, digits, algorithm, issuer", () => {
    const variants: [string, unknown][] = [
      ["driftSteps", 2],
      ["driftSteps", -1],
      ["digits", 7],
      ["algorithm", "MD5"],
      ["issuer", "a:b"],
      ["issuer", ""],
      ["enrolmentTtlSeconds", 901],
      ["approvalTtlSeconds", 601],
    ];
    for (const [key, value] of variants) {
      const config = structuredClone(testConfig) as unknown as { totp: Record<string, unknown> };
      config.totp[key] = value;
      expect(() => parseConfig(config), `${key}=${String(value)}`).toThrow();
    }
    const lockout = structuredClone(testConfig);
    lockout.totp.lockout.maxFailures = 101;
    expect(() => parseConfig(lockout)).toThrow();
  });

  it("the policy requires second-factor methods and the approval proof level", () => {
    const base = {
      signInMethods: ["email_otp"],
      secondFactor: "if_enrolled",
      secondFactorMethods: ["totp"],
      stepUpMethods: ["totp"],
      approvalProofLevel: "signature",
      createAccountOnFirstSignIn: true,
    };
    expect(() => signInPolicySchema.parse(base)).not.toThrow();
    for (const key of ["secondFactorMethods", "approvalProofLevel"]) {
      const copy: Record<string, unknown> = { ...base };
      delete copy[key];
      expect(() => signInPolicySchema.parse(copy), key).toThrow();
    }
    expect(() => signInPolicySchema.parse({ ...base, secondFactorMethods: [] })).toThrow();
    expect(() =>
      signInPolicySchema.parse({ ...base, secondFactor: "passkey_if_enrolled" }),
    ).toThrow();
    expect(() => signInPolicySchema.parse({ ...base, approvalProofLevel: "none" })).toThrow();
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
        secondFactorMethods: ["passkey"],
        approvalProofLevel: "signature",
        createAccountOnFirstSignIn: true,
      }),
    ).toThrow();
  });
});
