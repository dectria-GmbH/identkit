import { z } from "zod";

/**
 * Upper bound for the lifetime of a one-time code. NIST SP 800-63B-4 and OWASP ASVS 5.0.0
 * (6.5.5) limit out-of-band codes to 10 minutes; identkit refuses a longer lifetime.
 */
export const MAX_CODE_TTL_SECONDS = 600;

/** NIST SP 800-63B-4 caps consecutive failed attempts per authenticator at 100. */
export const MAX_ADDRESS_FAILURES = 100;

const seconds = (min: number, max: number) => z.number().int().min(min).max(max);

const DAY = 86_400;

const originSchema = z
  .string()
  .url()
  .refine(
    (value) => {
      const url = new URL(value);
      const isLocalhost = url.hostname === "localhost";
      return (
        (url.protocol === "https:" || (isLocalhost && url.protocol === "http:")) &&
        url.pathname === "/" &&
        url.search === "" &&
        url.hash === "" &&
        value === url.origin
      );
    },
    { message: "origin must be an https origin (http only for localhost) without path" },
  );

/**
 * Configuration of identkit. Every time and limit value is required: identkit has no
 * hidden defaults for them. See the configuration table in the README for sources.
 */
export const identkitConfigSchema = z
  .object({
    emailOtp: z
      .object({
        codeTtlSeconds: seconds(60, MAX_CODE_TTL_SECONDS),
        maxAttemptsPerCode: z.number().int().min(1).max(10),
        resendCooldownSeconds: seconds(1, 3600),
        addressLockout: z
          .object({
            maxFailures: z.number().int().min(1).max(MAX_ADDRESS_FAILURES),
            windowSeconds: seconds(60, DAY),
            lockSeconds: seconds(60, DAY),
          })
          .strict(),
      })
      .strict(),
    sessions: z
      .object({
        idleTimeoutSeconds: seconds(60, DAY),
        absoluteTimeoutSeconds: seconds(60, 30 * DAY),
        pendingTimeoutSeconds: seconds(30, 3600),
      })
      .strict()
      .refine((value) => value.absoluteTimeoutSeconds >= value.idleTimeoutSeconds, {
        message: "absoluteTimeoutSeconds must be at least idleTimeoutSeconds",
      }),
    stepUp: z
      .object({
        validitySeconds: seconds(30, 3600),
      })
      .strict(),
    webauthn: z
      .object({
        rpId: z
          .string()
          .min(1)
          .regex(/^[a-z0-9.-]+$/, "rpId must be a lowercase ASCII host name"),
        rpName: z.string().min(1).max(64),
        origins: z.array(originSchema).min(1),
        challengeTtlSeconds: seconds(30, 600),
      })
      .strict(),
    identityVerification: z
      .object({
        timeoutSeconds: seconds(60, 7 * DAY),
      })
      .strict(),
    enrollment: z
      .object({
        tokenTtlSeconds: seconds(60, 7 * DAY),
      })
      .strict(),
  })
  .strict();

export type IdentkitConfig = z.infer<typeof identkitConfigSchema>;

export function parseConfig(input: unknown): IdentkitConfig {
  return identkitConfigSchema.parse(input);
}

export type SignInMethod = "email_otp" | "passkey";
export type StepUpMethod = "email_otp" | "passkey";

/**
 * Operator policy for sign-in. The consumer owns where the policy is stored, who may change
 * it and how changes are approved; identkit enforces the policy on every call.
 */
export const signInPolicySchema = z
  .object({
    /** Methods that may start a session. */
    signInMethods: z.array(z.enum(["email_otp", "passkey"])).min(1),
    /**
     * After an e-mail code sign-in: `none` gives a full session, `passkey_if_enrolled`
     * asks for a passkey when the account has one.
     */
    secondFactor: z.enum(["none", "passkey_if_enrolled"]),
    /** Methods that may satisfy a step-up. A call may narrow this list further. */
    stepUpMethods: z.array(z.enum(["email_otp", "passkey"])).min(1),
    /** If false, an e-mail code sign-in for an unknown address fails like a wrong code. */
    createAccountOnFirstSignIn: z.boolean(),
  })
  .strict();

export type SignInPolicy = z.infer<typeof signInPolicySchema>;
