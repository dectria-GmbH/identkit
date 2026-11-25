import { z } from "zod";

/**
 * Upper bound for the lifetime of a one-time code. NIST SP 800-63B-4 and OWASP ASVS 5.0.0
 * (6.5.5) limit out-of-band codes to 10 minutes; identkit refuses a longer lifetime.
 */
export const MAX_CODE_TTL_SECONDS = 600;

/**
 * Upper bound for `maxFailures` and `maxConsecutiveFailures`, taken from NIST SP 800-63B-4
 * (at most 100 consecutive failed attempts per authenticator).
 */
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
 * Failure counting with escalating locks, shared by e-mail codes and TOTP. Two limits apply:
 * `maxFailures` per window, and `maxConsecutiveFailures` since the last success, across
 * windows. After the consecutive limit, each lock lets one attempt through.
 */
const lockoutSchema = z
  .object({
    maxFailures: z.number().int().min(1).max(MAX_ADDRESS_FAILURES),
    windowSeconds: seconds(60, DAY),
    maxConsecutiveFailures: z.number().int().min(1).max(MAX_ADDRESS_FAILURES),
    lockSeconds: seconds(60, DAY),
    maxLockSeconds: seconds(60, 30 * DAY),
  })
  .strict()
  .refine((value) => value.maxLockSeconds >= value.lockSeconds, {
    message: "maxLockSeconds must be at least lockSeconds",
  })
  .refine((value) => value.maxConsecutiveFailures >= value.maxFailures, {
    message: "maxConsecutiveFailures must be at least maxFailures",
  });

/** RFC 6238 section 5.2 recommends at most one time step of tolerance. */
export const MAX_TOTP_DRIFT_STEPS = 1;

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
        addressLockout: lockoutSchema,
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
    totp: z
      .object({
        /** Shown by the authenticator app. A colon would break the provisioning URI label. */
        issuer: z
          .string()
          .min(1)
          .max(64)
          .regex(/^[^:]+$/, "issuer must not contain a colon"),
        /**
         * Hash function for new factors. `SHA1` is the interoperable choice: several
         * authenticator apps ignore any other value. An enrolled factor keeps its own.
         */
        algorithm: z.enum(["SHA1", "SHA256", "SHA512"]),
        /** Code length for new factors. 6 is the interoperable choice. */
        digits: z.union([z.literal(6), z.literal(8)]),
        /** Time steps accepted on either side of the current one, for clock drift. */
        driftSteps: z.number().int().min(0).max(MAX_TOTP_DRIFT_STEPS),
        /** Time to confirm an enrolment with a first code. */
        enrolmentTtlSeconds: seconds(60, 900),
        /** Lifetime of a pending approval that waits for a code confirmation. */
        approvalTtlSeconds: seconds(30, 600),
        /** Failed codes per account, across sign-in, step-up and approval. */
        lockout: lockoutSchema,
      })
      .strict(),
  })
  .strict();

export type IdentkitConfig = z.infer<typeof identkitConfigSchema>;

export function parseConfig(input: unknown): IdentkitConfig {
  return identkitConfigSchema.parse(input);
}

export type SignInMethod = "email_otp" | "passkey";
/** A method that can complete a sign-in after an e-mail code. */
export type SecondFactorMethod = "passkey" | "totp";
/** Every method a session can record. TOTP never starts a session on its own. */
export type AuthMethod = SignInMethod | "totp";
export type StepUpMethod = "email_otp" | "passkey" | "totp";
/**
 * `signature`: a passkey signature over a challenge that commits to the payload. Anyone with
 * the public key can check it again. `code-confirmation`: a TOTP code, recorded by the
 * server. It is not bound to the payload and cannot be checked by a third party.
 */
export type ApprovalEvidenceLevel = "signature" | "code-confirmation";

/**
 * Operator policy for sign-in. The consumer owns where the policy is stored, who may change
 * it and how changes are approved; identkit enforces the policy on every call.
 */
export const signInPolicySchema = z
  .object({
    /** Methods that may start a session. */
    signInMethods: z.array(z.enum(["email_otp", "passkey"])).min(1),
    /**
     * After an e-mail code sign-in: `none` gives a full session, `if_enrolled` asks for a
     * second factor when the account has one (passkey or TOTP). A privileged account always
     * needs one, whatever this value says.
     */
    secondFactor: z.enum(["none", "if_enrolled"]),
    /** Methods that may complete a sign-in as second factor. */
    secondFactorMethods: z.array(z.enum(["passkey", "totp"])).min(1),
    /** Methods that may satisfy a step-up. A call may narrow this list further. */
    stepUpMethods: z.array(z.enum(["email_otp", "passkey", "totp"])).min(1),
    /**
     * Approval evidence levels accepted, exactly as listed. `["signature"]` refuses code
     * confirmations; list both to accept both. A call can narrow this list, never widen it.
     */
    approvalEvidenceLevels: z.array(z.enum(["signature", "code-confirmation"])).min(1),
    /** If false, an e-mail code sign-in for an unknown address fails like a wrong code. */
    createAccountOnFirstSignIn: z.boolean(),
  })
  .strict();

export type SignInPolicy = z.infer<typeof signInPolicySchema>;
