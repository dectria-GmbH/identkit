// Configuration shared by the workerd smoke test and its Node timing run.
export const ORIGIN = "https://portal.example";

export const config = {
  emailOtp: {
    codeTtlSeconds: 600,
    maxAttemptsPerCode: 5,
    resendCooldownSeconds: 30,
    addressLockout: {
      maxFailures: 10,
      windowSeconds: 900,
      maxConsecutiveFailures: 100,
      lockSeconds: 900,
      maxLockSeconds: 86_400,
    },
  },
  sessions: { idleTimeoutSeconds: 900, absoluteTimeoutSeconds: 43_200, pendingTimeoutSeconds: 300 },
  stepUp: { validitySeconds: 300 },
  webauthn: {
    rpId: "portal.example",
    rpName: "Example portal",
    origins: [ORIGIN],
    challengeTtlSeconds: 300,
  },
  identityVerification: { timeoutSeconds: 1800 },
  enrollment: { tokenTtlSeconds: 86_400 },
  totp: {
    issuer: "Example portal",
    algorithm: "SHA1",
    digits: 6,
    driftSteps: 1,
    enrolmentTtlSeconds: 600,
    approvalTtlSeconds: 300,
    lockout: {
      maxFailures: 10,
      windowSeconds: 900,
      maxConsecutiveFailures: 100,
      lockSeconds: 900,
      maxLockSeconds: 86_400,
    },
  },
};

export const oidcConfig = {
  transactionTtlSeconds: 600,
  clockSkewSeconds: 60,
  jwksCacheSeconds: 3600,
  jwksRefetchIntervalSeconds: 60,
  httpTimeoutSeconds: 10,
};

export const OIDC_CLIENT = { clientId: "smoke-client", clientSecret: "smoke-secret" };
export const OIDC_TENANT = "11111111-2222-4333-8444-555555555555";

export const basePolicy = {
  signInMethods: ["email_otp", "passkey"],
  secondFactor: "none",
  secondFactorMethods: ["passkey", "totp"],
  stepUpMethods: ["passkey", "email_otp", "totp"],
  approvalEvidenceLevels: ["signature"],
  createAccountOnFirstSignIn: true,
};
