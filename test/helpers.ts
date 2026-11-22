import { randomBytes } from "node:crypto";
import {
  createHmacHasher,
  createIdentkit,
  createMemoryStore,
  type SignInPolicy,
} from "../src/index.js";
import type { SecretSealer } from "../src/sealer.js";
import type { IdentkitStore } from "../src/storage/types.js";
import {
  createFakeClock,
  createFakeIdentityVerificationAdapter,
  createTestSealer,
  generateTotpCode,
  createRecordingAuditSink,
  createRecordingMailSender,
  createSoftwareAuthenticator,
  type FakeIdentityVerificationOptions,
} from "../src/testing/index.js";

export const ORIGIN = "https://portal.example";
export const RP_ID = "portal.example";

/** Example values for tests. See the README for which values are assumptions. */
export const testConfig = {
  emailOtp: {
    codeTtlSeconds: 600,
    maxAttemptsPerCode: 5,
    resendCooldownSeconds: 30,
    addressLockout: {
      maxFailures: 10,
      windowSeconds: 900,
      lockSeconds: 900,
      maxLockSeconds: 86_400,
    },
  },
  sessions: { idleTimeoutSeconds: 900, absoluteTimeoutSeconds: 43_200, pendingTimeoutSeconds: 300 },
  stepUp: { validitySeconds: 300 },
  webauthn: { rpId: RP_ID, rpName: "Example portal", origins: [ORIGIN], challengeTtlSeconds: 300 },
  identityVerification: { timeoutSeconds: 1800 },
  enrollment: { tokenTtlSeconds: 86_400 },
  totp: {
    issuer: "Example portal",
    algorithm: "SHA1" as "SHA1" | "SHA256" | "SHA512",
    digits: 6 as 6 | 8,
    driftSteps: 1,
    enrolmentTtlSeconds: 600,
    approvalTtlSeconds: 300,
    lockout: { maxFailures: 10, windowSeconds: 900, lockSeconds: 900, maxLockSeconds: 86_400 },
  },
};

export const emailFirstPolicy: SignInPolicy = {
  signInMethods: ["email_otp", "passkey"],
  secondFactor: "none",
  secondFactorMethods: ["passkey", "totp"],
  stepUpMethods: ["passkey", "email_otp", "totp"],
  approvalProofLevel: "signature",
  createAccountOnFirstSignIn: true,
};

export interface SetupOptions {
  policy?: SignInPolicy;
  store?: IdentkitStore;
  idv?: FakeIdentityVerificationOptions;
  counterStep?: number;
  /** Accounts the consumer marks as privileged, by e-mail address. */
  privilegedEmails?: string[];
  config?: typeof testConfig;
  sealer?: SecretSealer;
}

export function setup(options: SetupOptions = {}) {
  const clock = createFakeClock();
  const mail = createRecordingMailSender();
  const audit = createRecordingAuditSink();
  const store = options.store ?? createMemoryStore();
  const policy = { current: options.policy ?? emailFirstPolicy };
  const idv = createFakeIdentityVerificationAdapter(options.idv ?? { outcome: "succeed" });
  const testSealer = createTestSealer();
  const sealer = options.sealer ?? testSealer;
  const privileged = new Set(options.privilegedEmails ?? []);
  const ik = createIdentkit({
    config: options.config ?? testConfig,
    sealer,
    isPrivilegedAccount: (account) => privileged.has(account.email),
    store,
    hasher: createHmacHasher(randomBytes(32)),
    mail,
    audit,
    clock,
    policy: () => policy.current,
    identityVerification: idv,
  });
  const authenticator = createSoftwareAuthenticator({
    origin: ORIGIN,
    ...(options.counterStep !== undefined ? { counterStep: options.counterStep } : {}),
  });

  async function codeFor(email: string) {
    const requested = await ik.emailSignIn.requestCode({ email });
    if (requested.status !== "sent") throw new Error(`code not sent: ${requested.status}`);
    const code = mail.last()?.code;
    if (!code) throw new Error("no mail");
    return { flowId: requested.flowId, code };
  }

  async function signIn(email: string) {
    const { flowId, code } = await codeFor(email);
    const result = await ik.emailSignIn.verifyCode({ flowId, code });
    if (result.status !== "signed_in") throw new Error(`sign-in failed: ${result.status}`);
    return result;
  }

  async function registerPasskey(token: string) {
    const start = await ik.passkeys.startRegistration({ sessionToken: token });
    if (start.status !== "ok") throw new Error(`registration denied: ${start.reason}`);
    const response = authenticator.register(start.options);
    const finish = await ik.passkeys.finishRegistration({ sessionToken: token }, response);
    if (finish.status !== "registered") throw new Error(`registration failed: ${finish.status}`);
    return finish.credentialId;
  }

  /** The code an authenticator app shows for `secret`, `offsetSeconds` from now. */
  function totpCode(secret: string, offsetSeconds = 0) {
    const at = new Date(clock.now().getTime() + offsetSeconds * 1000);
    return generateTotpCode({ secret, at });
  }

  /** Enrols and confirms TOTP for the session's account. The confirming step is consumed. */
  async function enrolTotp(token: string) {
    const start = await ik.totp.startEnrolment(token);
    if (start.status !== "ok") throw new Error(`enrolment denied: ${start.reason}`);
    const confirmed = await ik.totp.confirmEnrolment(token, {
      factorId: start.factorId,
      code: totpCode(start.secret),
    });
    if (confirmed.status !== "enrolled") throw new Error(`enrolment failed: ${confirmed.status}`);
    return { factorId: start.factorId, secret: start.secret, start };
  }

  /** Signs in by e-mail and registers one passkey. Returns a session with a fresh step-up. */
  async function userWithPasskey(email: string) {
    const session = await signIn(email);
    const credentialId = await registerPasskey(session.token);
    return { ...session, credentialId };
  }

  return {
    ik,
    clock,
    mail,
    audit,
    store,
    policy,
    idv,
    sealer,
    testSealer,
    privileged,
    totpCode,
    enrolTotp,
    authenticator,
    codeFor,
    signIn,
    registerPasskey,
    userWithPasskey,
  };
}

/** A code from the same alphabet that differs from `code`. */
export function otherCode(code: string): string {
  return code === "000000" ? "000001" : "000000";
}

/** E-mail code first, then a second factor (passkey or TOTP) if the account has one. */
export const mfaPolicy: SignInPolicy = {
  signInMethods: ["email_otp", "passkey"],
  secondFactor: "if_enrolled",
  secondFactorMethods: ["passkey", "totp"],
  stepUpMethods: ["passkey", "email_otp", "totp"],
  approvalProofLevel: "signature",
  createAccountOnFirstSignIn: true,
};

/** Seconds per TOTP time step. */
export const STEP = 30;

/** A memory store with hooks that run a concurrent change at the exact point it would hurt. */
export function hookedTotpStore() {
  const inner = createMemoryStore();
  const hooks: {
    afterRecordStep: (() => Promise<void>) | null;
    beforeActivate: (() => Promise<void>) | null;
    /** Number of further revokeAllForAccount calls that throw. */
    failRevokeAll: number;
  } = { afterRecordStep: null, beforeActivate: null, failRevokeAll: 0 };
  const store: IdentkitStore = {
    ...inner,
    sessions: {
      ...inner.sessions,
      revokeAllForAccount: async (...args) => {
        if (hooks.failRevokeAll > 0) {
          hooks.failRevokeAll -= 1;
          throw new Error("store unavailable");
        }
        return inner.sessions.revokeAllForAccount(...args);
      },
    },
    totp: {
      ...inner.totp,
      recordStep: async (...args) => {
        const result = await inner.totp.recordStep(...args);
        const hook = hooks.afterRecordStep;
        hooks.afterRecordStep = null;
        if (hook) await hook();
        return result;
      },
      activate: async (...args) => {
        const hook = hooks.beforeActivate;
        hooks.beforeActivate = null;
        if (hook) await hook();
        return inner.totp.activate(...args);
      },
    },
  };
  return { inner, store, hooks };
}
