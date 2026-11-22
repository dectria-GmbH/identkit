import { randomBytes } from "node:crypto";
import {
  createHmacHasher,
  createIdentkit,
  createMemoryStore,
  type SignInPolicy,
} from "../src/index.js";
import type { IdentkitStore } from "../src/storage/types.js";
import {
  createFakeClock,
  createFakeIdentityVerificationAdapter,
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
};

export const emailFirstPolicy: SignInPolicy = {
  signInMethods: ["email_otp", "passkey"],
  secondFactor: "none",
  stepUpMethods: ["passkey", "email_otp"],
  createAccountOnFirstSignIn: true,
};

export interface SetupOptions {
  policy?: SignInPolicy;
  store?: IdentkitStore;
  idv?: FakeIdentityVerificationOptions;
  counterStep?: number;
}

export function setup(options: SetupOptions = {}) {
  const clock = createFakeClock();
  const mail = createRecordingMailSender();
  const audit = createRecordingAuditSink();
  const store = options.store ?? createMemoryStore();
  const policy = { current: options.policy ?? emailFirstPolicy };
  const idv = createFakeIdentityVerificationAdapter(options.idv ?? { outcome: "succeed" });
  const ik = createIdentkit({
    config: testConfig,
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
