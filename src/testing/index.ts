import type { AuditEvent, AuditSink } from "../audit.js";
import {
  bytesEqual,
  hmac,
  importHmacKey,
  randomBytes,
  toBase64Url,
  utf8,
  type WebCryptoKey,
} from "../bytes.js";
import { addSeconds, type Clock } from "../clock.js";
import type { MailSender } from "../context.js";
import type { IdentityVerificationAdapter, VendorResult } from "../identity-verification.js";
import { nodeCrypto } from "../node-crypto.js";
import { createAesGcmSealer, SealedSecretError, type SecretSealer } from "../sealer.js";
import {
  base32Decode,
  timeStepAt,
  totpAt,
  truncateHotp,
  type TotpAlgorithm,
  type TotpDigits,
} from "../totp-core.js";
import type { AssuranceLevel } from "../storage/types.js";

export {
  createSoftwareAuthenticator,
  type SoftwareAuthenticator,
  type SoftwareAuthenticatorOptions,
  type AssertOverrides,
} from "./software-authenticator.js";

export interface TestSealer extends SecretSealer {
  /** Number of `open` calls so far. */
  opened(): number;
  /** Makes the next `open` reject, as a wrong key or a changed value would. */
  failNextOpen(): void;
}

/**
 * Sealer for tests: AES-256-GCM with a random key that lives only in this process, plus a
 * switch to simulate an unreadable value. Not for production: the key is lost on exit.
 */
export function createTestSealer(): TestSealer {
  const inner = createAesGcmSealer({ keys: { test: randomBytes(32) }, activeKeyId: "test" });
  let opens = 0;
  let failNext = false;
  return {
    seal: (plaintext, context) => inner.seal(plaintext, context),
    open: (sealed, context) => {
      opens += 1;
      if (failNext) {
        failNext = false;
        return Promise.reject(new SealedSecretError());
      }
      return inner.open(sealed, context);
    },
    opened: () => opens,
    failNextOpen: () => {
      failNext = true;
    },
  };
}

export interface TotpCodeInput {
  /** The secret, base32, as the enrolment returns it. */
  secret: string;
  at: Date;
  algorithm?: TotpAlgorithm;
  digits?: TotpDigits;
}

/**
 * Computes the TOTP code an authenticator app would show for a base32 secret at `at`, for
 * tests and demos.
 */
export function generateTotpCodeAsync(input: TotpCodeInput): Promise<string> {
  return totpAt(base32Decode(input.secret), input.at, input.algorithm ?? "SHA1", input.digits ?? 6);
}

/**
 * Same result as `generateTotpCodeAsync`, computed synchronously.
 *
 * Node only; use generateTotpCodeAsync on Web Crypto runtimes. Elsewhere it throws
 * `NodeCryptoUnavailableError`.
 */
export function generateTotpCode(input: TotpCodeInput): string {
  const node = nodeCrypto("generateTotpCode", "generateTotpCodeAsync");
  const algorithm = input.algorithm ?? "SHA1";
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(timeStepAt(input.at)));
  const mac = node
    .createHmac(algorithm.toLowerCase(), base32Decode(input.secret))
    .update(message)
    .digest();
  return truncateHotp(mac, input.digits ?? 6);
}

export interface FakeClock extends Clock {
  set(date: Date): void;
  advanceSeconds(seconds: number): void;
}

export function createFakeClock(start = new Date("2030-01-01T00:00:00.000Z")): FakeClock {
  let current = new Date(start);
  return {
    now: () => new Date(current),
    set: (date) => {
      current = new Date(date);
    },
    advanceSeconds: (seconds) => {
      current = addSeconds(current, seconds);
    },
  };
}

export interface SentCode {
  to: string;
  code: string;
  purpose: string;
  expiresInMinutes: number;
}

export interface RecordingMailSender extends MailSender {
  sent: SentCode[];
  last(): SentCode | undefined;
}

/** Mail sender that keeps the messages in memory. */
export function createRecordingMailSender(): RecordingMailSender {
  const sent: SentCode[] = [];
  return {
    sent,
    sendCode: (message) => {
      sent.push({ ...message });
      return Promise.resolve();
    },
    last: () => sent.at(-1),
  };
}

export interface RecordingAuditSink extends AuditSink {
  events: AuditEvent[];
  ofType(type: AuditEvent["type"]): AuditEvent[];
}

export function createRecordingAuditSink(): RecordingAuditSink {
  const events: AuditEvent[] = [];
  return {
    events,
    emit: (event) => {
      events.push(event);
    },
    ofType: (type) => events.filter((e) => e.type === type),
  };
}

export type FakeOutcome = "succeed" | "fail" | "time_out";

export interface FakeIdentityVerificationOptions {
  /** Outcome for every new verification. Change it later with `setOutcome`. */
  outcome: FakeOutcome;
  assuranceLevel?: AssuranceLevel;
  /** Person key that a successful verification reports. Default: one key per verification. */
  personKey?: string | ((verificationId: string) => string);
  /**
   * Secret for the fake callback signature. Default: 32 random bytes per adapter, so no
   * known value can sign a callback. `callbackFor` signs with the secret in use.
   */
  callbackSecret?: string;
}

export interface FakeIdentityVerificationAdapter extends IdentityVerificationAdapter {
  setOutcome(vendorReference: string, outcome: FakeOutcome, personKey?: string): void;
  /** A signed callback payload, as the fake vendor would send it. */
  callbackForAsync(
    vendorReference: string,
  ): Promise<{ vendorReference: string; signature: string }>;
  /**
   * Same result as `callbackForAsync`, computed synchronously.
   *
   * Node only; use callbackForAsync on Web Crypto runtimes. Elsewhere it throws
   * `NodeCryptoUnavailableError`.
   */
  callbackFor(vendorReference: string): { vendorReference: string; signature: string };
  references(): string[];
}

/**
 * Identity verification adapter for tests and demos. It contacts nothing. A verification
 * succeeds, fails, or never completes (`time_out`), as configured.
 *
 * Unsafe for production: it verifies nobody. With `outcome: "succeed"` every verification
 * succeeds and links whatever person key it reports. Never wire it into a deployment.
 */
export function createFakeIdentityVerificationAdapter(
  options: FakeIdentityVerificationOptions,
): FakeIdentityVerificationAdapter {
  const secret = options.callbackSecret ?? toBase64Url(randomBytes(32));
  const state = new Map<string, { outcome: FakeOutcome; personKey: string }>();
  let counter = 0;

  const sign = (reference: string) =>
    nodeCrypto("callbackFor", "callbackForAsync")
      .createHmac("sha256", secret)
      .update(reference)
      .digest("base64url");
  let key: Promise<WebCryptoKey> | undefined;
  const signAsync = async (reference: string) => {
    key ??= importHmacKey(utf8(secret), "SHA-256");
    return toBase64Url(await hmac(await key, utf8(reference)));
  };

  return {
    start({ verificationId }) {
      counter += 1;
      const vendorReference = `fake-${counter}-${verificationId}`;
      const personKey =
        typeof options.personKey === "function"
          ? options.personKey(verificationId)
          : (options.personKey ?? `person-${verificationId}`);
      state.set(vendorReference, { outcome: options.outcome, personKey });
      return Promise.resolve({
        vendorReference,
        redirectUrl: `https://verification.example/session/${vendorReference}`,
      });
    },
    async parseCallback(payload) {
      const vendorReference: unknown =
        payload && typeof payload === "object"
          ? Reflect.get(payload, "vendorReference")
          : undefined;
      const signature: unknown =
        payload && typeof payload === "object" ? Reflect.get(payload, "signature") : undefined;
      if (typeof vendorReference !== "string" || typeof signature !== "string") {
        throw new Error("malformed callback");
      }
      if (!bytesEqual(utf8(await signAsync(vendorReference)), utf8(signature))) {
        throw new Error("callback signature invalid");
      }
      return { vendorReference };
    },
    fetchResult(vendorReference): Promise<VendorResult> {
      const entry = state.get(vendorReference);
      if (!entry) return Promise.reject(new Error("unknown reference"));
      switch (entry.outcome) {
        case "succeed":
          return Promise.resolve({
            status: "verified",
            assuranceLevel: options.assuranceLevel ?? "substantial",
            evidenceReference: `evidence-${vendorReference}`,
            personKey: entry.personKey,
          });
        case "fail":
          return Promise.resolve({ status: "failed", reason: "document_rejected" });
        case "time_out":
        default:
          return Promise.resolve({ status: "pending" });
      }
    },
    setOutcome(vendorReference, outcome, personKey) {
      const entry = state.get(vendorReference);
      if (!entry) throw new Error("unknown reference");
      entry.outcome = outcome;
      if (personKey !== undefined) entry.personKey = personKey;
    },
    callbackFor: (vendorReference) => ({ vendorReference, signature: sign(vendorReference) }),
    callbackForAsync: async (vendorReference) => ({
      vendorReference,
      signature: await signAsync(vendorReference),
    }),
    references: () => [...state.keys()],
  };
}
