import { createHmac, timingSafeEqual } from "node:crypto";
import type { AuditEvent, AuditSink } from "../audit.js";
import { addSeconds, type Clock } from "../clock.js";
import type { MailSender } from "../context.js";
import type { IdentityVerificationAdapter, VendorResult } from "../identity-verification.js";
import type { AssuranceLevel } from "../storage/types.js";

export {
  createSoftwareAuthenticator,
  type SoftwareAuthenticator,
  type SoftwareAuthenticatorOptions,
  type AssertOverrides,
} from "./software-authenticator.js";

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
  /** Secret for the fake callback signature. */
  callbackSecret?: string;
}

export interface FakeIdentityVerificationAdapter extends IdentityVerificationAdapter {
  setOutcome(vendorReference: string, outcome: FakeOutcome, personKey?: string): void;
  /** A signed callback payload, as the fake vendor would send it. */
  callbackFor(vendorReference: string): { vendorReference: string; signature: string };
  references(): string[];
}

/**
 * Identity verification adapter for tests and demos. It contacts nothing. A verification
 * succeeds, fails, or never completes (`time_out`), as configured.
 */
export function createFakeIdentityVerificationAdapter(
  options: FakeIdentityVerificationOptions,
): FakeIdentityVerificationAdapter {
  const secret = options.callbackSecret ?? "fake-callback-secret";
  const state = new Map<string, { outcome: FakeOutcome; personKey: string }>();
  let counter = 0;

  const sign = (reference: string) =>
    createHmac("sha256", secret).update(reference).digest("base64url");

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
    parseCallback(payload) {
      const vendorReference: unknown =
        payload && typeof payload === "object"
          ? Reflect.get(payload, "vendorReference")
          : undefined;
      const signature: unknown =
        payload && typeof payload === "object" ? Reflect.get(payload, "signature") : undefined;
      if (typeof vendorReference !== "string" || typeof signature !== "string") {
        return Promise.reject(new Error("malformed callback"));
      }
      const expected = Buffer.from(sign(vendorReference));
      const actual = Buffer.from(signature);
      if (expected.byteLength !== actual.byteLength || !timingSafeEqual(expected, actual)) {
        return Promise.reject(new Error("callback signature invalid"));
      }
      return Promise.resolve({ vendorReference });
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
    references: () => [...state.keys()],
  };
}
