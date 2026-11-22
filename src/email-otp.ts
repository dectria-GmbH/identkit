import { addSeconds, secondsUntil } from "./clock.js";
import type { Context } from "./context.js";
import { digestsEqual, randomId, randomNumericCode, OTP_DIGITS } from "./crypto.js";
import { normalizeEmail } from "./email.js";
import { MethodNotAllowedError } from "./errors.js";
import type { OtpFlowRecord, OtpPurpose } from "./storage/types.js";

export type RequestCodeResult =
  | { status: "sent"; flowId: string; expiresAt: Date; resendAfter: Date }
  | { status: "cooldown"; retryAfterSeconds: number }
  | { status: "locked"; retryAfterSeconds: number };

export type CodeFailure = { status: "failed"; reason: "invalid" | "expired" | "locked" };

export type CheckCodeResult = { status: "verified"; flow: OtpFlowRecord } | CodeFailure;

const throttleKey = (addressDigest: string) => `otp:${addressDigest}`;

const CODE_PATTERN = new RegExp(`^[0-9]{${OTP_DIGITS}}$`);
const FLOW_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export interface OtpEngine {
  issue(input: {
    email: string;
    purpose: OtpPurpose;
    sessionId: string | null;
  }): Promise<RequestCodeResult>;
  check(input: {
    flowId: string;
    code: string;
    purpose: OtpPurpose;
    sessionId: string | null;
  }): Promise<CheckCodeResult>;
}

/**
 * One-time codes by e-mail. The request path never reads account data, so it does the
 * same work for a known and an unknown address.
 */
export function createOtpEngine(ctx: Context): OtpEngine {
  const { config, store, hasher, clock, mail } = ctx;
  const rules = config.emailOtp;

  const codeDigest = (
    flow: Pick<OtpFlowRecord, "id" | "purpose" | "addressDigest" | "sessionId">,
    code: string,
  ) =>
    hasher.digest(
      "otp-code",
      [flow.id, flow.purpose, flow.addressDigest, flow.sessionId ?? "", code].join("\u0000"),
    );

  async function fail(
    reason: CodeFailure["reason"],
    detail: string,
    flow: OtpFlowRecord | null,
  ): Promise<CodeFailure> {
    await ctx.emit({
      type: "otp.verify_failed",
      ...(flow
        ? { flowId: flow.id, addressDigest: flow.addressDigest, purpose: flow.purpose }
        : {}),
      reason: detail,
    });
    return { status: "failed", reason };
  }

  async function issue(input: {
    email: string;
    purpose: OtpPurpose;
    sessionId: string | null;
  }): Promise<RequestCodeResult> {
    const email = normalizeEmail(input.email);
    const addressDigest = await hasher.digest("address", email);
    const now = clock.now();

    const lockedUntil = await store.throttle.peek(throttleKey(addressDigest), now);
    if (lockedUntil) {
      await ctx.emit({
        type: "otp.send_refused",
        addressDigest,
        purpose: input.purpose,
        reason: "locked",
      });
      return { status: "locked", retryAfterSeconds: secondsUntil(now, lockedUntil) };
    }

    const slot = await store.otp.claimSendSlot(
      `${input.purpose}:${addressDigest}`,
      now,
      rules.resendCooldownSeconds,
    );
    if (!slot.claimed) {
      await ctx.emit({
        type: "otp.send_refused",
        addressDigest,
        purpose: input.purpose,
        reason: "cooldown",
      });
      return { status: "cooldown", retryAfterSeconds: secondsUntil(now, slot.nextAllowedAt) };
    }

    await store.otp.supersedeOpen(addressDigest, input.purpose, now);
    const code = randomNumericCode();
    const base = {
      id: randomId(),
      purpose: input.purpose,
      addressDigest,
      sessionId: input.sessionId,
    };
    const flow: OtpFlowRecord = {
      ...base,
      email,
      codeDigest: await codeDigest(base, code),
      createdAt: now,
      expiresAt: addSeconds(now, rules.codeTtlSeconds),
      attempts: 0,
      maxAttempts: rules.maxAttemptsPerCode,
      consumedAt: null,
      supersededAt: null,
    };
    await store.otp.insert(flow);
    await mail.sendCode({
      to: email,
      code,
      purpose: input.purpose,
      expiresInMinutes: Math.floor(rules.codeTtlSeconds / 60),
    });
    await ctx.emit({ type: "otp.sent", flowId: flow.id, addressDigest, purpose: input.purpose });
    return {
      status: "sent",
      flowId: flow.id,
      expiresAt: flow.expiresAt,
      resendAfter: slot.nextAllowedAt,
    };
  }

  async function check(input: {
    flowId: string;
    code: string;
    purpose: OtpPurpose;
    sessionId: string | null;
  }): Promise<CheckCodeResult> {
    const code: unknown = input.code;
    const codeIsWellFormed = typeof code === "string" && CODE_PATTERN.test(code);
    const flow =
      typeof input.flowId === "string" && FLOW_ID_PATTERN.test(input.flowId)
        ? await store.otp.findById(input.flowId)
        : null;

    if (
      !flow ||
      flow.purpose !== input.purpose ||
      flow.sessionId !== input.sessionId ||
      !codeIsWellFormed
    ) {
      // Same hashing work as a real comparison, then the same failure as a wrong code.
      await hasher.digest("otp-code", `unknown\u0000${typeof code === "string" ? code : ""}`);
      return fail("invalid", flow ? "flow_mismatch" : "unknown_flow", flow);
    }

    const now = clock.now();
    const addressKey = throttleKey(flow.addressDigest);
    if (await store.throttle.peek(addressKey, now)) {
      return fail("locked", "address_locked", flow);
    }
    if (now.getTime() >= flow.expiresAt.getTime()) {
      return fail("expired", "expired", flow);
    }

    const attempt = await store.otp.reserveAttempt(flow.id, now);
    if (attempt.status === "unavailable") return fail("invalid", "not_open", flow);
    if (attempt.status === "exhausted") return fail("locked", "attempts_exhausted", flow);

    const throttle = await store.throttle.reserve(addressKey, now, rules.addressLockout);
    if (!throttle.allowed) {
      if (throttle.lockedNow) {
        await ctx.emit({
          type: "address.locked",
          addressDigest: flow.addressDigest,
          purpose: flow.purpose,
        });
      }
      return fail("locked", "address_locked", flow);
    }

    const matches = digestsEqual(await codeDigest(flow, input.code), flow.codeDigest);
    if (!matches) {
      const lastAttempt = attempt.attempts >= flow.maxAttempts;
      const failure = await fail(lastAttempt ? "locked" : "invalid", "wrong_code", flow);
      if (lastAttempt) {
        await ctx.emit({
          type: "otp.locked",
          flowId: flow.id,
          addressDigest: flow.addressDigest,
          purpose: flow.purpose,
        });
      }
      return failure;
    }

    if (!(await store.otp.consume(flow.id, now))) {
      return fail("invalid", "not_open", flow);
    }
    await store.throttle.reset(addressKey);
    await ctx.emit({
      type: "otp.verified",
      flowId: flow.id,
      addressDigest: flow.addressDigest,
      purpose: flow.purpose,
    });
    return { status: "verified", flow };
  }

  return { issue, check };
}

export function assertMethodAllowed(allowed: readonly string[], method: string): void {
  if (!allowed.includes(method)) throw new MethodNotAllowedError(method);
}
