import type { Context } from "./context.js";
import {
  assertMethodAllowed,
  type CodeFailure,
  type OtpEngine,
  type RequestCodeResult,
} from "./email-otp.js";
import type { PasskeyCore } from "./passkey-core.js";
import type { TotpEngine } from "./totp.js";
import type { IssuedSession, SessionInternals } from "./sessions.js";
import {
  authenticationOptions,
  type AuthenticationResponseJSON,
  type PasskeyRequestOptions,
} from "./webauthn.js";

export type StepUpResult =
  | ({ status: "granted" } & IssuedSession)
  | { status: "denied"; reason: "no_session" }
  | CodeFailure;

export interface StepUp {
  /** Sends a step-up code to the address of the session's account. */
  requestEmailCode(
    sessionToken: string,
  ): Promise<RequestCodeResult | { status: "denied"; reason: "no_session" }>;
  /** Verifies a step-up code. On success the session gets a new token. */
  verifyEmailCode(
    sessionToken: string,
    input: { flowId: string; code: string },
  ): Promise<StepUpResult>;
  startPasskey(
    sessionToken: string,
  ): Promise<
    | { status: "ok"; options: PasskeyRequestOptions }
    | { status: "denied"; reason: "no_session" | "no_passkey" }
  >;
  /** Verifies a passkey step-up. On success the session gets a new token. */
  finishPasskey(sessionToken: string, response: AuthenticationResponseJSON): Promise<StepUpResult>;
  /**
   * Verifies a TOTP step-up. On success the session gets a new token. The code's time step
   * is consumed: it cannot sign in, step up or approve again.
   */
  verifyTotp(sessionToken: string, input: { code: string }): Promise<StepUpResult>;
}

export function createStepUp(
  ctx: Context,
  otp: OtpEngine,
  core: PasskeyCore,
  totp: TotpEngine,
  internals: SessionInternals,
): StepUp {
  const { store, clock, config } = ctx;

  const failed = async (
    sessionId: string,
    accountId: string,
    method: string,
    reason: string,
  ): Promise<CodeFailure> => {
    await ctx.emit({ type: "step_up.failed", sessionId, accountId, method, reason });
    return { status: "failed", reason: "invalid" };
  };

  return {
    async requestEmailCode(sessionToken) {
      assertMethodAllowed((await ctx.getPolicy()).stepUpMethods, "email_otp");
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const account = await store.accounts.findById(loaded.record.accountId);
      if (!account || account.status !== "active")
        return { status: "denied", reason: "no_session" };
      return otp.issue({ email: account.email, purpose: "step_up", sessionId: loaded.record.id });
    },

    async verifyEmailCode(sessionToken, input) {
      assertMethodAllowed((await ctx.getPolicy()).stepUpMethods, "email_otp");
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const { record } = loaded;
      const checked = await otp.check({ ...input, purpose: "step_up", sessionId: record.id });
      if (checked.status !== "verified") {
        await ctx.emit({
          type: "step_up.failed",
          sessionId: record.id,
          accountId: record.accountId,
          method: "email_otp",
          reason: checked.reason,
        });
        return checked;
      }
      const issued = await internals.elevate(
        loaded,
        { stepUp: { method: "email_otp", at: clock.now() } },
        "step_up",
      );
      if (!issued) return failed(record.id, record.accountId, "email_otp", "rotation");
      await ctx.emit({
        type: "step_up.granted",
        sessionId: record.id,
        accountId: record.accountId,
        method: "email_otp",
      });
      return { status: "granted", ...issued };
    },

    async startPasskey(sessionToken) {
      assertMethodAllowed((await ctx.getPolicy()).stepUpMethods, "passkey");
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const allow = await core.allowList(loaded.record.accountId);
      if (allow.length === 0) return { status: "denied", reason: "no_passkey" };
      const { challenge } = await core.issueChallenge("step_up", {
        accountId: loaded.record.accountId,
        sessionId: loaded.record.id,
      });
      const options = await authenticationOptions({
        rp: core.rp,
        challenge,
        timeoutSeconds: config.webauthn.challengeTtlSeconds,
        allow,
      });
      return { status: "ok", options };
    },

    async finishPasskey(sessionToken, response) {
      assertMethodAllowed((await ctx.getPolicy()).stepUpMethods, "passkey");
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const { record } = loaded;
      const consumed = await core.consumeChallenge(response?.response?.clientDataJSON, "step_up");
      if (!consumed || consumed.record.sessionId !== record.id) {
        return failed(record.id, record.accountId, "passkey", "challenge");
      }
      const verified = await core.verifyCredentialAssertion({
        response,
        expectedChallenge: consumed.challenge,
        expectedAccountId: record.accountId,
      });
      if (!verified) return failed(record.id, record.accountId, "passkey", "assertion");
      const issued = await internals.elevate(
        loaded,
        { addMethod: "passkey", stepUp: { method: "passkey", at: clock.now() } },
        "step_up",
      );
      if (!issued) return failed(record.id, record.accountId, "passkey", "rotation");
      // A revocation that raced with this ceremony must not leave a fresh step-up behind.
      if (!(await core.isStillCurrent(verified.credential))) {
        if (await store.sessions.revoke(record.id, clock.now(), "credential_revoked")) {
          await ctx.emit({
            type: "session.revoked",
            accountId: record.accountId,
            sessionId: record.id,
            reason: "credential_revoked",
          });
        }
        return failed(record.id, record.accountId, "passkey", "credential_revoked");
      }
      await ctx.emit({
        type: "step_up.granted",
        sessionId: record.id,
        accountId: record.accountId,
        method: "passkey",
        credentialId: verified.credential.id,
      });
      return { status: "granted", ...issued };
    },

    async verifyTotp(sessionToken, input) {
      assertMethodAllowed((await ctx.getPolicy()).stepUpMethods, "totp");
      const loaded = await internals.load(sessionToken, "complete");
      if (!loaded) return { status: "denied", reason: "no_session" };
      const { record } = loaded;
      const checked = await totp.check({
        accountId: record.accountId,
        code: input.code,
        purpose: "step_up",
        sessionId: record.id,
      });
      if (checked.status !== "accepted") {
        await ctx.emit({
          type: "step_up.failed",
          sessionId: record.id,
          accountId: record.accountId,
          method: "totp",
          reason: checked.reason,
        });
        return checked;
      }
      const issued = await internals.elevate(
        loaded,
        { addMethod: "totp", stepUp: { method: "totp", at: clock.now() } },
        "step_up",
      );
      if (!issued) return failed(record.id, record.accountId, "totp", "rotation");
      // A removal that raced with this check must not leave a fresh step-up behind.
      if (!(await totp.isStillCurrent(checked.factor))) {
        if (await store.sessions.revoke(record.id, clock.now(), "factor_removed")) {
          await ctx.emit({
            type: "session.revoked",
            accountId: record.accountId,
            sessionId: record.id,
            reason: "factor_removed",
          });
        }
        return failed(record.id, record.accountId, "totp", "factor_removed");
      }
      await ctx.emit({
        type: "step_up.granted",
        sessionId: record.id,
        accountId: record.accountId,
        method: "totp",
        factorId: checked.factor.id,
      });
      return { status: "granted", ...issued };
    },
  };
}
