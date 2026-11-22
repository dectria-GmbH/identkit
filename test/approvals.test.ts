import { describe, expect, it } from "vitest";
import { hashPayload, verifyApprovalEvidence } from "../src/index.js";
import { ORIGIN, RP_ID, setup, testConfig } from "./helpers.js";

const payloadA = hashPayload(JSON.stringify({ request: "release", amount: 100 }));
const payloadB = hashPayload(JSON.stringify({ request: "release", amount: 100000 }));

async function startApproval(t: ReturnType<typeof setup>, token: string, payloadHash: string) {
  const start = await t.ik.approvals.start({ sessionToken: token, payloadHash });
  if (start.status !== "ok") throw new Error(`denied: ${start.reason}`);
  return start.options;
}

describe("approval proofs", () => {
  it("produces a proof bound to the account, the passkey and the payload hash", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const options = await startApproval(t, user.token, payloadA);
    const result = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
      response: t.authenticator.assert(options),
    });
    expect(result.status).toBe("approved");
    if (result.status !== "approved") return;
    expect(result.proof).toMatchObject({
      accountId: user.account.id,
      credentialId: user.credentialId,
      payloadHash: payloadA,
      rpId: RP_ID,
      origin: ORIGIN,
    });
    expect(t.audit.ofType("approval.verified")).toHaveLength(1);
  });

  it("rule: payload binding - an assertion for one payload does not approve another", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const options = await startApproval(t, user.token, payloadA);
    expect(
      await t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadB,
        response: t.authenticator.assert(options),
      }),
    ).toEqual({ status: "failed", reason: "invalid" });
  });

  it("rule: payload binding - an assertion over a self-chosen challenge is rejected", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const options = await startApproval(t, user.token, payloadA);
    const forged = t.authenticator.assert(options, { challenge: "B".repeat(43) });
    expect(
      (
        await t.ik.approvals.verify({
          sessionToken: user.token,
          payloadHash: payloadA,
          response: forged,
        })
      ).status,
    ).toBe("failed");
  });

  it("rule: challenge single use - an approval assertion cannot be replayed", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const options = await startApproval(t, user.token, payloadA);
    const response = t.authenticator.assert(options);
    expect(
      (await t.ik.approvals.verify({ sessionToken: user.token, payloadHash: payloadA, response }))
        .status,
    ).toBe("approved");
    expect(
      (await t.ik.approvals.verify({ sessionToken: user.token, payloadHash: payloadA, response }))
        .status,
    ).toBe("failed");
  });

  it("rule: challenge single use - an approval replay fails also without a counter", async () => {
    const t = setup({ counterStep: 0 });
    const user = await t.userWithPasskey("person@example.org");
    const options = await startApproval(t, user.token, payloadA);
    const response = t.authenticator.assert(options);
    const first = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
      response,
    });
    expect(first.status).toBe("approved");
    const second = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
      response,
    });
    expect(second.status).toBe("failed");
  });

  it("a passkey of another person does not approve for the session's account", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const other = await t.userWithPasskey("other@example.org");
    const options = await startApproval(t, user.token, payloadA);
    const response = t.authenticator.assert(
      { ...options, allowCredentials: [] },
      { credentialId: other.credentialId },
    );
    expect(
      (await t.ik.approvals.verify({ sessionToken: user.token, payloadHash: payloadA, response }))
        .status,
    ).toBe("failed");
  });

  it("an approval challenge does not work as a sign-in or step-up challenge, and the reverse", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const approvalOptions = await startApproval(t, user.token, payloadA);
    expect((await t.ik.passkeys.finishSignIn(t.authenticator.assert(approvalOptions))).status).toBe(
      "failed",
    );

    const { options: signInOptions } = await t.ik.passkeys.startSignIn();
    expect(
      (
        await t.ik.approvals.verify({
          sessionToken: user.token,
          payloadHash: payloadA,
          response: t.authenticator.assert(signInOptions),
        })
      ).status,
    ).toBe("failed");
  });

  it("needs a full session of the account", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const options = await startApproval(t, user.token, payloadA);
    await t.ik.sessions.revoke(user.token);
    expect(
      await t.ik.approvals.verify({
        sessionToken: user.token,
        payloadHash: payloadA,
        response: t.authenticator.assert(options),
      }),
    ).toEqual({ status: "failed", reason: "no_session" });
  });

  it("a removed passkey can no longer approve", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const options = await startApproval(t, user.token, payloadA);
    await t.ik.passkeys.revoke(user.account.id, user.credentialId);
    t.clock.advanceSeconds(testConfig.emailOtp.resendCooldownSeconds);
    const fresh = await t.signIn("person@example.org");
    expect(
      await t.ik.approvals.start({ sessionToken: fresh.token, payloadHash: payloadA }),
    ).toEqual({
      status: "denied",
      reason: "no_passkey",
    });
    void options;
  });

  it("refuses a payload hash that is not a SHA-256 hex digest", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    await expect(
      t.ik.approvals.start({ sessionToken: user.token, payloadHash: "abc" }),
    ).rejects.toThrow(TypeError);
  });

  it("evidence verifies offline with the public key, and not for another payload", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    const options = await startApproval(t, user.token, payloadA);
    const result = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash: payloadA,
      response: t.authenticator.assert(options),
    });
    if (result.status !== "approved") throw new Error("not approved");
    const credential = await t.store.credentials.findById(user.credentialId);
    const verifier = {
      credentialPublicKey: credential?.publicKey ?? new Uint8Array(),
      rpId: RP_ID,
      origins: [ORIGIN],
    };
    expect(await verifyApprovalEvidence(result.proof, verifier)).toBe(true);
    expect(await verifyApprovalEvidence({ ...result.proof, payloadHash: payloadB }, verifier)).toBe(
      false,
    );
    expect(
      await verifyApprovalEvidence(result.proof, {
        ...verifier,
        origins: ["https://other.example"],
      }),
    ).toBe(false);
  });
});
