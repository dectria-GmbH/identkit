import { randomBytes as nodeRandomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  approvalChallenge,
  checkApprovalEvidence,
  hashPayload,
  NodeCryptoUnavailableError,
} from "../src/index.js";
import { IdentkitError } from "../src/errors.js";
import {
  createFakeIdentityVerificationAdapter,
  createSoftwareAuthenticator,
  generateTotpCode,
  generateTotpCodeAsync,
} from "../src/testing/index.js";
import { base32Encode } from "../src/totp-core.js";
import { ORIGIN, RP_ID, setup } from "./helpers.js";

const original = Object.getOwnPropertyDescriptor(process, "getBuiltinModule");

/** Simulates a runtime without `process.getBuiltinModule`, as Cloudflare Workers are. */
function removeGetBuiltinModule() {
  Object.defineProperty(process, "getBuiltinModule", {
    configurable: true,
    writable: true,
    value: undefined,
  });
}

function restoreGetBuiltinModule() {
  if (original) Object.defineProperty(process, "getBuiltinModule", original);
}

afterEach(restoreGetBuiltinModule);

function expectUnavailable(call: () => unknown, alternative: string) {
  let thrown: unknown;
  try {
    call();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(NodeCryptoUnavailableError);
  expect(thrown).toBeInstanceOf(IdentkitError);
  expect((thrown as IdentkitError).code).toBe("node_crypto_unavailable");
  expect((thrown as Error).message).toContain(`use ${alternative}`);
}

const payloadHash = "4f6066c89d67ce45f43d8b020042199188957dfbdb4e927c516c86a32788c5ce";

describe("sync exports that need node:crypto", () => {
  it("rule: without getBuiltinModule they throw an error that names the async sibling", () => {
    const idv = createFakeIdentityVerificationAdapter({ outcome: "succeed" });
    const authenticator = createSoftwareAuthenticator({ origin: "https://app.example" });
    removeGetBuiltinModule();
    expectUnavailable(
      () => approvalChallenge("nonce", payloadHash, "account"),
      "approvalChallengeAsync",
    );
    expectUnavailable(() => hashPayload("payload"), "hashPayloadAsync");
    expectUnavailable(
      () => generateTotpCode({ secret: "JBSWY3DPEHPK3PXP", at: new Date(0) }),
      "generateTotpCodeAsync",
    );
    expectUnavailable(() => idv.callbackFor("ref"), "callbackForAsync");
    expectUnavailable(
      () =>
        authenticator.register({
          rp: { id: "app.example", name: "App" },
          user: { id: "dXNlcg", name: "user", displayName: "user" },
          challenge: "Y2hhbGxlbmdl",
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        }),
      "a Node runtime",
    );
  });

  it("they work again once getBuiltinModule is back", () => {
    removeGetBuiltinModule();
    expect(() => hashPayload("payload")).toThrow(NodeCryptoUnavailableError);
    if (original) Object.defineProperty(process, "getBuiltinModule", original);
    expect(hashPayload("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("rule: generateTotpCode and generateTotpCodeAsync agree for every algorithm", async () => {
    const secret = base32Encode(new Uint8Array(nodeRandomBytes(64)));
    const at = new Date(1_893_456_000_000);
    for (const algorithm of ["SHA1", "SHA256", "SHA512"] as const) {
      for (const digits of [6, 8] as const) {
        const input = { secret, at, algorithm, digits };
        expect(generateTotpCode(input), `${algorithm} ${digits}`).toBe(
          await generateTotpCodeAsync(input),
        );
      }
    }
    // RFC 6238 appendix B, SHA-1, T = 59.
    const rfc = { secret: base32Encode(Buffer.from("12345678901234567890")), at: new Date(59_000) };
    expect(generateTotpCode({ ...rfc, digits: 8 })).toBe("94287082");
    expect(await generateTotpCodeAsync({ ...rfc, digits: 8 })).toBe("94287082");
  });

  it("rule: callbackFor and callbackForAsync sign alike, and both verify", async () => {
    const idv = createFakeIdentityVerificationAdapter({
      outcome: "succeed",
      callbackSecret: "fixed-secret",
    });
    const sync = idv.callbackFor("fake-1-v");
    const async = await idv.callbackForAsync("fake-1-v");
    expect(async).toEqual(sync);
    expect(sync.signature).toBe(
      Buffer.from(
        (await import("node:crypto"))
          .createHmac("sha256", "fixed-secret")
          .update("fake-1-v")
          .digest(),
      ).toString("base64url"),
    );
    await expect(idv.parseCallback(sync)).resolves.toEqual({ vendorReference: "fake-1-v" });
    await expect(idv.parseCallback({ ...sync, signature: `${sync.signature}x` })).rejects.toThrow(
      "callback signature invalid",
    );
  });

  it("rule: identkit's own approval code runs without node:crypto", async () => {
    const t = setup();
    const user = await t.userWithPasskey("person@example.org");
    // Only the software authenticator, a test tool, needs Node; identkit itself must not.
    removeGetBuiltinModule();
    const start = await t.ik.approvals.start({ sessionToken: user.token, payloadHash });
    if (start.status !== "ok" || start.level !== "signature") throw new Error("denied");
    restoreGetBuiltinModule();
    const response = t.authenticator.assert(start.options);
    removeGetBuiltinModule();
    const result = await t.ik.approvals.verify({
      sessionToken: user.token,
      payloadHash,
      response,
    });
    if (result.status !== "approved" || result.evidence.level !== "signature") {
      throw new Error(`not approved: ${result.status}`);
    }
    const credential = await t.store.credentials.findById(user.credentialId);
    const verifier = {
      credentialPublicKey: credential?.publicKey ?? new Uint8Array(),
      rpId: RP_ID,
      origins: [ORIGIN],
    };
    expect(await checkApprovalEvidence({ evidence: result.evidence, verifier })).toEqual({
      status: "verified",
      level: "signature",
    });
  });
});
