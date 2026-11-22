import { describe, expect, it } from "vitest";
import {
  createHmacHasher,
  createIdentkit,
  createMemoryStore,
  NotConfiguredError,
} from "../src/index.js";
import { createRecordingAuditSink, createRecordingMailSender } from "../src/testing/index.js";
import { emailFirstPolicy, setup, testConfig } from "./helpers.js";

describe("identity verification", () => {
  it("succeeds through a callback and links the person to the account", async () => {
    const t = setup({ idv: { outcome: "succeed", assuranceLevel: "high", personKey: "person-1" } });
    const user = await t.signIn("person@example.org");
    const started = await t.ik.identityVerification.start({ accountId: user.account.id });
    expect(started.redirectUrl).toMatch(/^https:\/\/verification\.example\//);
    const reference = t.idv.references()[0] ?? "";
    const result = await t.ik.identityVerification.handleCallback(t.idv.callbackFor(reference));
    expect(result).toMatchObject({ status: "verified", assuranceLevel: "high" });
    expect(result.evidenceReference).toContain("evidence-");
    const account = await t.ik.accounts.get(user.account.id);
    expect(account).toMatchObject({ identityVerified: true, assuranceLevel: "high" });
    expect(t.audit.ofType("identity_verification.completed")).toHaveLength(1);
    expect(JSON.stringify(t.audit.events)).not.toContain("person-1");
  });

  it("records a failure", async () => {
    const t = setup({ idv: { outcome: "fail" } });
    const user = await t.signIn("person@example.org");
    const { verificationId } = await t.ik.identityVerification.start({
      accountId: user.account.id,
    });
    expect(await t.ik.identityVerification.refresh(verificationId)).toMatchObject({
      status: "failed",
      failureReason: "document_rejected",
    });
    expect((await t.ik.accounts.get(user.account.id))?.identityVerified).toBe(false);
  });

  it("expires when the vendor does not answer in time", async () => {
    const t = setup({ idv: { outcome: "time_out" } });
    const user = await t.signIn("person@example.org");
    const { verificationId } = await t.ik.identityVerification.start({
      accountId: user.account.id,
    });
    expect((await t.ik.identityVerification.refresh(verificationId))?.status).toBe("pending");
    t.clock.advanceSeconds(testConfig.identityVerification.timeoutSeconds);
    expect(await t.ik.identityVerification.refresh(verificationId)).toMatchObject({
      status: "expired",
      failureReason: "timeout",
    });
    // A late success does not change a final state.
    t.idv.setOutcome(t.idv.references()[0] ?? "", "succeed");
    expect((await t.ik.identityVerification.refresh(verificationId))?.status).toBe("expired");
  });

  it("one account per person: the same person cannot be linked to a second account", async () => {
    const t = setup({ idv: { outcome: "succeed", personKey: "same-person" } });
    const first = await t.signIn("first@example.org");
    const second = await t.signIn("second@example.org");
    const a = await t.ik.identityVerification.start({ accountId: first.account.id });
    expect((await t.ik.identityVerification.refresh(a.verificationId))?.status).toBe("verified");
    const b = await t.ik.identityVerification.start({ accountId: second.account.id });
    expect(await t.ik.identityVerification.refresh(b.verificationId)).toMatchObject({
      status: "conflict",
      failureReason: "person_linked_elsewhere",
    });
    expect((await t.ik.accounts.get(second.account.id))?.identityVerified).toBe(false);
    expect(t.audit.ofType("identity_verification.person_conflict")).toHaveLength(1);
  });

  it("an account linked to one person cannot be relinked to another person", async () => {
    let n = 0;
    const t = setup({ idv: { outcome: "succeed", personKey: () => `person-${(n += 1)}` } });
    const user = await t.signIn("person@example.org");
    const a = await t.ik.identityVerification.start({ accountId: user.account.id });
    expect((await t.ik.identityVerification.refresh(a.verificationId))?.status).toBe("verified");
    const b = await t.ik.identityVerification.start({ accountId: user.account.id });
    expect(await t.ik.identityVerification.refresh(b.verificationId)).toMatchObject({
      status: "conflict",
      failureReason: "account_has_other_person",
    });
  });

  it("rejects a callback with a wrong signature", async () => {
    const t = setup();
    const user = await t.signIn("person@example.org");
    await t.ik.identityVerification.start({ accountId: user.account.id });
    const reference = t.idv.references()[0] ?? "";
    await expect(
      t.ik.identityVerification.handleCallback({ vendorReference: reference, signature: "forged" }),
    ).rejects.toThrow("callback signature invalid");
  });

  it("throws a clear error without an adapter", async () => {
    const ik = createIdentkit({
      config: testConfig,
      store: createMemoryStore(),
      hasher: createHmacHasher(new Uint8Array(32).fill(7)),
      mail: createRecordingMailSender(),
      audit: createRecordingAuditSink(),
      policy: emailFirstPolicy,
    });
    const created = await ik.accounts.create({ email: "person@example.org" });
    if (created.status !== "created") throw new Error("not created");
    await expect(
      ik.identityVerification.start({ accountId: created.account.id }),
    ).rejects.toBeInstanceOf(NotConfiguredError);
  });
});
